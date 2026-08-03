#include <string.h>

#include "sms.h"
#include "sms_intl.h"

/* TPDU encode — TS 23.040 §9.2.2.x.
 *
 * The mirror of sms.c: a running cursor over the caller's buffer, one
 * bounds check per field, no allocation. Unlike the text codecs there
 * is no sticky-overflow write buffer here, because a TPDU is small,
 * fixed-shape and built in one call — sms_tpdu_encode() either writes
 * the whole thing or returns SMS_E_OVERFLOW having written nothing the
 * caller should look at.
 *
 * The octet-0 flag layout is per type and asymmetric (TP-SRI only
 * exists in a DELIVER, TP-SRR only in a SUBMIT or COMMAND), so each
 * branch composes its own byte rather than sharing a "flags" helper
 * that would have to know the type anyway. */

typedef struct {
    uint8_t* b;
    size_t   cap;
    size_t   off;
} wr_t;

static bool room(const wr_t* w, size_t k)
{
    return w->cap - w->off >= k;
}

static void put8(wr_t* w, uint8_t v)
{
    w->b[w->off++] = v;
}

/* TP-UDL + TP-UD. The length field is taken from the struct rather than
 * recomputed: for a 7-bit DCS it counts septets, which the packed
 * octets cannot tell us (140 octets is 160 septets, but so is any
 * shorter septet count that rounds to the same octet total). */
static int write_ud(wr_t* w, const sms_ud_t* ud)
{
    if (ud->len > SMS_UD_MAX) return SMS_E_LENGTH;
    if (ud->len && ud->p == NULL) return SMS_E_INVAL;
    if (!room(w, 1u + ud->len)) return SMS_E_OVERFLOW;
    put8(w, ud->udl);
    if (ud->len) {
        memcpy(w->b + w->off, ud->p, ud->len);
        w->off += ud->len;
    }
    return SMS_OK;
}

/* The optional TP-PI-driven tail (§9.2.3.27). The PI octet is derived
 * from the has_* flags rather than trusted from the struct, so a caller
 * cannot announce a field it did not fill. */
static uint8_t pi_of(bool has_pid, bool has_dcs, bool has_ud, uint8_t pi)
{
    uint8_t v = (uint8_t)(pi & 0x80); /* keep the extension bit */
    if (has_pid) v |= 0x01;
    if (has_dcs) v |= 0x02;
    if (has_ud) v |= 0x04;
    return v;
}

static int write_pi_tail(wr_t* w, bool has_pid, uint8_t pid, bool has_dcs,
                         uint8_t dcs, bool has_ud, const sms_ud_t* ud)
{
    if (has_pid) {
        if (!room(w, 1)) return SMS_E_OVERFLOW;
        put8(w, pid);
    }
    if (has_dcs) {
        if (!room(w, 1)) return SMS_E_OVERFLOW;
        put8(w, dcs);
    }
    if (has_ud) return write_ud(w, ud);
    return SMS_OK;
}

static int write_addr(wr_t* w, const sms_addr_t* a)
{
    int rc = sms_addr_encode(w->b + w->off, w->cap - w->off, a);
    if (rc < 0) return rc;
    w->off += (size_t)rc;
    return SMS_OK;
}

static int write_ts(wr_t* w, const sms_ts_t* t)
{
    int rc = sms_ts_encode(w->b + w->off, w->cap - w->off, t);
    if (rc < 0) return rc;
    w->off += (size_t)rc;
    return SMS_OK;
}

int sms_tpdu_encode(uint8_t* b, size_t cap, const sms_tpdu_t* t)
{
    if (b == NULL || t == NULL) return SMS_E_INVAL;
    if (t->type >= SMS_T_MAX) return SMS_E_INVAL;
    if (cap < 1) return SMS_E_OVERFLOW;

    wr_t w  = { b, cap, 0 };
    int  rc = SMS_OK;

    switch (t->type) {
    case SMS_T_DELIVER: {
        const sms_deliver_t* m  = &t->u.deliver;
        uint8_t              o0 = 0x00; /* MTI = 00 */
        if (m->mms) o0 |= 0x04;
        if (m->lp) o0 |= 0x08;
        if (m->sri) o0 |= 0x20;
        if (m->udhi) o0 |= 0x40;
        if (m->rp) o0 |= 0x80;
        put8(&w, o0);
        if ((rc = write_addr(&w, &m->oa)) < 0) return rc;
        if (!room(&w, 2)) return SMS_E_OVERFLOW;
        put8(&w, m->pid);
        put8(&w, m->dcs);
        if ((rc = write_ts(&w, &m->scts)) < 0) return rc;
        if ((rc = write_ud(&w, &m->ud)) < 0) return rc;
        break;
    }
    case SMS_T_SUBMIT: {
        const sms_submit_t* m = &t->u.submit;
        if (m->vp.fmt > SMS_VPF_ABSOLUTE) return SMS_E_INVAL;
        uint8_t o0 = 0x01; /* MTI = 01 */
        if (m->rd) o0 |= 0x04;
        o0 |= (uint8_t)((m->vp.fmt & 0x03) << 3);
        if (m->srr) o0 |= 0x20;
        if (m->udhi) o0 |= 0x40;
        if (m->rp) o0 |= 0x80;
        put8(&w, o0);
        if (!room(&w, 1)) return SMS_E_OVERFLOW;
        put8(&w, m->mr);
        if ((rc = write_addr(&w, &m->da)) < 0) return rc;
        if (!room(&w, 2)) return SMS_E_OVERFLOW;
        put8(&w, m->pid);
        put8(&w, m->dcs);
        switch (m->vp.fmt) {
        case SMS_VPF_NONE: break;
        case SMS_VPF_RELATIVE:
            if (!room(&w, 1)) return SMS_E_OVERFLOW;
            put8(&w, m->vp.rel);
            break;
        case SMS_VPF_ABSOLUTE:
            if ((rc = write_ts(&w, &m->vp.abs)) < 0) return rc;
            break;
        case SMS_VPF_ENHANCED:
            if (!room(&w, 7)) return SMS_E_OVERFLOW;
            memcpy(w.b + w.off, m->vp.enh, 7);
            w.off += 7;
            break;
        default: return SMS_E_INVAL;
        }
        if ((rc = write_ud(&w, &m->ud)) < 0) return rc;
        break;
    }
    case SMS_T_STATUS_REPORT: {
        const sms_status_report_t* m  = &t->u.status_report;
        uint8_t                    o0 = 0x02; /* MTI = 10 */
        if (m->mms) o0 |= 0x04;
        if (m->lp) o0 |= 0x08;
        if (m->srq) o0 |= 0x20;
        if (m->udhi) o0 |= 0x40;
        put8(&w, o0);
        if (!room(&w, 1)) return SMS_E_OVERFLOW;
        put8(&w, m->mr);
        if ((rc = write_addr(&w, &m->ra)) < 0) return rc;
        if ((rc = write_ts(&w, &m->scts)) < 0) return rc;
        if ((rc = write_ts(&w, &m->dt)) < 0) return rc;
        if (!room(&w, 1)) return SMS_E_OVERFLOW;
        put8(&w, m->st);
        /* TP-PI is optional here; emit it only when the caller asked
         * for it or filled something it gates. */
        if (m->has_pi || m->has_pid || m->has_dcs || m->has_ud) {
            if (!room(&w, 1)) return SMS_E_OVERFLOW;
            put8(&w, pi_of(m->has_pid, m->has_dcs, m->has_ud, m->pi));
            rc = write_pi_tail(&w, m->has_pid, m->pid, m->has_dcs, m->dcs,
                               m->has_ud, &m->ud);
            if (rc < 0) return rc;
        }
        break;
    }
    case SMS_T_COMMAND: {
        const sms_command_t* m  = &t->u.command;
        uint8_t              o0 = 0x02; /* MTI = 10 */
        if (m->srr) o0 |= 0x20;
        if (m->udhi) o0 |= 0x40;
        put8(&w, o0);
        if (!room(&w, 4)) return SMS_E_OVERFLOW;
        put8(&w, m->mr);
        put8(&w, m->pid);
        put8(&w, m->ct);
        put8(&w, m->mn);
        if ((rc = write_addr(&w, &m->da)) < 0) return rc;
        if (m->cdl > SMS_CD_MAX) return SMS_E_LENGTH;
        if (m->cdl && m->cd == NULL) return SMS_E_INVAL;
        if (!room(&w, 1u + m->cdl)) return SMS_E_OVERFLOW;
        put8(&w, m->cdl);
        if (m->cdl) {
            memcpy(w.b + w.off, m->cd, m->cdl);
            w.off += m->cdl;
        }
        break;
    }
    case SMS_T_DELIVER_REPORT:
    case SMS_T_SUBMIT_REPORT:  {
        const sms_report_t* m  = &t->u.report;
        uint8_t             o0 = t->type == SMS_T_SUBMIT_REPORT ? 0x01 : 0x00;
        if (m->udhi) o0 |= 0x40;
        put8(&w, o0);
        if (m->has_fcs) {
            if (!room(&w, 1)) return SMS_E_OVERFLOW;
            put8(&w, m->fcs);
        }
        if (!room(&w, 1)) return SMS_E_OVERFLOW;
        put8(&w, pi_of(m->has_pid, m->has_dcs, m->has_ud, m->pi));
        if (t->type == SMS_T_SUBMIT_REPORT) {
            if ((rc = write_ts(&w, &m->scts)) < 0) return rc;
        }
        rc = write_pi_tail(&w, m->has_pid, m->pid, m->has_dcs, m->dcs,
                           m->has_ud, &m->ud);
        if (rc < 0) return rc;
        break;
    }
    default: return SMS_E_INVAL;
    }
    return (int)w.off;
}
