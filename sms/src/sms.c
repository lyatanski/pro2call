#include <string.h>

#include "sms.h"
#include "sms_intl.h"

/* TPDU decode (TS 23.040 §9.2.2.x) plus the field codecs and name
 * tables the encoder in sms_write.c shares.
 *
 * Every decoder here takes the remaining buffer and returns how much
 * of it it consumed, so the message-level walk is a running cursor and
 * a single bounds check per field. Nothing reads past `n`. */

/* ---- cursor ---- */

typedef struct {
    const uint8_t* b;
    size_t         n;
    size_t         off;
} rd_t;

static bool need(const rd_t* r, size_t k)
{
    return r->n - r->off >= k;
}

static uint8_t u8(rd_t* r)
{
    return r->b[r->off++];
}

/* ---- addresses (§9.1.2.5) ---- */

int sms_addr_decode(const uint8_t* b, size_t n, sms_addr_t* out)
{
    if (b == NULL || out == NULL) return SMS_E_INVAL;
    if (n < 2) return SMS_E_SHORT;

    memset(out, 0, sizeof *out);
    unsigned alen = b[0]; /* useful semi-octets, not octets */
    uint8_t  toa  = b[1];
    out->ton      = (uint8_t)((toa >> 4) & 0x07);
    out->npi      = (uint8_t)(toa & 0x0F);

    if (alen > SMS_ADDR_MAX_DIGITS) return SMS_E_LENGTH;
    size_t vlen = (alen + 1) / 2; /* value octets */
    if (n < 2 + vlen) return SMS_E_SHORT;

    if (out->ton == SMS_TON_ALPHANUM) {
        /* The "digits" are GSM 7-bit packed text. The semi-octet count
         * only bounds the octets, so the septet count is whatever fits
         * — floor(bits/7) — which is why an alphanumeric address does
         * not survive a round-trip bit-for-bit and nobody sends one
         * expecting it to. */
        size_t  septets = (vlen * 8) / 7;
        uint8_t sep[16];
        if (septets > sizeof sep) septets = sizeof sep;
        int got = sms_gsm7_unpack(b + 2, vlen, 0, septets, sep, sizeof sep);
        if (got < 0) return got;
        int len =
            sms_gsm7_to_utf8(sep, (size_t)got, out->digits, sizeof out->digits);
        if (len < 0) return len;
    } else {
        /* alen counts semi-octets, so it — not vlen — decides where the
         * number ends; the last high nibble of an odd-length address is
         * the 0xF filler and must not become a digit. A filler that
         * turns up before then is a malformed field, not a short one. */
        size_t k = 0;
        for (size_t i = 0; i < vlen && k < alen; i++) {
            uint8_t o = b[2 + i];
            char    c = sms_bcd_char(o & 0x0F);
            if (c == '\0') return SMS_E_LENGTH;
            out->digits[k++] = c;
            if (k == alen) break;
            c = sms_bcd_char((uint8_t)(o >> 4));
            if (c == '\0') return SMS_E_LENGTH;
            out->digits[k++] = c;
        }
        out->digits[k] = '\0';
    }
    return (int)(2 + vlen);
}

int sms_addr_encode(uint8_t* b, size_t cap, const sms_addr_t* a)
{
    if (b == NULL || a == NULL) return SMS_E_INVAL;
    if (a->ton > 7 || a->npi > 15) return SMS_E_INVAL;
    uint8_t toa = (uint8_t)(0x80 | (a->ton << 4) | a->npi);

    if (a->ton == SMS_TON_ALPHANUM) {
        uint8_t sep[SMS_ADDR_MAX_DIGITS];
        int     ns =
            sms_gsm7_from_utf8(a->digits, strlen(a->digits), sep, sizeof sep);
        if (ns < 0) return ns;
        size_t vlen = ((size_t)ns * 7 + 7) / 8;
        if (vlen > SMS_ADDR_MAX_OCTETS - 2) return SMS_E_LENGTH;
        if (cap < 2 + vlen) return SMS_E_OVERFLOW;
        b[0] = (uint8_t)(vlen * 2); /* semi-octets the value occupies */
        b[1] = toa;
        memset(b + 2, 0, vlen);
        int packed = sms_gsm7_pack(sep, (size_t)ns, 0, b + 2, cap - 2);
        if (packed < 0) return packed;
        return (int)(2 + vlen);
    }

    size_t alen = strlen(a->digits);
    if (alen > SMS_ADDR_MAX_DIGITS) return SMS_E_LENGTH;
    size_t vlen = (alen + 1) / 2;
    if (cap < 2 + vlen) return SMS_E_OVERFLOW;
    b[0] = (uint8_t)alen;
    b[1] = toa;
    for (size_t i = 0; i < vlen; i++) {
        uint8_t lo = sms_bcd_nibble(a->digits[i * 2]);
        if (lo == 0xFF) return SMS_E_INVAL;
        uint8_t hi = 0x0F;
        if (i * 2 + 1 < alen) {
            hi = sms_bcd_nibble(a->digits[i * 2 + 1]);
            if (hi == 0xFF) return SMS_E_INVAL;
        }
        b[2 + i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)(2 + vlen);
}

int sms_addr_set(sms_addr_t* a, const char* num, int ton)
{
    if (a == NULL || num == NULL) return SMS_E_INVAL;
    memset(a, 0, sizeof *a);
    if (*num == '+') {
        ton = SMS_TON_INTERNATIONAL;
        num++;
    }
    a->ton   = (uint8_t)ton;
    a->npi   = SMS_NPI_ISDN;
    size_t k = 0;
    for (; num[k]; k++) {
        if (k >= SMS_ADDR_MAX_DIGITS) return SMS_E_LENGTH;
        if (sms_bcd_nibble(num[k]) == 0xFF) return SMS_E_INVAL;
        a->digits[k] = num[k];
    }
    a->digits[k] = '\0';
    return SMS_OK;
}

int sms_addr_set_text(sms_addr_t* a, const char* text)
{
    if (a == NULL || text == NULL) return SMS_E_INVAL;
    memset(a, 0, sizeof *a);
    a->ton = SMS_TON_ALPHANUM;
    a->npi = SMS_NPI_UNKNOWN;
    /* 11 septets is what the 10 value octets hold. */
    int septets = sms_gsm7_septets(text, strlen(text));
    if (septets < 0) return septets;
    if (septets > 11) return SMS_E_LENGTH;
    size_t len = strlen(text);
    if (len >= sizeof a->digits) return SMS_E_LENGTH;
    memcpy(a->digits, text, len + 1);
    return SMS_OK;
}

int sms_addr_e164(const sms_addr_t* a, char* out, size_t cap)
{
    if (a == NULL || out == NULL || cap == 0) return SMS_E_INVAL;
    size_t len  = strlen(a->digits);
    bool   plus = a->ton == SMS_TON_INTERNATIONAL;
    if (len + (plus ? 1u : 0u) + 1 > cap) return SMS_E_OVERFLOW;
    size_t k = 0;
    if (plus) out[k++] = '+';
    memcpy(out + k, a->digits, len);
    out[k + len] = '\0';
    return (int)(k + len);
}

/* ---- timestamps (§9.2.3.11) ---- */

int sms_ts_decode(const uint8_t* b, size_t n, sms_ts_t* out)
{
    if (b == NULL || out == NULL) return SMS_E_INVAL;
    if (n < 7) return SMS_E_SHORT;

    int yy = sms_bcd2(b[0]), mo = sms_bcd2(b[1]), dd = sms_bcd2(b[2]);
    int hh = sms_bcd2(b[3]), mi = sms_bcd2(b[4]), ss = sms_bcd2(b[5]);
    if (yy < 0 || mo < 0 || dd < 0 || hh < 0 || mi < 0 || ss < 0)
        return SMS_E_LENGTH;

    /* The timezone octet is semi-octet BCD like the rest, except that
     * bit 3 — the top bit of the tens digit once the nibbles are
     * swapped back — is the sign. Masking it off before the decode is
     * the whole trick. */
    uint8_t tz    = b[6];
    bool    neg   = (tz & 0x08) != 0;
    int     tens  = tz & 0x07;
    int     units = (tz >> 4) & 0x0F;
    if (units > 9) return SMS_E_LENGTH;
    int qh = tens * 10 + units;
    if (qh > 48) return SMS_E_LENGTH; /* ±12 h is the defined range */

    out->year  = (int16_t)(yy < SMS_YEAR_PIVOT ? 2000 + yy : 1900 + yy);
    out->mon   = (uint8_t)mo;
    out->day   = (uint8_t)dd;
    out->hour  = (uint8_t)hh;
    out->min   = (uint8_t)mi;
    out->sec   = (uint8_t)ss;
    out->tz_qh = (int8_t)(neg ? -qh : qh);
    return 7;
}

int sms_ts_encode(uint8_t* b, size_t cap, const sms_ts_t* t)
{
    if (b == NULL || t == NULL) return SMS_E_INVAL;
    if (cap < 7) return SMS_E_OVERFLOW;
    if (t->year < 1970 || t->year > 2069 || t->mon > 12 || t->day > 31 ||
        t->hour > 23 || t->min > 59 || t->sec > 59 || t->tz_qh < -48 ||
        t->tz_qh > 48)
        return SMS_E_INVAL;

    unsigned yy = (unsigned)(t->year % 100);
    b[0]        = sms_bcd2_enc(yy);
    b[1]        = sms_bcd2_enc(t->mon);
    b[2]        = sms_bcd2_enc(t->day);
    b[3]        = sms_bcd2_enc(t->hour);
    b[4]        = sms_bcd2_enc(t->min);
    b[5]        = sms_bcd2_enc(t->sec);

    int     qh = t->tz_qh < 0 ? -t->tz_qh : t->tz_qh;
    uint8_t tz = (uint8_t)((((unsigned)qh % 10) << 4) | ((unsigned)qh / 10));
    if (t->tz_qh < 0) tz |= 0x08;
    b[6] = tz;
    return 7;
}

/* Days from the civil epoch (1970-01-01) — Howard Hinnant's algorithm,
 * exact for every year this codec accepts and free of any libc time
 * dependency (the codecs stay freestanding). */
static int64_t days_from_civil(int y, unsigned m, unsigned d)
{
    y -= m <= 2;
    const int64_t  era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = (unsigned)(y - era * 400);
    const unsigned doy = (153u * (m + (m > 2 ? -3u : 9u)) + 2u) / 5u + d - 1u;
    const unsigned doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;
    return era * 146097 + (int64_t)doe - 719468;
}

static void civil_from_days(int64_t z, int* y, unsigned* m, unsigned* d)
{
    z += 719468;
    const int64_t  era = (z >= 0 ? z : z - 146096) / 146097;
    const unsigned doe = (unsigned)(z - era * 146097);
    const unsigned yoe =
        (doe - doe / 1460u + doe / 36524u - doe / 146096u) / 365u;
    const int      yy  = (int)((int64_t)yoe + era * 400);
    const unsigned doy = doe - (365u * yoe + yoe / 4u - yoe / 100u);
    const unsigned mp  = (5u * doy + 2u) / 153u;
    *d                 = doy - (153u * mp + 2u) / 5u + 1u;
    *m                 = mp + (mp < 10u ? 3u : -9u);
    *y                 = yy + (*m <= 2u);
}

int64_t sms_ts_unix(const sms_ts_t* t)
{
    if (t == NULL || t->mon < 1 || t->mon > 12 || t->day < 1 || t->day > 31 ||
        t->hour > 23 || t->min > 59 || t->sec > 59)
        return -1;
    int64_t days = days_from_civil(t->year, t->mon, t->day);
    int64_t secs = days * 86400 + t->hour * 3600 + t->min * 60 + t->sec;
    return secs - (int64_t)t->tz_qh * 900; /* local -> UTC */
}

void sms_ts_from_unix(sms_ts_t* out, int64_t secs, int tz_qh)
{
    if (out == NULL) return;
    if (tz_qh < -48) tz_qh = -48;
    if (tz_qh > 48) tz_qh = 48;
    int64_t local = secs + (int64_t)tz_qh * 900;
    int64_t days  = local / 86400;
    int64_t rem   = local % 86400;
    if (rem < 0) {
        rem += 86400;
        days -= 1;
    }
    int      y;
    unsigned m, d;
    civil_from_days(days, &y, &m, &d);
    out->year  = (int16_t)y;
    out->mon   = (uint8_t)m;
    out->day   = (uint8_t)d;
    out->hour  = (uint8_t)(rem / 3600);
    out->min   = (uint8_t)((rem % 3600) / 60);
    out->sec   = (uint8_t)(rem % 60);
    out->tz_qh = (int8_t)tz_qh;
}

static char* put2(char* p, unsigned v)
{
    *p++ = (char)('0' + (v / 10) % 10);
    *p++ = (char)('0' + v % 10);
    return p;
}

int sms_ts_iso8601(const sms_ts_t* t, char* out, size_t cap)
{
    if (t == NULL || out == NULL) return SMS_E_INVAL;
    if (cap < 26) return SMS_E_OVERFLOW;
    char* p = out;
    p       = put2(p, (unsigned)(t->year / 100));
    p       = put2(p, (unsigned)(t->year % 100));
    *p++    = '-';
    p       = put2(p, t->mon);
    *p++    = '-';
    p       = put2(p, t->day);
    *p++    = 'T';
    p       = put2(p, t->hour);
    *p++    = ':';
    p       = put2(p, t->min);
    *p++    = ':';
    p       = put2(p, t->sec);
    int qh  = t->tz_qh;
    *p++    = qh < 0 ? '-' : '+';
    if (qh < 0) qh = -qh;
    p    = put2(p, (unsigned)qh / 4);
    *p++ = ':';
    p    = put2(p, ((unsigned)qh % 4) * 15);
    *p   = '\0';
    return (int)(p - out);
}

/* ---- validity period (§9.2.3.12.1) ---- */

uint32_t sms_vp_secs(uint8_t rel)
{
    if (rel <= 143) return ((uint32_t)rel + 1) * 5 * 60;
    if (rel <= 167) return 12 * 3600 + ((uint32_t)rel - 143) * 30 * 60;
    if (rel <= 196) return ((uint32_t)rel - 166) * 86400;
    return ((uint32_t)rel - 192) * 7 * 86400;
}

uint8_t sms_vp_rel_from_secs(uint32_t secs)
{
    if (secs <= 12 * 3600) {
        uint32_t units = (secs + 299) / 300; /* round up to 5 min */
        if (units == 0) units = 1;
        return (uint8_t)(units - 1);
    }
    if (secs <= 24 * 3600) {
        uint32_t units = (secs - 12 * 3600 + 1799) / 1800;
        if (units == 0) units = 1;
        return (uint8_t)(143 + units);
    }
    if (secs <= 30u * 86400u) {
        uint32_t days = (secs + 86399) / 86400;
        return (uint8_t)(166 + days);
    }
    uint32_t weeks = (secs + 7u * 86400u - 1) / (7u * 86400u);
    if (weeks > 63) weeks = 63;
    return (uint8_t)(192 + weeks);
}

/* ---- TPDU decode ---- */

/* (TP-MTI, direction) -> type. TS 23.040 §9.2.3.1 table; MTI 3 is
 * reserved in both directions. */
static int mti_type(uint8_t mti, int dir)
{
    static const int8_t tbl[2][4] = {
        /* MS -> SC */ { SMS_T_DELIVER_REPORT, SMS_T_SUBMIT, SMS_T_COMMAND,
                         -1 },
        /* SC -> MS */
        { SMS_T_DELIVER, SMS_T_SUBMIT_REPORT, SMS_T_STATUS_REPORT, -1 },
    };
    return tbl[dir & 1][mti & 3];
}

/* TP-UD, shared by every type that has one. `septet_units` says the
 * TP-UDL is in septets, so the octet count has to be derived. */
static int read_ud(rd_t* r, uint8_t dcs, sms_ud_t* ud)
{
    if (!need(r, 1)) return SMS_E_SHORT;
    ud->udl = u8(r);

    size_t octets;
    if (sms_dcs_alphabet(dcs) == SMS_ALPHA_GSM7) octets = (ud->udl * 7 + 7) / 8;
    else octets = ud->udl;

    if (octets > SMS_UD_MAX) return SMS_E_LENGTH;
    if (!need(r, octets)) return SMS_E_SHORT;
    ud->len = (uint8_t)octets;
    ud->p   = octets ? r->b + r->off : NULL;
    r->off += octets;
    return SMS_OK;
}

/* The TP-PI-driven tail the two report TPDUs and the status report
 * share (§9.2.3.27): optional TP-PID, TP-DCS and TP-UDL+TP-UD, in that
 * order, each present when its bit is set. */
static int read_pi_tail(rd_t* r, uint8_t pi, bool* has_pid, uint8_t* pid,
                        bool* has_dcs, uint8_t* dcs, bool* has_ud, sms_ud_t* ud)
{
    *has_pid = (pi & 0x01) != 0;
    *has_dcs = (pi & 0x02) != 0;
    *has_ud  = (pi & 0x04) != 0;
    if (*has_pid) {
        if (!need(r, 1)) return SMS_E_SHORT;
        *pid = u8(r);
    }
    if (*has_dcs) {
        if (!need(r, 1)) return SMS_E_SHORT;
        *dcs = u8(r);
    }
    if (*has_ud) {
        int rc = read_ud(r, *has_dcs ? *dcs : 0, ud);
        if (rc < 0) return rc;
    }
    return SMS_OK;
}

int sms_tpdu_decode(const uint8_t* b, size_t n, int dir, sms_tpdu_t* out)
{
    if (b == NULL || out == NULL) return SMS_E_INVAL;
    if ((dir & ~(int)SMS_DIR_NEGATIVE) > SMS_DIR_SC_TO_MS || dir < 0)
        return SMS_E_INVAL;
    if (n < 1) return SMS_E_SHORT;

    bool negative = (dir & SMS_DIR_NEGATIVE) != 0;
    int  d        = dir & 1;

    memset(out, 0, sizeof *out);
    rd_t    r   = { b, n, 0 };
    uint8_t o0  = u8(&r);
    uint8_t mti = o0 & 0x03;
    int     ty  = mti_type(mti, d);
    if (ty < 0) return SMS_E_MTI;

    out->mti  = mti;
    out->dir  = (uint8_t)d;
    out->type = (uint8_t)ty;

    int rc;
    switch (ty) {
    case SMS_T_DELIVER: {
        sms_deliver_t* m = &out->u.deliver;
        m->mms           = (o0 & 0x04) != 0;
        m->lp            = (o0 & 0x08) != 0;
        m->sri           = (o0 & 0x20) != 0;
        m->udhi          = (o0 & 0x40) != 0;
        m->rp            = (o0 & 0x80) != 0;
        rc               = sms_addr_decode(r.b + r.off, r.n - r.off, &m->oa);
        if (rc < 0) return rc;
        r.off += (size_t)rc;
        if (!need(&r, 2)) return SMS_E_SHORT;
        m->pid = u8(&r);
        m->dcs = u8(&r);
        rc     = sms_ts_decode(r.b + r.off, r.n - r.off, &m->scts);
        if (rc < 0) return rc;
        r.off += (size_t)rc;
        rc = read_ud(&r, m->dcs, &m->ud);
        if (rc < 0) return rc;
        break;
    }
    case SMS_T_SUBMIT: {
        sms_submit_t* m = &out->u.submit;
        m->rd           = (o0 & 0x04) != 0;
        uint8_t vpf     = (uint8_t)((o0 >> 3) & 0x03);
        m->srr          = (o0 & 0x20) != 0;
        m->udhi         = (o0 & 0x40) != 0;
        m->rp           = (o0 & 0x80) != 0;
        if (!need(&r, 1)) return SMS_E_SHORT;
        m->mr = u8(&r);
        rc    = sms_addr_decode(r.b + r.off, r.n - r.off, &m->da);
        if (rc < 0) return rc;
        r.off += (size_t)rc;
        if (!need(&r, 2)) return SMS_E_SHORT;
        m->pid    = u8(&r);
        m->dcs    = u8(&r);
        m->vp.fmt = vpf;
        switch (vpf) {
        case SMS_VPF_NONE: break;
        case SMS_VPF_RELATIVE:
            if (!need(&r, 1)) return SMS_E_SHORT;
            m->vp.rel = u8(&r);
            break;
        case SMS_VPF_ABSOLUTE:
            rc = sms_ts_decode(r.b + r.off, r.n - r.off, &m->vp.abs);
            if (rc < 0) return rc;
            r.off += (size_t)rc;
            break;
        case SMS_VPF_ENHANCED:
            if (!need(&r, 7)) return SMS_E_SHORT;
            memcpy(m->vp.enh, r.b + r.off, 7);
            r.off += 7;
            break;
        default: return SMS_E_INVAL;
        }
        rc = read_ud(&r, m->dcs, &m->ud);
        if (rc < 0) return rc;
        break;
    }
    case SMS_T_STATUS_REPORT: {
        sms_status_report_t* m = &out->u.status_report;
        m->mms                 = (o0 & 0x04) != 0;
        m->lp                  = (o0 & 0x08) != 0;
        m->srq                 = (o0 & 0x20) != 0;
        m->udhi                = (o0 & 0x40) != 0;
        if (!need(&r, 1)) return SMS_E_SHORT;
        m->mr = u8(&r);
        rc    = sms_addr_decode(r.b + r.off, r.n - r.off, &m->ra);
        if (rc < 0) return rc;
        r.off += (size_t)rc;
        rc = sms_ts_decode(r.b + r.off, r.n - r.off, &m->scts);
        if (rc < 0) return rc;
        r.off += (size_t)rc;
        rc = sms_ts_decode(r.b + r.off, r.n - r.off, &m->dt);
        if (rc < 0) return rc;
        r.off += (size_t)rc;
        if (!need(&r, 1)) return SMS_E_SHORT;
        m->st = u8(&r);
        /* TP-PI and everything after it are optional in a status
         * report: a buffer that ends here is complete, not short. */
        if (need(&r, 1)) {
            m->has_pi = true;
            m->pi     = u8(&r);
            rc = read_pi_tail(&r, m->pi, &m->has_pid, &m->pid, &m->has_dcs,
                              &m->dcs, &m->has_ud, &m->ud);
            if (rc < 0) return rc;
        }
        break;
    }
    case SMS_T_COMMAND: {
        sms_command_t* m = &out->u.command;
        m->srr           = (o0 & 0x20) != 0;
        m->udhi          = (o0 & 0x40) != 0;
        if (!need(&r, 3)) return SMS_E_SHORT;
        m->mr  = u8(&r);
        m->pid = u8(&r);
        m->ct  = u8(&r);
        if (!need(&r, 1)) return SMS_E_SHORT;
        m->mn = u8(&r);
        rc    = sms_addr_decode(r.b + r.off, r.n - r.off, &m->da);
        if (rc < 0) return rc;
        r.off += (size_t)rc;
        if (!need(&r, 1)) return SMS_E_SHORT;
        m->cdl = u8(&r);
        if (m->cdl > SMS_CD_MAX) return SMS_E_LENGTH;
        if (!need(&r, m->cdl)) return SMS_E_SHORT;
        m->cd = m->cdl ? r.b + r.off : NULL;
        r.off += m->cdl;
        break;
    }
    case SMS_T_DELIVER_REPORT:
    case SMS_T_SUBMIT_REPORT:  {
        sms_report_t* m = &out->u.report;
        m->udhi         = (o0 & 0x40) != 0;
        m->has_fcs      = negative;
        if (negative) {
            if (!need(&r, 1)) return SMS_E_SHORT;
            m->fcs = u8(&r);
        }
        if (!need(&r, 1)) return SMS_E_SHORT;
        m->pi = u8(&r);
        if (ty == SMS_T_SUBMIT_REPORT) {
            m->has_scts = true;
            rc          = sms_ts_decode(r.b + r.off, r.n - r.off, &m->scts);
            if (rc < 0) return rc;
            r.off += (size_t)rc;
        }
        rc = read_pi_tail(&r, m->pi, &m->has_pid, &m->pid, &m->has_dcs, &m->dcs,
                          &m->has_ud, &m->ud);
        if (rc < 0) return rc;
        break;
    }
    default: return SMS_E_MTI;
    }
    return (int)r.off;
}

void sms_tpdu_init(sms_tpdu_t* t, sms_type_t type)
{
    if (t == NULL || type >= SMS_T_MAX) return;
    memset(t, 0, sizeof *t);
    t->type = (uint8_t)type;
    switch (type) {
    case SMS_T_DELIVER:
        t->mti = 0;
        t->dir = SMS_DIR_SC_TO_MS;
        break;
    case SMS_T_DELIVER_REPORT:
        t->mti = 0;
        t->dir = SMS_DIR_MS_TO_SC;
        break;
    case SMS_T_SUBMIT:
        t->mti = 1;
        t->dir = SMS_DIR_MS_TO_SC;
        break;
    case SMS_T_SUBMIT_REPORT:
        t->mti = 1;
        t->dir = SMS_DIR_SC_TO_MS;
        break;
    case SMS_T_STATUS_REPORT:
        t->mti = 2;
        t->dir = SMS_DIR_SC_TO_MS;
        break;
    case SMS_T_COMMAND:
        t->mti = 2;
        t->dir = SMS_DIR_MS_TO_SC;
        break;
    default: break;
    }
}

/* ---- name tables ---- */

const char* sms_type_name(sms_type_t t)
{
    static const char* n[SMS_T_MAX] = {
        "SMS-DELIVER",       "SMS-DELIVER-REPORT", "SMS-SUBMIT",
        "SMS-SUBMIT-REPORT", "SMS-STATUS-REPORT",  "SMS-COMMAND"
    };
    /* Cast, because the parameter is an enum and so the compare is signed:
     * these names are reachable from a script (sms.type_name in the Lua
     * module), which is free to pass a negative integer. */
    return (unsigned)t < SMS_T_MAX ? n[t] : "";
}

const char* sms_ton_name(sms_ton_t t)
{
    static const char* n[8] = { "unknown",     "international", "national",
                                "network",     "subscriber",    "alphanumeric",
                                "abbreviated", "reserved" };
    return (unsigned)t < 8 ? n[t] : "";
}

const char* sms_npi_name(sms_npi_t p)
{
    switch (p) {
    case SMS_NPI_UNKNOWN:  return "unknown";
    case SMS_NPI_ISDN:     return "ISDN/E.164";
    case SMS_NPI_DATA:     return "data/X.121";
    case SMS_NPI_TELEX:    return "telex";
    case SMS_NPI_SC_SPEC1: return "SC-specific-1";
    case SMS_NPI_SC_SPEC2: return "SC-specific-2";
    case SMS_NPI_NATIONAL: return "national";
    case SMS_NPI_PRIVATE:  return "private";
    case SMS_NPI_ERMES:    return "ERMES";
    case SMS_NPI_RESERVED: return "reserved";
    default:               return "";
    }
}

const char* sms_err_name(int err)
{
    switch (err) {
    case SMS_OK:         return "ok";
    case SMS_E_SHORT:    return "truncated";
    case SMS_E_LENGTH:   return "bad length";
    case SMS_E_OVERFLOW: return "buffer too small";
    case SMS_E_INVAL:    return "invalid argument";
    case SMS_E_ALPHABET: return "not representable in this alphabet";
    case SMS_E_MTI:      return "reserved message type for this direction";
    case SMS_E_MISSING:  return "not present";
    default:             return "unknown error";
    }
}

/* TP-ST — §9.2.3.15. Bits 6-5 band the value; bits 4-0 name it within
 * the band, and each band reserves a "specific to each SC" range. */
const char* sms_st_name(uint8_t st)
{
    switch (st) {
    case 0x00: return "delivered to SME";
    case 0x01: return "forwarded by the SC, delivery unconfirmed";
    case 0x02: return "replaced by the SC";
    case 0x20: return "congestion";
    case 0x21: return "SME busy";
    case 0x22: return "no response from SME";
    case 0x23: return "service rejected";
    case 0x24: return "quality of service not available";
    case 0x25: return "error in SME";
    case 0x40: return "remote procedure error";
    case 0x41: return "incompatible destination";
    case 0x42: return "connection rejected by SME";
    case 0x43: return "not obtainable";
    case 0x44: return "quality of service not available";
    case 0x45: return "no interworking available";
    case 0x46: return "validity period expired";
    case 0x47: return "deleted by originating SME";
    case 0x48: return "deleted by SC administration";
    case 0x49: return "message does not exist";
    case 0x60: return "congestion, SC giving up";
    case 0x61: return "SME busy, SC giving up";
    case 0x62: return "no response from SME, SC giving up";
    case 0x63: return "service rejected, SC giving up";
    case 0x64: return "quality of service not available, SC giving up";
    case 0x65: return "error in SME, SC giving up";
    default:   break;
    }
    if (st >= 0x10 && st <= 0x1F) return "completed, SC-specific";
    if (st >= 0x30 && st <= 0x3F) return "temporary error, SC-specific";
    if (st >= 0x50 && st <= 0x5F) return "permanent error, SC-specific";
    if (st >= 0x70 && st <= 0x7F) return "SC giving up, SC-specific";
    if (st >= 0x80) return "reserved (bit 7 set)";
    return "reserved";
}

bool sms_st_completed(uint8_t st)
{
    return (st & 0x60) == 0x00 && st < 0x80;
}

bool sms_st_temporary(uint8_t st)
{
    /* 001xxxxx: the SC is still trying. */
    return (st & 0x60) == 0x20 && st < 0x80;
}

bool sms_st_permanent(uint8_t st)
{
    /* 010xxxxx is a permanent error and 011xxxxx a temporary one the
     * SC has stopped retrying — both mean nothing more will happen. */
    return st < 0x80 && ((st & 0x60) == 0x40 || (st & 0x60) == 0x60);
}

/* TP-FCS — §9.2.3.22. */
const char* sms_fcs_name(uint8_t fcs)
{
    switch (fcs) {
    case 0x80: return "telematic interworking not supported";
    case 0x81: return "short message type 0 not supported";
    case 0x82: return "cannot replace short message";
    case 0x8F: return "unspecified TP-PID error";
    case 0x90: return "data coding scheme not supported";
    case 0x91: return "message class not supported";
    case 0x9F: return "unspecified TP-DCS error";
    case 0xA0: return "command cannot be actioned";
    case 0xA1: return "command unsupported";
    case 0xAF: return "unspecified TP-Command error";
    case 0xB0: return "TPDU not supported";
    case 0xC0: return "SC busy";
    case 0xC1: return "no SC subscription";
    case 0xC2: return "SC system failure";
    case 0xC3: return "invalid SME address";
    case 0xC4: return "destination SME barred";
    case 0xC5: return "rejected duplicate SM";
    case 0xC6: return "TP-VPF not supported";
    case 0xC7: return "TP-VP not supported";
    case 0xD0: return "(U)SIM SMS storage full";
    case 0xD1: return "no SMS storage capability in (U)SIM";
    case 0xD2: return "error in MS";
    case 0xD3: return "memory capacity exceeded";
    case 0xD4: return "(U)SIM Application Toolkit busy";
    case 0xD5: return "(U)SIM data download error";
    case 0xFF: return "unspecified error cause";
    default:   break;
    }
    if (fcs < 0x80) return "reserved";
    if (fcs >= 0xE0 && fcs <= 0xFE) return "application-specific";
    return "reserved";
}

/* TP-PID — §9.2.3.9. Only the points a gateway dispatches on. */
const char* sms_pid_name(uint8_t pid)
{
    switch (pid) {
    case 0x00: return "implicit (SME-to-SME)";
    case 0x20: return "implicit, no telematic interworking";
    case 0x22: return "fax group 3";
    case 0x24: return "voice telephone";
    case 0x25: return "ERMES";
    case 0x26: return "national paging system";
    case 0x2D: return "e-mail";
    case 0x3E: return "any GSM/UMTS mobile station";
    case 0x40: return "short message type 0";
    case 0x41: return "replace short message type 1";
    case 0x42: return "replace short message type 2";
    case 0x43: return "replace short message type 3";
    case 0x44: return "replace short message type 4";
    case 0x45: return "replace short message type 5";
    case 0x46: return "replace short message type 6";
    case 0x47: return "replace short message type 7";
    case 0x5F: return "return call message";
    case 0x7C: return "(U)SIM data download";
    case 0x7D: return "ME data download";
    case 0x7E: return "ME de-personalization short message";
    case 0x7F: return "(U)SIM data download (SIM Toolkit)";
    default:   break;
    }
    if (pid >= 0x21 && pid <= 0x3F) return "telematic interworking";
    if (pid >= 0x48 && pid <= 0x5E) return "reserved";
    if (pid >= 0x60 && pid <= 0x7B) return "reserved";
    if (pid >= 0x80 && pid <= 0xBF) return "reserved";
    return "SC-specific";
}

/* TP-CT — §9.2.3.19. */
const char* sms_ct_name(uint8_t ct)
{
    switch (ct) {
    case 0x00: return "enquiry relating to a previously submitted SM";
    case 0x01: return "cancel status report request";
    case 0x02: return "delete previously submitted SM";
    case 0x03: return "enable status report request";
    default:   break;
    }
    if (ct >= 0xE0) return "SC-specific";
    return "reserved";
}
