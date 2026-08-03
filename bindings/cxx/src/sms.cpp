#include "smsxx.hpp"

#include <cstring>
#include <ctime>

namespace sms
{

const char* const CONTENT_TYPE = "application/vnd.3gpp.sms";
const char* const FEATURE_TAG  = "+g.3gpp.smsip";

namespace
{

[[noreturn]] void fail(const char* what, int code)
{
    std::string m = what;
    m += ": ";
    m += sms_err_name(code);
    throw Error(m, code);
}

void check(int rc, const char* what)
{
    if (rc < 0) fail(what, rc);
}

int64_t now_secs()
{
    return (int64_t)std::time(nullptr);
}

Address addr_out(const sms_addr_t& a)
{
    Address o;
    o.ton    = a.ton;
    o.npi    = a.npi;
    o.digits = a.digits;
    return o;
}

Address addr_out(const sms_rp_addr_t& a)
{
    Address o;
    if (!a.present) return o;
    o.ton    = a.ton;
    o.npi    = a.npi;
    o.digits = a.digits;
    return o;
}

void addr_in(sms_addr_t* out, const Address& a)
{
    if (a.ton == TON_ALPHANUM) {
        check(sms_addr_set_text(out, a.digits.c_str()), "address");
        return;
    }
    check(sms_addr_set(out, a.digits.c_str(), a.ton), "address");
    /* sms_addr_set assumes E.164; honour an explicitly chosen plan. */
    out->npi = (uint8_t)a.npi;
}

/* A number string straight into a TPDU address; a leading '+' selects
 * the international type of number, as everywhere else. */
void addr_in(sms_addr_t* out, const std::string& num)
{
    check(sms_addr_set(out, num.c_str(), SMS_TON_UNKNOWN), "address");
}

Timestamp ts_out(const sms_ts_t& t)
{
    Timestamp o;
    o.year = t.year;
    o.mon  = t.mon;
    o.day  = t.day;
    o.hour = t.hour;
    o.min  = t.min;
    o.sec  = t.sec;
    o.tz   = t.tz_qh;
    return o;
}

void ts_in(sms_ts_t* out, const Timestamp& t)
{
    out->year  = (int16_t)t.year;
    out->mon   = (uint8_t)t.mon;
    out->day   = (uint8_t)t.day;
    out->hour  = (uint8_t)t.hour;
    out->min   = (uint8_t)t.min;
    out->sec   = (uint8_t)t.sec;
    out->tz_qh = (int8_t)t.tz;
}

std::string bytes(const uint8_t* p, size_t n)
{
    return (p && n) ? std::string((const char*)p, n) : std::string();
}

/* std::string::data() is a valid pointer even for an empty string, so
 * this never hands the C layer a NULL. That matters: the codecs treat
 * NULL as a caller bug (SMS_E_INVAL) and a zero length as a truncated
 * message (SMS_E_SHORT), and collapsing "" onto NULL would report an
 * empty body as the wrong one of the two. */
const uint8_t* raw(const std::string& s)
{
    return (const uint8_t*)s.data();
}

/* Copy the C tagged union out onto the flat facade type. */
Tpdu tpdu_out(const sms_tpdu_t& t)
{
    Tpdu o;
    o.type = t.type;
    o.mti  = t.mti;
    o.dir  = t.dir;

    switch (t.type) {
    case SMS_T_DELIVER: {
        const sms_deliver_t& d = t.u.deliver;
        o.mms                  = d.mms;
        o.lp                   = d.lp;
        o.rp                   = d.rp;
        o.udhi                 = d.udhi;
        o.sri                  = d.sri;
        o.addr                 = addr_out(d.oa);
        o.pid                  = d.pid;
        o.dcs                  = d.dcs;
        o.scts                 = ts_out(d.scts);
        o.has_scts             = true;
        o.user_data            = bytes(d.ud.p, d.ud.len);
        o.udl                  = d.ud.udl;
        o.has_user_data        = true;
        break;
    }
    case SMS_T_SUBMIT: {
        const sms_submit_t& s = t.u.submit;
        o.rd                  = s.rd;
        o.rp                  = s.rp;
        o.udhi                = s.udhi;
        o.srr                 = s.srr;
        o.mr                  = s.mr;
        o.addr                = addr_out(s.da);
        o.pid                 = s.pid;
        o.dcs                 = s.dcs;
        o.vpf                 = s.vp.fmt;
        o.vp_rel              = s.vp.rel;
        if (s.vp.fmt == SMS_VPF_ABSOLUTE) o.vp_abs = ts_out(s.vp.abs);
        o.user_data     = bytes(s.ud.p, s.ud.len);
        o.udl           = s.ud.udl;
        o.has_user_data = true;
        break;
    }
    case SMS_T_STATUS_REPORT: {
        const sms_status_report_t& r = t.u.status_report;
        o.mms                        = r.mms;
        o.lp                         = r.lp;
        o.udhi                       = r.udhi;
        o.srq                        = r.srq;
        o.mr                         = r.mr;
        o.addr                       = addr_out(r.ra);
        o.scts                       = ts_out(r.scts);
        o.has_scts                   = true;
        o.dt                         = ts_out(r.dt);
        o.st                         = r.st;
        o.has_pid                    = r.has_pid;
        o.has_dcs                    = r.has_dcs;
        o.pid                        = r.pid;
        o.dcs                        = r.dcs;
        o.has_user_data              = r.has_ud;
        if (r.has_ud) {
            o.user_data = bytes(r.ud.p, r.ud.len);
            o.udl       = r.ud.udl;
        }
        break;
    }
    case SMS_T_COMMAND: {
        const sms_command_t& c = t.u.command;
        o.udhi                 = c.udhi;
        o.srr                  = c.srr;
        o.mr                   = c.mr;
        o.pid                  = c.pid;
        o.ct                   = c.ct;
        o.mn                   = c.mn;
        o.addr                 = addr_out(c.da);
        o.command_data         = bytes(c.cd, c.cdl);
        break;
    }
    case SMS_T_DELIVER_REPORT:
    case SMS_T_SUBMIT_REPORT:  {
        const sms_report_t& r = t.u.report;
        o.udhi                = r.udhi;
        o.has_fcs             = r.has_fcs;
        o.fcs                 = r.fcs;
        o.has_scts            = r.has_scts;
        if (r.has_scts) o.scts = ts_out(r.scts);
        o.has_pid       = r.has_pid;
        o.has_dcs       = r.has_dcs;
        o.pid           = r.pid;
        o.dcs           = r.dcs;
        o.has_user_data = r.has_ud;
        if (r.has_ud) {
            o.user_data = bytes(r.ud.p, r.ud.len);
            o.udl       = r.ud.udl;
        }
        break;
    }
    default: break;
    }
    return o;
}

/* And back. The user data is taken verbatim: the facade never
 * re-encodes text on the way out, so whatever was decoded (or built by
 * sms_ud_from_utf8) survives byte for byte. */
void tpdu_in(sms_tpdu_t* out, const Tpdu& t)
{
    if (t.type < 0 || t.type >= SMS_T_MAX) fail("encode", SMS_E_INVAL);
    sms_tpdu_init(out, (sms_type_t)t.type);

    sms_ud_t ud;
    ud.udl = (uint8_t)t.udl;
    ud.len = (uint8_t)t.user_data.size();
    ud.p   = raw(t.user_data);

    switch (t.type) {
    case SMS_T_DELIVER: {
        sms_deliver_t* d = &out->u.deliver;
        d->mms           = t.mms;
        d->lp            = t.lp;
        d->rp            = t.rp;
        d->udhi          = t.udhi;
        d->sri           = t.sri;
        addr_in(&d->oa, t.addr);
        d->pid = (uint8_t)t.pid;
        d->dcs = (uint8_t)t.dcs;
        ts_in(&d->scts, t.scts);
        d->ud = ud;
        break;
    }
    case SMS_T_SUBMIT: {
        sms_submit_t* s = &out->u.submit;
        s->rd           = t.rd;
        s->rp           = t.rp;
        s->udhi         = t.udhi;
        s->srr          = t.srr;
        s->mr           = (uint8_t)t.mr;
        addr_in(&s->da, t.addr);
        s->pid    = (uint8_t)t.pid;
        s->dcs    = (uint8_t)t.dcs;
        s->vp.fmt = (uint8_t)t.vpf;
        s->vp.rel = (uint8_t)t.vp_rel;
        if (t.vpf == SMS_VPF_ABSOLUTE) ts_in(&s->vp.abs, t.vp_abs);
        s->ud = ud;
        break;
    }
    case SMS_T_STATUS_REPORT: {
        sms_status_report_t* r = &out->u.status_report;
        r->mms                 = t.mms;
        r->lp                  = t.lp;
        r->udhi                = t.udhi;
        r->srq                 = t.srq;
        r->mr                  = (uint8_t)t.mr;
        addr_in(&r->ra, t.addr);
        ts_in(&r->scts, t.scts);
        ts_in(&r->dt, t.dt);
        r->st      = (uint8_t)t.st;
        r->has_pid = t.has_pid;
        r->has_dcs = t.has_dcs;
        r->pid     = (uint8_t)t.pid;
        r->dcs     = (uint8_t)t.dcs;
        r->has_ud  = t.has_user_data && !t.user_data.empty();
        r->ud      = ud;
        break;
    }
    case SMS_T_COMMAND: {
        sms_command_t* c = &out->u.command;
        c->udhi          = t.udhi;
        c->srr           = t.srr;
        c->mr            = (uint8_t)t.mr;
        c->pid           = (uint8_t)t.pid;
        c->ct            = (uint8_t)t.ct;
        c->mn            = (uint8_t)t.mn;
        addr_in(&c->da, t.addr);
        if (t.command_data.size() > SMS_CD_MAX) fail("encode", SMS_E_LENGTH);
        c->cdl = (uint8_t)t.command_data.size();
        c->cd  = raw(t.command_data);
        break;
    }
    case SMS_T_DELIVER_REPORT:
    case SMS_T_SUBMIT_REPORT:  {
        sms_report_t* r = &out->u.report;
        r->udhi         = t.udhi;
        r->has_fcs      = t.has_fcs;
        r->fcs          = (uint8_t)t.fcs;
        r->has_scts     = t.type == SMS_T_SUBMIT_REPORT;
        if (r->has_scts) ts_in(&r->scts, t.scts);
        r->has_pid = t.has_pid;
        r->has_dcs = t.has_dcs;
        r->pid     = (uint8_t)t.pid;
        r->dcs     = (uint8_t)t.dcs;
        r->has_ud  = t.has_user_data && !t.user_data.empty();
        r->ud      = ud;
        break;
    }
    default: fail("encode", SMS_E_INVAL);
    }
}

/* The TP-UD build shared by submit() and deliver(): pick the alphabet,
 * copy the header in front, apply the septet alignment. */
void build_ud(const std::string& text, int alphabet, const std::string& udh,
              int cls, std::vector<uint8_t>* ud, uint8_t* udl, uint8_t* dcs)
{
    ud->assign(SMS_UD_MAX, 0);
    if (udh.size() > SMS_UD_MAX) fail("user data header", SMS_E_LENGTH);
    int n = sms_ud_from_utf8(text.data(), text.size(), alphabet, raw(udh),
                             udh.size(), ud->data(), ud->size(), udl, dcs);
    check(n, "user data");
    ud->resize((size_t)n);
    /* The class bit lives in the DCS, which the encoder just chose; put
     * it back rather than re-deriving the alphabet here. */
    if (cls >= 0 && cls <= 3)
        *dcs = (uint8_t)sms_dcs_make(sms_dcs_alphabet(*dcs), cls);
}

std::string encode_tpdu(const sms_tpdu_t& t)
{
    uint8_t buf[SMS_TPDU_MAX];
    int     n = sms_tpdu_encode(buf, sizeof buf, &t);
    check(n, "tpdu encode");
    return std::string((const char*)buf, (size_t)n);
}

} // namespace

/* ---- Address / Timestamp ---- */

std::string Address::display() const
{
    if (ton == TON_INTERNATIONAL && !digits.empty()) return "+" + digits;
    return digits;
}

int64_t Timestamp::unix_time() const
{
    sms_ts_t t;
    ts_in(&t, *this);
    return sms_ts_unix(&t);
}

std::string Timestamp::iso8601() const
{
    sms_ts_t t;
    ts_in(&t, *this);
    char buf[32];
    int  n = sms_ts_iso8601(&t, buf, sizeof buf);
    if (n < 0) return std::string();
    return std::string(buf, (size_t)n);
}

/* ---- Tpdu ---- */

std::string Tpdu::text() const
{
    if (!has_user_data) return std::string();
    char buf[SMS_UD_MAX * 4 + 1];
    int n = sms_ud_to_utf8((uint8_t)dcs, udhi, raw(user_data), user_data.size(),
                           (uint8_t)udl, buf, sizeof buf);
    check(n, "user data");
    return std::string(buf, (size_t)n);
}

int Tpdu::alphabet() const
{
    return sms_dcs_alphabet((uint8_t)dcs);
}

Dcs Tpdu::coding() const
{
    return dcs_decode(dcs);
}

unsigned Tpdu::vp_seconds() const
{
    if (vpf != VPF_RELATIVE) return 0;
    return sms_vp_secs((uint8_t)vp_rel);
}

bool Tpdu::has_udh() const
{
    return udhi && sms_udh_len(raw(user_data), user_data.size()) > 1;
}

int Tpdu::udh_count() const
{
    if (!udhi) return 0;
    sms_udh_iter_t it;
    sms_udh_ie_t ie;
    int          n = 0;
    if (!sms_udh_begin(&it, raw(user_data), user_data.size())) return 0;
    while (sms_udh_next(&it, &ie))
        n++;
    return n;
}

UdhIe Tpdu::udh_at(int i) const
{
    sms_udh_iter_t it;
    sms_udh_ie_t ie;
    if (i < 0 || !udhi || !sms_udh_begin(&it, raw(user_data), user_data.size()))
        fail("udh_at", SMS_E_INVAL);
    for (int k = 0; sms_udh_next(&it, &ie); k++) {
        if (k != i) continue;
        UdhIe o;
        o.iei  = ie.iei;
        o.data = bytes(ie.data, ie.len);
        return o;
    }
    fail("udh_at", SMS_E_INVAL);
}

bool Tpdu::has_concat() const
{
    sms_concat_t c;
    return udhi && sms_concat_get(raw(user_data), user_data.size(), &c);
}

Concat Tpdu::concat() const
{
    sms_concat_t c;
    if (!udhi || !sms_concat_get(raw(user_data), user_data.size(), &c))
        fail("concat", SMS_E_MISSING);
    Concat o;
    o.ref   = c.ref;
    o.total = c.total;
    o.seq   = c.seq;
    o.ref16 = c.ref16;
    return o;
}

std::string Tpdu::type_name() const
{
    return sms_type_name((sms_type_t)type);
}

std::string Tpdu::status_name() const
{
    return sms_st_name((uint8_t)st);
}

std::string Tpdu::cause_name() const
{
    return sms_fcs_name((uint8_t)fcs);
}

std::string Tpdu::encode() const
{
    sms_tpdu_t t;
    tpdu_in(&t, *this);
    return encode_tpdu(t);
}

/* ---- Rpdu ---- */

Tpdu Rpdu::tpdu() const
{
    if (!has_tpdu()) fail("tpdu", SMS_E_MISSING);
    /* The TPDU travels the same way the RPDU does, and a report inside
     * an RP-ERROR carries a TP-FCS the RP-ACK form does not. */
    int dir = from_ms ? DIR_MS_TO_SC : DIR_SC_TO_MS;
    if (type == RP_T_ERROR) dir |= DIR_NEGATIVE;
    return parse_tpdu(user_data, dir);
}

std::string Rpdu::type_name() const
{
    return sms_rp_type_name((sms_rp_type_t)type);
}

std::string Rpdu::cause_name() const
{
    return sms_rp_cause_name((uint8_t)cause);
}

std::string Rpdu::encode() const
{
    sms_rp_pdu_t p;
    sms_rp_init(&p, (sms_rp_type_t)type,
                from_ms ? SMS_DIR_MS_TO_SC : SMS_DIR_SC_TO_MS);
    p.mr = (uint8_t)mr;
    check(sms_rp_addr_set(
              &p.oa, oa.digits.empty() ? nullptr : oa.digits.c_str(), oa.ton),
          "rp originator");
    check(sms_rp_addr_set(
              &p.da, da.digits.empty() ? nullptr : da.digits.c_str(), da.ton),
          "rp destination");
    p.cause          = (uint8_t)cause;
    p.has_cause_diag = has_cause_diag;
    p.cause_diag     = (uint8_t)cause_diag;
    if (user_data.size() > 255) fail("rp encode", SMS_E_LENGTH);
    /* RP-DATA's user data element is mandatory, so it goes out even when
     * empty; in RP-ACK/RP-ERROR an empty one is simply omitted. */
    p.has_ud = type == RP_T_DATA ? true : has_user_data;
    p.ud     = raw(user_data);
    p.ud_len = (uint8_t)user_data.size();

    uint8_t buf[SMS_RP_MAX];
    int     n = sms_rp_encode(buf, sizeof buf, &p);
    check(n, "rp encode");
    return std::string((const char*)buf, (size_t)n);
}

/* ---- parse ---- */

Rpdu parse_rpdu(const std::string& wire, int dir)
{
    sms_rp_pdu_t p;
    int          n = sms_rp_decode(raw(wire), wire.size(), dir, &p);
    check(n, "parse_rpdu");

    Rpdu o;
    o.type           = p.type;
    o.mti            = p.mti;
    o.from_ms        = p.from_ms;
    o.mr             = p.mr;
    o.oa             = addr_out(p.oa);
    o.da             = addr_out(p.da);
    o.cause          = p.cause;
    o.has_cause_diag = p.has_cause_diag;
    o.cause_diag     = p.cause_diag;
    o.has_user_data  = p.has_ud;
    o.user_data      = bytes(p.ud, p.ud_len);
    return o;
}

Tpdu parse_tpdu(const std::string& wire, int dir)
{
    sms_tpdu_t t;
    check(sms_tpdu_decode(raw(wire), wire.size(), dir, &t), "parse_tpdu");
    return tpdu_out(t);
}

/* ---- build ---- */

std::string submit_tpdu(const Submission& s)
{
    if (s.to.empty()) fail("submit", SMS_E_INVAL);

    sms_tpdu_t t;
    sms_tpdu_init(&t, SMS_T_SUBMIT);
    sms_submit_t* m = &t.u.submit;
    m->srr          = s.srr;
    m->rd           = s.rd;
    m->rp           = s.rp;
    m->mr           = (uint8_t)s.mr;
    m->pid          = (uint8_t)s.pid;
    addr_in(&m->da, s.to);
    if (s.validity > 0) {
        m->vp.fmt = SMS_VPF_RELATIVE;
        m->vp.rel = sms_vp_rel_from_secs((uint32_t)s.validity);
    }

    std::vector<uint8_t> ud;
    uint8_t              udl = 0, dcs = 0;
    build_ud(s.text, s.alphabet, s.udh, s.cls, &ud, &udl, &dcs);
    m->udhi   = !s.udh.empty();
    m->dcs    = dcs;
    m->ud.udl = udl;
    m->ud.len = (uint8_t)ud.size();
    m->ud.p   = ud.empty() ? nullptr : ud.data();

    return encode_tpdu(t);
}

std::string submit(const Submission& s)
{
    return rp_data(DIR_MS_TO_SC, s.mr, s.sc, submit_tpdu(s));
}

std::string deliver_tpdu(const Delivery& d)
{
    if (d.from.empty()) fail("deliver", SMS_E_INVAL);

    sms_tpdu_t t;
    sms_tpdu_init(&t, SMS_T_DELIVER);
    sms_deliver_t* m = &t.u.deliver;
    m->sri           = d.sri;
    /* TP-MMS is 1 for "no more messages waiting", so the flag inverts. */
    m->mms = !d.more;
    m->rp  = d.rp;
    m->pid = (uint8_t)d.pid;
    addr_in(&m->oa, d.from);
    sms_ts_from_unix(&m->scts, d.scts ? d.scts : now_secs(), d.tz);

    std::vector<uint8_t> ud;
    uint8_t              udl = 0, dcs = 0;
    build_ud(d.text, d.alphabet, d.udh, d.cls, &ud, &udl, &dcs);
    m->udhi   = !d.udh.empty();
    m->dcs    = dcs;
    m->ud.udl = udl;
    m->ud.len = (uint8_t)ud.size();
    m->ud.p   = ud.empty() ? nullptr : ud.data();

    return encode_tpdu(t);
}

std::string deliver(const Delivery& d)
{
    return rp_data(DIR_SC_TO_MS, d.mr, d.sc, deliver_tpdu(d));
}

std::string rp_data(int dir, int mr, const std::string& sc,
                    const std::string& tpdu)
{
    uint8_t buf[SMS_RP_MAX];
    int     n =
        sms_rp_data(buf, sizeof buf, dir, (uint8_t)mr,
                    sc.empty() ? nullptr : sc.c_str(), raw(tpdu), tpdu.size());
    check(n, "rp_data");
    return std::string((const char*)buf, (size_t)n);
}

std::string ack(int dir, int mr, const std::string& tpdu)
{
    uint8_t buf[SMS_RP_MAX];
    int     n =
        sms_rp_ack(buf, sizeof buf, dir, (uint8_t)mr, raw(tpdu), tpdu.size());
    check(n, "ack");
    return std::string((const char*)buf, (size_t)n);
}

std::string error(int dir, int mr, int cause, const std::string& tpdu)
{
    uint8_t buf[SMS_RP_MAX];
    int     n = sms_rp_error(buf, sizeof buf, dir, (uint8_t)mr, (uint8_t)cause,
                             raw(tpdu), tpdu.size());
    check(n, "error");
    return std::string((const char*)buf, (size_t)n);
}

std::string smma(int mr)
{
    uint8_t buf[SMS_RP_MAX];
    int     n = sms_rp_smma(buf, sizeof buf, (uint8_t)mr);
    check(n, "smma");
    return std::string((const char*)buf, (size_t)n);
}

std::string deliver_from_submit(const std::string& tpdu, const std::string& oa,
                                int64_t scts, int tz, bool more)
{
    sms_tpdu_t in;
    check(sms_tpdu_decode(raw(tpdu), tpdu.size(), SMS_DIR_MS_TO_SC, &in),
          "deliver_from_submit");
    if (in.type != SMS_T_SUBMIT) fail("deliver_from_submit", SMS_E_MTI);
    const sms_submit_t& s = in.u.submit;

    sms_tpdu_t out;
    sms_tpdu_init(&out, SMS_T_DELIVER);
    sms_deliver_t* d = &out.u.deliver;
    d->mms           = !more;
    d->rp            = s.rp;
    d->sri           = s.srr; /* the SC will report back, so say so */
    d->udhi          = s.udhi;
    check(sms_addr_set(&d->oa, oa.c_str(), SMS_TON_UNKNOWN), "originator");
    /* Verbatim: re-encoding would destroy 8-bit data, a user data
     * header, a concatenation element or a national-language shift. */
    d->pid = s.pid;
    d->dcs = s.dcs;
    d->ud  = s.ud;
    sms_ts_from_unix(&d->scts, scts ? scts : now_secs(), tz);

    return encode_tpdu(out);
}

std::string status_report_tpdu(const std::string& ra, int mr, int st,
                               int64_t scts, int64_t dt, int tz)
{
    sms_tpdu_t t;
    sms_tpdu_init(&t, SMS_T_STATUS_REPORT);
    sms_status_report_t* r = &t.u.status_report;
    r->mr                  = (uint8_t)mr;
    r->st                  = (uint8_t)st;
    r->mms                 = true; /* nothing else queued */
    check(sms_addr_set(&r->ra, ra.c_str(), SMS_TON_UNKNOWN), "recipient");
    int64_t t0 = scts ? scts : now_secs();
    sms_ts_from_unix(&r->scts, t0, tz);
    sms_ts_from_unix(&r->dt, dt ? dt : t0, tz);
    return encode_tpdu(t);
}

/* ---- concatenation ---- */

std::string Parts::at(int i) const
{
    if (i < 0 || (size_t)i >= v_.size()) fail("Parts::at", SMS_E_INVAL);
    return v_[(size_t)i];
}

std::string Parts::tpdu_at(int i) const
{
    if (i < 0 || (size_t)i >= tv_.size()) fail("Parts::tpdu_at", SMS_E_INVAL);
    return tv_[(size_t)i];
}

namespace
{

/* One split, shared by the two entry points: build every part's TP-UD,
 * then let the caller wrap each in its own TPDU. */
std::vector<sms_part_t> split(const std::string& text, int alphabet, int ref,
                              bool ref16)
{
    /* 255 is the ceiling the one-octet sequence number imposes; a body
     * that needs more parts than that has no legal encoding. */
    std::vector<sms_part_t> parts(255);
    int n = sms_concat_split(text.data(), text.size(), alphabet, (uint16_t)ref,
                             ref16, parts.data(), (int)parts.size());
    check(n, "split");
    parts.resize((size_t)n);
    return parts;
}

} // namespace

Parts submit_parts(const Submission& s, int ref, bool ref16)
{
    if (s.to.empty()) fail("submit_parts", SMS_E_INVAL);
    std::vector<sms_part_t> ps = split(s.text, s.alphabet, ref, ref16);

    Parts out;
    for (size_t i = 0; i < ps.size(); i++) {
        sms_tpdu_t t;
        sms_tpdu_init(&t, SMS_T_SUBMIT);
        sms_submit_t* m = &t.u.submit;
        m->srr          = s.srr;
        m->rd           = s.rd;
        m->rp           = s.rp;
        /* One TP-MR per part: the reports come back per message, and a
         * shared reference would make them ambiguous. */
        m->mr  = (uint8_t)(s.mr + i);
        m->pid = (uint8_t)s.pid;
        addr_in(&m->da, s.to);
        if (s.validity > 0) {
            m->vp.fmt = SMS_VPF_RELATIVE;
            m->vp.rel = sms_vp_rel_from_secs((uint32_t)s.validity);
        }
        m->udhi = ps[i].total > 1;
        m->dcs = s.cls >= 0 && s.cls <= 3
                     ? (uint8_t)sms_dcs_make(sms_dcs_alphabet(ps[i].dcs), s.cls)
                     : ps[i].dcs;
        m->ud.udl = ps[i].udl;
        m->ud.len = ps[i].ud_len;
        m->ud.p   = ps[i].ud;

        std::string tp = encode_tpdu(t);
        out.tv_.push_back(tp);
        out.v_.push_back(rp_data(DIR_MS_TO_SC, s.mr + (int)i, s.sc, tp));
    }
    return out;
}

Parts deliver_parts(const Delivery& d, int ref, bool ref16)
{
    if (d.from.empty()) fail("deliver_parts", SMS_E_INVAL);
    std::vector<sms_part_t> ps = split(d.text, d.alphabet, ref, ref16);
    int64_t                 t0 = d.scts ? d.scts : now_secs();

    Parts out;
    for (size_t i = 0; i < ps.size(); i++) {
        sms_tpdu_t t;
        sms_tpdu_init(&t, SMS_T_DELIVER);
        sms_deliver_t* m = &t.u.deliver;
        m->sri           = d.sri;
        m->mms           = !d.more;
        m->rp            = d.rp;
        m->pid           = (uint8_t)d.pid;
        addr_in(&m->oa, d.from);
        sms_ts_from_unix(&m->scts, t0, d.tz);
        m->udhi = ps[i].total > 1;
        m->dcs = d.cls >= 0 && d.cls <= 3
                     ? (uint8_t)sms_dcs_make(sms_dcs_alphabet(ps[i].dcs), d.cls)
                     : ps[i].dcs;
        m->ud.udl = ps[i].udl;
        m->ud.len = ps[i].ud_len;
        m->ud.p   = ps[i].ud;

        std::string tp = encode_tpdu(t);
        out.tv_.push_back(tp);
        out.v_.push_back(rp_data(DIR_SC_TO_MS, d.mr + (int)i, d.sc, tp));
    }
    return out;
}

/* ---- helpers ---- */

int gsm7_septets(const std::string& text)
{
    int n = sms_gsm7_septets(text.data(), text.size());
    check(n, "gsm7_septets");
    return n;
}

bool is_gsm7(const std::string& text)
{
    return sms_gsm7_septets(text.data(), text.size()) >= 0;
}

int dcs_make(int alphabet, int cls)
{
    return sms_dcs_make(alphabet, cls);
}

Dcs dcs_decode(int octet)
{
    sms_dcs_t d;
    sms_dcs_decode((uint8_t)octet, &d);
    Dcs o;
    o.octet       = octet;
    o.alphabet    = d.alphabet;
    o.compressed  = d.compressed;
    o.has_class   = d.has_class;
    o.cls         = d.cls;
    o.auto_delete = d.auto_delete;
    o.mwi         = d.mwi;
    o.mwi_active  = d.mwi_active;
    o.mwi_type    = d.mwi_type;
    o.mwi_discard = d.mwi_discard;
    return o;
}

unsigned vp_seconds(int rel_code)
{
    return sms_vp_secs((uint8_t)rel_code);
}

int vp_code(unsigned seconds)
{
    return sms_vp_rel_from_secs(seconds);
}

std::string type_name(int type)
{
    return sms_type_name((sms_type_t)type);
}

std::string rp_type_name(int type)
{
    return sms_rp_type_name((sms_rp_type_t)type);
}

std::string rp_cause_name(int cause)
{
    return sms_rp_cause_name((uint8_t)cause);
}

std::string status_name(int st)
{
    return sms_st_name((uint8_t)st);
}

std::string failure_name(int fcs)
{
    return sms_fcs_name((uint8_t)fcs);
}

std::string pid_name(int pid)
{
    return sms_pid_name((uint8_t)pid);
}

std::string ton_name(int ton)
{
    return sms_ton_name((sms_ton_t)ton);
}

int rp_cause_fold(int cause)
{
    return sms_rp_cause_fold((uint8_t)cause);
}

} // namespace sms
