/* Typed and raw message codecs. The generated gtp2_msg.h layer now
 * exposes every IE as an opaque view, so the typed value-type messages
 * here are encoded and decoded directly against the base codec
 * (gtp2.h header + gtp2_ie.h IE walk and sub-IE codecs). Borrowed views
 * point into locals that outlive the C calls. */

#include "gtpxx_intl.hpp"

#include <cstring>

namespace gtp
{

using namespace intl;

enum {
    WIRE_MAX       = 65552, /* 16-bit Length + 12-byte header, rounded */
    BC_MAX_FTEID   = 4,     /* F-TEIDs kept per bearer context */
    CS_MAX_BEARERS = 11,    /* bearer contexts kept per message */
};

/* ---- wire helpers ---- */

static size_t put_hdr(gtp2_wbuf_t& w, uint8_t mt, uint32_t teid, uint32_t seq)
{
    gtp2_hdr_t h;
    std::memset(&h, 0, sizeof h);
    h.has_teid     = true;
    h.message_type = mt;
    h.teid         = teid;
    h.sequence     = seq;

    const size_t off = w.off;
    const int    hl  = gtp2_hdr_encode(w.buf + w.off, w.cap - w.off, &h);
    if (hl < 0) throw_gtp2(hl, "encode header");
    w.off += static_cast<size_t>(hl);
    return off;
}

static Bytes finish(gtp2_wbuf_t& w, Bytes& out, size_t hdr_off,
                    const char* doing)
{
    const int rc = gtp2_hdr_finalize(&w, hdr_off);
    if (rc != GTP2_OK) throw_gtp2(rc, doing);
    out.resize(w.off);
    return out;
}

static void put_bytes(gtp2_wbuf_t& w, uint8_t type, uint8_t inst,
                      const Bytes& b)
{
    if (!b.empty())
        gtp2_ie_put(&w, type, inst, b.data(), static_cast<uint16_t>(b.size()));
}

/* Copy a decoded IE's value bytes out of the wire buffer. */
static Bytes ie_bytes(const gtp2_ie_view_t& v)
{
    return v.value ? Bytes(v.value, v.value + v.len) : Bytes();
}

/* Cause IE (§8.4): value octet + a spare/flags octet. */
static void put_cause(gtp2_wbuf_t& w, uint8_t inst, uint8_t cause)
{
    const uint8_t v[2] = { cause, 0 };
    gtp2_ie_put(&w, GTP2_IE_CAUSE, inst, v, sizeof v);
}

static uint32_t be32(const uint8_t* p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 |
           (uint32_t)p[3];
}
static uint16_t be16(const uint8_t* p)
{
    return (uint16_t)(p[0] << 8 | p[1]);
}

/* ---- Bearer Context <-> grouped IE ---- */

void BearerContext::add_fteid(uint8_t inst, const Fteid& f)
{
    FteidEntry e;
    e.instance = inst;
    e.fteid    = f;
    fteids.push_back(e);
}

static void put_bearer(gtp2_wbuf_t& w, const BearerContext& b)
{
    if (b.fteids.size() > BC_MAX_FTEID)
        throw Error("bearer context: more than 4 F-TEIDs");

    const int h = gtp2_ie_begin(&w, GTP2_IE_BEARER_CONTEXT, b.instance);
    gtp2_ie_put_u8(&w, GTP2_IE_EBI, 0, static_cast<uint8_t>(b.ebi & 0x0f));
    if (b.cause >= 0) put_cause(w, 0, static_cast<uint8_t>(b.cause));
    put_bytes(w, GTP2_IE_BEARER_TFT, 0, b.tft);
    if (b.has_qos) {
        const gtp2_bearer_qos_t q = qos_to_c(b.qos);
        gtp2_bearer_qos_put(&w, 0, &q);
    }
    for (const FteidEntry& fe : b.fteids) {
        const gtp2_fteid_t f = fteid_to_c(fe.fteid);
        gtp2_fteid_put(&w, fe.instance, &f);
    }
    if (b.charging_id >= 0)
        gtp2_ie_put_u32(&w, GTP2_IE_CHARGING_ID, 0,
                        static_cast<uint32_t>(b.charging_id));
    gtp2_ie_end(&w, h);
}

static BearerContext bearer_from_view(const gtp2_ie_view_t& g)
{
    BearerContext b;
    b.instance = g.instance;
    b.ebi      = 0;

    gtp2_ie_iter_t it;
    gtp2_ie_iter_grouped(&it, &g);
    gtp2_ie_view_t ie;
    while (gtp2_ie_iter_next(&it, &ie)) {
        switch (ie.type) {
        case GTP2_IE_EBI:
            if (ie.len) b.ebi = ie.value[0] & 0x0f;
            break;
        case GTP2_IE_CAUSE:
            if (ie.len) b.cause = ie.value[0];
            break;
        case GTP2_IE_BEARER_TFT:
            b.tft.assign(ie.value, ie.value + ie.len);
            break;
        case GTP2_IE_BEARER_QOS: {
            gtp2_bearer_qos_t q;
            if (gtp2_bearer_qos_decode(&ie, &q) == GTP2_OK) {
                b.has_qos = true;
                b.qos     = qos_from_c(q);
            }
            break;
        }
        case GTP2_IE_FTEID: {
            gtp2_fteid_t f;
            if (gtp2_fteid_decode(&ie, &f) == GTP2_OK &&
                b.fteids.size() < BC_MAX_FTEID)
                b.add_fteid(ie.instance, fteid_from_c(f));
            break;
        }
        case GTP2_IE_CHARGING_ID:
            if (ie.len >= 4) b.charging_id = static_cast<long>(be32(ie.value));
            break;
        default: break;
        }
    }
    return b;
}

/* Iterate a decoded message's top-level IEs. */
namespace
{
struct IeWalk {
    gtp2_ie_iter_t it;
    gtp2_ie_view_t ie;
    explicit IeWalk(const gtp2_hdr_t& h, const uint8_t* buf, int hlen)
    {
        gtp2_ie_iter_init(&it, buf + hlen, (size_t)h.length + 4 - (size_t)hlen);
    }
    bool next()
    {
        return gtp2_ie_iter_next(&it, &ie);
    }
};
} /* namespace */

/* Decode the header, rejecting the wrong message type; returns the
 * header length. */
static int open_msg(const Bytes& wire, uint8_t want_mt, gtp2_hdr_t& h,
                    const char* doing)
{
    const int hl = gtp2_hdr_decode(wire.data(), wire.size(), &h);
    if (hl < 0) throw_gtp2(hl, doing);
    if (h.message_type != want_mt) throw_gtp2(GTP2_E_INVAL, doing);
    return hl;
}

/* ---- Create Session Request ---- */

Bytes CreateSessionRequest::encode() const
{
    if (apn.empty())
        throw Error("Create Session Request: APN is mandatory", GTP2_E_MISSING);
    if (bearers.empty())
        throw Error("Create Session Request: a bearer context is mandatory",
                    GTP2_E_MISSING);

    Bytes       out(WIRE_MAX);
    gtp2_wbuf_t w;
    gtp2_wbuf_init(&w, out.data(), out.size());
    const size_t off =
        put_hdr(w, GTP2_MT_CREATE_SESSION_REQUEST, teid, sequence);

    const Bytes imsi_b   = imsi.empty() ? Bytes() : bcd_encode(imsi);
    const Bytes msisdn_b = msisdn.empty() ? Bytes() : bcd_encode(msisdn);
    const Bytes mei_b    = mei.empty() ? Bytes() : bcd_encode(mei);
    const Bytes apn_b    = apn_encode(apn);

    put_bytes(w, GTP2_IE_IMSI, 0, imsi_b);
    put_bytes(w, GTP2_IE_MSISDN, 0, msisdn_b);
    put_bytes(w, GTP2_IE_MEI, 0, mei_b);
    put_bytes(w, GTP2_IE_ULI, 0, uli);
    put_bytes(w, GTP2_IE_SERVING_NETWORK, 0, serving_network);
    gtp2_ie_put_u8(&w, GTP2_IE_RAT_TYPE, 0, rat_type);

    const gtp2_fteid_t sf = fteid_to_c(sender_fteid);
    gtp2_fteid_put(&w, 0, &sf);
    if (has_pgw_fteid) {
        const gtp2_fteid_t pf = fteid_to_c(pgw_fteid);
        gtp2_fteid_put(&w, 1, &pf);
    }

    put_bytes(w, GTP2_IE_APN, 0, apn_b);
    if (selection_mode >= 0)
        gtp2_ie_put_u8(&w, GTP2_IE_SELECTION_MODE, 0,
                       static_cast<uint8_t>(selection_mode & 0x03));
    if (pdn_type >= 0)
        gtp2_ie_put_u8(&w, GTP2_IE_PDN_TYPE, 0,
                       static_cast<uint8_t>(pdn_type & 0x07));
    if (has_paa) {
        const gtp2_paa_t p = paa_to_c(paa);
        gtp2_paa_put(&w, 0, &p);
    }
    if (apn_restriction >= 0)
        gtp2_ie_put_u8(&w, GTP2_IE_APN_RESTRICTION, 0,
                       static_cast<uint8_t>(apn_restriction));
    if (has_ambr) {
        const gtp2_ambr_t a = { ambr.ul_kbps, ambr.dl_kbps };
        gtp2_ambr_put(&w, 0, &a);
    }
    put_bytes(w, GTP2_IE_PCO, 0, pco);
    for (const BearerContext& b : bearers)
        put_bearer(w, b);
    if (recovery >= 0)
        gtp2_ie_put_u8(&w, GTP2_IE_RECOVERY, 0, static_cast<uint8_t>(recovery));
    if (charging_char >= 0)
        gtp2_ie_put_u16(&w, GTP2_IE_CHARGING_CHARACTERISTICS, 0,
                        static_cast<uint16_t>(charging_char));

    return finish(w, out, off, "encode Create Session Request");
}

CreateSessionRequest CreateSessionRequest::decode(const Bytes& wire)
{
    gtp2_hdr_t h;
    const int  hl = open_msg(wire, GTP2_MT_CREATE_SESSION_REQUEST, h,
                             "decode Create Session Request");

    CreateSessionRequest m;
    m.teid     = h.teid;
    m.sequence = h.sequence;

    IeWalk it (h, wire.data(), hl);
    while (it.next()) {
        const gtp2_ie_view_t& v = it.ie;
        switch (v.type) {
        case GTP2_IE_IMSI:            m.imsi = bcd_decode(ie_bytes(v)); break;
        case GTP2_IE_MSISDN:          m.msisdn = bcd_decode(ie_bytes(v)); break;
        case GTP2_IE_MEI:             m.mei = bcd_decode(ie_bytes(v)); break;
        case GTP2_IE_ULI:             m.uli = ie_bytes(v); break;
        case GTP2_IE_SERVING_NETWORK: m.serving_network = ie_bytes(v); break;
        case GTP2_IE_RAT_TYPE:
            if (v.len) m.rat_type = v.value[0];
            break;
        case GTP2_IE_FTEID: {
            gtp2_fteid_t f;
            if (gtp2_fteid_decode(&v, &f) != GTP2_OK) break;
            if (v.instance == 0) m.sender_fteid = fteid_from_c(f);
            else if (v.instance == 1) {
                m.has_pgw_fteid = true;
                m.pgw_fteid     = fteid_from_c(f);
            }
            break;
        }
        case GTP2_IE_APN:
            if (v.len) m.apn = apn_decode(ie_bytes(v));
            break;
        case GTP2_IE_SELECTION_MODE:
            if (v.len) m.selection_mode = v.value[0] & 0x03;
            break;
        case GTP2_IE_PDN_TYPE:
            if (v.len) m.pdn_type = v.value[0] & 0x07;
            break;
        case GTP2_IE_PAA: {
            gtp2_paa_t p;
            if (gtp2_paa_decode(&v, &p) == GTP2_OK) {
                m.has_paa = true;
                m.paa     = paa_from_c(p);
            }
            break;
        }
        case GTP2_IE_APN_RESTRICTION:
            if (v.len) m.apn_restriction = v.value[0];
            break;
        case GTP2_IE_AMBR: {
            gtp2_ambr_t a;
            if (gtp2_ambr_decode(&v, &a) == GTP2_OK) {
                m.has_ambr = true;
                m.ambr     = { a.ul_kbps, a.dl_kbps };
            }
            break;
        }
        case GTP2_IE_PCO: m.pco = ie_bytes(v); break;
        case GTP2_IE_BEARER_CONTEXT:
            if (m.bearers.size() < CS_MAX_BEARERS)
                m.bearers.push_back(bearer_from_view(v));
            break;
        case GTP2_IE_RECOVERY:
            if (v.len) m.recovery = v.value[0];
            break;
        case GTP2_IE_CHARGING_CHARACTERISTICS:
            if (v.len >= 2) m.charging_char = be16(v.value);
            break;
        default: break;
        }
    }
    if (m.apn.empty() || m.bearers.empty())
        throw Error("decode Create Session Request: mandatory IE absent",
                    GTP2_E_MISSING);
    return m;
}

/* ---- Create Session Response ---- */

Bytes CreateSessionResponse::encode() const
{
    Bytes       out(WIRE_MAX);
    gtp2_wbuf_t w;
    gtp2_wbuf_init(&w, out.data(), out.size());
    const size_t off =
        put_hdr(w, GTP2_MT_CREATE_SESSION_RESPONSE, teid, sequence);

    put_cause(w, 0, cause);
    if (has_sender_fteid) {
        const gtp2_fteid_t f = fteid_to_c(sender_fteid);
        gtp2_fteid_put(&w, 0, &f);
    }
    if (has_pgw_fteid) {
        const gtp2_fteid_t f = fteid_to_c(pgw_fteid);
        gtp2_fteid_put(&w, 1, &f);
    }
    if (has_paa) {
        const gtp2_paa_t p = paa_to_c(paa);
        gtp2_paa_put(&w, 0, &p);
    }
    if (apn_restriction >= 0)
        gtp2_ie_put_u8(&w, GTP2_IE_APN_RESTRICTION, 0,
                       static_cast<uint8_t>(apn_restriction));
    if (has_ambr) {
        const gtp2_ambr_t a = { ambr.ul_kbps, ambr.dl_kbps };
        gtp2_ambr_put(&w, 0, &a);
    }
    put_bytes(w, GTP2_IE_PCO, 0, pco);
    for (const BearerContext& b : bearers)
        put_bearer(w, b);
    if (recovery >= 0)
        gtp2_ie_put_u8(&w, GTP2_IE_RECOVERY, 0, static_cast<uint8_t>(recovery));

    return finish(w, out, off, "encode Create Session Response");
}

CreateSessionResponse CreateSessionResponse::decode(const Bytes& wire)
{
    gtp2_hdr_t h;
    const int  hl = open_msg(wire, GTP2_MT_CREATE_SESSION_RESPONSE, h,
                             "decode Create Session Response");

    CreateSessionResponse m;
    m.teid          = h.teid;
    m.sequence      = h.sequence;
    bool have_cause = false;

    IeWalk it (h, wire.data(), hl);
    while (it.next()) {
        const gtp2_ie_view_t& v = it.ie;
        switch (v.type) {
        case GTP2_IE_CAUSE:
            if (v.len) {
                m.cause    = v.value[0];
                have_cause = true;
            }
            break;
        case GTP2_IE_FTEID: {
            gtp2_fteid_t f;
            if (gtp2_fteid_decode(&v, &f) != GTP2_OK) break;
            if (v.instance == 0) {
                m.has_sender_fteid = true;
                m.sender_fteid     = fteid_from_c(f);
            } else if (v.instance == 1) {
                m.has_pgw_fteid = true;
                m.pgw_fteid     = fteid_from_c(f);
            }
            break;
        }
        case GTP2_IE_PAA: {
            gtp2_paa_t p;
            if (gtp2_paa_decode(&v, &p) == GTP2_OK) {
                m.has_paa = true;
                m.paa     = paa_from_c(p);
            }
            break;
        }
        case GTP2_IE_APN_RESTRICTION:
            if (v.len) m.apn_restriction = v.value[0];
            break;
        case GTP2_IE_AMBR: {
            gtp2_ambr_t a;
            if (gtp2_ambr_decode(&v, &a) == GTP2_OK) {
                m.has_ambr = true;
                m.ambr     = { a.ul_kbps, a.dl_kbps };
            }
            break;
        }
        case GTP2_IE_PCO: m.pco = ie_bytes(v); break;
        case GTP2_IE_BEARER_CONTEXT:
            if (m.bearers.size() < CS_MAX_BEARERS)
                m.bearers.push_back(bearer_from_view(v));
            break;
        case GTP2_IE_RECOVERY:
            if (v.len) m.recovery = v.value[0];
            break;
        default: break;
        }
    }
    if (!have_cause)
        throw Error("decode Create Session Response: Cause is mandatory",
                    GTP2_E_MISSING);
    return m;
}

/* ---- Modify Bearer Request ---- */

Bytes ModifyBearerRequest::encode() const
{
    Bytes       out(WIRE_MAX);
    gtp2_wbuf_t w;
    gtp2_wbuf_init(&w, out.data(), out.size());
    const size_t off =
        put_hdr(w, GTP2_MT_MODIFY_BEARER_REQUEST, teid, sequence);

    const Bytes mei_b = mei.empty() ? Bytes() : bcd_encode(mei);
    put_bytes(w, GTP2_IE_MEI, 0, mei_b);
    put_bytes(w, GTP2_IE_ULI, 0, uli);
    put_bytes(w, GTP2_IE_SERVING_NETWORK, 0, serving_network);
    if (rat_type >= 0)
        gtp2_ie_put_u8(&w, GTP2_IE_RAT_TYPE, 0, static_cast<uint8_t>(rat_type));
    if (has_sender_fteid) {
        const gtp2_fteid_t f = fteid_to_c(sender_fteid);
        gtp2_fteid_put(&w, 0, &f);
    }
    if (has_ambr) {
        const gtp2_ambr_t a = { ambr.ul_kbps, ambr.dl_kbps };
        gtp2_ambr_put(&w, 0, &a);
    }
    if (delay_dl_pn >= 0)
        gtp2_ie_put_u8(&w, GTP2_IE_DELAY_VALUE, 0,
                       static_cast<uint8_t>(delay_dl_pn));
    for (const BearerContext& b : bearers)
        put_bearer(w, b);
    if (recovery >= 0)
        gtp2_ie_put_u8(&w, GTP2_IE_RECOVERY, 0, static_cast<uint8_t>(recovery));

    return finish(w, out, off, "encode Modify Bearer Request");
}

ModifyBearerRequest ModifyBearerRequest::decode(const Bytes& wire)
{
    gtp2_hdr_t h;
    const int  hl = open_msg(wire, GTP2_MT_MODIFY_BEARER_REQUEST, h,
                             "decode Modify Bearer Request");

    ModifyBearerRequest m;
    m.teid     = h.teid;
    m.sequence = h.sequence;

    IeWalk it (h, wire.data(), hl);
    while (it.next()) {
        const gtp2_ie_view_t& v = it.ie;
        switch (v.type) {
        case GTP2_IE_MEI:             m.mei = bcd_decode(ie_bytes(v)); break;
        case GTP2_IE_ULI:             m.uli = ie_bytes(v); break;
        case GTP2_IE_SERVING_NETWORK: m.serving_network = ie_bytes(v); break;
        case GTP2_IE_RAT_TYPE:
            if (v.len) m.rat_type = v.value[0];
            break;
        case GTP2_IE_FTEID: {
            gtp2_fteid_t f;
            if (gtp2_fteid_decode(&v, &f) == GTP2_OK && v.instance == 0) {
                m.has_sender_fteid = true;
                m.sender_fteid     = fteid_from_c(f);
            }
            break;
        }
        case GTP2_IE_AMBR: {
            gtp2_ambr_t a;
            if (gtp2_ambr_decode(&v, &a) == GTP2_OK) {
                m.has_ambr = true;
                m.ambr     = { a.ul_kbps, a.dl_kbps };
            }
            break;
        }
        case GTP2_IE_DELAY_VALUE:
            if (v.len) m.delay_dl_pn = v.value[0];
            break;
        case GTP2_IE_BEARER_CONTEXT:
            if (m.bearers.size() < CS_MAX_BEARERS)
                m.bearers.push_back(bearer_from_view(v));
            break;
        case GTP2_IE_RECOVERY:
            if (v.len) m.recovery = v.value[0];
            break;
        default: break;
        }
    }
    return m;
}

/* ---- Modify Bearer Response ---- */

Bytes ModifyBearerResponse::encode() const
{
    Bytes       out(WIRE_MAX);
    gtp2_wbuf_t w;
    gtp2_wbuf_init(&w, out.data(), out.size());
    const size_t off =
        put_hdr(w, GTP2_MT_MODIFY_BEARER_RESPONSE, teid, sequence);

    put_cause(w, 0, cause);
    const Bytes msisdn_b = msisdn.empty() ? Bytes() : bcd_encode(msisdn);
    put_bytes(w, GTP2_IE_MSISDN, 0, msisdn_b);
    if (linked_ebi >= 0)
        gtp2_ie_put_u8(&w, GTP2_IE_EBI, 0,
                       static_cast<uint8_t>(linked_ebi & 0x0f));
    if (apn_restriction >= 0)
        gtp2_ie_put_u8(&w, GTP2_IE_APN_RESTRICTION, 0,
                       static_cast<uint8_t>(apn_restriction));
    if (has_ambr) {
        const gtp2_ambr_t a = { ambr.ul_kbps, ambr.dl_kbps };
        gtp2_ambr_put(&w, 0, &a);
    }
    put_bytes(w, GTP2_IE_PCO, 0, pco);
    for (const BearerContext& b : bearers)
        put_bearer(w, b);
    if (recovery >= 0)
        gtp2_ie_put_u8(&w, GTP2_IE_RECOVERY, 0, static_cast<uint8_t>(recovery));

    return finish(w, out, off, "encode Modify Bearer Response");
}

ModifyBearerResponse ModifyBearerResponse::decode(const Bytes& wire)
{
    gtp2_hdr_t h;
    const int  hl = open_msg(wire, GTP2_MT_MODIFY_BEARER_RESPONSE, h,
                             "decode Modify Bearer Response");

    ModifyBearerResponse m;
    m.teid          = h.teid;
    m.sequence      = h.sequence;
    bool have_cause = false;

    IeWalk it (h, wire.data(), hl);
    while (it.next()) {
        const gtp2_ie_view_t& v = it.ie;
        switch (v.type) {
        case GTP2_IE_CAUSE:
            if (v.len) {
                m.cause    = v.value[0];
                have_cause = true;
            }
            break;
        case GTP2_IE_MSISDN: m.msisdn = bcd_decode(ie_bytes(v)); break;
        case GTP2_IE_EBI:
            if (v.len) m.linked_ebi = v.value[0] & 0x0f;
            break;
        case GTP2_IE_APN_RESTRICTION:
            if (v.len) m.apn_restriction = v.value[0];
            break;
        case GTP2_IE_AMBR: {
            gtp2_ambr_t a;
            if (gtp2_ambr_decode(&v, &a) == GTP2_OK) {
                m.has_ambr = true;
                m.ambr     = { a.ul_kbps, a.dl_kbps };
            }
            break;
        }
        case GTP2_IE_PCO: m.pco = ie_bytes(v); break;
        case GTP2_IE_BEARER_CONTEXT:
            if (m.bearers.size() < CS_MAX_BEARERS)
                m.bearers.push_back(bearer_from_view(v));
            break;
        case GTP2_IE_RECOVERY:
            if (v.len) m.recovery = v.value[0];
            break;
        default: break;
        }
    }
    if (!have_cause)
        throw Error("decode Modify Bearer Response: Cause is mandatory",
                    GTP2_E_MISSING);
    return m;
}

/* ---- Delete Session Request ---- */

Bytes DeleteSessionRequest::encode() const
{
    Bytes       out(WIRE_MAX);
    gtp2_wbuf_t w;
    gtp2_wbuf_init(&w, out.data(), out.size());
    const size_t off =
        put_hdr(w, GTP2_MT_DELETE_SESSION_REQUEST, teid, sequence);

    if (cause >= 0) put_cause(w, 0, static_cast<uint8_t>(cause));
    if (linked_ebi >= 0)
        gtp2_ie_put_u8(&w, GTP2_IE_EBI, 0,
                       static_cast<uint8_t>(linked_ebi & 0x0f));
    put_bytes(w, GTP2_IE_ULI, 0, uli);
    put_bytes(w, GTP2_IE_INDICATION, 0, indication);
    put_bytes(w, GTP2_IE_PCO, 0, pco);
    if (has_sender_fteid) {
        const gtp2_fteid_t f = fteid_to_c(sender_fteid);
        gtp2_fteid_put(&w, 0, &f);
    }

    return finish(w, out, off, "encode Delete Session Request");
}

DeleteSessionRequest DeleteSessionRequest::decode(const Bytes& wire)
{
    gtp2_hdr_t h;
    const int  hl = open_msg(wire, GTP2_MT_DELETE_SESSION_REQUEST, h,
                             "decode Delete Session Request");

    DeleteSessionRequest m;
    m.teid     = h.teid;
    m.sequence = h.sequence;

    IeWalk it (h, wire.data(), hl);
    while (it.next()) {
        const gtp2_ie_view_t& v = it.ie;
        switch (v.type) {
        case GTP2_IE_CAUSE:
            if (v.len) m.cause = v.value[0];
            break;
        case GTP2_IE_EBI:
            if (v.len) m.linked_ebi = v.value[0] & 0x0f;
            break;
        case GTP2_IE_ULI:        m.uli = ie_bytes(v); break;
        case GTP2_IE_INDICATION: m.indication = ie_bytes(v); break;
        case GTP2_IE_PCO:        m.pco = ie_bytes(v); break;
        case GTP2_IE_FTEID:      {
            gtp2_fteid_t f;
            if (gtp2_fteid_decode(&v, &f) == GTP2_OK && v.instance == 0) {
                m.has_sender_fteid = true;
                m.sender_fteid     = fteid_from_c(f);
            }
            break;
        }
        default: break;
        }
    }
    return m;
}

/* ---- Delete Session Response ---- */

Bytes DeleteSessionResponse::encode() const
{
    Bytes       out(WIRE_MAX);
    gtp2_wbuf_t w;
    gtp2_wbuf_init(&w, out.data(), out.size());
    const size_t off =
        put_hdr(w, GTP2_MT_DELETE_SESSION_RESPONSE, teid, sequence);

    put_cause(w, 0, cause);
    if (recovery >= 0)
        gtp2_ie_put_u8(&w, GTP2_IE_RECOVERY, 0, static_cast<uint8_t>(recovery));
    put_bytes(w, GTP2_IE_PCO, 0, pco);

    return finish(w, out, off, "encode Delete Session Response");
}

DeleteSessionResponse DeleteSessionResponse::decode(const Bytes& wire)
{
    gtp2_hdr_t h;
    const int  hl = open_msg(wire, GTP2_MT_DELETE_SESSION_RESPONSE, h,
                             "decode Delete Session Response");

    DeleteSessionResponse m;
    m.teid          = h.teid;
    m.sequence      = h.sequence;
    bool have_cause = false;

    IeWalk it (h, wire.data(), hl);
    while (it.next()) {
        const gtp2_ie_view_t& v = it.ie;
        switch (v.type) {
        case GTP2_IE_CAUSE:
            if (v.len) {
                m.cause    = v.value[0];
                have_cause = true;
            }
            break;
        case GTP2_IE_RECOVERY:
            if (v.len) m.recovery = v.value[0];
            break;
        case GTP2_IE_PCO: m.pco = ie_bytes(v); break;
        default:          break;
        }
    }
    if (!have_cause)
        throw Error("decode Delete Session Response: Cause is mandatory",
                    GTP2_E_MISSING);
    return m;
}

/* ---- Create Bearer Request ---- */

Bytes CreateBearerRequest::encode() const
{
    Bytes       out(WIRE_MAX);
    gtp2_wbuf_t w;
    gtp2_wbuf_init(&w, out.data(), out.size());
    const size_t off =
        put_hdr(w, GTP2_MT_CREATE_BEARER_REQUEST, teid, sequence);

    if (pti >= 0)
        gtp2_ie_put_u8(&w, GTP2_IE_PTI, 0, static_cast<uint8_t>(pti));
    if (linked_ebi >= 0)
        gtp2_ie_put_u8(&w, GTP2_IE_EBI, 0,
                       static_cast<uint8_t>(linked_ebi & 0x0f));
    if (has_ambr) {
        const gtp2_ambr_t a = { ambr.ul_kbps, ambr.dl_kbps };
        gtp2_ambr_put(&w, 0, &a);
    }
    put_bytes(w, GTP2_IE_PCO, 0, pco);
    for (const BearerContext& b : bearers)
        put_bearer(w, b);

    return finish(w, out, off, "encode Create Bearer Request");
}

CreateBearerRequest CreateBearerRequest::decode(const Bytes& wire)
{
    gtp2_hdr_t h;
    const int  hl = open_msg(wire, GTP2_MT_CREATE_BEARER_REQUEST, h,
                             "decode Create Bearer Request");

    CreateBearerRequest m;
    m.teid     = h.teid;
    m.sequence = h.sequence;

    IeWalk it (h, wire.data(), hl);
    while (it.next()) {
        const gtp2_ie_view_t& v = it.ie;
        switch (v.type) {
        case GTP2_IE_PTI:
            if (v.len) m.pti = v.value[0];
            break;
        case GTP2_IE_EBI: /* top-level EBI is the Linked EPS Bearer ID */
            if (v.len) m.linked_ebi = v.value[0] & 0x0f;
            break;
        case GTP2_IE_AMBR: {
            gtp2_ambr_t a;
            if (gtp2_ambr_decode(&v, &a) == GTP2_OK) {
                m.has_ambr = true;
                m.ambr     = { a.ul_kbps, a.dl_kbps };
            }
            break;
        }
        case GTP2_IE_PCO: m.pco = ie_bytes(v); break;
        case GTP2_IE_BEARER_CONTEXT:
            if (m.bearers.size() < CS_MAX_BEARERS)
                m.bearers.push_back(bearer_from_view(v));
            break;
        default: break;
        }
    }
    return m;
}

/* ---- Create Bearer Response ---- */

Bytes CreateBearerResponse::encode() const
{
    Bytes       out(WIRE_MAX);
    gtp2_wbuf_t w;
    gtp2_wbuf_init(&w, out.data(), out.size());
    const size_t off =
        put_hdr(w, GTP2_MT_CREATE_BEARER_RESPONSE, teid, sequence);

    put_cause(w, 0, cause);
    if (pti >= 0)
        gtp2_ie_put_u8(&w, GTP2_IE_PTI, 0, static_cast<uint8_t>(pti));
    for (const BearerContext& b : bearers)
        put_bearer(w, b);
    put_bytes(w, GTP2_IE_PCO, 0, pco);
    if (recovery >= 0)
        gtp2_ie_put_u8(&w, GTP2_IE_RECOVERY, 0, static_cast<uint8_t>(recovery));

    return finish(w, out, off, "encode Create Bearer Response");
}

CreateBearerResponse CreateBearerResponse::decode(const Bytes& wire)
{
    gtp2_hdr_t h;
    const int  hl = open_msg(wire, GTP2_MT_CREATE_BEARER_RESPONSE, h,
                             "decode Create Bearer Response");

    CreateBearerResponse m;
    m.teid          = h.teid;
    m.sequence      = h.sequence;
    bool have_cause = false;

    IeWalk it (h, wire.data(), hl);
    while (it.next()) {
        const gtp2_ie_view_t& v = it.ie;
        switch (v.type) {
        case GTP2_IE_CAUSE:
            if (v.len) {
                m.cause    = v.value[0];
                have_cause = true;
            }
            break;
        case GTP2_IE_PTI:
            if (v.len) m.pti = v.value[0];
            break;
        case GTP2_IE_PCO: m.pco = ie_bytes(v); break;
        case GTP2_IE_RECOVERY:
            if (v.len) m.recovery = v.value[0];
            break;
        case GTP2_IE_BEARER_CONTEXT:
            if (m.bearers.size() < CS_MAX_BEARERS)
                m.bearers.push_back(bearer_from_view(v));
            break;
        default: break;
        }
    }
    if (!have_cause)
        throw Error("decode Create Bearer Response: Cause is mandatory",
                    GTP2_E_MISSING);
    return m;
}

/* ---- Raw messages ---- */

static bool is_grouped(uint8_t type)
{
    switch (type) {
    case GTP2_IE_BEARER_CONTEXT:
    case GTP2_IE_PDN_CONNECTION:
    case GTP2_IE_OVERLOAD_CONTROL_INFORMATION:
    case GTP2_IE_LOAD_CONTROL_INFORMATION:
    case GTP2_IE_REMOTE_UE_CONTEXT:            return true;
    default:                                   return false;
    }
}

static std::vector<Ie> walk_ies(const uint8_t* payload, size_t len)
{
    std::vector<Ie> out;
    gtp2_ie_iter_t it;
    gtp2_ie_iter_init(&it, payload, len);
    gtp2_ie_view_t v;
    while (gtp2_ie_iter_next(&it, &v)) {
        Ie ie;
        ie.type     = v.type;
        ie.instance = v.instance;
        ie.value.assign(v.value, v.value + v.len);
        if (is_grouped(v.type)) ie.children = walk_ies(v.value, v.len);
        out.push_back(std::move(ie));
    }
    return out;
}

std::vector<Ie> ie_children(const Bytes& grouped_value)
{
    return walk_ies(grouped_value.data(), grouped_value.size());
}

const Ie& RawMessage::find(uint8_t type, uint8_t instance) const
{
    for (const Ie& ie : ies)
        if (ie.type == type && ie.instance == instance) return ie;
    throw Error("IE " + std::to_string(type) + " (instance " +
                std::to_string(instance) + ") not present");
}

bool RawMessage::has(uint8_t type, uint8_t instance) const
{
    for (const Ie& ie : ies)
        if (ie.type == type && ie.instance == instance) return true;
    return false;
}

static void put_ie(gtp2_wbuf_t& w, const Ie& ie)
{
    if (!ie.children.empty()) {
        int h = gtp2_ie_begin(&w, ie.type, ie.instance);
        for (const Ie& child : ie.children)
            put_ie(w, child);
        gtp2_ie_end(&w, h);
    } else {
        gtp2_ie_put(&w, ie.type, ie.instance,
                    ie.value.empty() ? nullptr : ie.value.data(),
                    static_cast<uint16_t>(ie.value.size()));
    }
}

Bytes RawMessage::encode() const
{
    Bytes       out(WIRE_MAX);
    gtp2_wbuf_t w;
    gtp2_wbuf_init(&w, out.data(), out.size());

    gtp2_hdr_t h;
    std::memset(&h, 0, sizeof h);
    h.has_teid     = has_teid;
    h.message_type = message_type;
    h.teid         = teid;
    h.sequence     = sequence;

    size_t hdr_off = w.off;
    int    hl      = gtp2_hdr_encode(w.buf + w.off, w.cap - w.off, &h);
    if (hl < 0) throw_gtp2(hl, "encode header");
    w.off += static_cast<size_t>(hl);

    for (const Ie& ie : ies)
        put_ie(w, ie);

    int rc = gtp2_hdr_finalize(&w, hdr_off);
    if (rc != GTP2_OK) throw_gtp2(rc, "encode message");
    out.resize(w.off);
    return out;
}

RawMessage RawMessage::decode(const Bytes& wire)
{
    gtp2_hdr_t h;
    int        hl = gtp2_hdr_decode(wire.data(), wire.size(), &h);
    if (hl < 0) throw_gtp2(hl, "decode header");

    size_t total = static_cast<size_t>(h.length) + 4;
    if (total > wire.size() || total < static_cast<size_t>(hl))
        throw_gtp2(GTP2_E_LENGTH, "decode message");

    RawMessage m;
    m.message_type = h.message_type;
    m.has_teid     = h.has_teid;
    m.teid         = h.teid;
    m.sequence     = h.sequence;
    m.piggyback    = h.piggyback;
    m.ies = walk_ies(wire.data() + hl, total - static_cast<size_t>(hl));
    return m;
}

} /* namespace gtp */
