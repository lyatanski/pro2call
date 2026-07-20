#include "diamxx.hpp"

#include <cstdio>

/* diamxx facade implementation. The C layer parses zero-copy into
 * views; everything a script sees is copied out of them right here,
 * once, so no C++ object ever borrows from a wire buffer. */

namespace diam
{

enum { MAX_GROUP_DEPTH = 16 };

static const char* errstr(int rc)
{
    switch (rc) {
    case DIAM_E_SHORT:    return "message incomplete";
    case DIAM_E_VERSION:  return "not Diameter version 1";
    case DIAM_E_LENGTH:   return "length field inconsistent";
    case DIAM_E_OVERFLOW: return "write buffer too small";
    case DIAM_E_INVAL:    return "invalid argument";
    case DIAM_E_TYPE:     return "data does not fit the type";
    default:              return "error";
    }
}

[[noreturn]] static void fail(const char* op, int rc)
{
    throw Error(std::string(op) + ": " + errstr(rc), rc);
}

/* Dictionary entry for a bare code: the standard registry first, then
 * any vendor. Lets scripts say put_u32(AVP_CC_REQUEST_TYPE, ...) and
 * put_str(AVP_PUBLIC_IDENTITY, ...) without spelling out the vendor. */
static const diam_dict_entry_t* lookup(uint32_t code)
{
    if (const diam_dict_entry_t* e = diam_dict_get(code, 0)) return e;
    for (size_t i = 0; const diam_dict_entry_t* e = diam_dict_at(i); i++) {
        if (e->code == code) return e;
    }
    return nullptr;
}

/* ---- Avp ---- */

std::string Avp::name() const
{
    const char* n = diam_avp_name(code, vendor_id);
    return n ? n : "";
}

int Avp::type() const
{
    const diam_dict_entry_t* e = diam_dict_get(code, vendor_id);
    return e ? e->type : -1;
}

static void need_len(const Avp& a, size_t n, const char* op)
{
    if (a.data.size() != n) fail(op, DIAM_E_TYPE);
}

uint32_t Avp::u32() const
{
    need_len(*this, 4, "u32");
    const uint8_t* p = (const uint8_t*)data.data();
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

uint64_t Avp::u64() const
{
    need_len(*this, 8, "u64");
    const uint8_t* p = (const uint8_t*)data.data();
    uint64_t       v = 0;
    for (int i = 0; i < 8; i++)
        v = (v << 8) | p[i];
    return v;
}

int32_t Avp::i32() const
{
    need_len(*this, 4, "i32");
    const uint8_t* p = (const uint8_t*)data.data();
    return (int32_t)(((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                     ((uint32_t)p[2] << 8) | (uint32_t)p[3]);
}

int64_t Avp::i64() const
{
    need_len(*this, 8, "i64");
    const uint8_t* p = (const uint8_t*)data.data();
    uint64_t       v = 0;
    for (int i = 0; i < 8; i++)
        v = (v << 8) | p[i];
    return (int64_t)v;
}

std::string Avp::value_name() const
{
    if (data.size() != 4) return "";
    const char* n = diam_enum_name(code, vendor_id, i32());
    return n ? n : "";
}

bool Avp::has_child(uint32_t c, uint32_t vendor) const
{
    for (const Avp& a : children)
        if (a.code == c && a.vendor_id == vendor) return true;
    return false;
}

Avp Avp::child(uint32_t c, uint32_t vendor) const
{
    for (const Avp& a : children)
        if (a.code == c && a.vendor_id == vendor) return a;
    throw Error("child: AVP " + std::to_string(c) + " absent");
}

/* ---- parse ---- */

static void parse_avps(const uint8_t* p, size_t len, std::vector<Avp>& out,
                       int depth)
{
    diam_avp_iter_t it;
    diam_avp_iter_init(&it, p, len);

    diam_avp_view_t v;
    while (diam_avp_iter_next(&it, &v)) {
        Avp a;
        a.code      = v.code;
        a.vendor_id = v.vendor_id;
        a.flags     = v.flags;
        a.data.assign((const char*)v.value, v.len);

        const diam_dict_entry_t* e = diam_dict_get(v.code, v.vendor_id);
        if (e && e->type == DIAM_TYPE_GROUPED && depth < MAX_GROUP_DEPTH) {
            /* Children of an unknown or malformed grouped AVP stay a
             * leaf; the raw bytes are still in data. */
            try {
                parse_avps(v.value, v.len, a.children, depth + 1);
            } catch (const Error&) {
                a.children.clear();
            }
        }
        out.push_back(std::move(a));
    }
    /* The iterator stops both at end-of-stream and on a malformed
     * entry; leftover bytes tell the two apart. */
    if (it.cur != it.end) fail("parse", DIAM_E_LENGTH);
}

Msg parse(const std::string& wire)
{
    const uint8_t* buf = (const uint8_t*)wire.data();

    diam_hdr_t h;
    const int  rc = diam_hdr_decode(buf, wire.size(), &h);
    if (rc < 0) fail("parse", rc);

    Msg m;
    m.request    = h.request;
    m.proxiable  = h.proxiable;
    m.error      = h.error;
    m.retransmit = h.retransmit;
    m.cmd        = h.cmd_code;
    m.app        = h.app_id;
    m.hbh        = h.hbh;
    m.e2e        = h.e2e;
    parse_avps(buf + DIAM_HDR_LEN, h.length - DIAM_HDR_LEN, m.avps, 0);
    return m;
}

/* ---- Msg ---- */

std::string Msg::name() const
{
    const char* n = diam_cmd_name(cmd);
    return n ? n : "";
}

Avp Msg::avp_at(int i) const
{
    if (i < 0 || (size_t)i >= avps.size()) fail("avp_at", DIAM_E_INVAL);
    return avps[(size_t)i];
}

bool Msg::has(uint32_t code, uint32_t vendor) const
{
    for (const Avp& a : avps)
        if (a.code == code && a.vendor_id == vendor) return true;
    return false;
}

Avp Msg::find(uint32_t code, uint32_t vendor) const
{
    for (const Avp& a : avps)
        if (a.code == code && a.vendor_id == vendor) return a;
    throw Error("find: AVP " + std::to_string(code) + " absent");
}

uint32_t Msg::u32(uint32_t code, uint32_t vendor) const
{
    return find(code, vendor).u32();
}

std::string Msg::str(uint32_t code, uint32_t vendor) const
{
    return find(code, vendor).str();
}

/* ---- Builder ---- */

/* 64 KiB — a generous ceiling for signalling messages. */
Builder::Builder() : buf_(64 * 1024)
{
    diam_wbuf_init(&w_, buf_.data(), buf_.size());
    hdr_ = diam_hdr_t{};
}

void Builder::ensure_started(const char* op)
{
    if (!started_)
        throw Error(std::string(op) + ": call request() or answer() first");
}

Builder& Builder::request(uint32_t cmd, uint32_t app)
{
    hdr_          = diam_hdr_t{};
    hdr_.request  = true;
    hdr_.cmd_code = cmd;
    hdr_.app_id   = app;
    diam_wbuf_init(&w_, buf_.data(), buf_.size());
    w_.off = DIAM_HDR_LEN; /* header encoded by done() */
    groups_.clear();
    started_ = true;
    return *this;
}

Builder& Builder::answer(uint32_t cmd, uint32_t app)
{
    request(cmd, app);
    hdr_.request = false;
    return *this;
}

Builder& Builder::ids(uint32_t hbh, uint32_t e2e)
{
    ensure_started("ids");
    hdr_.hbh = hbh;
    hdr_.e2e = e2e;
    return *this;
}

Builder& Builder::proxiable(bool on)
{
    ensure_started("proxiable");
    hdr_.proxiable = on;
    return *this;
}

Builder& Builder::error(bool on)
{
    ensure_started("error");
    hdr_.error = on;
    return *this;
}

Builder& Builder::retransmit(bool on)
{
    ensure_started("retransmit");
    hdr_.retransmit = on;
    return *this;
}

/* Vendor id and wire flags for a code, from the dictionary. wanted is
 * an explicit vendor id or VENDOR_AUTO (standard registry first, then
 * any vendor). */
static void resolve(uint32_t code, uint32_t wanted, uint32_t* vendor,
                    uint8_t* flags)
{
    const diam_dict_entry_t* e =
        wanted == VENDOR_AUTO ? lookup(code) : diam_dict_get(code, wanted);
    if (e) {
        *vendor = e->vendor_id;
        *flags  = e->flags;
        return;
    }
    *vendor = wanted == VENDOR_AUTO ? 0 : wanted;
    *flags  = *vendor ? DIAM_AVP_F_VENDOR : 0;
}

Builder& Builder::put_raw(uint32_t code, uint32_t vendor_id, unsigned flags,
                          const std::string& data)
{
    ensure_started("put_raw");
    const int rc = diam_avp_put(&w_, code, (uint8_t)flags, vendor_id,
                                data.data(), (uint32_t)data.size());
    if (rc != DIAM_OK) fail("put_raw", rc);
    return *this;
}

Builder& Builder::put_str(uint32_t code, const std::string& data,
                          uint32_t vendor_id)
{
    ensure_started("put_str");
    uint32_t vendor;
    uint8_t  flags;
    resolve(code, vendor_id, &vendor, &flags);
    const int rc = diam_avp_put(&w_, code, flags, vendor, data.data(),
                                (uint32_t)data.size());
    if (rc != DIAM_OK) fail("put_str", rc);
    return *this;
}

Builder& Builder::put_u32(uint32_t code, uint32_t v, uint32_t vendor_id)
{
    ensure_started("put_u32");
    uint32_t vendor;
    uint8_t  flags;
    resolve(code, vendor_id, &vendor, &flags);
    const int rc = diam_avp_put_u32(&w_, code, flags, vendor, v);
    if (rc != DIAM_OK) fail("put_u32", rc);
    return *this;
}

Builder& Builder::put_u64(uint32_t code, uint64_t v, uint32_t vendor_id)
{
    ensure_started("put_u64");
    uint32_t vendor;
    uint8_t  flags;
    resolve(code, vendor_id, &vendor, &flags);
    const int rc = diam_avp_put_u64(&w_, code, flags, vendor, v);
    if (rc != DIAM_OK) fail("put_u64", rc);
    return *this;
}

Builder& Builder::put_i32(uint32_t code, int32_t v, uint32_t vendor_id)
{
    return put_u32(code, (uint32_t)v, vendor_id);
}

Builder& Builder::put_i64(uint32_t code, int64_t v, uint32_t vendor_id)
{
    return put_u64(code, (uint64_t)v, vendor_id);
}

Builder& Builder::put_addr4(uint32_t code, const std::string& dotted,
                            uint32_t vendor_id)
{
    ensure_started("put_addr4");
    uint8_t  a[4];
    unsigned b[4];
    if (sscanf(dotted.c_str(), "%u.%u.%u.%u", &b[0], &b[1], &b[2], &b[3]) !=
            4 ||
        b[0] > 255 || b[1] > 255 || b[2] > 255 || b[3] > 255)
        fail("put_addr4", DIAM_E_INVAL);
    for (int i = 0; i < 4; i++)
        a[i] = (uint8_t)b[i];

    uint32_t vendor;
    uint8_t  flags;
    resolve(code, vendor_id, &vendor, &flags);
    const int rc = diam_avp_put_addr(&w_, code, flags, vendor,
                                     1 /* IANA IPv4 */, a, sizeof a);
    if (rc != DIAM_OK) fail("put_addr4", rc);
    return *this;
}

Builder& Builder::begin_group(uint32_t code, uint32_t vendor_id)
{
    ensure_started("begin_group");
    if (groups_.size() >= MAX_GROUP_DEPTH) fail("begin_group", DIAM_E_INVAL);
    uint32_t vendor;
    uint8_t  flags;
    resolve(code, vendor_id, &vendor, &flags);
    const int h = diam_avp_begin(&w_, code, flags, vendor);
    if (h < 0) fail("begin_group", h);
    groups_.push_back(h);
    return *this;
}

Builder& Builder::end_group()
{
    ensure_started("end_group");
    if (groups_.empty()) throw Error("end_group: no open group");
    const int rc = diam_avp_end(&w_, groups_.back());
    if (rc != DIAM_OK) fail("end_group", rc);
    groups_.pop_back();
    return *this;
}

std::string Builder::done()
{
    ensure_started("done");
    if (!groups_.empty()) throw Error("done: unclosed group");

    int rc = diam_hdr_encode(buf_.data(), buf_.size(), &hdr_);
    if (rc < 0) fail("done", rc);
    rc = diam_hdr_finalize(&w_, 0);
    if (rc != DIAM_OK) fail("done", rc);

    std::string out((const char*)buf_.data(), w_.off);
    started_ = false;
    return out;
}

/* ---- Session ---- */

Session::Session(int kind) : fsm_(nullptr), kind_(kind)
{
    switch (kind) {
    case SESS_CLIENT: fsm_ = diam_sess_fsm_client(); break;
    case SESS_SERVER: fsm_ = diam_sess_fsm_server(); break;
    default:          fail("Session", DIAM_E_INVAL);
    }
    if (!fsm_) throw Error("Session: out of memory");
}

Session::~Session()
{
    fsm_destroy(fsm_);
}

int Session::state() const
{
    return fsm_get_current_state(fsm_);
}

std::string Session::state_name() const
{
    return diam_sess_state_name(fsm_get_current_state(fsm_));
}

bool Session::open() const
{
    return fsm_get_current_state(fsm_) == DIAM_SESS_ST_OPEN;
}

bool Session::closed() const
{
    return fsm_terminated(fsm_);
}

Session& Session::event(int ev)
{
    int rc = fsm_act(fsm_, ev, NULL, NULL);
    if (rc != FSM_OK)
        throw Error(std::string("event: ") + diam_sess_event_name(ev) +
                        " is illegal in state " + state_name(),
                    rc);
    return *this;
}

/* An answer succeeds on a 2xxx Result-Code; the 3GPP applications park
 * their grant codes under Experimental-Result instead, so 2xxx counts
 * from there too. */
static bool answer_ok(const Msg& m)
{
    if (m.error) return false;
    if (m.has(DIAM_AVP_RESULT_CODE))
        return m.u32(DIAM_AVP_RESULT_CODE) / 1000 == 2;
    if (m.has(DIAM_AVP_EXPERIMENTAL_RESULT)) {
        const Avp g = m.find(DIAM_AVP_EXPERIMENTAL_RESULT);
        if (g.has_child(DIAM_AVP_EXPERIMENTAL_RESULT_CODE))
            return g.child(DIAM_AVP_EXPERIMENTAL_RESULT_CODE).u32() / 1000 == 2;
    }
    return false;
}

/* Message -> session event; -1 for messages with no state change of
 * their own (STA out goes with the STR that already closed the
 * session, ASA and RAA ride on the ASR/RAR). */
static int msg_event(const Msg& m, bool sending)
{
    if (m.request) {
        switch (m.cmd) {
        case DIAM_CMD_SESSION_TERMINATION:
            return sending ? DIAM_SESS_EV_SEND_STR : DIAM_SESS_EV_RECV_STR;
        case DIAM_CMD_ABORT_SESSION: return DIAM_SESS_EV_ABORT;
        case DIAM_CMD_RE_AUTH:       return DIAM_SESS_EV_REAUTH;
        default:
            return sending ? DIAM_SESS_EV_SEND_REQUEST
                           : DIAM_SESS_EV_RECV_REQUEST;
        }
    }
    switch (m.cmd) {
    case DIAM_CMD_SESSION_TERMINATION:
        return sending ? -1 : DIAM_SESS_EV_RECV_STA;
    case DIAM_CMD_ABORT_SESSION:
    case DIAM_CMD_RE_AUTH:       return -1;
    default:
        return answer_ok(m) ? DIAM_SESS_EV_ANSWER_OK : DIAM_SESS_EV_ANSWER_FAIL;
    }
}

Session& Session::send(const Msg& m)
{
    const int ev = msg_event(m, true);
    return ev < 0 ? *this : event(ev);
}

Session& Session::recv(const Msg& m)
{
    const int ev = msg_event(m, false);
    return ev < 0 ? *this : event(ev);
}

} /* namespace diam */
