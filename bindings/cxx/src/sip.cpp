#include "sipxx.hpp"

/* sipxx facade implementation. The C layer parses zero-copy into
 * slices; everything a script sees is copied out of them right here,
 * once, so no C++ object ever borrows from a wire buffer. */

namespace sip
{

static std::string str(sip_str_t s)
{
    return std::string(s.p ? s.p : "", s.len);
}

static sip_str_t slice(const std::string& s)
{
    sip_str_t out;
    out.p   = s.data();
    out.len = (uint32_t)s.size();
    return out;
}

static const char* errstr(int rc)
{
    switch (rc) {
    case SIP_E_SHORT:    return "message incomplete";
    case SIP_E_LINE:     return "malformed start line";
    case SIP_E_VERSION:  return "version is not SIP/2.0";
    case SIP_E_HEADER:   return "malformed header field";
    case SIP_E_HEADERS:  return "too many header fields";
    case SIP_E_OVERFLOW: return "message too large";
    case SIP_E_INVAL:    return "invalid argument";
    case SIP_E_URI:      return "malformed URI or address";
    case SIP_E_MISSING:  return "header absent";
    default:             return "error";
    }
}

[[noreturn]] static void fail(const char* op, int rc)
{
    throw Error(std::string(op) + ": " + errstr(rc), rc);
}

static bool ieq(const std::string& a, const std::string& b)
{
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++)
        if ((a[i] | 0x20) != (b[i] | 0x20)) return false;
    return true;
}

/* ---- Msg ---- */

int Msg::header_count() const
{
    return (int)hdrs.size();
}

Header Msg::header_at(int i) const
{
    if (i < 0 || (size_t)i >= hdrs.size()) fail("header_at", SIP_E_INVAL);
    return hdrs[(size_t)i];
}

/* Same matching rules as the C layer: a known name (long or compact,
 * any case) matches on the enum, an extension name matches literally. */
static bool matches(const Header& h, const std::string& name, int id)
{
    if (id != SIP_H_OTHER) return h.id == id;
    return h.id == SIP_H_OTHER && ieq(h.name, name);
}

bool Msg::has_header(const std::string& name) const
{
    int id = sip_hdr_from(name.data(), name.size());
    for (const Header& h : hdrs)
        if (matches(h, name, id)) return true;
    return false;
}

std::string Msg::header(const std::string& name) const
{
    int id = sip_hdr_from(name.data(), name.size());
    for (const Header& h : hdrs)
        if (matches(h, name, id)) return h.value;
    return "";
}

std::vector<std::string> Msg::header_values(const std::string& name) const
{
    int                      id = sip_hdr_from(name.data(), name.size());
    std::vector<std::string> out;
    for (const Header& h : hdrs)
        if (matches(h, name, id)) out.push_back(h.value);
    return out;
}

static const Header* find_id(const Msg& m, int id)
{
    for (const Header& h : m.hdrs)
        if (h.id == id) return &h;
    return nullptr;
}

CSeq Msg::cseq() const
{
    const Header* h = find_id(*this, SIP_H_CSEQ);
    if (!h) fail("cseq", SIP_E_MISSING);
    sip_cseq_t cs;
    int        rc = sip_cseq_parse(slice(h->value), &cs);
    if (rc != SIP_OK) fail("cseq", rc);
    CSeq out;
    out.number      = cs.seq;
    out.method      = cs.method;
    out.method_name = str(cs.method_name);
    return out;
}

static Addr addr_of(const Msg& m, int id, const char* op)
{
    const Header* h = find_id(m, id);
    if (!h) fail(op, SIP_E_MISSING);
    return parse_addr(h->value);
}

Addr Msg::from_() const
{
    return addr_of(*this, SIP_H_FROM, "from");
}
Addr Msg::to_() const
{
    return addr_of(*this, SIP_H_TO, "to");
}

Via Msg::top_via() const
{
    const Header* h = find_id(*this, SIP_H_VIA);
    if (!h) fail("top_via", SIP_E_MISSING);
    return parse_via(h->value);
}

/* ---- parsers ---- */

Msg parse(const std::string& wire)
{
    sip_msg_t m;
    int       rc = sip_msg_parse(&m, wire.data(), wire.size());
    if (rc < 0) fail("parse", rc);

    Msg out;
    out.request     = m.is_request;
    out.method      = m.method;
    out.method_name = str(m.method_name);
    out.uri         = str(m.ruri);
    out.status      = m.status;
    out.reason      = str(m.reason);
    out.body        = str(m.body);
    out.hdrs.reserve(m.hdr_count);
    for (uint16_t i = 0; i < m.hdr_count; i++) {
        Header h;
        h.id    = m.hdrs[i].id;
        h.name  = str(m.hdrs[i].name);
        h.value = str(m.hdrs[i].value);
        out.hdrs.push_back(std::move(h));
    }
    return out;
}

Uri parse_uri(const std::string& s)
{
    sip_uri_t u;
    int       rc = sip_uri_parse(&u, s.data(), s.size());
    if (rc != SIP_OK) fail("parse_uri", rc);
    Uri out;
    out.scheme  = str(u.scheme_name);
    out.user    = str(u.user);
    out.host    = str(u.host);
    out.port    = u.port;
    out.params  = str(u.params);
    out.headers = str(u.headers);
    return out;
}

Addr parse_addr(const std::string& value)
{
    sip_addr_t a;
    int        rc = sip_addr_parse(slice(value), &a);
    if (rc != SIP_OK) fail("parse_addr", rc);
    Addr out;
    out.display = str(a.display);
    out.uri     = str(a.uri);
    out.params  = str(a.params);
    out.tag     = str(a.tag);
    return out;
}

Via parse_via(const std::string& value)
{
    sip_via_t v;
    int       rc = sip_via_parse(slice(value), &v);
    if (rc != SIP_OK) fail("parse_via", rc);
    Via out;
    out.transport = str(v.transport);
    out.host      = str(v.host);
    out.port      = v.port;
    out.params    = str(v.params);
    out.branch    = str(v.branch);
    return out;
}

/* ---- auth-header helpers ---- */

static bool param_boundary(char c)
{
    return c == ',' || c == ';' || c == ' ' || c == '\t';
}

std::string auth_param(const std::string& v, const std::string& key)
{
    const size_t n = v.size(), k = key.size();
    if (k == 0) return "";
    for (size_t i = 0; i + k <= n; i++) {
        if (i != 0 && !param_boundary(v[i - 1])) continue; /* mid-token */
        if (v.compare(i, k, key) != 0) continue;
        size_t j = i + k;
        while (j < n && (v[j] == ' ' || v[j] == '\t')) j++;
        if (j >= n || v[j] != '=') continue;
        j++;
        while (j < n && (v[j] == ' ' || v[j] == '\t')) j++;
        if (j < n && v[j] == '"') { /* quoted value */
            size_t e = v.find('"', ++j);
            return v.substr(j, (e == std::string::npos ? n : e) - j);
        }
        size_t e = j; /* bare token */
        while (e < n && !param_boundary(v[e])) e++;
        return v.substr(j, e - j);
    }
    return "";
}

std::string b64decode(const std::string& s)
{
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    signed char map[256];
    for (int i = 0; i < 256; i++) map[i] = -1;
    for (int i = 0; i < 64; i++) map[(unsigned char)alphabet[i]] = (signed char)i;

    std::string out;
    uint32_t    acc   = 0;
    int         nbits = 0;
    for (unsigned char c : s) {
        signed char v = map[c];
        if (v < 0) continue; /* skip '=', whitespace, line breaks */
        acc = acc << 6 | (uint32_t)v;
        nbits += 6;
        if (nbits >= 8) {
            nbits -= 8;
            out.push_back(static_cast<char>(acc >> nbits & 0xff));
        }
    }
    return out;
}

/* ---- name tables ---- */

std::string method_name(int method)
{
    return sip_method_name((sip_method_t)method);
}

std::string hdr_name(int hdr)
{
    return sip_hdr_name((sip_hdr_t)hdr);
}

std::string status_phrase(int status)
{
    return sip_status_phrase((unsigned)status);
}

/* ---- Builder ---- */

enum { BUILDER_CAP = 64 * 1024 };

Builder::Builder() : buf_(BUILDER_CAP)
{
    sip_wbuf_init(&w_, buf_.data(), buf_.size());
}

Builder& Builder::request(int method, const std::string& uri)
{
    int rc = sip_put_request(&w_, (sip_method_t)method, uri.data(), uri.size());
    if (rc != SIP_OK) fail("request", rc);
    return *this;
}

Builder& Builder::response(int status, const std::string& reason)
{
    int rc =
        sip_put_status(&w_, (unsigned)status,
                       reason.empty() ? NULL : reason.data(), reason.size());
    if (rc != SIP_OK) fail("response", rc);
    return *this;
}

Builder& Builder::header(int hdr, const std::string& value)
{
    int rc = sip_put_hdr(&w_, (sip_hdr_t)hdr, value.data(), value.size());
    if (rc != SIP_OK) fail("header", rc);
    return *this;
}

Builder& Builder::header_name(const std::string& name, const std::string& value)
{
    int rc = sip_put_hdr_name(&w_, name.data(), name.size(), value.data(),
                              value.size());
    if (rc != SIP_OK) fail("header", rc);
    return *this;
}

Builder& Builder::header_u32(int hdr, unsigned value)
{
    int rc = sip_put_hdr_u32(&w_, (sip_hdr_t)hdr, value);
    if (rc != SIP_OK) fail("header", rc);
    return *this;
}

std::string Builder::done(const std::string& body)
{
    int n = sip_put_body(&w_, body.data(), body.size());
    if (n < 0) {
        sip_wbuf_init(&w_, buf_.data(), buf_.size());
        fail("done", n);
    }
    std::string out(buf_.data(), (size_t)n);
    sip_wbuf_init(&w_, buf_.data(), buf_.size()); /* ready for the next */
    return out;
}

/* ---- Transaction ---- */

Transaction::Transaction(int kind) : fsm_(nullptr), kind_(kind)
{
    switch (kind) {
    case INVITE_CLIENT:     fsm_ = sip_trans_fsm_invite_client(); break;
    case INVITE_SERVER:     fsm_ = sip_trans_fsm_invite_server(); break;
    case NON_INVITE_CLIENT: fsm_ = sip_trans_fsm_client(); break;
    case NON_INVITE_SERVER: fsm_ = sip_trans_fsm_server(); break;
    default:                fail("Transaction", SIP_E_INVAL);
    }
    if (!fsm_) throw Error("Transaction: out of memory");
}

Transaction::~Transaction()
{
    fsm_destroy(fsm_);
}

int Transaction::state() const
{
    return fsm_get_current_state(fsm_);
}

std::string Transaction::state_name() const
{
    return sip_trans_state_name(fsm_get_current_state(fsm_));
}

bool Transaction::terminated() const
{
    return fsm_terminated(fsm_);
}

Transaction& Transaction::event(int ev)
{
    int rc = fsm_act(fsm_, ev, NULL, NULL);
    if (rc != FSM_OK)
        throw Error(std::string("event: ") + sip_trans_event_name(ev) +
                        " is illegal in state " + state_name(),
                    rc);
    return *this;
}

/* Map a response's status class to its send/recv event. */
static int status_event(const Msg& m, bool sending)
{
    if (m.status < 200)
        return sending ? SIP_TRANS_EV_SEND_1XX : SIP_TRANS_EV_RECV_1XX;
    if (m.status < 300)
        return sending ? SIP_TRANS_EV_SEND_2XX : SIP_TRANS_EV_RECV_2XX;
    return sending ? SIP_TRANS_EV_SEND_3XX_6XX : SIP_TRANS_EV_RECV_3XX_6XX;
}

Transaction& Transaction::send(const Msg& m)
{
    if (m.request && m.method == SIP_M_ACK)
        return *this; /* below the TU or a separate transaction */
    return event(m.request ? SIP_TRANS_EV_SEND_REQUEST : status_event(m, true));
}

Transaction& Transaction::recv(const Msg& m)
{
    if (m.request && m.method == SIP_M_ACK) return event(SIP_TRANS_EV_RECV_ACK);
    return event(m.request ? SIP_TRANS_EV_RECV_REQUEST
                           : status_event(m, false));
}

/* ---- Dialog ---- */

Dialog::Dialog() : fsm_(sip_dialog_fsm())
{
    if (!fsm_) throw Error("Dialog: out of memory");
}

Dialog::~Dialog()
{
    fsm_destroy(fsm_);
}

int Dialog::state() const
{
    return fsm_get_current_state(fsm_);
}

std::string Dialog::state_name() const
{
    return sip_dialog_state_name(fsm_get_current_state(fsm_));
}

bool Dialog::early() const
{
    return fsm_get_current_state(fsm_) == SIP_DIALOG_ST_EARLY;
}

bool Dialog::confirmed() const
{
    return fsm_get_current_state(fsm_) == SIP_DIALOG_ST_CONFIRMED;
}

bool Dialog::terminated() const
{
    return fsm_terminated(fsm_);
}

Dialog& Dialog::event(int ev)
{
    int rc = fsm_act(fsm_, ev, NULL, NULL);
    if (rc != FSM_OK)
        throw Error(std::string("event: ") + sip_dialog_event_name(ev) +
                        " is illegal in state " + state_name(),
                    rc);
    return *this;
}

/* The To-tag / CSeq accessors throw when the header is absent; a dialog
 * being driven from real traffic tolerates that, so read them softly. */
static std::string soft_to_tag(const Msg& m)
{
    try {
        return m.to_().tag;
    } catch (const Error&) {
        return "";
    }
}

static int soft_cseq_method(const Msg& m)
{
    try {
        return m.cseq().method;
    } catch (const Error&) {
        return M_UNKNOWN;
    }
}

/* Message -> dialog event; -1 for messages that do not move the dialog
 * (a mid-dialog request, a 100 Trying, a re-INVITE failure once
 * confirmed). Works for both directions: a UAS sending a 2xx confirms
 * and sending/receiving a BYE terminates, just as a UAC receiving them
 * does. */
static int dialog_event(const Msg& m, int state)
{
    if (m.request)
        return m.method == SIP_M_BYE ? SIP_DIALOG_EV_TERMINATE : -1;

    if (soft_cseq_method(m) != SIP_M_INVITE) return -1; /* only INVITE forms it */
    if (m.status >= 200 && m.status < 300) return SIP_DIALOG_EV_CONFIRM;
    if (m.status > 100 && m.status < 200)
        return soft_to_tag(m).empty() ? -1 : SIP_DIALOG_EV_EARLY;
    if (m.status >= 300) /* a confirmed dialog survives a re-INVITE failure */
        return state == SIP_DIALOG_ST_CONFIRMED ? -1 : SIP_DIALOG_EV_TERMINATE;
    return -1;
}

Dialog& Dialog::send(const Msg& m)
{
    const int ev = dialog_event(m, state());
    return ev < 0 ? *this : event(ev);
}

Dialog& Dialog::recv(const Msg& m)
{
    const int ev = dialog_event(m, state());
    return ev < 0 ? *this : event(ev);
}

/* ---- Registration ---- */

Registration::Registration() : fsm_(sip_reg_fsm())
{
    if (!fsm_) throw Error("Registration: out of memory");
}

Registration::~Registration()
{
    fsm_destroy(fsm_);
}

int Registration::state() const
{
    return fsm_get_current_state(fsm_);
}

std::string Registration::state_name() const
{
    return sip_reg_state_name(fsm_get_current_state(fsm_));
}

bool Registration::registered() const
{
    return fsm_get_current_state(fsm_) == SIP_REG_ST_REGISTERED;
}

bool Registration::done() const
{
    return fsm_get_current_state(fsm_) == SIP_REG_ST_DONE;
}

bool Registration::failed() const
{
    return fsm_terminated(fsm_);
}

Registration& Registration::event(int ev)
{
    int rc = fsm_act(fsm_, ev, NULL, NULL);
    if (rc != FSM_OK)
        throw Error(std::string("event: ") + sip_reg_event_name(ev) +
                        " is illegal in state " + state_name(),
                    rc);
    return *this;
}

/* A REGISTER is a de-registration when it removes the binding: Expires: 0,
 * a wildcard "Contact: *", or a Contact carrying expires=0. */
static bool is_deregister(const Msg& m)
{
    if (m.header("Expires") == "0") return true;
    const std::string c = m.header("Contact");
    if (c == "*") return true;
    return auth_param(c, "expires") == "0";
}

Registration& Registration::send(const Msg& m)
{
    if (!m.request || m.method != SIP_M_REGISTER) return *this;
    switch (state()) {
    case SIP_REG_ST_IDLE:       return event(SIP_REG_EV_SEND);
    case SIP_REG_ST_CHALLENGED: return event(SIP_REG_EV_AUTH);
    case SIP_REG_ST_REGISTERED:
        return event(is_deregister(m) ? SIP_REG_EV_DEREGISTER
                                      : SIP_REG_EV_REFRESH);
    default: return *this; /* a retransmission while a REGISTER is in flight */
    }
}

Registration& Registration::recv(const Msg& m)
{
    if (m.request) return *this;
    if (m.status == 401 || m.status == 407) return event(SIP_REG_EV_CHALLENGE);
    if (m.status >= 200 && m.status < 300) return event(SIP_REG_EV_OK);
    if (m.status >= 300) return event(SIP_REG_EV_FAIL);
    return *this; /* 1xx */
}

/* ---- AuthChallenge ---- */

AuthChallenge::AuthChallenge() : fsm_(sip_auth_fsm())
{
    if (!fsm_) throw Error("AuthChallenge: out of memory");
}

AuthChallenge::~AuthChallenge()
{
    fsm_destroy(fsm_);
}

int AuthChallenge::state() const
{
    return fsm_get_current_state(fsm_);
}

std::string AuthChallenge::state_name() const
{
    return sip_auth_state_name(fsm_get_current_state(fsm_));
}

bool AuthChallenge::challenged() const
{
    return fsm_get_current_state(fsm_) == SIP_AUTH_ST_CHALLENGED;
}

bool AuthChallenge::authenticated() const
{
    return fsm_get_current_state(fsm_) == SIP_AUTH_ST_AUTHENTICATED;
}

bool AuthChallenge::failed() const
{
    return fsm_terminated(fsm_);
}

AuthChallenge& AuthChallenge::event(int ev)
{
    int rc = fsm_act(fsm_, ev, NULL, NULL);
    if (rc != FSM_OK)
        throw Error(std::string("event: ") + sip_auth_event_name(ev) +
                        " is illegal in state " + state_name(),
                    rc);
    return *this;
}

AuthChallenge& AuthChallenge::send(const Msg& m)
{
    return m.request ? event(SIP_AUTH_EV_SEND) : *this;
}

AuthChallenge& AuthChallenge::recv(const Msg& m)
{
    if (m.request) return *this;
    if (m.status == 401 || m.status == 407) return event(SIP_AUTH_EV_CHALLENGE);
    if (m.status >= 200 && m.status < 300) return event(SIP_AUTH_EV_SUCCESS);
    if (m.status >= 300) return event(SIP_AUTH_EV_FAILURE);
    return *this; /* 1xx */
}

} /* namespace sip */
