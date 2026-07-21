/* GTPv2-C session layer: gtp::Endpoint drives transactions over a
 * net::Loop-registered UDP socket (sequence allocation, T3/N3
 * retransmission, response matching), gtp::Session tracks one PDN
 * connection, and EndpointHandler carries the callbacks.
 *
 * The endpoint registers its socket and timers with the loop's raw
 * net_loop (netxx.hpp Loop::raw()/life()); the life() token lets the
 * destructor skip unregistration when the loop was torn down first
 * (garbage collectors free in any order). Handler callbacks — SWIG
 * directors from Python, the hand-written table bridge for Lua — run
 * inside the loop trampolines here; an exception they raise is captured
 * with Loop::defer_exception() and re-raised from Loop::step()/run()
 * rather than unwinding through net_loop's C frames. */

#include "gtpxx.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <map>
#include <memory>
#include <vector>

namespace gtp
{

/* ---- EndpointHandler: all callbacks default to no-ops ----
 *
 * Defining them out of line here (rather than inline in the header)
 * emits the vtable and typeinfo in this translation unit. */

void EndpointHandler::on_create_session_response(Session&,
                                                 const CreateSessionResponse&)
{
}
void EndpointHandler::on_modify_bearer_response(Session&,
                                                const ModifyBearerResponse&)
{
}
void EndpointHandler::on_delete_session_response(Session&,
                                                 const DeleteSessionResponse&)
{
}
void EndpointHandler::on_user_plane(Session&, const UserPlaneTunnel&) {}
void EndpointHandler::on_timeout(Session&, int) {}
void EndpointHandler::on_echo_request(const std::string&, uint16_t, int) {}
void EndpointHandler::on_echo_response(const std::string&, uint16_t, int) {}
void EndpointHandler::on_create_session_request(const CreateSessionRequest&,
                                                const std::string&, uint16_t)
{
}
void EndpointHandler::on_modify_bearer_request(const ModifyBearerRequest&,
                                               const std::string&, uint16_t)
{
}
void EndpointHandler::on_delete_session_request(const DeleteSessionRequest&,
                                                const std::string&, uint16_t)
{
}
void EndpointHandler::on_create_bearer_request(const CreateBearerRequest&,
                                               const std::string&, uint16_t)
{
}
void EndpointHandler::on_message(int, const Bytes&, const std::string&,
                                 uint16_t)
{
}

/* ---- local helpers ---- */

namespace
{

/* net_addr -> literal host + port, unwrapping v4-mapped v6 (mirrors the
 * netxx facade's addr_split). */
void addr_split(const net_addr& a, std::string& host, uint16_t& port)
{
    port                       = net_addr_port(&a);
    char buf[INET6_ADDRSTRLEN] = "";
    if (a.sa.sa_family == AF_INET) {
        inet_ntop(AF_INET, &a.v4.sin_addr, buf, sizeof buf);
    } else {
        const struct in6_addr* i6 = &a.v6.sin6_addr;
        if (IN6_IS_ADDR_V4MAPPED(i6))
            inet_ntop(AF_INET, &i6->s6_addr[12], buf, sizeof buf);
        else inet_ntop(AF_INET6, i6, buf, sizeof buf);
    }
    host = buf;
}

/* Recovery counter carried by an Echo Request/Response, or -1 if absent
 * or the message does not parse. */
int recovery_of(const Bytes& wire)
{
    try {
        RawMessage m = RawMessage::decode(wire);
        if (m.has(GTP2_IE_RECOVERY)) {
            const Ie& ie = m.find(GTP2_IE_RECOVERY);
            if (!ie.value.empty()) return ie.value[0];
        }
    } catch (...) {
    }
    return -1;
}

/* First bearer F-TEID TEID our own request carried for this EBI (0 when
 * we sent no F-TEID for it) — the local end of an on_user_plane tunnel. */
uint32_t local_teid_for_ebi(const std::vector<BearerContext>& sent, uint8_t ebi)
{
    for (const BearerContext& b : sent)
        if (b.ebi == ebi)
            for (const FteidEntry& fe : b.fteids)
                return fe.fteid.teid;
    return 0;
}

/* One tunnel per bearer F-TEID in an accepted response, pairing the
 * peer's F-TEID with the local F-TEID we sent for the same EBI. */
std::vector<UserPlaneTunnel>
tunnels_from(const std::vector<BearerContext>& sent,
             const std::vector<BearerContext>& answered)
{
    std::vector<UserPlaneTunnel> out;
    for (const BearerContext& bc : answered) {
        for (const FteidEntry& fe : bc.fteids) {
            UserPlaneTunnel t;
            t.ebi         = bc.ebi;
            t.if_type     = fe.fteid.if_type;
            t.remote_teid = fe.fteid.teid;
            t.remote_addr =
                !fe.fteid.addr4.empty() ? fe.fteid.addr4 : fe.fteid.addr6;
            t.local_teid = local_teid_for_ebi(sent, bc.ebi);
            out.push_back(t);
        }
    }
    return out;
}

} /* namespace */

/* ---- Endpoint internals ---- */

/* An outstanding request awaiting its response: the wire bytes to
 * retransmit, the owning session's local control TEID, the peer, and the
 * T3 timer. */
struct Endpoint::Txn {
    Endpoint*   ep = nullptr;
    uint32_t    seq;
    uint8_t     mt; /* request message type */
    Bytes       wire;
    uint32_t    session_teid;
    std::string host;
    uint16_t    port;
    unsigned    sends    = 0; /* transmissions so far (capped at n3_) */
    uint64_t    timer_id = 0;
};

struct Endpoint::Impl {
    net::Loop*                 loop = nullptr;
    std::shared_ptr<net_loop*> life; /* *life == nullptr once loop freed */
    net_sock                   sock;
    bool                       sock_open = false;
    std::string                local_host;
    uint16_t                   local_port = 0;
    uint32_t                   seq        = 0; /* sequence allocator */
    uint32_t                   ctrl_teid  = 0; /* local control TEID allocator */

    std::vector<std::unique_ptr<Session>>    sessions;
    std::map<uint32_t, std::unique_ptr<Txn>> txns; /* keyed by request seq */

    net_loop* lp() const
    {
        return *life;
    }

    /* net_loop C trampolines. As Endpoint::Impl members they may touch
     * Endpoint's private members; they catch handler exceptions and defer
     * them to the loop instead of unwinding through C frames. */
    static void io_tramp(void* ud, int, unsigned)
    {
        auto* ep = static_cast<Endpoint*>(ud);
        try {
            ep->on_readable();
        } catch (...) {
            ep->impl_->loop->defer_exception();
        }
    }
    static void timer_tramp(void* ud)
    {
        auto*     t  = static_cast<Txn*>(ud);
        Endpoint* ep = t->ep;
        try {
            ep->on_txn_timer(*t);
        } catch (...) {
            ep->impl_->loop->defer_exception();
        }
    }
};

Endpoint::Endpoint(net::Loop& loop, const std::string& local_host,
                   uint16_t local_port)
    : impl_(new Impl)
{
    impl_->loop = &loop;
    impl_->life = loop.life();

    net_addr a;
    if (net_addr_from(&a, local_host.empty() ? nullptr : local_host.c_str(),
                      local_port) != NET_OK) {
        delete impl_;
        throw Error("bad local address: " + local_host);
    }
    if (net_udp_open(&impl_->sock, &a, NET_BOUND) != NET_OK) {
        delete impl_;
        throw Error("cannot bind " + local_host + ":" +
                    std::to_string(local_port));
    }
    impl_->sock_open = true;
    addr_split(impl_->sock.local, impl_->local_host, impl_->local_port);

    if (net_loop_add(impl_->lp(), impl_->sock.fd, NET_RD, &Impl::io_tramp,
                     this) != NET_OK) {
        net_sock_close(&impl_->sock);
        delete impl_;
        throw Error("net_loop_add failed");
    }
}

Endpoint::~Endpoint()
{
    if (net_loop* lp = *impl_->life) { /* skip when loop freed first */
        for (auto& kv : impl_->txns)
            net_loop_cancel(lp, kv.second->timer_id);
        if (impl_->sock_open) net_loop_del(lp, impl_->sock.fd);
    }
    if (impl_->sock_open) net_sock_close(&impl_->sock);
    delete impl_;
}

std::string Endpoint::local_host() const
{
    return impl_->local_host;
}

uint16_t Endpoint::local_port() const
{
    return impl_->local_port;
}

uint32_t Endpoint::next_seq()
{
    uint32_t v;
    do
        v = ++impl_->seq & 0xFFFFFFu; /* 24-bit; never 0 */
    while (v == 0);
    return v;
}

void Endpoint::send_to(const Bytes& wire, const std::string& host,
                       uint16_t port)
{
    net_addr to;
    if (net_addr_from(&to, host.c_str(), port) != NET_OK)
        throw Error("bad peer address: " + host);
    ssize_t n = net_udp_send(&impl_->sock, wire.data(), wire.size(), &to);
    if (n == NET_ERR)
        throw Error("gtp send to " + host + ":" + std::to_string(port) +
                    " failed");
}

void Endpoint::start_txn(uint32_t seq, uint8_t mt, const Bytes& wire,
                         uint32_t session_teid, const std::string& host,
                         uint16_t port)
{
    auto t          = std::make_unique<Txn>();
    t->ep           = this;
    t->seq          = seq;
    t->mt           = mt;
    t->wire         = wire;
    t->session_teid = session_teid;
    t->host         = host;
    t->port         = port;

    send_to(wire, host, port);
    t->sends    = 1;
    t->timer_id = net_loop_after(impl_->lp(), t3_ms_, &Impl::timer_tramp,
                                 t.get());
    if (t->timer_id == 0) throw Error("net_loop_after failed");
    impl_->txns[seq] = std::move(t);
}

void Endpoint::on_txn_timer(Txn& t)
{
    if (t.sends < n3_) { /* retransmit and wait another T3 */
        send_to(t.wire, t.host, t.port);
        t.sends++;
        t.timer_id =
            net_loop_after(impl_->lp(), t3_ms_, &Impl::timer_tramp, &t);
        if (t.timer_id == 0) throw Error("net_loop_after failed");
        return;
    }

    /* N3 sends exhausted: detach the txn, fail the session, notify. */
    const uint32_t seq   = t.seq;
    const uint8_t  mt    = t.mt;
    const uint32_t steid = t.session_teid;

    std::unique_ptr<Txn> owned; /* keeps t alive across the callback */
    auto                 it = impl_->txns.find(seq);
    if (it != impl_->txns.end()) {
        owned = std::move(it->second);
        impl_->txns.erase(it);
    }

    Session* s = session_by_teid(steid);
    if (s) s->state_ = Session::FAILED;
    if (s && handler_) handler_->on_timeout(*s, mt);
}

Session* Endpoint::create_session(const CreateSessionRequest& req_in,
                                  const std::string& peer_host,
                                  uint16_t           peer_port)
{
    CreateSessionRequest req = req_in;
    if (req.sequence == 0) req.sequence = next_seq();

    /* Fill the sender F-TEID: a fully-default one also gets if_type S11
     * MME; an unset TEID a fresh local control TEID; an addressless one
     * the bound local address. */
    Fteid&     sf = req.sender_fteid;
    const bool fully_default = sf.if_type == 0 && sf.teid == 0 &&
                               sf.addr4.empty() && sf.addr6.empty();
    if (fully_default) sf.if_type = GTP2_IF_S11_MME;
    if (sf.teid == 0) {
        do
            sf.teid = ++impl_->ctrl_teid;
        while (sf.teid == 0);
    }
    if (sf.addr4.empty() && sf.addr6.empty()) {
        if (impl_->sock.local.sa.sa_family == AF_INET) sf.addr4 = local_host();
        else sf.addr6 = local_host();
    }

    auto s        = std::make_unique<Session>();
    s->ep_        = this;
    s->state_     = Session::CREATING;
    s->local_teid_ = sf.teid;
    s->peer_host_ = peer_host;
    s->peer_port_ = peer_port;
    s->req_       = req;
    Session* ret  = s.get();
    impl_->sessions.push_back(std::move(s));

    start_txn(req.sequence, GTP2_MT_CREATE_SESSION_REQUEST, req.encode(),
              ret->local_teid_, peer_host, peer_port);
    return ret;
}

void Endpoint::send_echo(const std::string& peer_host, uint16_t peer_port)
{
    RawMessage m;
    m.message_type = GTP2_MT_ECHO_REQUEST;
    m.has_teid     = false;
    m.sequence     = next_seq();
    m.add_ie(Ie(GTP2_IE_RECOVERY, Bytes{ recovery_ }));
    send_to(m.encode(), peer_host, peer_port);
}

void Endpoint::send_create_session_response(const CreateSessionResponse& rsp,
                                            const std::string&           host,
                                            uint16_t                     port)
{
    send_to(rsp.encode(), host, port);
}

void Endpoint::send_modify_bearer_response(const ModifyBearerResponse& rsp,
                                           const std::string&          host,
                                           uint16_t                    port)
{
    send_to(rsp.encode(), host, port);
}

void Endpoint::send_delete_session_response(const DeleteSessionResponse& rsp,
                                            const std::string&           host,
                                            uint16_t                     port)
{
    send_to(rsp.encode(), host, port);
}

void Endpoint::send_create_bearer_response(const CreateBearerResponse& rsp,
                                           const std::string&          host,
                                           uint16_t                    port)
{
    send_to(rsp.encode(), host, port);
}

void Endpoint::send_raw(const Bytes& wire, const std::string& host,
                        uint16_t port)
{
    send_to(wire, host, port);
}

Session* Endpoint::session_by_teid(uint32_t local_teid)
{
    for (auto& s : impl_->sessions)
        if (s->local_teid_ == local_teid) return s.get();
    return nullptr;
}

std::vector<Session*> Endpoint::sessions()
{
    std::vector<Session*> out;
    out.reserve(impl_->sessions.size());
    for (auto& s : impl_->sessions)
        out.push_back(s.get());
    return out;
}

void Endpoint::purge()
{
    for (auto it = impl_->sessions.begin(); it != impl_->sessions.end();) {
        Session::State st = (*it)->state_;
        if (st == Session::DELETED || st == Session::FAILED)
            it = impl_->sessions.erase(it);
        else ++it;
    }
}

/* ---- receive path ---- */

void Endpoint::on_readable()
{
    for (;;) {
        uint8_t  buf[65535];
        net_addr from;
        ssize_t  n = net_udp_recv(&impl_->sock, buf, sizeof buf, &from, -1);
        if (n < 0) break; /* NET_TIMEOUT: drained; NET_ERR: give up */
        handle_datagram(buf, static_cast<size_t>(n), from);
    }
}

void Endpoint::handle_datagram(const uint8_t* buf, size_t len,
                               const net_addr& from)
{
    gtp2_hdr_t h;
    if (gtp2_hdr_decode(buf, len, &h) < 0) return; /* not a GTPv2 message */
    std::string host;
    uint16_t    port;
    addr_split(from, host, port);
    dispatch(buf, len, h, host, port);
}

void Endpoint::dispatch(const uint8_t* msg, size_t len, const gtp2_hdr_t& h,
                        const std::string& host, uint16_t port)
{
    const Bytes wire(msg, msg + len);

    switch (h.message_type) {
    case GTP2_MT_ECHO_REQUEST: {
        const int rec = recovery_of(wire);
        RawMessage resp;
        resp.message_type = GTP2_MT_ECHO_RESPONSE;
        resp.has_teid     = false;
        resp.sequence     = h.sequence;
        resp.add_ie(Ie(GTP2_IE_RECOVERY, Bytes{ recovery_ }));
        send_to(resp.encode(), host, port);
        if (handler_) handler_->on_echo_request(host, port, rec);
        break;
    }
    case GTP2_MT_ECHO_RESPONSE:
        if (handler_)
            handler_->on_echo_response(host, port, recovery_of(wire));
        break;

    case GTP2_MT_CREATE_SESSION_RESPONSE:
    case GTP2_MT_MODIFY_BEARER_RESPONSE:
    case GTP2_MT_DELETE_SESSION_RESPONSE:
        if (handle_response(wire, h, host, port)) break;
        if (handler_) handler_->on_message(h.message_type, wire, host, port);
        break;

    case GTP2_MT_CREATE_SESSION_REQUEST:
        if (handler_)
            handler_->on_create_session_request(
                CreateSessionRequest::decode(wire), host, port);
        break;
    case GTP2_MT_MODIFY_BEARER_REQUEST:
        if (handler_)
            handler_->on_modify_bearer_request(
                ModifyBearerRequest::decode(wire), host, port);
        break;
    case GTP2_MT_DELETE_SESSION_REQUEST:
        if (handler_)
            handler_->on_delete_session_request(
                DeleteSessionRequest::decode(wire), host, port);
        break;
    case GTP2_MT_CREATE_BEARER_REQUEST:
        if (handler_)
            handler_->on_create_bearer_request(
                CreateBearerRequest::decode(wire), host, port);
        break;

    default:
        if (handler_) handler_->on_message(h.message_type, wire, host, port);
        break;
    }
}

bool Endpoint::handle_response(const Bytes& wire, const gtp2_hdr_t& h,
                               const std::string& host, uint16_t port)
{
    (void)host; /* responses are matched by sequence, not by source */
    (void)port;
    auto it = impl_->txns.find(h.sequence);
    if (it == impl_->txns.end()) return false;

    /* Detach the txn (so a re-entrant handler cannot touch it) and stop
     * its retransmission timer before decoding the response. */
    std::unique_ptr<Txn> t = std::move(it->second);
    impl_->txns.erase(it);
    net_loop_cancel(impl_->lp(), t->timer_id);

    Session* s = session_by_teid(t->session_teid);
    if (!s) return true;

    switch (h.message_type) {
    case GTP2_MT_CREATE_SESSION_RESPONSE: {
        CreateSessionResponse rsp = CreateSessionResponse::decode(wire);
        if (rsp.cause == GTP2_CAUSE_REQUEST_ACCEPTED) {
            s->state_ = Session::ACTIVE;
            if (rsp.has_sender_fteid) s->remote_teid_ = rsp.sender_fteid.teid;
            s->tunnels_ = tunnels_from(
                CreateSessionRequest::decode(t->wire).bearers, rsp.bearers);
        } else {
            s->state_ = Session::FAILED;
        }
        if (handler_) handler_->on_create_session_response(*s, rsp);
        if (rsp.cause == GTP2_CAUSE_REQUEST_ACCEPTED && handler_)
            for (const UserPlaneTunnel& t2 : s->tunnels_)
                handler_->on_user_plane(*s, t2);
        break;
    }
    case GTP2_MT_MODIFY_BEARER_RESPONSE: {
        ModifyBearerResponse rsp = ModifyBearerResponse::decode(wire);
        if (rsp.cause == GTP2_CAUSE_REQUEST_ACCEPTED)
            s->tunnels_ = tunnels_from(
                ModifyBearerRequest::decode(t->wire).bearers, rsp.bearers);
        if (handler_) handler_->on_modify_bearer_response(*s, rsp);
        if (rsp.cause == GTP2_CAUSE_REQUEST_ACCEPTED && handler_)
            for (const UserPlaneTunnel& t2 : s->tunnels_)
                handler_->on_user_plane(*s, t2);
        break;
    }
    case GTP2_MT_DELETE_SESSION_RESPONSE: {
        DeleteSessionResponse rsp = DeleteSessionResponse::decode(wire);
        s->state_                 = Session::DELETED;
        if (handler_) handler_->on_delete_session_response(*s, rsp);
        break;
    }
    default: break;
    }
    return true;
}

/* ---- Session ---- */

uint8_t Session::default_ebi() const
{
    if (!req_.bearers.empty()) return req_.bearers.front().ebi;
    return 5; /* default EPS bearer id */
}

void Session::modify_bearer(const ModifyBearerRequest& req_in)
{
    if (!ep_) throw Error("session not attached to an endpoint");
    ModifyBearerRequest req = req_in;
    req.teid                = remote_teid_;
    req.sequence            = ep_->next_seq();
    ep_->start_txn(req.sequence, GTP2_MT_MODIFY_BEARER_REQUEST, req.encode(),
                   local_teid_, peer_host_, peer_port_);
}

void Session::delete_session()
{
    DeleteSessionRequest req;
    req.linked_ebi = default_ebi();
    delete_session_req(req);
}

void Session::delete_session_req(const DeleteSessionRequest& req_in)
{
    if (!ep_) throw Error("session not attached to an endpoint");
    DeleteSessionRequest req = req_in;
    req.teid                 = remote_teid_;
    req.sequence             = ep_->next_seq();
    state_                   = DELETING;
    ep_->start_txn(req.sequence, GTP2_MT_DELETE_SESSION_REQUEST, req.encode(),
                   local_teid_, peer_host_, peer_port_);
}

} /* namespace gtp */
