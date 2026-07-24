/* Event-loop and UDP-socket facade over net_loop + net_sock, wrapped by
 * bindings/swig/net.i. It is the standalone counterpart of the loop and
 * socket the gtp module embeds (bindings/cxx/src/endpoint.cpp): same
 * exception-deferral machinery so a handler callback — a SWIG director
 * calling into Python, or the Lua bridge — never unwinds through
 * net_loop's C frames; any exception it raises is captured and rethrown
 * from Loop::step()/run(). */

#include "netxx.hpp"
#include "rtnl.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <exception>
#include <ifaddrs.h>
#include <map>
#include <memory>
#include <net/if.h>

namespace net
{

/* ---- address helpers ---- */

static net_addr addr_of(const std::string& host, uint16_t port)
{
    net_addr a;
    if (net_addr_from(&a, host.empty() ? nullptr : host.c_str(), port) !=
        NET_OK)
        throw Error("bad address: " + host);
    return a;
}

static void addr_split(const net_addr& a, std::string& host, uint16_t& port)
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

/* ---- Loop ---- */

struct Loop::Impl {
    struct TimerCtx {
        Loop*         loop;
        TimerHandler* h;
        uint64_t      id;
    };
    struct IoCtx {
        Loop*      loop;
        IoHandler* h;
    };

    std::exception_ptr                            pending;
    std::map<uint64_t, std::unique_ptr<TimerCtx>> timers;
    std::map<int, std::unique_ptr<IoCtx>>         ios;

    /* net_loop trampolines; a nested class reaches Loop's privates. */
    static void timer_tramp(void* ud)
    {
        auto*         ctx  = static_cast<TimerCtx*>(ud);
        Loop*         loop = ctx->loop;
        TimerHandler* h    = ctx->h;
        loop->impl_->timers.erase(ctx->id); /* one-shot; ctx dies here */
        try {
            h->on_timer();
        } catch (...) {
            loop->defer_exception();
        }
    }

    static void io_tramp(void* ud, int fd, unsigned ev)
    {
        auto* ctx = static_cast<IoCtx*>(ud);
        try {
            ctx->h->on_io(fd, ev);
        } catch (...) {
            ctx->loop->defer_exception();
        }
    }
};

Loop::Loop() : impl_(new Impl), l_(net_loop_new())
{
    if (!l_) {
        delete impl_;
        throw Error("net_loop_new failed");
    }
    life_ = std::make_shared<net_loop*>(l_);
}

Loop::~Loop()
{
    *life_ = nullptr;
    net_loop_free(l_);
    delete impl_;
}

void Loop::defer_exception()
{
    if (!impl_->pending) impl_->pending = std::current_exception();
    net_loop_stop(l_);
}

void Loop::rethrow_pending()
{
    if (impl_->pending) {
        std::exception_ptr p = impl_->pending;
        impl_->pending       = nullptr;
        std::rethrow_exception(p);
    }
}

int Loop::step(int timeout_ms)
{
    int rc = net_loop_step(l_, timeout_ms);
    rethrow_pending();
    if (rc < 0) throw Error("event loop step failed", rc);
    return rc;
}

void Loop::run()
{
    net_loop_run(l_);
    rethrow_pending();
}

void Loop::stop()
{
    net_loop_stop(l_);
}

uint64_t Loop::after(uint64_t ms, TimerHandler* h)
{
    if (!h) throw Error("timer handler is null");
    auto ctx    = std::make_unique<Impl::TimerCtx>();
    ctx->loop   = this;
    ctx->h      = h;
    uint64_t id = net_loop_after(l_, ms, Impl::timer_tramp, ctx.get());
    if (id == 0) throw Error("net_loop_after failed");
    ctx->id           = id;
    impl_->timers[id] = std::move(ctx);
    return id;
}

void Loop::cancel(uint64_t timer_id)
{
    net_loop_cancel(l_, timer_id);
    impl_->timers.erase(timer_id);
}

void Loop::add_fd(int fd, unsigned events, IoHandler* h)
{
    if (!h) throw Error("io handler is null");
    auto ctx  = std::make_unique<Impl::IoCtx>();
    ctx->loop = this;
    ctx->h    = h;
    if (net_loop_add(l_, fd, events, Impl::io_tramp, ctx.get()) != NET_OK)
        throw Error("net_loop_add failed");
    impl_->ios[fd] = std::move(ctx);
}

void Loop::mod_fd(int fd, unsigned events)
{
    if (net_loop_mod(l_, fd, events) != NET_OK)
        throw Error("net_loop_mod failed");
}

void Loop::del_fd(int fd)
{
    net_loop_del(l_, fd);
    impl_->ios.erase(fd);
}

uint64_t now_ms()
{
    return net_now_ms();
}

/* ---- interface helpers ---- */

uint32_t if_index(const std::string& name)
{
    if (name.empty()) return 0;
    return if_nametoindex(name.c_str()); /* 0 when no such interface */
}

std::string if_addr4(const std::string& name)
{
    if (name.empty()) return "";
    struct ifaddrs* ifas = nullptr;
    if (getifaddrs(&ifas) != 0) return "";
    std::string out;
    for (struct ifaddrs* p = ifas; p; p = p->ifa_next) {
        if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET) continue;
        if (name != p->ifa_name) continue;
        char  buf[INET_ADDRSTRLEN] = "";
        auto* sin = reinterpret_cast<struct sockaddr_in*>(p->ifa_addr);
        if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof buf)) {
            out = buf;
            break;
        }
    }
    freeifaddrs(ifas);
    return out;
}

/* Run one RTNETLINK address op on a throwaway socket, turning a non-OK
 * return into a net::Error. Interface-address ops are rare and stateless,
 * so a per-call socket keeps this a pair of free functions beside
 * if_index/if_addr4, with no handle for the script to own. */
static void rtnl_addr_op(const char* doing, const std::string& name,
                         const std::string& addr, uint8_t prefixlen, bool add)
{
    uint32_t idx = name.empty() ? 0 : if_nametoindex(name.c_str());
    if (idx == 0) throw Error(std::string(doing) + ": no such interface");

    rtnl_sock s;
    if (rtnl_open(&s) != RTNL_OK)
        throw Error(std::string("rtnl_open: ") + std::strerror(errno),
                    RTNL_E_SYS);

    rtnl_addr a;
    std::memset(&a, 0, sizeof a);
    a.addr      = addr.c_str();
    a.prefixlen = prefixlen;
    a.ifindex   = idx;

    int rc = add ? rtnl_addr_add(&s, &a) : rtnl_addr_del(&s, &a);
    int nl = s.nl_errno;
    rtnl_close(&s);
    if (rc == RTNL_OK) return;

    std::string what = doing;
    if (rc == RTNL_E_ACK)
        what += std::string(": kernel rejected it (") + std::strerror(nl) + ")";
    else if (rc == RTNL_E_SYS) what += std::string(": ") + std::strerror(errno);
    else if (rc == RTNL_E_INVAL) what += ": invalid argument";
    else what += ": error";
    throw Error(what, rc);
}

void addr_add(const std::string& name, const std::string& addr,
              uint8_t prefixlen)
{
    rtnl_addr_op("addr_add", name, addr, prefixlen, true);
}

void addr_del(const std::string& name, const std::string& addr,
              uint8_t prefixlen)
{
    rtnl_addr_op("addr_del", name, addr, prefixlen, false);
}

/* ---- UdpSocket ---- */

UdpSocket::UdpSocket(const std::string& local_host, uint16_t local_port,
                     bool reuseport, bool nonlocal_src)
{
    net_addr a     = addr_of(local_host, local_port);
    unsigned flags = NET_BOUND;
    if (reuseport) flags |= NET_REUSEPORT;
    if (nonlocal_src) flags |= NET_NONLOCAL_SRC;
    int rc = net_udp_open(&s_, &a, flags);
    if (rc != NET_OK)
        throw Error(
            "cannot bind " + local_host + ":" + std::to_string(local_port), rc);
    open_ = true;
}

UdpSocket::~UdpSocket()
{
    close();
}

void UdpSocket::close()
{
    if (open_) {
        net_sock_close(&s_);
        open_ = false;
    }
}

void UdpSocket::connect(const std::string& host, uint16_t port)
{
    net_addr to = addr_of(host, port);
    if (net_udp_conn(&s_, &to) != NET_OK)
        throw Error("connect to " + host + ":" + std::to_string(port) +
                    " failed");
}

void UdpSocket::sendto(const std::string& data, const std::string& host,
                       uint16_t port)
{
    net_addr to = addr_of(host, port);
    ssize_t  n  = net_udp_send(&s_, data.data(), data.size(), &to);
    if (n < 0)
        throw Error("send to " + host + ":" + std::to_string(port) + " failed",
                    static_cast<int>(n));
}

void UdpSocket::send(const std::string& data)
{
    ssize_t n = net_udp_send(&s_, data.data(), data.size(), nullptr);
    if (n < 0) throw Error("send failed", static_cast<int>(n));
}

Datagram UdpSocket::recv(int timeout_ms)
{
    Datagram d;
    uint8_t  buf[65535];
    net_addr from;
    ssize_t  n = net_udp_recv(&s_, buf, sizeof buf, &from, timeout_ms);
    if (n == NET_TIMEOUT) {
        d.timed_out = true;
        return d;
    }
    if (n < 0) throw Error("recv failed", static_cast<int>(n));
    d.data.assign(reinterpret_cast<const char*>(buf), static_cast<size_t>(n));
    addr_split(from, d.host, d.port);
    return d;
}

std::string UdpSocket::local_host() const
{
    std::string h;
    uint16_t    p;
    addr_split(s_.local, h, p);
    return h;
}

uint16_t UdpSocket::local_port() const
{
    return net_addr_port(&s_.local);
}

int UdpSocket::fd() const
{
    return s_.fd;
}

/* ---- Resolver ---- */

namespace
{
/* Gathers the records net_dns delivers into a DnsRecord vector. Lives on
 * the stack of Resolver::resolve for the duration of one query; net_dns
 * invokes the callback exactly once (answer, rcode or timeout). */
struct SyncCollect {
    bool                   done   = false;
    int                    status = 0;
    std::vector<DnsRecord> rr;
};

void sync_dns_cb(void* ud, int status, const net_dns_rr* rr, size_t n)
{
    auto* c   = static_cast<SyncCollect*>(ud);
    c->done   = true;
    c->status = status;
    for (size_t i = 0; i < n; i++) {
        DnsRecord d;
        d.type                     = rr[i].type;
        d.ttl                      = rr[i].ttl;
        char buf[INET6_ADDRSTRLEN] = "";
        switch (rr[i].type) {
        case NET_DNS_A:
            if (inet_ntop(AF_INET, &rr[i].u.a, buf, sizeof buf)) d.addr = buf;
            break;
        case NET_DNS_AAAA:
            if (inet_ntop(AF_INET6, &rr[i].u.aaaa, buf, sizeof buf))
                d.addr = buf;
            break;
        case NET_DNS_SRV:
            d.prio   = rr[i].u.srv.prio;
            d.weight = rr[i].u.srv.weight;
            d.port   = rr[i].u.srv.port;
            d.target = rr[i].u.srv.target;
            break;
        case NET_DNS_NAPTR:
            d.order   = rr[i].u.naptr.order;
            d.pref    = rr[i].u.naptr.pref;
            d.flags   = rr[i].u.naptr.flags;
            d.service = rr[i].u.naptr.service;
            d.regexp  = rr[i].u.naptr.regexp;
            d.replace = rr[i].u.naptr.replace;
            break;
        default: continue;
        }
        c->rr.push_back(std::move(d));
    }
}
} /* namespace */

Resolver::Resolver(const std::string& server)
{
    net_addr  a;
    net_addr* sp = nullptr;
    if (!server.empty()) {
        if (net_addr_from(&a, server.c_str(), 53) != NET_OK)
            throw Error("bad DNS server address: " + server);
        sp = &a;
    }
    d_ = net_dns_new(loop_.raw(), sp);
    if (!d_) throw Error("cannot create DNS resolver");
}

Resolver::~Resolver()
{
    /* Free the engine (which deregisters its socket from loop_) while
     * loop_ is still alive: members are destroyed only after this body
     * returns, so the private loop outlives its DNS engine. */
    if (d_) net_dns_free(d_);
}

void Resolver::conf(int timeout_ms, int tries)
{
    net_dns_conf(d_, timeout_ms, tries);
}

std::vector<DnsRecord> Resolver::resolve(const std::string& name, int type)
{
    SyncCollect c;
    if (net_dns_query(d_, name.c_str(), static_cast<uint16_t>(type),
                      sync_dns_cb, &c) != NET_OK)
        throw Error("cannot start DNS query for " + name);
    /* Bounded by the engine's retransmit timer: a silent server fires the
     * timeout callback (which sets done) after the configured tries. */
    while (!c.done)
        loop_.step(-1);
    if (c.status < 0)
        throw Error("DNS resolve " + name + " timed out or failed", c.status);
    return c.rr; /* status > 0 is a DNS rcode (e.g. NXDOMAIN): empty list */
}

std::string Resolver::resolve4(const std::string& name)
{
    struct in_addr v4; /* a literal address resolves to itself */
    if (inet_pton(AF_INET, name.c_str(), &v4) == 1) return name;
    for (const auto& r : resolve(name, NET_DNS_A))
        if (r.type == NET_DNS_A) return r.addr;
    throw Error("no A record for " + name);
}

std::string Resolver::resolve6(const std::string& name)
{
    struct in6_addr v6;
    if (inet_pton(AF_INET6, name.c_str(), &v6) == 1) return name;
    for (const auto& r : resolve(name, NET_DNS_AAAA))
        if (r.type == NET_DNS_AAAA) return r.addr;
    throw Error("no AAAA record for " + name);
}

} /* namespace net */
