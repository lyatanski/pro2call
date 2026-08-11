#ifndef NETXX_HPP
#define NETXX_HPP

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "net.h"
#include "net_dns.h"
#include "net_loop.h"
#include "net_sock.h"
#include "net_txq.h"

/* netxx — C++ facade over the C net transport layer (net/), written to
 * be wrapped by SWIG (bindings/swig/net.i) and driven from scripting
 * languages. It exposes the two pieces a script needs to put bytes on
 * the wire and react to them: the epoll event loop (net_loop) and a
 * non-blocking UDP socket (net_sock).
 *
 * Same design rules as gtpxx (bindings/cxx/inc/gtpxx.hpp):
 *   - human-format fields: addresses are literal host strings and
 *     integer ports, payloads are byte strings;
 *   - callbacks are virtual methods on handler classes — SWIG directors
 *     for Python, a hand-written table/function bridge for Lua;
 *   - errors are exceptions (net::Error), never return codes.
 *
 * The loop is single-threaded by design (so is the C net_loop): handler
 * callbacks run inside step()/run() and may freely add or drop fds and
 * timers. An exception raised in a callback is captured, the loop is
 * stopped, and it re-raises from step()/run() rather than unwinding
 * through the C dispatcher's frames.
 */

struct ippool; /* opaque; task/inc/ippool.h is not needed by users */

namespace net
{

/* Every failure surfaces as this; code() keeps the underlying NET_*
 * return value when there is one. */
class Error : public std::runtime_error
{
  public:
    explicit Error(const std::string& what, int code = 0)
        : std::runtime_error(what), code_(code)
    {
    }
    int code() const
    {
        return code_;
    }

  private:
    int code_;
};

/* ---- Event loop ---- */

class TimerHandler
{
  public:
    virtual ~TimerHandler() = default;
    virtual void on_timer() = 0;
};

class IoHandler
{
  public:
    virtual ~IoHandler()                        = default;
    virtual void on_io(int fd, unsigned events) = 0; /* NET_RD/NET_WR/NET_ER */
};

/* Wraps net_loop (net/inc/net_loop.h): the single-threaded epoll
 * dispatcher every transport socket registers its fd with. Handlers are
 * borrowed — the caller keeps them alive (the Lua binding pins them in
 * registries; the Python layer pins them on the proxy). */
class Loop
{
  public:
    Loop();
    ~Loop();
    Loop(const Loop&)            = delete;
    Loop& operator=(const Loop&) = delete;

    /* One poll iteration; timeout_ms < 0 waits for the next event or
     * timer. Returns the number of fd events dispatched. */
    int  step(int timeout_ms = -1);
    void run(); /* step until stop() */
    void stop();

    /* One-shot timer; returns a cancellation id (never 0). */
    uint64_t after(uint64_t ms, TimerHandler* h);
    void     cancel(uint64_t timer_id);

    /* Register / update / drop an fd. events is NET_RD|NET_WR. */
    void add_fd(int fd, unsigned events, IoHandler* h);
    void mod_fd(int fd, unsigned events);
    void del_fd(int fd);

    net_loop* raw() const
    {
        return l_;
    }

    /* Liveness token: nulled by ~Loop so dependents destroyed after the
     * loop (garbage collectors order teardown freely) skip their
     * unregistration instead of touching a freed net_loop. Used by the
     * gtp session layer, which registers its socket and timers with
     * raw() and must survive the loop being torn down first. */
    std::shared_ptr<net_loop*> life() const
    {
        return life_;
    }

    /* Internal (used by callback trampolines): capture the in-flight
     * exception, stop the loop, and rethrow it from step()/run(). */
    void defer_exception();
    void rethrow_pending();

  private:
    struct Impl;
    Impl*                      impl_;
    net_loop*                  l_;
    std::shared_ptr<net_loop*> life_;
};

/* Milliseconds on CLOCK_MONOTONIC (net_now_ms) — the clock the loop's
 * timers run on, for scheduling and elapsed-time measurements. */
uint64_t now_ms();

/* ---- interface helpers ---- */

/* Interface name -> kernel ifindex (if_nametoindex); 0 when the name is
 * empty or there is no such interface — the value the GTP-U datapath's
 * attach() reads as "skip this direction". */
uint32_t if_index(const std::string& name);

/* An interface's first IPv4 address as a literal string, or "" when the
 * name is empty/absent or the interface has no IPv4 address (getifaddrs).
 * Used to derive a source address from the interface a tunnel egresses. */
std::string if_addr4(const std::string& name);

/* Add or remove an interface address, as `ip addr add`/`ip addr del
 * <addr>/<prefixlen> dev <name>` do, over RTNETLINK (netlink/rtnl) — so a
 * script needs no external `ip` tool. Adding makes the address locally
 * deliverable (the kernel installs its `local` route), which lets a
 * socket bound to an address this host does not otherwise own — e.g. a
 * simulated UE's PDN address on `lo` — receive traffic destined to it.
 * addr_add is idempotent (an address already present is left in place).
 * Both need CAP_NET_ADMIN and throw net::Error on failure, including an
 * unknown interface name. */
void addr_add(const std::string& name, const std::string& addr,
              uint8_t prefixlen);
void addr_del(const std::string& name, const std::string& addr,
              uint8_t prefixlen);

/* A route, as `ip route replace <dst>/<prefixlen> [via <gateway>] [dev
 * <dev>] [mtu <mtu>] [metric <metric>]` installs it. An empty dst with
 * prefixlen 0 is the default route (and then the family comes from the
 * gateway); everything the route does not say — table, protocol, type,
 * scope — takes the value `ip route` picks, so a route with a gateway is
 * scope universe and one with only a dev is scope link.
 *
 * mtu is the per-route MTU. It is what a sender needs when something
 * downstream of it grows the packet and cannot fragment — a TC/eBPF hook
 * adding GTP-U encapsulation, say: a datagram that fits the link before
 * the hook and not after is dropped there, silently. Lowering the MTU on
 * the route toward that destination makes the kernel fragment on the way
 * out instead, while the interface MTU stays what the encapsulated
 * packets need. */
struct Route {
    std::string dst;           /* destination prefix; "" = default route */
    uint8_t     prefixlen = 0; /* its length in bits                     */
    std::string gateway;       /* next hop; "" = on-link, needs dev      */
    std::string dev;           /* output interface name; "" = unset      */
    uint32_t    mtu    = 0;    /* per-route MTU; 0 = leave it alone      */
    uint32_t    metric = 0;    /* route priority; 0 = kernel default     */
};

/* Install (replacing any route for the same destination, so repeatable)
 * or remove a route over RTNETLINK (netlink/rtnl) — `ip route replace` /
 * `ip route del` without the external tool. A delete keys on what the
 * Route names: the destination, narrowed by dev/gateway/metric when
 * several routes share it. Both need CAP_NET_ADMIN and throw net::Error
 * on failure, including an unknown interface name and a delete of a route
 * that is not there. */
void route_add(const Route& r);
void route_del(const Route& r);

/* ---- UDP socket ---- */

/* A datagram from UdpSocket::recv: data/host/port on success, or
 * timed_out set with empty data when the receive timed out. */
struct Datagram {
    std::string data;          /* received bytes; empty when timed_out */
    std::string host;          /* sender address                      */
    uint16_t    port      = 0; /* sender port                         */
    bool        timed_out = false;
};

/* Non-blocking UDP socket over net_sock. The fd is created non-blocking
 * and close-on-exec, so fd() can go straight into Loop::add_fd() for
 * event-driven receive; recv(timeout_ms) also emulates blocking for the
 * simple linear flows scripts drive. IPv6 sockets are dual-stack — an
 * IPv4 destination is mapped transparently. */
class UdpSocket
{
  public:
    /* Binds local_host:local_port. Host "" (or "0.0.0.0"/"::") is the
     * any-address, port 0 an ephemeral one; reuseport sets SO_REUSEPORT
     * for multi-socket load spreading. nonlocal_src sets IP_FREEBIND +
     * IP_TRANSPARENT so a source address this host does not own (e.g. a
     * simulated UE's PDN address) can be both bound and sent from — needs
     * CAP_NET_ADMIN. Throws Error on failure. */
    UdpSocket(const std::string& local_host = "", uint16_t local_port = 0,
              bool reuseport = false, bool nonlocal_src = false);
    ~UdpSocket();
    UdpSocket(const UdpSocket&)            = delete;
    UdpSocket& operator=(const UdpSocket&) = delete;

    /* Fix a default peer so send()/recv() need no address; the kernel
     * then also drops datagrams from any other source. */
    void connect(const std::string& host, uint16_t port);

    void sendto(const std::string& data, const std::string& host,
                uint16_t port);
    void send(const std::string& data); /* to the connected peer */

    /* ---- loop-driven output (net_txq) ----
     *
     * Move this socket's send side onto `loop`: sendto()/send() then only
     * queue the datagram and return, and the loop pushes the queue out at
     * the top of each iteration with sendmmsg() — one syscall per batch of
     * NET_TXQ_BATCH instead of one per datagram, and no syscall at all on
     * the caller's path. A handler that answers a burst therefore does not
     * stop to enter the kernel between messages, and a full socket buffer
     * suspends the queue (resumed on writability) instead of failing the
     * send.
     *
     * base_events is the fd's steady-state interest, so this composes with
     * the caller's own Loop::add_fd for the same fd; the queue adds NET_WR
     * to it only while it has a backlog. Registering the fd with the loop
     * (as an event-driven receiver does) is the normal case; without it the
     * queue falls back to a 1 ms retry timer.
     *
     * Off by default: a linear script that sends and then blocks in recv()
     * never runs a loop, and must keep the direct syscall. */
    void tx_loop(Loop& loop, unsigned base_events = NET_RD,
                 size_t max_queue_bytes = 0);
    bool tx_queued() const; /* is output loop-driven? */

    /* Push the queue now, without running the loop (before closing, or from
     * a linear flow). No-op unless tx_loop() was called. Returns the number
     * of datagrams sent. */
    int  tx_flush();
    /* Datagrams still queued, and the counters over the socket's life:
     * datagrams sent, sendmmsg() calls (sent/calls = the batching ratio),
     * datagrams the kernel refused for good, and how often it pushed back. */
    size_t   tx_pending() const;
    uint64_t tx_sent() const;
    uint64_t tx_calls() const;
    uint64_t tx_dropped() const;
    uint64_t tx_blocked() const;

    /* timeout_ms >= 0 waits up to that long; < 0 polls once (drain a
     * loop-signalled fd). A timeout returns a Datagram with timed_out
     * set and no data. */
    Datagram recv(int timeout_ms = -1);

    std::string local_host() const;
    uint16_t    local_port() const;
    int         fd() const;
    void        close();

  private:
    net_sock                   s_;
    bool                       open_ = false;
    net_txq*                   txq_  = nullptr;
    std::shared_ptr<net_loop*> life_; /* nulled by ~Loop; see Loop::life() */
};

/* ---- TCP / SCTP stream socket ---- */

/* The result of StreamConn::recv: bytes when data arrived, timed_out when
 * the poll came up empty, or closed when the peer shut the connection down
 * (an orderly EOF — net_sock_recv returned 0). The three are mutually
 * exclusive; data is empty unless bytes actually arrived. */
struct StreamData {
    std::string data;             /* received bytes                       */
    bool        timed_out = false;
    bool        closed    = false; /* peer closed the connection (EOF)    */
};

/* One connected stream (TCP or SCTP one-to-one), wrapping a net_sock. Not
 * constructed directly from a script — StreamListener::accept() hands one
 * back for each incoming connection, and stream_connect() for an outgoing
 * one. The fd is non-blocking and close-on-exec, so fd() goes straight
 * into Loop::add_fd() and recv() drains what the loop signalled. */
class StreamConn
{
  public:
    ~StreamConn();
    StreamConn(const StreamConn&)            = delete;
    StreamConn& operator=(const StreamConn&) = delete;

    /* timeout_ms >= 0 waits up to that long for bytes; < 0 polls once
     * (drain a loop-signalled fd) and returns timed_out when nothing is
     * queued. A peer close returns closed. Throws Error on a socket
     * failure. */
    StreamData recv(int timeout_ms = -1);

    /* Push the whole buffer. timeout_ms bounds the wait when the send
     * would block (a full send buffer); < 0 polls once. Throws Error on a
     * socket failure or a short write (the buffer did not fully drain
     * within the timeout). */
    void send(const std::string& data, int timeout_ms = -1);

    std::string peer_host() const;
    uint16_t    peer_port() const;
    int         fd() const;
    void        close();

  private:
    explicit StreamConn(const net_sock& s) : s_(s), open_(true) {}
    friend class StreamListener;
    friend StreamConn* stream_connect(const std::string&, uint16_t, int, int);

    net_sock s_;
    bool     open_ = false;
};

/* A listening stream socket. Binds local_host:local_port and listens;
 * proto is 0 for TCP or IPPROTO_SCTP (132) for SCTP. Host "" (or
 * "0.0.0.0"/"::") is the any-address. Throws Error on failure. */
class StreamListener
{
  public:
    StreamListener(const std::string& local_host, uint16_t local_port,
                   int proto = 0);
    ~StreamListener();
    StreamListener(const StreamListener&)            = delete;
    StreamListener& operator=(const StreamListener&) = delete;

    /* Accept one pending connection. timeout_ms >= 0 waits up to that
     * long; < 0 polls once. Returns nullptr (nil in Lua) when nothing is
     * pending within the timeout, so an fd-readable handler can drain the
     * backlog with `while (c = accept(-1)) ...`. Throws Error on failure.
     * The returned StreamConn is owned by the caller (Lua GC frees it). */
    StreamConn* accept(int timeout_ms = -1);

    std::string local_host() const;
    uint16_t    local_port() const; /* the bound port (resolved when 0) */
    int         fd() const;
    void        close();

  private:
    net_sock s_;
    bool     open_ = false;
};

/* Dial a stream peer (TCP or SCTP). local address is ephemeral; timeout_ms
 * bounds the connect. Returns a connected StreamConn (caller-owned) or
 * throws Error on failure/timeout. */
StreamConn* stream_connect(const std::string& host, uint16_t port,
                           int proto = 0, int timeout_ms = 5000);

/* ---- IP address pool ---- */

/* Address allocation with reuse over the task library's pool
 * (task/inc/ippool.h): the allocator a PGW/SMF assigns PDN addresses
 * from, or a DHCP server its leases. The C core is binary and
 * index-based; this facade is the literal-string surface — a scope is
 * "10.45.0.0/16" or a first..last pair, and every address in and out is
 * a literal ("10.45.0.7", "2001:db8::7").
 *
 * An IPv4 prefix shorter than /31 excludes its network and broadcast
 * address, as a DHCP scope does; reserve() takes the gateway (or any
 * address a subscriber must keep) out of circulation. A released
 * address is not handed out again until the allocator has swept the
 * rest of the pool, so a detaching UE's address does not go straight to
 * the next attach.
 *
 *   local pool = net.IpPool("10.45.0.0/16")
 *   pool:reserve("10.45.0.1")                 -- the gateway
 *   if pool:available() > 0 then
 *       local ue = pool:alloc()               -- "10.45.0.2"
 *       ...
 *       pool:release(ue)
 *   end
 */
class IpPool
{
  public:
    /* "10.45.0.0/16" or "2001:db8:0:1::/64"; any address inside the
     * prefix names the same scope. Throws Error on a malformed scope. */
    explicit IpPool(const std::string& cidr);

    /* Explicit inclusive range, both ends usable and of one family:
     * IpPool("10.45.0.100", "10.45.0.200"). */
    IpPool(const std::string& first, const std::string& last);

    ~IpPool();
    IpPool(const IpPool&)            = delete;
    IpPool& operator=(const IpPool&) = delete;

    /* Next free address. Throws Error (code IPPOOL_E_FULL) when the pool
     * is exhausted — available() answers that without throwing. */
    std::string alloc();

    /* Claim one specific address; throws when it is outside the pool or
     * already allocated. */
    void reserve(const std::string& addr);

    /* Hand an address back for reuse; throws on a double release or an
     * address that is not one of the pool's. */
    void release(const std::string& addr);

    /* Release everything, as a restart would. */
    void reset();

    bool allocated(const std::string& addr) const;

    uint32_t size() const;      /* addresses in the pool     */
    uint32_t used() const;      /* currently allocated       */
    uint32_t available() const; /* size() - used()           */

    /* The pool's own numbering: addr_at(i) is the address of slot i
     * (throws past the end), index_of(addr) its slot or -1 when the
     * address is not one of the pool's. Neither says whether the slot is
     * allocated. */
    std::string addr_at(uint32_t index) const;
    long        index_of(const std::string& addr) const;

  private:
    ippool* p_;
};

/* ---- DNS resolver ---- */

/* One record from Resolver::resolve. Only the fields that apply to `type`
 * are populated: addr for A / AAAA; prio/weight/port/target for SRV;
 * order/pref/flags/service/regexp/replace for NAPTR. */
struct DnsRecord {
    int         type = 0; /* NET_DNS_A / _AAAA / _SRV / _NAPTR */
    uint32_t    ttl  = 0;

    std::string addr; /* A / AAAA: address literal */

    uint16_t    prio   = 0; /* SRV */
    uint16_t    weight = 0; /* SRV */
    uint16_t    port   = 0; /* SRV */
    std::string target;     /* SRV */

    uint16_t    order = 0; /* NAPTR */
    uint16_t    pref  = 0; /* NAPTR */
    std::string flags;     /* NAPTR */
    std::string service;   /* NAPTR */
    std::string regexp;    /* NAPTR */
    std::string replace;   /* NAPTR */
};

/* Synchronous DNS resolver over the C net_dns engine (net/src/dns.c): A /
 * AAAA / SRV / NAPTR over UDP with EDNS0. The engine is asynchronous and
 * loop-driven; this facade owns a private event loop and steps it until
 * each query completes, so resolve() reads as a plain blocking call for
 * the linear flows scripts drive. It never blocks forever — the engine's
 * own retransmit timer (default 500 ms, 3 tries) bounds every query, so a
 * dead or silent server surfaces as a timeout Error.
 *
 * The private loop is separate from any the caller runs, so a Resolver
 * can be created and discarded around a lookup without disturbing an
 * application loop (and without the teardown-ordering hazards a borrowed
 * loop would bring under a garbage collector). */
class Resolver
{
  public:
    /* server: "" (default) uses the first nameserver in /etc/resolv.conf;
     * otherwise a numeric IPv4/IPv6 address, queried on port 53. Throws
     * Error when the address is malformed or the engine cannot start. */
    explicit Resolver(const std::string& server = "");
    ~Resolver();
    Resolver(const Resolver&)            = delete;
    Resolver& operator=(const Resolver&) = delete;

    /* Retransmit timeout (ms) and try count; a non-positive value leaves
     * the corresponding default unchanged. */
    void conf(int timeout_ms, int tries);

    /* Resolve `name` for record `type` (NET_DNS_A / _AAAA / _SRV /
     * _NAPTR). Returns the answers of that type — empty on NXDOMAIN or no
     * data of the type. Throws Error on timeout or transport failure. */
    std::vector<DnsRecord> resolve(const std::string& name, int type);

    /* The first A / AAAA address as a literal string. Throws Error when
     * the name has no address record of that family. */
    std::string resolve4(const std::string& name);
    std::string resolve6(const std::string& name);

  private:
    Loop     loop_;         /* private; driven synchronously by resolve() */
    net_dns* d_ = nullptr;
};

} /* namespace net */

#endif /* NETXX_HPP */
