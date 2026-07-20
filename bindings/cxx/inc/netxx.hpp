#ifndef NETXX_HPP
#define NETXX_HPP

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>

#include "net.h"
#include "net_loop.h"
#include "net_sock.h"

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
     * for multi-socket load spreading. Throws Error on failure. */
    UdpSocket(const std::string& local_host = "", uint16_t local_port = 0,
              bool reuseport = false);
    ~UdpSocket();
    UdpSocket(const UdpSocket&)            = delete;
    UdpSocket& operator=(const UdpSocket&) = delete;

    /* Fix a default peer so send()/recv() need no address; the kernel
     * then also drops datagrams from any other source. */
    void connect(const std::string& host, uint16_t port);

    void sendto(const std::string& data, const std::string& host,
                uint16_t port);
    void send(const std::string& data); /* to the connected peer */

    /* timeout_ms >= 0 waits up to that long; < 0 polls once (drain a
     * loop-signalled fd). A timeout returns a Datagram with timed_out
     * set and no data. */
    Datagram recv(int timeout_ms = -1);

    std::string local_host() const;
    uint16_t    local_port() const;
    int         fd() const;
    void        close();

  private:
    net_sock s_;
    bool     open_ = false;
};

} /* namespace net */

#endif /* NETXX_HPP */
