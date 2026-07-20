#define _GNU_SOURCE
#include "net_sock.h"
#include "net_loop.h"

#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>

#ifndef SCTP_NODELAY
#define SCTP_NODELAY 3 /* linux/sctp.h; avoids a libsctp-dev dependency */
#endif
#ifndef IP_FREEBIND
#define IP_FREEBIND 15 /* linux/in.h */
#endif
#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT 19 /* linux/in.h */
#endif
#ifndef IPV6_FREEBIND
#define IPV6_FREEBIND 78 /* linux/in6.h */
#endif
#ifndef IPV6_TRANSPARENT
#define IPV6_TRANSPARENT 75 /* linux/in6.h */
#endif

int net_sock_wait(int fd, unsigned ev, int timeout_ms)
{
    if (timeout_ms < 0) return NET_TIMEOUT;
    struct pollfd p = {
        .fd = fd,
        .events =
            (short)((ev & NET_RD ? POLLIN : 0) | (ev & NET_WR ? POLLOUT : 0)),
    };
    int r;
    do
        r = poll(&p, 1, timeout_ms);
    while (r < 0 && errno == EINTR);
    if (r < 0) return NET_ERR;
    return r ? NET_OK : NET_TIMEOUT;
}

static int left(uint64_t due)
{
    uint64_t now = net_now_ms();
    return now >= due ? 0 : (int)(due - now);
}

static int sock_new(net_sock* s, int family, int type, int proto)
{
    memset(s, 0, sizeof *s);
    s->proto = proto;
    s->fd    = socket(family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, proto);
    if (s->fd < 0) return NET_ERR;
    if (family == AF_INET6) {
        int off = 0; /* dual-stack: serve v4-mapped peers too */
        setsockopt(s->fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof off);
    }
    if (type == SOCK_STREAM) {
        int on = 1;
        setsockopt(s->fd, proto == IPPROTO_SCTP ? IPPROTO_SCTP : IPPROTO_TCP,
                   proto == IPPROTO_SCTP ? SCTP_NODELAY : TCP_NODELAY, &on,
                   sizeof on);
    }
    return NET_OK;
}

static int sock_bind(net_sock* s, const net_addr* local, unsigned flags,
                     int reuseaddr)
{
    int on = 1;
    if (flags & NET_REUSEPORT)
        if (setsockopt(s->fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof on) < 0)
            return NET_ERR;
    if (reuseaddr) /* streams only: SO_REUSEADDR on UDP would defeat REUSEPORT
                    */
        setsockopt(s->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    if (flags & NET_NONLOCAL_SRC) {
        /* Use a source address this host does not own (e.g. a simulated
         * UE's PDN address). IP_FREEBIND lifts the bind-time locality
         * check; IP_TRANSPARENT additionally lets the kernel *route and
         * send* from that source (IP_FREEBIND alone binds, but sends then
         * fail with ENETUNREACH). Neither adds the address, so packets
         * *to* it still route out instead of being delivered locally.
         * Needs CAP_NET_ADMIN; being plain setsockopts (no /proc write)
         * they work where /proc/sys is read-only, e.g. a default Docker
         * mount. Best-effort: if refused, the bind or a later send fails
         * and the caller sees the error. */
        if (local->sa.sa_family == AF_INET6) {
            setsockopt(s->fd, IPPROTO_IPV6, IPV6_FREEBIND, &on, sizeof on);
            setsockopt(s->fd, IPPROTO_IPV6, IPV6_TRANSPARENT, &on, sizeof on);
        } else {
            setsockopt(s->fd, IPPROTO_IP, IP_FREEBIND, &on, sizeof on);
            setsockopt(s->fd, IPPROTO_IP, IP_TRANSPARENT, &on, sizeof on);
        }
    }
    if (bind(s->fd, &local->sa, net_addr_len(local)) < 0) return NET_ERR;
    socklen_t sl = sizeof s->local;
    getsockname(s->fd, &s->local.sa, &sl); /* resolve ephemeral port */
    s->flags |= flags | NET_BOUND;
    return NET_OK;
}

static int fail(net_sock* s)
{
    int e = errno;
    close(s->fd);
    s->fd = -1;
    errno = e;
    return NET_ERR;
}

/* IPv4 destination on a dual-stack v6 socket → v4-mapped v6 address. */
static const net_addr* map6(const net_sock* s, const net_addr* a, net_addr* tmp)
{
    if (s->local.sa.sa_family != AF_INET6 || a->sa.sa_family != AF_INET)
        return a;
    memset(tmp, 0, sizeof *tmp);
    tmp->v6.sin6_family           = AF_INET6;
    tmp->v6.sin6_port             = a->v4.sin_port;
    tmp->v6.sin6_addr.s6_addr[10] = 0xff;
    tmp->v6.sin6_addr.s6_addr[11] = 0xff;
    memcpy(&tmp->v6.sin6_addr.s6_addr[12], &a->v4.sin_addr, 4);
    return tmp;
}

static void unmap6(net_addr* a)
{
    if (a->sa.sa_family != AF_INET6 || !IN6_IS_ADDR_V4MAPPED(&a->v6.sin6_addr))
        return;
    net_addr v4;
    memset(&v4, 0, sizeof v4);
    v4.v4.sin_family = AF_INET;
    v4.v4.sin_port   = a->v6.sin6_port;
    memcpy(&v4.v4.sin_addr, &a->v6.sin6_addr.s6_addr[12], 4);
    *a = v4;
}

/* --- UDP -------------------------------------------------------------- */

int net_udp_open(net_sock* s, const net_addr* local, unsigned flags)
{
    if (sock_new(s, local->sa.sa_family, SOCK_DGRAM, 0)) return NET_ERR;
    if (sock_bind(s, local, flags, 0)) return fail(s);
    return NET_OK;
}

int net_udp_conn(net_sock* s, const net_addr* peer)
{
    net_addr        tmp;
    const net_addr* to = map6(s, peer, &tmp);
    if (connect(s->fd, &to->sa, net_addr_len(to)) < 0) return NET_ERR;
    s->peer = *peer;
    return NET_OK;
}

ssize_t net_udp_send(net_sock* s, const void* buf, size_t len,
                     const net_addr* to)
{
    net_addr tmp;
    if (to) to = map6(s, to, &tmp);
    ssize_t n;
    do
        n = to ? sendto(s->fd, buf, len, 0, &to->sa, net_addr_len(to))
               : send(s->fd, buf, len, 0);
    while (n < 0 && errno == EINTR);
    if (n < 0)
        return errno == EAGAIN || errno == EWOULDBLOCK ? NET_TIMEOUT : NET_ERR;
    return n;
}

ssize_t net_udp_recv(net_sock* s, void* buf, size_t len, net_addr* from,
                     int timeout_ms)
{
    for (;;) {
        net_addr  a;
        socklen_t sl = sizeof a;
        ssize_t   n  = recvfrom(s->fd, buf, len, 0, &a.sa, &sl);
        if (n >= 0) {
            if (from) {
                unmap6(&a);
                *from = a;
            }
            return n;
        }
        if (errno == EINTR) continue;
        if (errno != EAGAIN && errno != EWOULDBLOCK) return NET_ERR;
        int w = net_sock_wait(s->fd, NET_RD, timeout_ms);
        if (w != NET_OK) return w;
        timeout_ms = 0; /* datagram already queued; don't wait twice */
    }
}

/* --- TCP / SCTP streams ------------------------------------------------ */

int net_sock_done(net_sock* s, int timeout_ms)
{
    int w = net_sock_wait(s->fd, NET_WR, timeout_ms);
    if (w != NET_OK) return w;
    int       err = 0;
    socklen_t sl  = sizeof err;
    if (getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &err, &sl) < 0 || err) {
        errno = err;
        return NET_ERR;
    }
    return NET_OK;
}

static int stream_conn(net_sock* s, const net_addr* local, const net_addr* peer,
                       int proto, int timeout_ms)
{
    if (sock_new(s, peer->sa.sa_family, SOCK_STREAM, proto)) return NET_ERR;
    if (local && sock_bind(s, local, 0, 1)) return fail(s);
    s->peer = *peer;
    if (connect(s->fd, &peer->sa, net_addr_len(peer)) == 0) return NET_OK;
    if (errno != EINPROGRESS) return fail(s);
    if (timeout_ms < 0) return NET_WANT_WR;
    int r = net_sock_done(s, timeout_ms);
    if (r == NET_ERR) return fail(s);
    return r;
}

static int stream_bind(net_sock* s, const net_addr* local, int backlog,
                       int proto)
{
    if (sock_new(s, local->sa.sa_family, SOCK_STREAM, proto)) return NET_ERR;
    if (sock_bind(s, local, 0, 1)) return fail(s);
    if (listen(s->fd, backlog > 0 ? backlog : 64) < 0) return fail(s);
    s->flags |= NET_LISTEN;
    return NET_OK;
}

int net_tcp_conn(net_sock* s, const net_addr* local, const net_addr* peer,
                 int timeout_ms)
{
    return stream_conn(s, local, peer, 0, timeout_ms);
}

int net_tcp_bind(net_sock* s, const net_addr* local, int backlog)
{
    return stream_bind(s, local, backlog, 0);
}

int net_sctp_conn(net_sock* s, const net_addr* local, const net_addr* peer,
                  int timeout_ms)
{
    return stream_conn(s, local, peer, IPPROTO_SCTP, timeout_ms);
}

int net_sctp_bind(net_sock* s, const net_addr* local, int backlog)
{
    return stream_bind(s, local, backlog, IPPROTO_SCTP);
}

int net_sock_accept(net_sock* srv, net_sock* out, int timeout_ms)
{
    for (;;) {
        memset(out, 0, sizeof *out);
        socklen_t sl = sizeof out->peer;
        int       fd =
            accept4(srv->fd, &out->peer.sa, &sl, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd >= 0) {
            out->fd    = fd;
            out->proto = srv->proto;
            unmap6(&out->peer);
            sl = sizeof out->local;
            getsockname(fd, &out->local.sa, &sl);
            int on = 1;
            setsockopt(fd,
                       srv->proto == IPPROTO_SCTP ? IPPROTO_SCTP : IPPROTO_TCP,
                       srv->proto == IPPROTO_SCTP ? SCTP_NODELAY : TCP_NODELAY,
                       &on, sizeof on);
            return NET_OK;
        }
        if (errno == EINTR) continue;
        if (errno != EAGAIN && errno != EWOULDBLOCK) return NET_ERR;
        int w = net_sock_wait(srv->fd, NET_RD, timeout_ms);
        if (w != NET_OK) return w;
    }
}

ssize_t net_sock_send(net_sock* s, const void* buf, size_t len, int timeout_ms)
{
    size_t   off = 0;
    uint64_t due = net_now_ms() + (timeout_ms > 0 ? (uint64_t)timeout_ms : 0);
    while (off < len) {
        ssize_t n =
            send(s->fd, (const char*)buf + off, len - off, MSG_NOSIGNAL);
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            int w =
                net_sock_wait(s->fd, NET_WR, timeout_ms < 0 ? -1 : left(due));
            if (w == NET_OK) continue;
            if (w == NET_ERR) return NET_ERR;
            break; /* timeout: report what went out */
        }
        return NET_ERR;
    }
    if (off || !len) return (ssize_t)off;
    return NET_TIMEOUT;
}

ssize_t net_sock_recv(net_sock* s, void* buf, size_t len, int timeout_ms)
{
    for (;;) {
        ssize_t n = recv(s->fd, buf, len, 0);
        if (n >= 0) return n;
        if (errno == EINTR) continue;
        if (errno != EAGAIN && errno != EWOULDBLOCK) return NET_ERR;
        int w = net_sock_wait(s->fd, NET_RD, timeout_ms);
        if (w != NET_OK) return w;
        timeout_ms = 0;
    }
}

int net_sock_reconn(net_sock* s, int timeout_ms)
{
    if ((s->flags & NET_LISTEN) || !s->peer.sa.sa_family) return NET_ERR;
    net_addr local = s->local;
    net_addr peer  = s->peer;
    int      proto = s->proto;
    unsigned flags = s->flags;
    net_sock_close(s);
    return stream_conn(s, flags & NET_BOUND ? &local : NULL, &peer, proto,
                       timeout_ms);
}

void net_sock_close(net_sock* s)
{
    if (s->fd >= 0) close(s->fd);
    s->fd = -1;
}
