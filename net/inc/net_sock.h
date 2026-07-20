#ifndef NET_SOCK_H
#define NET_SOCK_H

#include "net.h"
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* UDP/TCP/SCTP socket wrappers. Every fd is created non-blocking and
 * close-on-exec so it can go straight into the net_loop dispatcher; the
 * synchronous send/recv/conn/accept calls emulate blocking with poll()
 * up to timeout_ms (negative = single non-blocking attempt).
 *
 * IPv6 sockets are opened dual-stack (IPV6_V6ONLY off): binding the
 * IPv6 any-address serves IPv4 peers too, and net_udp_send transparently
 * maps IPv4 destinations onto a v6 socket.
 *
 * SCTP uses one-to-one (SOCK_STREAM) style sockets, so the TCP calls
 * and the stream send/recv apply unchanged. */

enum {
    NET_REUSEPORT = 1, /* SO_REUSEPORT, for multi-UE load testing */
    NET_BOUND     = 2, /* caller supplied the local address       */
    NET_LISTEN    = 4,
};

typedef struct {
    int      fd;
    int      proto; /* 0 or IPPROTO_SCTP */
    unsigned flags;
    net_addr local; /* actual bound address (after ephemeral resolve) */
    net_addr peer;  /* connect/accept peer */
} net_sock;

/* --- UDP ------------------------------------------------------------- */

API_EXPORT int net_udp_open(net_sock*, const net_addr* local, unsigned flags);
API_EXPORT int net_udp_conn(net_sock*, const net_addr* peer);
API_EXPORT ssize_t net_udp_send(net_sock*, const void*, size_t,
                                const net_addr* to);
API_EXPORT ssize_t net_udp_recv(net_sock*, void*, size_t, net_addr* from,
                                int timeout_ms);

/* --- TCP / SCTP ------------------------------------------------------ */

/* conn: local may be NULL (ephemeral). Returns NET_OK when connected,
 * NET_WANT_WR when timeout_ms < 0 and the connect is in flight (finish
 * with net_sock_done once writable), NET_TIMEOUT or NET_ERR. */
API_EXPORT int net_tcp_conn(net_sock*, const net_addr* local,
                            const net_addr* peer, int timeout_ms);
API_EXPORT int net_tcp_bind(net_sock*, const net_addr* local, int backlog);
API_EXPORT int net_sctp_conn(net_sock*, const net_addr* local,
                             const net_addr* peer, int timeout_ms);
API_EXPORT int net_sctp_bind(net_sock*, const net_addr* local, int backlog);

API_EXPORT int net_sock_done(net_sock*,
                             int timeout_ms); /* finish async connect */
API_EXPORT int net_sock_accept(net_sock* srv, net_sock* out, int timeout_ms);

/* Stream send: pushes the whole buffer, polling up to timeout_ms.
 * Returns bytes sent (may be short on timeout), NET_TIMEOUT if none,
 * or NET_ERR. Recv returns >0 bytes, 0 on orderly close, NET_TIMEOUT,
 * or NET_ERR. */
API_EXPORT ssize_t net_sock_send(net_sock*, const void*, size_t,
                                 int timeout_ms);
API_EXPORT ssize_t net_sock_recv(net_sock*, void*, size_t, int timeout_ms);

/* Drop and redial the stored peer, rebinding the local address only if
 * the caller chose it originally. */
API_EXPORT int  net_sock_reconn(net_sock*, int timeout_ms);
API_EXPORT void net_sock_close(net_sock*);

/* poll() one fd for NET_RD/NET_WR: NET_OK, NET_TIMEOUT or NET_ERR. */
API_EXPORT int net_sock_wait(int fd, unsigned ev, int timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* NET_SOCK_H */
