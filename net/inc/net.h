#ifndef NET_H
#define NET_H

#include <stdint.h>
#include <netinet/in.h>
#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Common return codes. Calls taking timeout_ms treat a negative timeout as
 * "do not wait" (single non-blocking attempt) and 0.. as milliseconds. */
enum {
    NET_OK      = 0,
    NET_ERR     = -1, /* system error, errno set                */
    NET_TIMEOUT = -2, /* nothing happened within the timeout    */
    NET_WANT_RD = 1,  /* in progress, retry when fd is readable */
    NET_WANT_WR = 2,  /* in progress, retry when fd is writable */
};

/* Socket address, IPv4 or IPv6; family lives in sa.sa_family. */
typedef union {
    struct sockaddr         sa;
    struct sockaddr_in      v4;
    struct sockaddr_in6     v6;
    struct sockaddr_storage ss;
} net_addr;

#define NET_ADDR_STRLEN 64 /* "[v6]:port" worst case */

/* Parse a numeric IPv4/IPv6 host. NULL host binds the IPv6 any-address,
 * which accepts IPv4 too (dual-stack, see net_udp_open/net_tcp_bind). */
API_EXPORT int       net_addr_from(net_addr*, const char* host, uint16_t port);
API_EXPORT int       net_addr_any(net_addr*, int family, uint16_t port);
API_EXPORT socklen_t net_addr_len(const net_addr*);
API_EXPORT uint16_t  net_addr_port(const net_addr*);
API_EXPORT void      net_addr_set_port(net_addr*, uint16_t);
API_EXPORT int       net_addr_eq(const net_addr*, const net_addr*);
API_EXPORT const char* net_addr_str(const net_addr*, char buf[NET_ADDR_STRLEN]);

#ifdef __cplusplus
}
#endif

#endif /* NET_H */
