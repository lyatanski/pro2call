#ifndef NET_DNS_H
#define NET_DNS_H

#include "net_loop.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Asynchronous DNS resolver: A, AAAA, SRV and NAPTR over UDP with EDNS0,
 * driven entirely by the event loop — a query never blocks. Retransmits
 * on timeout (default 500 ms, 3 tries) then reports NET_TIMEOUT.
 *
 * The callback runs inside net_loop_step with the parsed records on the
 * stack (no allocation, valid only during the call):
 *   status 0   — rr[0..n) hold the answers of the queried type
 *   status > 0 — DNS rcode (3 = NXDOMAIN), n == 0
 *   status < 0 — NET_TIMEOUT / NET_ERR, n == 0 */

enum {
    NET_DNS_A     = 1,
    NET_DNS_AAAA  = 28,
    NET_DNS_SRV   = 33,
    NET_DNS_NAPTR = 35,
};

#define NET_DNS_MAX 32 /* records delivered per response */

typedef struct {
    uint16_t type;
    uint32_t ttl;
    union {
        struct in_addr  a;
        struct in6_addr aaaa;
        struct {
            uint16_t prio, weight, port;
            char     target[256];
        } srv;
        struct {
            uint16_t order, pref;
            char     flags[16], service[64], regexp[256], replace[256];
        } naptr;
    } u;
} net_dns_rr;

typedef void (*net_dns_f)(void* ud, int status, const net_dns_rr* rr, size_t n);

typedef struct net_dns net_dns;

/* server: NULL for the first nameserver in /etc/resolv.conf (port 53). */
API_EXPORT net_dns* net_dns_new(net_loop*, const net_addr* server);
API_EXPORT void     net_dns_free(net_dns*);
API_EXPORT void     net_dns_conf(net_dns*, int timeout_ms, int tries);
API_EXPORT int      net_dns_query(net_dns*, const char* name, uint16_t type,
                                  net_dns_f cb, void* ud);

#ifdef __cplusplus
}
#endif

#endif /* NET_DNS_H */
