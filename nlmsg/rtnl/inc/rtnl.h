#ifndef RTNL_H
#define RTNL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Interface address and route management over the kernel's RTNETLINK
 * interface (NETLINK_ROUTE, see RFC 3549 and Linux
 * Documentation/networking). Adds and removes interface addresses and
 * routes the same way `ip addr add`/`ip addr del` and `ip route
 * replace`/`ip route del` do: by exchanging RTM_NEWADDR / RTM_DELADDR and
 * RTM_NEWROUTE / RTM_DELROUTE messages with the kernel. Adding an address
 * makes it locally deliverable — the kernel installs the matching entry
 * in the `local` routing table — which is why a simulated endpoint (e.g.
 * a UE PDN address the host does not really own, put on `lo`) needs it to
 * receive its own decapsulated traffic without shelling out to iproute2.
 *
 * The wire format and the two-layer split mirror the sibling xfrm module
 * (netlink/xfrm/inc/xfrm.h): a struct nlmsghdr, a message-specific fixed
 * payload (struct ifaddrmsg or struct rtmsg), then a run of netlink
 * attributes encoded with the shared TLV codec (task/inc/tlv.h) under its
 * TLV_PROF_NETLINK profile.
 *
 *   - message builders (rtnl_*_msg): pure functions that render one
 *     netlink request into a caller buffer. No socket, no privilege —
 *     unit-testable on any host.
 *   - transactions (rtnl_addr_add, rtnl_route_add, ...): open a socket,
 *     send a built message and read the kernel's ACK. These need
 *     CAP_NET_ADMIN (typically root).
 *
 * Addresses are literal strings ("10.0.0.1", "fd00::1"); the family is
 * inferred from them. The interface is a kernel ifindex (if_nametoindex),
 * so this module needs no name-resolution machinery of its own.
 */

enum {
    RTNL_OK         = 0,
    RTNL_E_SYS      = -1, /* syscall failed; errno is set              */
    RTNL_E_INVAL    = -2, /* bad argument (e.g. unparseable address)   */
    RTNL_E_OVERFLOW = -3, /* request did not fit the supplied buffer   */
    RTNL_E_PROTO    = -4, /* malformed or unexpected netlink reply     */
    RTNL_E_ACK      = -5, /* kernel rejected the request (see nl_errno)*/
};

/* An interface address: the local address, its prefix length, and the
 * interface it belongs to. scope is an rtnetlink RT_SCOPE_* value; 0
 * (RT_SCOPE_UNIVERSE) is the right default for a routable address, as
 * `ip addr add` picks for anything outside 127.0.0.0/8. */
typedef struct {
    const char* addr;      /* local address literal, required          */
    uint8_t     prefixlen; /* prefix length in bits (<=32 v4, <=128 v6) */
    uint32_t    ifindex;   /* target interface (if_nametoindex)         */
    uint8_t     scope;     /* RT_SCOPE_*; 0 = universe (global)         */
} rtnl_addr;

/* A route, as `ip route replace <dst>/<dstlen> [via <gateway>] [dev <if>]
 * [mtu <mtu>] [metric <priority>]` installs it.
 *
 * A NULL (or empty) dst with dstlen 0 is the default route, and then the
 * address family is taken from the gateway; otherwise it comes from dst,
 * and a gateway of the other family is rejected. Each remaining field
 * left at 0 takes the value `ip route` would pick: table main, protocol
 * boot, type unicast, and scope link for a device route or universe for
 * one through a gateway.
 *
 * mtu is the per-route MTU (RTAX_MTU among the kernel's per-route
 * metrics), and is the reason this module has routes at all. When
 * something past the sending socket grows the packet — a TC/eBPF hook
 * adding GTP-U encapsulation, say, which cannot fragment, because a TC
 * program cannot split a packet — a datagram that fits the link before
 * that and not after is dropped, silently and with no ICMP to learn
 * from. Lowering the MTU of the route toward that destination makes the
 * kernel fragment on the way out instead, before the hook, while the
 * interface MTU stays what the grown packets themselves need. */
typedef struct {
    const char* dst;      /* destination prefix; NULL = default route     */
    uint8_t     dstlen;   /* its prefix length in bits (<=32 v4, <=128 v6)*/
    const char* gateway;  /* next hop, or NULL for an on-link route       */
    uint32_t    ifindex;  /* output interface (RTA_OIF); 0 = unset        */
    uint32_t    mtu;      /* per-route MTU (RTAX_MTU); 0 = leave alone    */
    uint32_t    priority; /* metric (RTA_PRIORITY); 0 = kernel default    */
    uint8_t     table;    /* RT_TABLE_*; 0 = main                         */
    uint8_t     scope;    /* RT_SCOPE_*; 0 = derived from the gateway     */
    uint8_t     protocol; /* RTPROT_*; 0 = boot                           */
    uint8_t     type;     /* RTN_*; 0 = unicast                           */
} rtnl_route;

/* ---- Message builders (no socket, no privilege) ---------------------
 *
 * Each renders one complete netlink request (nlmsghdr + ifaddrmsg or
 * rtmsg + attributes) into buf. seq is the caller's sequence number,
 * echoed in the kernel's ACK. Returns the total byte length written, or a
 * negative RTNL_E_* code (RTNL_E_OVERFLOW if it would not fit,
 * RTNL_E_INVAL on a bad address / out-of-range prefix / zero ifindex /
 * a route with neither a destination nor a gateway).
 *
 * An add request carries NLM_F_CREATE | NLM_F_REPLACE, so re-adding an
 * address or route already present succeeds (idempotent) rather than
 * failing with EEXIST — `ip route replace`, not `ip route add`, which is
 * what makes installing a route MTU repeatable.
 *
 * A delete keys on what it is given and leaves the zero-valued route
 * fields as the wildcards the kernel reads them as: protocol, scope and
 * type default to "any" for RTM_DELROUTE rather than to the add-side
 * defaults, so deleting a route needs only its destination (plus the
 * interface or gateway when several match).
 */
API_EXPORT int rtnl_addr_msg(uint8_t* buf, size_t cap, uint32_t seq,
                             const rtnl_addr* a);
API_EXPORT int rtnl_addr_del_msg(uint8_t* buf, size_t cap, uint32_t seq,
                                 const rtnl_addr* a);
API_EXPORT int rtnl_route_msg(uint8_t* buf, size_t cap, uint32_t seq,
                              const rtnl_route* r);
API_EXPORT int rtnl_route_del_msg(uint8_t* buf, size_t cap, uint32_t seq,
                                  const rtnl_route* r);

/* ---- Transactions (need CAP_NET_ADMIN) ------------------------------ */

typedef struct {
    int      fd;       /* AF_NETLINK / NETLINK_ROUTE socket, -1 = closed */
    uint32_t seq;      /* next sequence number, auto-incremented         */
    uint32_t portid;   /* kernel-assigned local port id                  */
    int      nl_errno; /* last kernel-reported errno on RTNL_E_ACK       */
} rtnl_sock;

/* Open/close the RTNETLINK socket. rtnl_open returns RTNL_OK or
 * RTNL_E_SYS (errno set). Opening needs no privilege; adding/removing
 * addresses needs CAP_NET_ADMIN. */
API_EXPORT int  rtnl_open(rtnl_sock* s);
API_EXPORT void rtnl_close(rtnl_sock* s);

/* Add (idempotent) or remove an interface address. */
API_EXPORT int rtnl_addr_add(rtnl_sock* s, const rtnl_addr* a);
API_EXPORT int rtnl_addr_del(rtnl_sock* s, const rtnl_addr* a);

/* Install (idempotent, replacing any route for the same destination) or
 * remove a route. */
API_EXPORT int rtnl_route_add(rtnl_sock* s, const rtnl_route* r);
API_EXPORT int rtnl_route_del(rtnl_sock* s, const rtnl_route* r);

#ifdef __cplusplus
}
#endif

#endif /* RTNL_H */
