#ifndef RTNL_H
#define RTNL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Interface address management over the kernel's RTNETLINK interface
 * (NETLINK_ROUTE, see RFC 3549 and Linux Documentation/networking). Adds
 * and removes interface addresses the same way `ip addr add`/`ip addr
 * del` do: by exchanging RTM_NEWADDR / RTM_DELADDR messages with the
 * kernel. Adding an address makes it locally deliverable — the kernel
 * installs the matching entry in the `local` routing table — which is
 * why a simulated endpoint (e.g. a UE PDN address the host does not
 * really own, put on `lo`) needs it to receive its own decapsulated
 * traffic without shelling out to iproute2.
 *
 * The wire format and the two-layer split mirror the sibling xfrm module
 * (netlink/xfrm/inc/xfrm.h): a struct nlmsghdr, a message-specific fixed
 * payload (struct ifaddrmsg), then a run of netlink attributes encoded
 * with the shared TLV codec (task/inc/tlv.h) under its TLV_PROF_NETLINK
 * profile.
 *
 *   - message builders (rtnl_*_msg): pure functions that render one
 *     netlink request into a caller buffer. No socket, no privilege —
 *     unit-testable on any host.
 *   - transactions (rtnl_addr_add, rtnl_addr_del): open a socket, send a
 *     built message and read the kernel's ACK. These need CAP_NET_ADMIN
 *     (typically root).
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

/* ---- Message builders (no socket, no privilege) ---------------------
 *
 * Each renders one complete netlink request (nlmsghdr + ifaddrmsg +
 * attributes) into buf. seq is the caller's sequence number, echoed in
 * the kernel's ACK. Returns the total byte length written, or a negative
 * RTNL_E_* code (RTNL_E_OVERFLOW if it would not fit, RTNL_E_INVAL on a
 * bad address / out-of-range prefix / zero ifindex).
 *
 * The add request carries NLM_F_CREATE | NLM_F_REPLACE, so re-adding an
 * address already present succeeds (idempotent) rather than failing with
 * EEXIST.
 */
API_EXPORT int rtnl_addr_msg(uint8_t* buf, size_t cap, uint32_t seq,
                             const rtnl_addr* a);
API_EXPORT int rtnl_addr_del_msg(uint8_t* buf, size_t cap, uint32_t seq,
                                 const rtnl_addr* a);

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

#ifdef __cplusplus
}
#endif

#endif /* RTNL_H */
