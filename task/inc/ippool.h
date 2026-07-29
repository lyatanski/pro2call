#ifndef IPPOOL_H
#define IPPOOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Address pool with reuse — the allocator behind a DHCP server's lease
 * table or a PGW/SMF's PDN address assignment.
 *
 * A pool is a contiguous run of addresses (a CIDR prefix or an explicit
 * first..last range) in either family, numbered 0..size-1. Its whole
 * state is one occupancy bitmap plus a rotating cursor:
 *
 *   - allocate: from the cursor, scan forward 64 slots at a time for a
 *     clear bit, claim it, leave the cursor just past it. A pool with
 *     room ahead of the cursor costs one word load and a count-trailing-
 *     zeros; a saturated one costs at most size/64 loads, and
 *     exhaustion is answered from the used counter without scanning.
 *   - free: clear the bit. The cursor never moves backwards, so a
 *     released address is only handed out again after the cursor has
 *     swept the rest of the pool — the quarantine a DHCP server wants
 *     between a lease ending and the same address going out again,
 *     without a timestamp per address.
 *   - reserve a specific address (a gateway, a static subscriber, a
 *     Create Session Request asking for the address it held before):
 *     set that bit directly.
 *
 * Memory is one bit per address and nothing else: 8 KiB for a /16, 2 MiB
 * for the largest pool accepted (IPPOOL_MAX_SIZE addresses). No
 * allocation, no syscalls and no text parsing happen after create, and
 * (like the codecs) a pool is confined to one thread.
 *
 * Addresses are binary here — this module carries no dependency beyond
 * the C library; the literal-string surface lives in the bindings facade
 * (bindings/cxx/inc/netxx.hpp, net.IpPool).
 */

typedef enum {
    IPPOOL_OK      = 0,
    IPPOOL_E_INVAL = -1, /* invalid argument                            */
    IPPOOL_E_NOMEM = -2, /* allocation failure                          */
    IPPOOL_E_FULL  = -3, /* every address is allocated                  */
    IPPOOL_E_RANGE = -4, /* address is not one of the pool's            */
    IPPOOL_E_INUSE = -5, /* reserve of an already-allocated address     */
    IPPOOL_E_FREE  = -6  /* release of an address that is not allocated */
} ippool_err_t;

/* Address sizes in bytes, doubling as the family tag. */
enum { IPPOOL_V4 = 4, IPPOOL_V6 = 16 };

/* Largest pool accepted; a bigger prefix is clamped to this many
 * addresses from the start of the range (a /8 of IPv4 exactly). */
#define IPPOOL_MAX_SIZE (1u << 24)

/* One address, network byte order — the wire layout, so it drops
 * straight into an F-TEID, a PAA or a Framed-IP-Address. */
typedef struct {
    uint8_t len;   /* IPPOOL_V4 / IPPOOL_V6; 0 = unset */
    uint8_t b[16]; /* first len bytes significant       */
} ippool_addr_t;

/* Address constructors/accessors, so callers need no byte shuffling.
 * ippool_addr4 takes the address in host order: 0x0A2D0001 is
 * 10.45.0.1. */
static inline ippool_addr_t ippool_addr4(uint32_t host_order)
{
    ippool_addr_t a;
    memset(&a, 0, sizeof a);
    a.len  = IPPOOL_V4;
    a.b[0] = (uint8_t)(host_order >> 24);
    a.b[1] = (uint8_t)(host_order >> 16);
    a.b[2] = (uint8_t)(host_order >> 8);
    a.b[3] = (uint8_t)host_order;
    return a;
}

static inline ippool_addr_t ippool_addr6(const uint8_t bytes[16])
{
    ippool_addr_t a;
    memset(&a, 0, sizeof a);
    a.len = IPPOOL_V6;
    memcpy(a.b, bytes, 16);
    return a;
}

static inline uint32_t ippool_addr4_u32(const ippool_addr_t* a)
{
    return ((uint32_t)a->b[0] << 24) | ((uint32_t)a->b[1] << 16) |
           ((uint32_t)a->b[2] << 8) | (uint32_t)a->b[3];
}

static inline bool ippool_addr_eq(const ippool_addr_t* x,
                                  const ippool_addr_t* y)
{
    return x->len == y->len && memcmp(x->b, y->b, x->len) == 0;
}

typedef struct ippool ippool_t;

/* Pool over a CIDR prefix. prefix is masked to prefix_len, so
 * (10.45.7.9, 16) and (10.45.0.0, 16) describe the same pool.
 *
 * An IPv4 prefix shorter than /31 excludes its network and broadcast
 * address, as a DHCP scope does — 10.45.0.0/16 yields 10.45.0.1 ..
 * 10.45.255.254 (65534 addresses). /31 and /32, and every IPv6 prefix,
 * use every address in the range. Reserve the gateway with
 * ippool_reserve() when it lives inside the prefix.
 *
 * Returns NULL on a bad argument or an allocation failure. */
API_EXPORT ippool_t* ippool_create(const ippool_addr_t* prefix,
                                   uint8_t              prefix_len);

/* Pool over an explicit inclusive range, both ends usable and both of
 * the same family: the "10.45.0.100 .. 10.45.0.200" form of a DHCP
 * scope. Returns NULL unless first <= last. */
API_EXPORT ippool_t* ippool_create_range(const ippool_addr_t* first,
                                         const ippool_addr_t* last);

API_EXPORT void ippool_destroy(ippool_t* self);

/* Claim the next free address. IPPOOL_E_FULL when none is left; *out is
 * only written on success. */
API_EXPORT int ippool_alloc(ippool_t* self, ippool_addr_t* out);

/* Claim one specific address: IPPOOL_E_RANGE when it is outside the
 * pool, IPPOOL_E_INUSE when it is already allocated. */
API_EXPORT int ippool_reserve(ippool_t* self, const ippool_addr_t* addr);

/* Release an address back for reuse. IPPOOL_E_FREE on a double release
 * (the caller's bookkeeping is wrong), IPPOOL_E_RANGE when the address
 * is not one of the pool's. */
API_EXPORT int ippool_free(ippool_t* self, const ippool_addr_t* addr);

/* Release everything, as a restart would. */
API_EXPORT void ippool_reset(ippool_t* self);

API_EXPORT bool ippool_is_allocated(const ippool_t*      self,
                                    const ippool_addr_t* addr);

API_EXPORT uint32_t ippool_size(const ippool_t* self);
API_EXPORT uint32_t ippool_used(const ippool_t* self);
API_EXPORT uint32_t ippool_avail(const ippool_t* self);

/* The pool's own numbering, for callers that key their session table by
 * slot instead of by address: ippool_addr_at() maps a slot to its
 * address (IPPOOL_E_RANGE past the end), ippool_index_of() an address
 * back to its slot (-1 when it is not one of the pool's). Both are
 * arithmetic — neither says whether the slot is allocated. */
API_EXPORT int     ippool_addr_at(const ippool_t* self, uint32_t index,
                                  ippool_addr_t* out);
API_EXPORT int64_t ippool_index_of(const ippool_t*      self,
                                   const ippool_addr_t* addr);

#ifdef __cplusplus
}
#endif

#endif /* IPPOOL_H */
