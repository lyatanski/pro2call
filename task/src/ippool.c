/* Address pool over an occupancy bitmap and a rotating cursor; the
 * design and the reuse policy are described in inc/ippool.h. Everything
 * here is byte arithmetic on network-order addresses, so one code path
 * serves both families. */

#include <stdlib.h>

#include "ippool.h"
#include "mesg.h"

struct ippool {
    uint8_t  len;      /* address size: IPPOOL_V4 / IPPOOL_V6 */
    uint8_t  base[16]; /* the address of slot 0              */
    uint32_t size;     /* slot count                         */
    uint32_t used;
    uint32_t cursor; /* slot to probe first on the next alloc */

    uint64_t* bits; /* 1 = allocated; tail padding pre-set    */
    size_t    words;
};

/* Lowest set bit of a non-zero word. */
#if defined(__GNUC__) || defined(__clang__)
#define IPPOOL_CTZ64(v) ((uint32_t)__builtin_ctzll(v))
#else
static uint32_t ippool_ctz64(uint64_t v)
{
    uint32_t n = 0;
    while (!(v & 1)) {
        v >>= 1;
        ++n;
    }
    return n;
}
#define IPPOOL_CTZ64(v) ippool_ctz64(v)
#endif

/* ---- address arithmetic ---- */

/* out = addr + index, big-endian with carry. */
static void addr_offset(const uint8_t* addr, uint8_t len, uint32_t index,
                        uint8_t* out)
{
    uint64_t carry = index;
    int      i;

    memcpy(out, addr, len);
    for (i = (int)len - 1; i >= 0 && carry; --i) {
        carry += out[i];
        out[i] = (uint8_t)carry;
        carry >>= 8;
    }
}

/* *out = a - b when a >= b and the difference fits in 64 bits; false
 * otherwise (b is past a, or they are further apart than any pool). */
static bool addr_delta(const uint8_t* a, const uint8_t* b, uint8_t len,
                       uint64_t* out)
{
    uint8_t  diff[16];
    unsigned borrow = 0;
    uint64_t d      = 0;
    int      i;

    for (i = (int)len - 1; i >= 0; --i) {
        unsigned v = (unsigned)a[i] - (unsigned)b[i] - borrow;
        borrow     = (v >> 8) & 1u; /* borrowed when the subtraction wrapped */
        diff[i]    = (uint8_t)v;
    }
    if (borrow) return false; /* a < b */

    for (i = 0; i + 8 < (int)len; ++i)
        if (diff[i]) return false; /* wider than 64 bits */
    for (i = (len > 8) ? (int)len - 8 : 0; i < (int)len; ++i)
        d = (d << 8) | diff[i];

    *out = d;
    return true;
}

/* ---- construction ---- */

/* Slots past size share the last word; pre-set them so a scan for a
 * clear bit can never pick one. */
static void mark_tail(ippool_t* self)
{
    unsigned tail = self->size & 63u;
    if (tail) self->bits[self->words - 1] = ~0ULL << tail;
}

static ippool_t* pool_new(const uint8_t* base, uint8_t len, uint64_t size)
{
    ippool_t* self;

    if (!size) {
        MESG_FAIL("ippool: %s", "empty range");
        return NULL;
    }
    if (size > IPPOOL_MAX_SIZE) {
        MESG_WARN("ippool: range of %llu addresses clamped to %u",
                  (unsigned long long)size, IPPOOL_MAX_SIZE);
        size = IPPOOL_MAX_SIZE;
    }

    self = calloc(1, sizeof(*self));
    if (!self) {
        MESG_FAIL("ippool: %s", "out of memory");
        return NULL;
    }
    self->len   = len;
    self->size  = (uint32_t)size;
    self->words = (size + 63) / 64;
    self->bits  = calloc(self->words, sizeof(*self->bits));
    if (!self->bits) {
        MESG_FAIL("ippool: %s", "out of memory");
        free(self);
        return NULL;
    }
    memcpy(self->base, base, len);
    mark_tail(self);
    return self;
}

ippool_t* ippool_create(const ippool_addr_t* prefix, uint8_t prefix_len)
{
    uint8_t  net[16];
    uint8_t  len;
    unsigned bits;
    unsigned hostbits;
    uint64_t size;
    unsigned i;

    if (!prefix || (prefix->len != IPPOOL_V4 && prefix->len != IPPOOL_V6)) {
        MESG_FAIL("ippool: %s", "invalid prefix address");
        return NULL;
    }
    len  = prefix->len;
    bits = (unsigned)len * 8u;
    if (prefix_len > bits) {
        MESG_FAIL("ippool: prefix length %u exceeds %u", prefix_len, bits);
        return NULL;
    }
    hostbits = bits - prefix_len;

    /* Mask the host part off, so any address inside the prefix names it. */
    for (i = 0; i < len; ++i) {
        unsigned keep = (prefix_len > i * 8u) ? prefix_len - i * 8u : 0u;
        uint8_t  mask = (keep >= 8u) ? 0xFFu : (uint8_t)(0xFFu << (8u - keep));
        net[i]        = prefix->b[i] & mask;
    }

    /* A prefix wider than 64 host bits has no exact size to report; the
     * pool is the clamped head of it either way. */
    if (hostbits >= 64) {
        MESG_WARN("ippool: /%u covers 2^%u addresses; pool is the first %u",
                  prefix_len, hostbits, IPPOOL_MAX_SIZE);
        return pool_new(net, len, IPPOOL_MAX_SIZE);
    }
    size = (uint64_t)1 << hostbits;

    /* An IPv4 scope shorter than /31 keeps its network and broadcast
     * address out of the pool, as a DHCP scope does. */
    if (len == IPPOOL_V4 && hostbits >= 2) {
        uint8_t first[16];
        addr_offset(net, len, 1, first);
        return pool_new(first, len, size - 2);
    }
    return pool_new(net, len, size);
}

ippool_t* ippool_create_range(const ippool_addr_t* first,
                              const ippool_addr_t* last)
{
    uint64_t delta;

    if (!first || !last || first->len != last->len ||
        (first->len != IPPOOL_V4 && first->len != IPPOOL_V6)) {
        MESG_FAIL("ippool: %s", "invalid range endpoints");
        return NULL;
    }
    if (!addr_delta(last->b, first->b, first->len, &delta)) {
        MESG_FAIL("ippool: %s", "range end precedes its start");
        return NULL;
    }
    if (delta == UINT64_MAX) { /* no exact size to report; clamp as above */
        MESG_WARN("ippool: range covers 2^64 addresses; pool is the first %u",
                  IPPOOL_MAX_SIZE);
        return pool_new(first->b, first->len, IPPOOL_MAX_SIZE);
    }
    return pool_new(first->b, first->len, delta + 1);
}

void ippool_destroy(ippool_t* self)
{
    if (self) {
        free(self->bits);
        free(self);
    }
}

/* ---- allocation ---- */

static int slot_addr(const ippool_t* self, uint32_t slot, ippool_addr_t* out)
{
    memset(out, 0, sizeof *out);
    out->len = self->len;
    addr_offset(self->base, self->len, slot, out->b);
    return IPPOOL_OK;
}

int ippool_alloc(ippool_t* self, ippool_addr_t* out)
{
    size_t   w;
    uint64_t mask;
    size_t   n;

    if (!self || !out) {
        MESG_FAIL("ippool: %s", "invalid parameter");
        return IPPOOL_E_INVAL;
    }
    if (self->used == self->size) return IPPOOL_E_FULL;

    /* One sweep from the cursor: the cursor's word masked to the bits at
     * or after it, every other word whole, then that first word again for
     * the bits before the cursor. */
    w    = self->cursor >> 6;
    mask = ~0ULL << (self->cursor & 63u);
    for (n = 0; n <= self->words; ++n) {
        uint64_t free_bits = ~self->bits[w] & mask;
        if (free_bits) {
            uint32_t slot = (uint32_t)(w << 6) + IPPOOL_CTZ64(free_bits);
            self->bits[w] |= (uint64_t)1 << (slot & 63u);
            ++self->used;
            self->cursor = (slot + 1 < self->size) ? slot + 1 : 0;
            return slot_addr(self, slot, out);
        }
        w    = (w + 1 == self->words) ? 0 : w + 1;
        mask = ~0ULL;
    }
    return IPPOOL_E_FULL; /* unreachable while used < size */
}

int ippool_reserve(ippool_t* self, const ippool_addr_t* addr)
{
    int64_t  i;
    uint64_t bit;

    if (!self || !addr) {
        MESG_FAIL("ippool: %s", "invalid parameter");
        return IPPOOL_E_INVAL;
    }
    if ((i = ippool_index_of(self, addr)) < 0) return IPPOOL_E_RANGE;
    bit = (uint64_t)1 << ((uint32_t)i & 63u);
    if (self->bits[(uint32_t)i >> 6] & bit) return IPPOOL_E_INUSE;

    self->bits[(uint32_t)i >> 6] |= bit;
    ++self->used;
    return IPPOOL_OK;
}

int ippool_free(ippool_t* self, const ippool_addr_t* addr)
{
    int64_t  i;
    uint64_t bit;

    if (!self || !addr) {
        MESG_FAIL("ippool: %s", "invalid parameter");
        return IPPOOL_E_INVAL;
    }
    if ((i = ippool_index_of(self, addr)) < 0) return IPPOOL_E_RANGE;
    bit = (uint64_t)1 << ((uint32_t)i & 63u);
    if (!(self->bits[(uint32_t)i >> 6] & bit)) return IPPOOL_E_FREE;

    self->bits[(uint32_t)i >> 6] &= ~bit;
    --self->used;
    return IPPOOL_OK;
}

void ippool_reset(ippool_t* self)
{
    if (!self) return;
    memset(self->bits, 0, self->words * sizeof(*self->bits));
    mark_tail(self);
    self->used   = 0;
    self->cursor = 0;
}

bool ippool_is_allocated(const ippool_t* self, const ippool_addr_t* addr)
{
    int64_t i = ippool_index_of(self, addr);
    if (i < 0) return false;
    return (self->bits[(uint32_t)i >> 6] &
            ((uint64_t)1 << ((uint32_t)i & 63u))) != 0;
}

uint32_t ippool_size(const ippool_t* self)
{
    return self ? self->size : 0;
}

uint32_t ippool_used(const ippool_t* self)
{
    return self ? self->used : 0;
}

uint32_t ippool_avail(const ippool_t* self)
{
    return self ? self->size - self->used : 0;
}

int ippool_addr_at(const ippool_t* self, uint32_t index, ippool_addr_t* out)
{
    if (!self || !out) {
        MESG_FAIL("ippool: %s", "invalid parameter");
        return IPPOOL_E_INVAL;
    }
    if (index >= self->size) return IPPOOL_E_RANGE;
    return slot_addr(self, index, out);
}

int64_t ippool_index_of(const ippool_t* self, const ippool_addr_t* addr)
{
    uint64_t delta;

    if (!self || !addr || addr->len != self->len) return -1;
    if (!addr_delta(addr->b, self->base, self->len, &delta)) return -1;
    if (delta >= self->size) return -1;
    return (int64_t)delta;
}
