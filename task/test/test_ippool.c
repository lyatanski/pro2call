#include "ippool.h"
#include "test.h"
#include <string.h>

/* 10.45.0.0/16 style scope used by most of the cases below. */
static ippool_t* scope16(void)
{
    ippool_addr_t p = ippool_addr4(0x0A2D0000u); /* 10.45.0.0 */
    return ippool_create(&p, 16);
}

static bool is4(const ippool_addr_t* a, uint32_t host_order)
{
    return a->len == IPPOOL_V4 && ippool_addr4_u32(a) == host_order;
}

spec ("ippool") {
    context ("scope layout") {
        it ("excludes the network and broadcast address of an IPv4 scope") {
            ippool_t*     p = scope16();
            ippool_addr_t a;
            check(p != NULL);
            check(ippool_size(p) == 65534);
            check(ippool_used(p) == 0);
            check(ippool_avail(p) == 65534);

            check(ippool_alloc(p, &a) == IPPOOL_OK);
            check(is4(&a, 0x0A2D0001u)); /* 10.45.0.1 */

            check(ippool_addr_at(p, 65533, &a) == IPPOOL_OK);
            check(is4(&a, 0x0A2DFFFEu)); /* 10.45.255.254 */
            check(ippool_addr_at(p, 65534, &a) == IPPOOL_E_RANGE);
            ippool_destroy(p);
        }

        it ("names the scope from any address inside the prefix") {
            ippool_addr_t inside = ippool_addr4(0x0A2D0709u); /* 10.45.7.9 */
            ippool_t*     p      = ippool_create(&inside, 16);
            ippool_addr_t a;
            check(p != NULL);
            check(ippool_size(p) == 65534);
            check(ippool_alloc(p, &a) == IPPOOL_OK);
            check(is4(&a, 0x0A2D0001u));
            ippool_destroy(p);
        }

        it ("uses every address of a /31 and a /32") {
            ippool_addr_t n   = ippool_addr4(0x0A2D0004u); /* 10.45.0.4 */
            ippool_t*     p31 = ippool_create(&n, 31);
            ippool_t*     p32 = ippool_create(&n, 32);
            ippool_addr_t a;
            check(p31 && p32);
            check(ippool_size(p31) == 2);
            check(ippool_size(p32) == 1);
            check(ippool_alloc(p32, &a) == IPPOOL_OK);
            check(is4(&a, 0x0A2D0004u));
            check(ippool_alloc(p32, &a) == IPPOOL_E_FULL);
            ippool_destroy(p31);
            ippool_destroy(p32);
        }

        it ("takes an explicit first..last range, both ends usable") {
            ippool_addr_t f = ippool_addr4(0x0A2D0064u); /* 10.45.0.100 */
            ippool_addr_t l = ippool_addr4(0x0A2D0066u); /* 10.45.0.102 */
            ippool_t*     p = ippool_create_range(&f, &l);
            ippool_addr_t a;
            check(p != NULL);
            check(ippool_size(p) == 3);
            check(ippool_alloc(p, &a) == IPPOOL_OK && is4(&a, 0x0A2D0064u));
            check(ippool_alloc(p, &a) == IPPOOL_OK && is4(&a, 0x0A2D0065u));
            check(ippool_alloc(p, &a) == IPPOOL_OK && is4(&a, 0x0A2D0066u));
            check(ippool_alloc(p, &a) == IPPOOL_E_FULL);
            ippool_destroy(p);
        }

        it ("rejects a reversed range and an oversized prefix length") {
            ippool_addr_t f = ippool_addr4(0x0A2D0064u);
            ippool_addr_t l = ippool_addr4(0x0A2D0001u);
            ippool_addr_t n = ippool_addr4(0x0A2D0000u);
            check(ippool_create_range(&f, &l) == NULL);
            check(ippool_create(&n, 33) == NULL);
            check(ippool_create(NULL, 16) == NULL);
        }

        it ("clamps a prefix larger than the pool ceiling") {
            ippool_addr_t n = ippool_addr4(0x0A000000u); /* 10.0.0.0/7 */
            ippool_t*     p = ippool_create(&n, 7);
            check(p != NULL);
            check(ippool_size(p) == IPPOOL_MAX_SIZE);
            ippool_destroy(p);
        }
    }

    context ("allocation") {
        it ("hands out consecutive addresses") {
            ippool_t*     p = scope16();
            ippool_addr_t a;
            for (int i = 1; i <= 500; i++) {
                check(ippool_alloc(p, &a) == IPPOOL_OK);
                check(is4(&a, 0x0A2D0000u + (uint32_t)i));
            }
            check(ippool_used(p) == 500);
            check(ippool_avail(p) == 65534 - 500);
            ippool_destroy(p);
        }

        it ("reports an address as allocated and maps it to its slot") {
            ippool_t*     p = scope16();
            ippool_addr_t a, other = ippool_addr4(0x0A2D0002u);
            check(ippool_alloc(p, &a) == IPPOOL_OK);
            check(ippool_is_allocated(p, &a));
            check(!ippool_is_allocated(p, &other));
            check(ippool_index_of(p, &a) == 0);
            check(ippool_index_of(p, &other) == 1);
            ippool_destroy(p);
        }

        it ("exhausts and refuses further allocation") {
            ippool_addr_t f = ippool_addr4(0x0A2D0001u);
            ippool_addr_t l = ippool_addr4(0x0A2D0080u); /* 128 addresses */
            ippool_t*     p = ippool_create_range(&f, &l);
            ippool_addr_t a;
            check(p != NULL);
            for (int i = 0; i < 128; i++)
                check(ippool_alloc(p, &a) == IPPOOL_OK);
            check(ippool_used(p) == 128);
            check(ippool_avail(p) == 0);
            check(ippool_alloc(p, &a) == IPPOOL_E_FULL);
            ippool_destroy(p);
        }

        it ("never yields a slot past the end of a partial last word") {
            ippool_addr_t f = ippool_addr4(0x0A2D0001u);
            ippool_addr_t l = ippool_addr4(0x0A2D0003u); /* 3 of 64 bits */
            ippool_t*     p = ippool_create_range(&f, &l);
            ippool_addr_t a;
            check(p != NULL);
            for (int i = 0; i < 3; i++) {
                check(ippool_alloc(p, &a) == IPPOOL_OK);
                check(ippool_index_of(p, &a) == i);
            }
            check(ippool_alloc(p, &a) == IPPOOL_E_FULL);
            ippool_destroy(p);
        }
    }

    context ("release and reuse") {
        it ("hands released addresses back in the order they were released") {
            ippool_addr_t f = ippool_addr4(0x0A2D0001u);
            ippool_addr_t l = ippool_addr4(0x0A2D0004u); /* 4 addresses */
            ippool_t*     p = ippool_create_range(&f, &l);
            ippool_addr_t a[4], b;
            check(p != NULL);
            for (int i = 0; i < 4; i++)
                check(ippool_alloc(p, &a[i]) == IPPOOL_OK);

            /* Release the first two; the next allocation takes the one
             * released first, not the most recent. */
            check(ippool_free(p, &a[0]) == IPPOOL_OK);
            check(ippool_free(p, &a[1]) == IPPOOL_OK);
            check(ippool_used(p) == 2);
            check(ippool_alloc(p, &b) == IPPOOL_OK);
            check(ippool_addr_eq(&b, &a[0]));
            check(ippool_alloc(p, &b) == IPPOOL_OK);
            check(ippool_addr_eq(&b, &a[1]));
            check(ippool_alloc(p, &b) == IPPOOL_E_FULL);
            ippool_destroy(p);
        }

        it ("keeps a released address out until the cursor comes round") {
            ippool_t*     p = scope16();
            ippool_addr_t first, a;
            check(ippool_alloc(p, &first) == IPPOOL_OK);
            check(ippool_free(p, &first) == IPPOOL_OK);
            /* The cursor sits past the released slot, so the next
             * allocations walk on rather than handing it straight back. */
            for (int i = 0; i < 8; i++) {
                check(ippool_alloc(p, &a) == IPPOOL_OK);
                check(!ippool_addr_eq(&a, &first));
            }
            ippool_destroy(p);
        }

        it ("rejects a double release and a foreign address") {
            ippool_t*     p = scope16();
            ippool_addr_t a, alien = ippool_addr4(0x0A2E0001u); /* 10.46.0.1 */
            ippool_addr_t v6bytes;
            memset(&v6bytes, 0, sizeof v6bytes);
            v6bytes.len = IPPOOL_V6;

            check(ippool_alloc(p, &a) == IPPOOL_OK);
            check(ippool_free(p, &a) == IPPOOL_OK);
            check(ippool_free(p, &a) == IPPOOL_E_FREE);
            check(ippool_free(p, &alien) == IPPOOL_E_RANGE);
            check(ippool_free(p, &v6bytes) == IPPOOL_E_RANGE);
            check(ippool_free(NULL, &a) == IPPOOL_E_INVAL);
            ippool_destroy(p);
        }

        it ("releases everything on reset") {
            ippool_t*     p = scope16();
            ippool_addr_t a;
            for (int i = 0; i < 100; i++)
                check(ippool_alloc(p, &a) == IPPOOL_OK);
            ippool_reset(p);
            check(ippool_used(p) == 0);
            check(ippool_avail(p) == 65534);
            check(ippool_alloc(p, &a) == IPPOOL_OK);
            check(is4(&a, 0x0A2D0001u)); /* numbering starts over */
            ippool_destroy(p);
        }
    }

    context ("reservation") {
        it ("reserves a specific address and keeps it out of allocation") {
            ippool_t*     p        = scope16();
            ippool_addr_t gateway  = ippool_addr4(0x0A2D0001u);
            ippool_addr_t reserved = ippool_addr4(0x0A2D0003u);
            ippool_addr_t a;
            check(ippool_reserve(p, &gateway) == IPPOOL_OK);
            check(ippool_reserve(p, &reserved) == IPPOOL_OK);
            check(ippool_used(p) == 2);

            check(ippool_alloc(p, &a) == IPPOOL_OK);
            check(is4(&a, 0x0A2D0002u)); /* skipped both */
            check(ippool_alloc(p, &a) == IPPOOL_OK);
            check(is4(&a, 0x0A2D0004u));
            ippool_destroy(p);
        }

        it ("refuses to reserve twice or outside the pool") {
            ippool_t*     p     = scope16();
            ippool_addr_t addr  = ippool_addr4(0x0A2D0005u);
            ippool_addr_t alien = ippool_addr4(0x0A2E0005u);
            check(ippool_reserve(p, &addr) == IPPOOL_OK);
            check(ippool_reserve(p, &addr) == IPPOOL_E_INUSE);
            check(ippool_reserve(p, &alien) == IPPOOL_E_RANGE);
            check(ippool_free(p, &addr) == IPPOOL_OK);
            check(ippool_reserve(p, &addr) == IPPOOL_OK);
            ippool_destroy(p);
        }
    }

    context ("IPv6") {
        it ("allocates from a prefix, network address included") {
            uint8_t       net[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1,
                                      0,    0,    0,    0,    0, 0, 0, 0 };
            ippool_addr_t prefix  = ippool_addr6(net);
            ippool_t*     p       = ippool_create(&prefix, 64);
            ippool_addr_t a;
            check(p != NULL);
            /* A /64 is far past the ceiling, so the pool is the clamped
             * head of the prefix. */
            check(ippool_size(p) == IPPOOL_MAX_SIZE);
            check(ippool_alloc(p, &a) == IPPOOL_OK);
            check(a.len == IPPOOL_V6);
            check(memcmp(a.b, net, 16) == 0); /* ::0 of the prefix */
            check(ippool_alloc(p, &a) == IPPOOL_OK);
            check(a.b[15] == 1);
            check(ippool_index_of(p, &a) == 1);
            ippool_destroy(p);
        }

        it ("carries into the higher bytes of an address") {
            uint8_t net[16]     = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0,    2,
                                    0,    0,    0,    0,    0, 0, 0xff, 0xfe };
            ippool_addr_t first = ippool_addr6(net);
            uint8_t       last[16];
            memcpy(last, net, 16);
            last[13]        = 0x01;
            last[14]        = 0x00;
            last[15]        = 0x02;
            ippool_addr_t l = ippool_addr6(last);
            ippool_t*     p = ippool_create_range(&first, &l);
            ippool_addr_t a;
            check(p != NULL);
            check(ippool_size(p) == 5); /* fffe, ffff, 1:0000, 1:0001, 1:0002 */
            for (int i = 0; i < 3; i++)
                check(ippool_alloc(p, &a) == IPPOOL_OK);
            check(a.b[13] == 0x01 && a.b[14] == 0x00 && a.b[15] == 0x00);
            ippool_destroy(p);
        }

        it ("keeps the families apart") {
            uint8_t       net[16] = { 0x20, 0x01, 0x0d, 0xb8 };
            ippool_addr_t prefix  = ippool_addr6(net);
            ippool_t*     p       = ippool_create(&prefix, 120);
            ippool_addr_t v4      = ippool_addr4(0x0A2D0001u);
            check(p != NULL);
            check(ippool_size(p) == 256);
            check(ippool_index_of(p, &v4) == -1);
            check(ippool_reserve(p, &v4) == IPPOOL_E_RANGE);
            ippool_destroy(p);
        }
    }

    context ("churn") {
        it ("survives repeated allocate/release cycles over a full pool") {
            ippool_addr_t f = ippool_addr4(0x0A2D0001u);
            ippool_addr_t l = ippool_addr4(0x0A2D0100u); /* 256 addresses */
            ippool_t*     p = ippool_create_range(&f, &l);
            ippool_addr_t held[256];
            check(p != NULL);

            for (int round = 0; round < 20; round++) {
                for (int i = 0; i < 256; i++)
                    check(ippool_alloc(p, &held[i]) == IPPOOL_OK);
                check(ippool_avail(p) == 0);
                for (int i = 0; i < 256; i++)
                    check(ippool_free(p, &held[i]) == IPPOOL_OK);
                check(ippool_used(p) == 0);
            }
            /* Every address is back and each is still distinct. */
            for (int i = 0; i < 256; i++) {
                check(ippool_alloc(p, &held[i]) == IPPOOL_OK);
                check(ippool_index_of(p, &held[i]) >= 0);
            }
            check(ippool_alloc(p, &held[0]) == IPPOOL_E_FULL);
            ippool_destroy(p);
        }
    }
}
