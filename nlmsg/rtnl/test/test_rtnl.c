#include "rtnl.h"
#include "tlv.h"
#include "test.h"

#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

#include <net/if.h>
#include <linux/if_addr.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

/* Aligned scratch buffer for a built request. */
typedef union {
    struct nlmsghdr h;
    uint64_t        align;
    uint8_t         b[1024];
} buf_t;

static const tlv_prof_t netlink = TLV_PROF_NETLINK;

/* Locate a netlink attribute in a built message by type. fixed_len is
 * the message's fixed payload size; the attribute run follows it. */
static const uint8_t* find_attr(const uint8_t* buf, size_t fixed_len,
                                uint16_t want, uint32_t* out_len)
{
    const struct nlmsghdr* nh   = (const struct nlmsghdr*)buf;
    size_t                 base = (NLMSG_HDRLEN + fixed_len + 3u) & ~(size_t)3u;
    size_t                 attrs = nh->nlmsg_len - base;

    tlv_iter_t it;
    tlv_view_t v;
    tlv_iter_init(&it, &netlink, buf + base, attrs);
    while (tlv_iter_next(&it, &v)) {
        if (v.type == want) {
            if (out_len) *out_len = v.len;
            return v.value;
        }
    }
    return NULL;
}

spec ("rtnl") {
    context ("address message (RTM_NEWADDR)") {
        it ("encodes the header and ifaddrmsg fixed payload") {
            rtnl_addr a;
            memset(&a, 0, sizeof a);
            a.addr      = "10.10.0.5";
            a.prefixlen = 32;
            a.ifindex   = 1;

            buf_t m;
            int   len = rtnl_addr_msg(m.b, sizeof m.b, 7, &a);
            check(len > 0);

            struct nlmsghdr* nh = &m.h;
            check(nh->nlmsg_type == RTM_NEWADDR);
            check(nh->nlmsg_seq == 7);
            check((nh->nlmsg_flags & NLM_F_REQUEST) != 0);
            check((nh->nlmsg_flags & NLM_F_CREATE) != 0);
            check((nh->nlmsg_flags & NLM_F_REPLACE) != 0);
            check(nh->nlmsg_len == (uint32_t)len);

            struct ifaddrmsg ifa;
            memcpy(&ifa, m.b + NLMSG_HDRLEN, sizeof ifa);
            check(ifa.ifa_family == AF_INET);
            check(ifa.ifa_prefixlen == 32);
            check(ifa.ifa_index == 1);
        }

        it ("carries the address as IFA_LOCAL and IFA_ADDRESS") {
            rtnl_addr a;
            memset(&a, 0, sizeof a);
            a.addr      = "10.10.0.5";
            a.prefixlen = 32;
            a.ifindex   = 2;

            buf_t m;
            check(rtnl_addr_msg(m.b, sizeof m.b, 1, &a) > 0);

            uint32_t       llen = 0, alen = 0;
            const uint8_t* lv =
                find_attr(m.b, sizeof(struct ifaddrmsg), IFA_LOCAL, &llen);
            const uint8_t* av =
                find_attr(m.b, sizeof(struct ifaddrmsg), IFA_ADDRESS, &alen);
            check(lv != NULL);
            check(av != NULL);
            check(llen == 4);
            check(alen == 4);

            struct in_addr want;
            want.s_addr = inet_addr("10.10.0.5");
            check(memcmp(lv, &want, 4) == 0);
            check(memcmp(av, &want, 4) == 0);
        }

        it ("uses only IFA_ADDRESS for an IPv6 address") {
            rtnl_addr a;
            memset(&a, 0, sizeof a);
            a.addr      = "fd00::5";
            a.prefixlen = 128;
            a.ifindex   = 1;

            buf_t m;
            check(rtnl_addr_msg(m.b, sizeof m.b, 1, &a) > 0);

            struct ifaddrmsg ifa;
            memcpy(&ifa, m.b + NLMSG_HDRLEN, sizeof ifa);
            check(ifa.ifa_family == AF_INET6);

            uint32_t alen = 0;
            check(find_attr(m.b, sizeof(struct ifaddrmsg), IFA_ADDRESS,
                            &alen) != NULL);
            check(alen == 16);
            check(find_attr(m.b, sizeof(struct ifaddrmsg), IFA_LOCAL, NULL) ==
                  NULL);
        }

        it ("rejects a missing address or a zero ifindex") {
            rtnl_addr a;
            buf_t     m;

            memset(&a, 0, sizeof a);
            a.ifindex = 1;
            check(rtnl_addr_msg(m.b, sizeof m.b, 1, &a) == RTNL_E_INVAL);

            memset(&a, 0, sizeof a);
            a.addr = "10.0.0.1"; /* ifindex left 0 */
            check(rtnl_addr_msg(m.b, sizeof m.b, 1, &a) == RTNL_E_INVAL);
        }

        it ("rejects a prefix longer than the address family allows") {
            rtnl_addr a;
            memset(&a, 0, sizeof a);
            a.addr      = "10.0.0.1";
            a.prefixlen = 33; /* > 32 for IPv4 */
            a.ifindex   = 1;
            buf_t m;
            check(rtnl_addr_msg(m.b, sizeof m.b, 1, &a) == RTNL_E_INVAL);
        }

        it ("rejects a buffer too small to hold the request") {
            rtnl_addr a;
            memset(&a, 0, sizeof a);
            a.addr      = "10.0.0.1";
            a.prefixlen = 32;
            a.ifindex   = 1;
            uint8_t small[8];
            check(rtnl_addr_msg(small, sizeof small, 1, &a) == RTNL_E_OVERFLOW);
        }
    }

    context ("address delete (RTM_DELADDR)") {
        it ("builds a delete request keyed on the same address") {
            rtnl_addr a;
            memset(&a, 0, sizeof a);
            a.addr      = "192.0.2.9";
            a.prefixlen = 32;
            a.ifindex   = 1;

            buf_t m;
            int   len = rtnl_addr_del_msg(m.b, sizeof m.b, 5, &a);
            check(len > 0);
            check(m.h.nlmsg_type == RTM_DELADDR);
            check((m.h.nlmsg_flags & NLM_F_CREATE) == 0);

            uint32_t llen = 0;
            check(find_attr(m.b, sizeof(struct ifaddrmsg), IFA_LOCAL, &llen) !=
                  NULL);
            check(llen == 4);
        }
    }

    context ("live kernel transaction") {
        /* Opening the socket needs no privilege, but adding an address
         * needs CAP_NET_ADMIN — gate on root and skip cleanly otherwise
         * (an unprivileged add is rejected with EPERM). Uses a private
         * host address on loopback, then removes it. */
        rtnl_sock s;
        int       opened     = rtnl_open(&s);
        int       privileged = (opened == RTNL_OK) && (geteuid() == 0);

        xit ("adds and deletes a loopback host address", privileged ? 1 : 0) {
            rtnl_addr a;
            memset(&a, 0, sizeof a);
            a.addr      = "10.255.255.254";
            a.prefixlen = 32;
            a.ifindex   = if_nametoindex("lo");
            check(a.ifindex != 0);

            check(rtnl_addr_add(&s, &a) == RTNL_OK);
            /* Idempotent: a second add of the same address still succeeds. */
            check(rtnl_addr_add(&s, &a) == RTNL_OK);
            check(rtnl_addr_del(&s, &a) == RTNL_OK);
        }

        if (opened == RTNL_OK) rtnl_close(&s);
    }
}
