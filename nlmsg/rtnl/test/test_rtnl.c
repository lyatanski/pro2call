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

    context ("route message (RTM_NEWROUTE)") {
        it ("encodes a device route with a per-route MTU") {
            rtnl_route r;
            memset(&r, 0, sizeof r);
            r.dst     = "10.10.0.5";
            r.dstlen  = 32;
            r.ifindex = 3;
            r.mtu     = 1464;

            buf_t m;
            int   len = rtnl_route_msg(m.b, sizeof m.b, 9, &r);
            check(len > 0);

            struct nlmsghdr* nh = &m.h;
            check(nh->nlmsg_type == RTM_NEWROUTE);
            check(nh->nlmsg_seq == 9);
            check((nh->nlmsg_flags & NLM_F_REQUEST) != 0);
            check((nh->nlmsg_flags & NLM_F_CREATE) != 0);
            check((nh->nlmsg_flags & NLM_F_REPLACE) != 0);
            check(nh->nlmsg_len == (uint32_t)len);

            struct rtmsg rt;
            memcpy(&rt, m.b + NLMSG_HDRLEN, sizeof rt);
            check(rt.rtm_family == AF_INET);
            check(rt.rtm_dst_len == 32);
            check(rt.rtm_table == RT_TABLE_MAIN);
            check(rt.rtm_protocol == RTPROT_BOOT);
            check(rt.rtm_type == RTN_UNICAST);
            /* No gateway: the destination is on the link. */
            check(rt.rtm_scope == RT_SCOPE_LINK);

            uint32_t       dlen = 0, olen = 0;
            const uint8_t* dv =
                find_attr(m.b, sizeof(struct rtmsg), RTA_DST, &dlen);
            const uint8_t* ov =
                find_attr(m.b, sizeof(struct rtmsg), RTA_OIF, &olen);
            check(dv != NULL);
            check(dlen == 4);
            struct in_addr want;
            want.s_addr = inet_addr("10.10.0.5");
            check(memcmp(dv, &want, 4) == 0);
            check(ov != NULL);
            check(olen == 4);
            uint32_t oif = 0;
            memcpy(&oif, ov, 4);
            check(oif == 3);

            check(find_attr(m.b, sizeof(struct rtmsg), RTA_GATEWAY, NULL) ==
                  NULL);

            /* RTA_METRICS is a nested attribute run; the MTU sits inside
             * it as RTAX_MTU, not beside it. */
            uint32_t       mlen = 0;
            const uint8_t* mv =
                find_attr(m.b, sizeof(struct rtmsg), RTA_METRICS, &mlen);
            check(mv != NULL);
            tlv_iter_t it;
            tlv_view_t v;
            uint32_t   mtu = 0;
            tlv_iter_init(&it, &netlink, mv, mlen);
            while (tlv_iter_next(&it, &v))
                if (v.type == RTAX_MTU && v.len == 4) memcpy(&mtu, v.value, 4);
            check(mtu == 1464);
        }

        it ("puts a gateway route at scope universe") {
            rtnl_route r;
            memset(&r, 0, sizeof r);
            r.dst      = "10.45.0.0";
            r.dstlen   = 16;
            r.gateway  = "192.168.69.22";
            r.priority = 100;

            buf_t m;
            check(rtnl_route_msg(m.b, sizeof m.b, 1, &r) > 0);

            struct rtmsg rt;
            memcpy(&rt, m.b + NLMSG_HDRLEN, sizeof rt);
            check(rt.rtm_scope == RT_SCOPE_UNIVERSE);
            check(rt.rtm_dst_len == 16);

            uint32_t       glen = 0, plen = 0;
            const uint8_t* gv =
                find_attr(m.b, sizeof(struct rtmsg), RTA_GATEWAY, &glen);
            check(gv != NULL);
            check(glen == 4);
            struct in_addr want;
            want.s_addr = inet_addr("192.168.69.22");
            check(memcmp(gv, &want, 4) == 0);

            const uint8_t* pv =
                find_attr(m.b, sizeof(struct rtmsg), RTA_PRIORITY, &plen);
            check(pv != NULL);
            uint32_t prio = 0;
            memcpy(&prio, pv, 4);
            check(prio == 100);
            /* Nothing asked for an MTU, so no metrics run at all. */
            check(find_attr(m.b, sizeof(struct rtmsg), RTA_METRICS, NULL) ==
                  NULL);
        }

        it ("takes the family from the gateway of a default route") {
            rtnl_route r;
            memset(&r, 0, sizeof r);
            r.gateway = "fd00::1"; /* no dst: the default route */
            r.ifindex = 2;

            buf_t m;
            check(rtnl_route_msg(m.b, sizeof m.b, 1, &r) > 0);

            struct rtmsg rt;
            memcpy(&rt, m.b + NLMSG_HDRLEN, sizeof rt);
            check(rt.rtm_family == AF_INET6);
            check(rt.rtm_dst_len == 0);

            uint32_t glen = 0;
            check(find_attr(m.b, sizeof(struct rtmsg), RTA_GATEWAY, &glen) !=
                  NULL);
            check(glen == 16);
            check(find_attr(m.b, sizeof(struct rtmsg), RTA_DST, NULL) == NULL);
        }

        it ("honours an explicit table, protocol, type and scope") {
            rtnl_route r;
            memset(&r, 0, sizeof r);
            r.dst      = "192.0.2.0";
            r.dstlen   = 24;
            r.ifindex  = 1;
            r.table    = RT_TABLE_LOCAL;
            r.protocol = RTPROT_STATIC;
            r.type     = RTN_BLACKHOLE;
            r.scope    = RT_SCOPE_HOST;

            buf_t m;
            check(rtnl_route_msg(m.b, sizeof m.b, 1, &r) > 0);

            struct rtmsg rt;
            memcpy(&rt, m.b + NLMSG_HDRLEN, sizeof rt);
            check(rt.rtm_table == RT_TABLE_LOCAL);
            check(rt.rtm_protocol == RTPROT_STATIC);
            check(rt.rtm_type == RTN_BLACKHOLE);
            check(rt.rtm_scope == RT_SCOPE_HOST);
        }

        it ("rejects a route with nothing to route, or mismatched families") {
            rtnl_route r;
            buf_t      m;

            memset(&r, 0, sizeof r); /* neither dst nor gateway */
            r.ifindex = 1;
            check(rtnl_route_msg(m.b, sizeof m.b, 1, &r) == RTNL_E_INVAL);

            memset(&r, 0, sizeof r);
            r.dst     = "10.0.0.0";
            r.dstlen  = 8;
            r.gateway = "fd00::1"; /* v6 next hop for a v4 prefix */
            check(rtnl_route_msg(m.b, sizeof m.b, 1, &r) == RTNL_E_INVAL);

            memset(&r, 0, sizeof r);
            r.dst    = "10.0.0.1";
            r.dstlen = 33; /* > 32 for IPv4 */
            check(rtnl_route_msg(m.b, sizeof m.b, 1, &r) == RTNL_E_INVAL);

            memset(&r, 0, sizeof r);
            r.gateway = "10.0.0.1";
            r.dstlen  = 24; /* a prefix length with no prefix */
            check(rtnl_route_msg(m.b, sizeof m.b, 1, &r) == RTNL_E_INVAL);

            memset(&r, 0, sizeof r);
            r.dst    = "10.0.0.0";
            r.dstlen = 24;
            uint8_t small[8];
            check(rtnl_route_msg(small, sizeof small, 1, &r) ==
                  RTNL_E_OVERFLOW);
        }
    }

    context ("route delete (RTM_DELROUTE)") {
        it ("leaves protocol, scope and type as wildcards") {
            rtnl_route r;
            memset(&r, 0, sizeof r);
            r.dst     = "10.10.0.5";
            r.dstlen  = 32;
            r.ifindex = 3;

            buf_t m;
            int   len = rtnl_route_del_msg(m.b, sizeof m.b, 4, &r);
            check(len > 0);
            check(m.h.nlmsg_type == RTM_DELROUTE);
            check((m.h.nlmsg_flags & NLM_F_CREATE) == 0);
            check((m.h.nlmsg_flags & NLM_F_REPLACE) == 0);

            struct rtmsg rt;
            memcpy(&rt, m.b + NLMSG_HDRLEN, sizeof rt);
            check(rt.rtm_protocol == 0);
            check(rt.rtm_type == 0);
            check(rt.rtm_scope == RT_SCOPE_NOWHERE);
            check(rt.rtm_table == RT_TABLE_MAIN);

            uint32_t dlen = 0;
            check(find_attr(m.b, sizeof(struct rtmsg), RTA_DST, &dlen) != NULL);
            check(dlen == 4);
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

        xit ("installs and removes a host route with an MTU",
             privileged ? 1 : 0) {
            rtnl_route r;
            memset(&r, 0, sizeof r);
            r.dst     = "10.255.255.253";
            r.dstlen  = 32;
            r.ifindex = if_nametoindex("lo");
            r.mtu     = 1400;
            check(r.ifindex != 0);

            check(rtnl_route_add(&s, &r) == RTNL_OK);
            /* NLM_F_REPLACE: installing it again, with another MTU, is the
             * `ip route replace` the tunnel-MTU fixup relies on. */
            r.mtu = 1464;
            check(rtnl_route_add(&s, &r) == RTNL_OK);
            check(rtnl_route_del(&s, &r) == RTNL_OK);
            /* Gone: a second delete is ESRCH, not silence. */
            check(rtnl_route_del(&s, &r) == RTNL_E_ACK);
        }

        if (opened == RTNL_OK) rtnl_close(&s);
    }
}
