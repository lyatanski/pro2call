#include "xfrm.h"
#include "tlv.h"
#include "test.h"

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <linux/netlink.h>
#include <linux/xfrm.h>

/* Aligned scratch buffer: xfrm payloads carry __u64 lifetime counters. */
typedef union {
    struct nlmsghdr h;
    uint64_t        align;
    uint8_t         b[2048];
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

spec ("xfrm") {
    context ("SA message (XFRM_MSG_NEWSA)") {
        it ("encodes the header and usersa_info fixed payload") {
            static const uint8_t ekey[16] = { 0x11, 0x22, 0x33, 0x44 };
            static const uint8_t akey[20] = { 0xAA, 0xBB };
            xfrm_sa              sa;
            memset(&sa, 0, sizeof sa);
            sa.src          = "10.0.0.1";
            sa.dst          = "10.0.0.2";
            sa.spi          = 0x12345678;
            sa.proto        = XFRM_PROTO_ESP;
            sa.mode         = XFRM_M_TUNNEL;
            sa.reqid        = 42;
            sa.enc_alg      = "cbc(aes)";
            sa.enc_key      = ekey;
            sa.enc_key_len  = sizeof ekey;
            sa.auth_alg     = "hmac(sha1)";
            sa.auth_key     = akey;
            sa.auth_key_len = sizeof akey;

            buf_t m;
            int   len = xfrm_sa_msg(m.b, sizeof m.b, 7, &sa);
            check(len > 0);

            struct nlmsghdr* nh = &m.h;
            check(nh->nlmsg_type == XFRM_MSG_NEWSA);
            check(nh->nlmsg_seq == 7);
            check((nh->nlmsg_flags & NLM_F_REQUEST) != 0);
            check((nh->nlmsg_flags & NLM_F_CREATE) != 0);
            check((nh->nlmsg_flags & NLM_F_EXCL) != 0);
            check(nh->nlmsg_len == (uint32_t)len);

            struct xfrm_usersa_info info;
            memcpy(&info, m.b + NLMSG_HDRLEN, sizeof info);
            check(info.family == AF_INET);
            check(info.id.proto == XFRM_PROTO_ESP);
            check(info.mode == XFRM_M_TUNNEL);
            check(info.reqid == 42);
            check(info.id.spi == htonl(0x12345678));

            struct in_addr d;
            memcpy(&d, &info.id.daddr.a4, 4);
            check(d.s_addr == inet_addr("10.0.0.2"));
        }

        it ("carries the cipher and auth keys as XFRMA_ALG_* attributes") {
            static const uint8_t ekey[16] = { 1, 2, 3, 4, 5, 6, 7, 8 };
            static const uint8_t akey[20] = { 9, 8, 7 };
            xfrm_sa              sa;
            memset(&sa, 0, sizeof sa);
            sa.src          = "10.0.0.1";
            sa.dst          = "10.0.0.2";
            sa.spi          = 1;
            sa.proto        = XFRM_PROTO_ESP;
            sa.enc_alg      = "cbc(aes)";
            sa.enc_key      = ekey;
            sa.enc_key_len  = sizeof ekey;
            sa.auth_alg     = "hmac(sha256)";
            sa.auth_key     = akey;
            sa.auth_key_len = sizeof akey;

            buf_t m;
            check(xfrm_sa_msg(m.b, sizeof m.b, 1, &sa) > 0);

            uint32_t       elen = 0, alen = 0;
            const uint8_t* ev = find_attr(m.b, sizeof(struct xfrm_usersa_info),
                                          XFRMA_ALG_CRYPT, &elen);
            const uint8_t* av = find_attr(m.b, sizeof(struct xfrm_usersa_info),
                                          XFRMA_ALG_AUTH, &alen);
            check(ev != NULL);
            check(av != NULL);

            struct xfrm_algo alg;
            memcpy(&alg, ev, sizeof alg);
            check(strcmp(alg.alg_name, "cbc(aes)") == 0);
            check(alg.alg_key_len == sizeof(ekey) * 8);
            check(elen == sizeof(struct xfrm_algo) + sizeof ekey);
            check(memcmp(ev + sizeof(struct xfrm_algo), ekey, sizeof ekey) ==
                  0);

            memcpy(&alg, av, sizeof alg);
            check(strcmp(alg.alg_name, "hmac(sha256)") == 0);
            check(alg.alg_key_len == sizeof(akey) * 8);
        }

        it ("emits XFRMA_ALG_AEAD with the ICV length for an AEAD SA") {
            static const uint8_t key[20] = { 0 }; /* 16-byte key + 4 salt */
            xfrm_sa              sa;
            memset(&sa, 0, sizeof sa);
            sa.src           = "fd00::1";
            sa.dst           = "fd00::2";
            sa.spi           = 0xABCD;
            sa.proto         = XFRM_PROTO_ESP;
            sa.mode          = XFRM_M_TUNNEL;
            sa.aead_alg      = "rfc4106(gcm(aes))";
            sa.aead_key      = key;
            sa.aead_key_len  = sizeof key;
            sa.aead_icv_bits = 128;

            buf_t m;
            check(xfrm_sa_msg(m.b, sizeof m.b, 3, &sa) > 0);

            struct xfrm_usersa_info info;
            memcpy(&info, m.b + NLMSG_HDRLEN, sizeof info);
            check(info.family == AF_INET6);

            uint32_t       vlen = 0;
            const uint8_t* v = find_attr(m.b, sizeof(struct xfrm_usersa_info),
                                         XFRMA_ALG_AEAD, &vlen);
            check(v != NULL);
            struct xfrm_algo_aead aead;
            memcpy(&aead, v, sizeof aead);
            check(strcmp(aead.alg_name, "rfc4106(gcm(aes))") == 0);
            check(aead.alg_key_len == sizeof(key) * 8);
            check(aead.alg_icv_len == 128);
        }

        it ("rejects an SA with no algorithm") {
            xfrm_sa sa;
            memset(&sa, 0, sizeof sa);
            sa.src = "10.0.0.1";
            sa.dst = "10.0.0.2";
            buf_t m;
            check(xfrm_sa_msg(m.b, sizeof m.b, 1, &sa) == XFRM_E_INVAL);
        }

        it ("rejects a buffer too small to hold the request") {
            static const uint8_t ekey[16] = { 0 };
            xfrm_sa              sa;
            memset(&sa, 0, sizeof sa);
            sa.src         = "10.0.0.1";
            sa.dst         = "10.0.0.2";
            sa.enc_alg     = "cbc(aes)";
            sa.enc_key     = ekey;
            sa.enc_key_len = sizeof ekey;
            uint8_t small[8];
            check(xfrm_sa_msg(small, sizeof small, 1, &sa) == XFRM_E_OVERFLOW);
        }
    }

    context ("SA delete (XFRM_MSG_DELSA)") {
        it ("encodes the usersa_id key") {
            xfrm_sa_id id;
            memset(&id, 0, sizeof id);
            id.dst   = "192.0.2.9";
            id.spi   = 0xDEAD;
            id.proto = XFRM_PROTO_ESP;

            buf_t m;
            int   len = xfrm_sa_del_msg(m.b, sizeof m.b, 5, &id);
            check(len > 0);
            check(m.h.nlmsg_type == XFRM_MSG_DELSA);

            struct xfrm_usersa_id sid;
            memcpy(&sid, m.b + NLMSG_HDRLEN, sizeof sid);
            check(sid.family == AF_INET);
            check(sid.proto == XFRM_PROTO_ESP);
            check(sid.spi == htonl(0xDEAD));
        }
    }

    context ("policy message (XFRM_MSG_NEWPOLICY)") {
        it ("encodes the selector and a transform template") {
            xfrm_policy p;
            memset(&p, 0, sizeof p);
            p.src        = "10.1.0.0";
            p.src_prefix = 24;
            p.dst        = "10.2.0.0";
            p.dst_prefix = 24;
            p.dir        = XFRM_DIR_OUT;
            p.action     = XFRM_ACT_ALLOW;
            p.priority   = 100;
            p.has_tmpl   = true;
            p.tmpl_src   = "10.0.0.1";
            p.tmpl_dst   = "10.0.0.2";
            p.tmpl_reqid = 42;
            p.tmpl_proto = XFRM_PROTO_ESP;
            p.tmpl_mode  = XFRM_M_TUNNEL;

            buf_t m;
            int   len = xfrm_policy_msg(m.b, sizeof m.b, 9, &p);
            check(len > 0);
            check(m.h.nlmsg_type == XFRM_MSG_NEWPOLICY);

            struct xfrm_userpolicy_info info;
            memcpy(&info, m.b + NLMSG_HDRLEN, sizeof info);
            check(info.dir == XFRM_DIR_OUT);
            check(info.priority == 100);
            check(info.sel.family == AF_INET);
            check(info.sel.prefixlen_s == 24);
            check(info.sel.prefixlen_d == 24);

            uint32_t       tlen = 0;
            const uint8_t* tv   = find_attr(
                m.b, sizeof(struct xfrm_userpolicy_info), XFRMA_TMPL, &tlen);
            check(tv != NULL);
            check(tlen == sizeof(struct xfrm_user_tmpl));
            struct xfrm_user_tmpl t;
            memcpy(&t, tv, sizeof t);
            check(t.reqid == 42);
            check(t.mode == XFRM_M_TUNNEL);
            check(t.id.proto == XFRM_PROTO_ESP);
            check(t.family == AF_INET);
        }
    }

    context ("policy delete (XFRM_MSG_DELPOLICY)") {
        it ("matches by index when one is given") {
            xfrm_policy_id id;
            memset(&id, 0, sizeof id);
            id.index = 0x1000;
            id.dir   = XFRM_DIR_IN;

            buf_t m;
            check(xfrm_policy_del_msg(m.b, sizeof m.b, 2, &id) > 0);
            struct xfrm_userpolicy_id pid;
            memcpy(&pid, m.b + NLMSG_HDRLEN, sizeof pid);
            check(pid.index == 0x1000);
            check(pid.dir == XFRM_DIR_IN);
        }
    }

    context ("flush messages") {
        it ("builds FLUSHSA and FLUSHPOLICY requests") {
            buf_t m;
            check(xfrm_flush_sa_msg(m.b, sizeof m.b, 1, XFRM_PROTO_ESP) > 0);
            check(m.h.nlmsg_type == XFRM_MSG_FLUSHSA);
            struct xfrm_usersa_flush f;
            memcpy(&f, m.b + NLMSG_HDRLEN, sizeof f);
            check(f.proto == XFRM_PROTO_ESP);

            check(xfrm_flush_policy_msg(m.b, sizeof m.b, 2) > 0);
            check(m.h.nlmsg_type == XFRM_MSG_FLUSHPOLICY);
        }
    }

    context ("live kernel transaction") {
        /* Opening the socket needs no privilege, but manipulating SAs
         * needs CAP_NET_ADMIN — gate on root and skip cleanly otherwise
         * (an unprivileged add is rejected with EPERM). */
        xfrm_sock s;
        int       opened     = xfrm_open(&s);
        int       privileged = (opened == XFRM_OK) && (geteuid() == 0);

        xit ("adds and deletes a transport SA", privileged ? 1 : 0) {
            static const uint8_t akey[20] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
            xfrm_sa              sa;
            memset(&sa, 0, sizeof sa);
            sa.src          = "203.0.113.1";
            sa.dst          = "203.0.113.2";
            sa.spi          = 0x0BADF00D;
            sa.proto        = XFRM_PROTO_ESP;
            sa.mode         = XFRM_M_TRANSPORT;
            sa.auth_alg     = "hmac(sha1)";
            sa.auth_key     = akey;
            sa.auth_key_len = sizeof akey;
            sa.enc_alg      = "cbc(aes)";
            sa.enc_key      = akey;
            sa.enc_key_len  = 16;

            check(xfrm_sa_add(&s, &sa) == XFRM_OK);

            xfrm_sa_id id;
            memset(&id, 0, sizeof id);
            id.dst   = sa.dst;
            id.spi   = sa.spi;
            id.proto = sa.proto;
            check(xfrm_sa_del(&s, &id) == XFRM_OK);
        }

        if (opened == XFRM_OK) xfrm_close(&s);
    }
}
