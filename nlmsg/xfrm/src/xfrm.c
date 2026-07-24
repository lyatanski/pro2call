/* IPsec SA/policy manipulation over NETLINK_XFRM. The message layout is
 * struct nlmsghdr + a fixed payload + netlink attributes; the attribute
 * run is built with the shared TLV codec (task/inc/tlv.h) under its
 * netlink profile, so this module carries no attribute (de)serializer of
 * its own. */

#include "xfrm.h"
#include "tlv.h"

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/xfrm.h>

/* struct rtattr / nlattr layout: len(2) | type(2), host byte order,
 * length counts the 4-byte header, entries padded to 4. */
static const tlv_prof_t xfrm_nla = TLV_PROF_NETLINK;

/* A netlink buffer must be aligned for the widest field it carries
 * (xfrm lifetime counters are __u64), so callers pass this union. */
#define XFRM_BUF_MAX 2048
typedef union {
    struct nlmsghdr h;
    uint64_t        align;
    uint8_t         b[XFRM_BUF_MAX];
} xfrm_buf;

static size_t align4(size_t n)
{
    return (n + 3u) & ~(size_t)3u;
}

/* Parse a literal address into an xfrm_address_t (kept in network byte
 * order, as inet_pton yields) and report its address family. */
static int addr_pton(const char* s, xfrm_address_t* out, uint16_t* fam)
{
    if (!s || !*s) return XFRM_E_INVAL;
    memset(out, 0, sizeof *out);
    if (inet_pton(AF_INET, s, &out->a4) == 1) {
        *fam = AF_INET;
        return XFRM_OK;
    }
    if (inet_pton(AF_INET6, s, out->a6) == 1) {
        *fam = AF_INET6;
        return XFRM_OK;
    }
    return XFRM_E_INVAL;
}

/* Lay down the header and fixed payload, then point an attribute writer
 * at the aligned remainder. Returns the attribute base offset, or a
 * negative XFRM_E_* code. */
static int msg_begin(uint8_t* buf, size_t cap, uint16_t type, uint16_t flags,
                     uint32_t seq, const void* fixed, size_t fixed_len,
                     tlv_wbuf_t* w)
{
    const size_t base = align4(NLMSG_HDRLEN + fixed_len);
    if (base > cap) return XFRM_E_OVERFLOW;

    memset(buf, 0, base);
    struct nlmsghdr* nh = (struct nlmsghdr*)buf;
    nh->nlmsg_type      = type;
    nh->nlmsg_flags     = flags;
    nh->nlmsg_seq       = seq;
    nh->nlmsg_pid       = 0; /* to the kernel */
    if (fixed_len) memcpy(buf + NLMSG_HDRLEN, fixed, fixed_len);

    tlv_wbuf_init(w, buf + base, cap - base);
    return (int)base;
}

/* Backfill nlmsg_len and report the total request size. */
static int msg_end(uint8_t* buf, int base, tlv_wbuf_t* w)
{
    if (base < 0) return base;
    if (w->overflow) return XFRM_E_OVERFLOW;
    struct nlmsghdr* nh = (struct nlmsghdr*)buf;
    nh->nlmsg_len       = (uint32_t)((size_t)base + w->off);
    return (int)nh->nlmsg_len;
}

/* Append an XFRMA_ALG_* attribute (struct xfrm_algo: fixed name +
 * bit-length prefix, then the raw key). */
static void put_algo(tlv_wbuf_t* w, uint16_t attr, const char* name,
                     const uint8_t* key, uint16_t key_len)
{
    uint8_t           tmp[sizeof(struct xfrm_algo) + 512];
    struct xfrm_algo* a = (struct xfrm_algo*)tmp;
    if (key_len > 512) {
        w->overflow = true;
        return;
    }

    memset(a, 0, sizeof *a);
    strncpy(a->alg_name, name, sizeof a->alg_name - 1);
    a->alg_key_len = (unsigned)key_len * 8u;
    if (key_len) memcpy(tmp + sizeof(struct xfrm_algo), key, key_len);
    tlv_put(w, &xfrm_nla, attr, 0, tmp,
            (uint32_t)(sizeof(struct xfrm_algo) + key_len));
}

/* Append XFRMA_ALG_AEAD (struct xfrm_algo_aead: adds an ICV bit-length). */
static void put_aead(tlv_wbuf_t* w, const char* name, const uint8_t* key,
                     uint16_t key_len, uint16_t icv_bits)
{
    uint8_t                tmp[sizeof(struct xfrm_algo_aead) + 512];
    struct xfrm_algo_aead* a = (struct xfrm_algo_aead*)tmp;
    if (key_len > 512) {
        w->overflow = true;
        return;
    }

    memset(a, 0, sizeof *a);
    strncpy(a->alg_name, name, sizeof a->alg_name - 1);
    a->alg_key_len = (unsigned)key_len * 8u;
    a->alg_icv_len = icv_bits;
    if (key_len) memcpy(tmp + sizeof(struct xfrm_algo_aead), key, key_len);
    tlv_put(w, &xfrm_nla, XFRMA_ALG_AEAD, 0, tmp,
            (uint32_t)(sizeof(struct xfrm_algo_aead) + key_len));
}

/* Fill a traffic selector from prefix/port fields (shared by policy add
 * and delete). Returns the address family, or a negative XFRM_E_* code. */
static int fill_selector(struct xfrm_selector* sel, const char* src,
                         uint8_t src_prefix, const char* dst,
                         uint8_t dst_prefix, uint8_t proto, uint16_t sport,
                         uint16_t dport)
{
    uint16_t fs, fd;
    int      rc;
    memset(sel, 0, sizeof *sel);
    if ((rc = addr_pton(src, &sel->saddr, &fs))) return rc;
    if ((rc = addr_pton(dst, &sel->daddr, &fd))) return rc;
    if (fs != fd) return XFRM_E_INVAL;

    sel->family      = fs;
    sel->prefixlen_s = src_prefix;
    sel->prefixlen_d = dst_prefix;
    sel->proto       = proto;
    sel->sport       = htons(sport);
    sel->dport       = htons(dport);
    if (sport) sel->sport_mask = 0xFFFF;
    if (dport) sel->dport_mask = 0xFFFF;
    return (int)fs;
}

/* ---- message builders ---------------------------------------------- */

static int sa_build(uint8_t* buf, size_t cap, uint16_t type, uint16_t flags,
                    uint32_t seq, const xfrm_sa* sa)
{
    if (!sa || !sa->src || !sa->dst) return XFRM_E_INVAL;
    if (!sa->aead_alg && !sa->enc_alg && !sa->auth_alg) return XFRM_E_INVAL;

    struct xfrm_usersa_info info;
    uint16_t                fs, fd;
    int                     rc;
    memset(&info, 0, sizeof info);
    if ((rc = addr_pton(sa->dst, &info.id.daddr, &fd))) return rc;
    if ((rc = addr_pton(sa->src, &info.saddr, &fs))) return rc;
    if (fs != fd) return XFRM_E_INVAL;

    info.family                = fd;
    info.id.spi                = htonl(sa->spi);
    info.id.proto              = sa->proto;
    info.mode                  = sa->mode;
    info.reqid                 = sa->reqid;
    info.replay_window         = sa->replay_window;
    info.flags                 = (uint8_t)sa->flags;
    info.lft.soft_byte_limit   = XFRM_INF;
    info.lft.hard_byte_limit   = XFRM_INF;
    info.lft.soft_packet_limit = XFRM_INF;
    info.lft.hard_packet_limit = XFRM_INF;

    tlv_wbuf_t w;
    int base = msg_begin(buf, cap, type, flags, seq, &info, sizeof info, &w);
    if (base < 0) return base;

    if (sa->aead_alg)
        put_aead(&w, sa->aead_alg, sa->aead_key, sa->aead_key_len,
                 sa->aead_icv_bits);
    if (sa->enc_alg)
        put_algo(&w, XFRMA_ALG_CRYPT, sa->enc_alg, sa->enc_key,
                 sa->enc_key_len);
    if (sa->auth_alg)
        put_algo(&w, XFRMA_ALG_AUTH, sa->auth_alg, sa->auth_key,
                 sa->auth_key_len);

    if (sa->encap_sport || sa->encap_dport) {
        struct xfrm_encap_tmpl enc;
        uint16_t               f;
        memset(&enc, 0, sizeof enc);
        enc.encap_type  = 2; /* UDP_ENCAP_ESPINUDP */
        enc.encap_sport = htons(sa->encap_sport);
        enc.encap_dport = htons(sa->encap_dport);
        if (sa->encap_oaddr) addr_pton(sa->encap_oaddr, &enc.encap_oa, &f);
        tlv_put(&w, &xfrm_nla, XFRMA_ENCAP, 0, &enc, sizeof enc);
    }

    return msg_end(buf, base, &w);
}

int xfrm_sa_msg(uint8_t* buf, size_t cap, uint32_t seq, const xfrm_sa* sa)
{
    return sa_build(buf, cap, XFRM_MSG_NEWSA,
                    NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, seq,
                    sa);
}

int xfrm_sa_del_msg(uint8_t* buf, size_t cap, uint32_t seq,
                    const xfrm_sa_id* id)
{
    if (!id || !id->dst) return XFRM_E_INVAL;

    struct xfrm_usersa_id sid;
    uint16_t              fam;
    int                   rc;
    memset(&sid, 0, sizeof sid);
    if ((rc = addr_pton(id->dst, &sid.daddr, &fam))) return rc;
    sid.family = fam;
    sid.spi    = htonl(id->spi);
    sid.proto  = id->proto;

    tlv_wbuf_t w;
    int base = msg_begin(buf, cap, XFRM_MSG_DELSA, NLM_F_REQUEST | NLM_F_ACK,
                         seq, &sid, sizeof sid, &w);
    return msg_end(buf, base, &w);
}

static int policy_build(uint8_t* buf, size_t cap, uint16_t type, uint16_t flags,
                        uint32_t seq, const xfrm_policy* pol)
{
    if (!pol || !pol->src || !pol->dst) return XFRM_E_INVAL;

    struct xfrm_userpolicy_info info;
    int                         fam;
    memset(&info, 0, sizeof info);
    fam =
        fill_selector(&info.sel, pol->src, pol->src_prefix, pol->dst,
                      pol->dst_prefix, pol->sel_proto, pol->sport, pol->dport);
    if (fam < 0) return fam;

    info.priority              = pol->priority;
    info.index                 = pol->index;
    info.dir                   = pol->dir;
    info.action                = pol->action;
    info.lft.soft_byte_limit   = XFRM_INF;
    info.lft.hard_byte_limit   = XFRM_INF;
    info.lft.soft_packet_limit = XFRM_INF;
    info.lft.hard_packet_limit = XFRM_INF;

    tlv_wbuf_t w;
    int base = msg_begin(buf, cap, type, flags, seq, &info, sizeof info, &w);
    if (base < 0) return base;

    if (pol->has_tmpl) {
        struct xfrm_user_tmpl t;
        uint16_t              tf = (uint16_t)fam;
        memset(&t, 0, sizeof t);
        if (pol->tmpl_dst) {
            int rc = addr_pton(pol->tmpl_dst, &t.id.daddr, &tf);
            if (rc) return rc;
        }
        if (pol->tmpl_src) {
            uint16_t sf;
            int      rc = addr_pton(pol->tmpl_src, &t.saddr, &sf);
            if (rc) return rc;
        }
        t.family   = tf;
        t.id.proto = pol->tmpl_proto;
        t.reqid    = pol->tmpl_reqid;
        t.mode     = pol->tmpl_mode;
        t.aalgos = t.ealgos = t.calgos = ~0u; /* accept any algorithm */
        tlv_put(&w, &xfrm_nla, XFRMA_TMPL, 0, &t, sizeof t);
    }

    return msg_end(buf, base, &w);
}

int xfrm_policy_msg(uint8_t* buf, size_t cap, uint32_t seq,
                    const xfrm_policy* pol)
{
    return policy_build(buf, cap, XFRM_MSG_NEWPOLICY,
                        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
                        seq, pol);
}

int xfrm_policy_del_msg(uint8_t* buf, size_t cap, uint32_t seq,
                        const xfrm_policy_id* id)
{
    if (!id) return XFRM_E_INVAL;

    struct xfrm_userpolicy_id pid;
    memset(&pid, 0, sizeof pid);
    if (id->index) {
        pid.index = id->index;
    } else {
        int fam =
            fill_selector(&pid.sel, id->src, id->src_prefix, id->dst,
                          id->dst_prefix, id->sel_proto, id->sport, id->dport);
        if (fam < 0) return fam;
    }
    pid.dir = id->dir;

    tlv_wbuf_t w;
    int base = msg_begin(buf, cap, XFRM_MSG_DELPOLICY,
                         NLM_F_REQUEST | NLM_F_ACK, seq, &pid, sizeof pid, &w);
    return msg_end(buf, base, &w);
}

int xfrm_flush_sa_msg(uint8_t* buf, size_t cap, uint32_t seq, uint8_t proto)
{
    struct xfrm_usersa_flush f;
    memset(&f, 0, sizeof f);
    f.proto = proto; /* 0 = every protocol */

    tlv_wbuf_t w;
    int base = msg_begin(buf, cap, XFRM_MSG_FLUSHSA, NLM_F_REQUEST | NLM_F_ACK,
                         seq, &f, sizeof f, &w);
    return msg_end(buf, base, &w);
}

int xfrm_flush_policy_msg(uint8_t* buf, size_t cap, uint32_t seq)
{
    tlv_wbuf_t w;
    int        base = msg_begin(buf, cap, XFRM_MSG_FLUSHPOLICY,
                                NLM_F_REQUEST | NLM_F_ACK, seq, NULL, 0, &w);
    return msg_end(buf, base, &w);
}

/* ---- transactions -------------------------------------------------- */

int xfrm_open(xfrm_sock* s)
{
    if (!s) return XFRM_E_INVAL;
    s->fd       = -1;
    s->seq      = 1;
    s->portid   = 0;
    s->nl_errno = 0;

    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_XFRM);
    if (fd < 0) return XFRM_E_SYS;

    struct sockaddr_nl local;
    memset(&local, 0, sizeof local);
    local.nl_family = AF_NETLINK;
    if (bind(fd, (struct sockaddr*)&local, sizeof local) < 0) {
        close(fd);
        return XFRM_E_SYS;
    }

    socklen_t sl = sizeof local;
    if (getsockname(fd, (struct sockaddr*)&local, &sl) == 0)
        s->portid = local.nl_pid;

    s->fd = fd;
    return XFRM_OK;
}

void xfrm_close(xfrm_sock* s)
{
    if (s && s->fd >= 0) {
        close(s->fd);
        s->fd = -1;
    }
}

/* Send one request and consume the kernel's ACK. Every builder sets
 * NLM_F_ACK, so the kernel always answers with an NLMSG_ERROR carrying
 * either 0 (success) or a negative errno. */
static int transact(xfrm_sock* s, const void* req, size_t len)
{
    struct sockaddr_nl kernel;
    memset(&kernel, 0, sizeof kernel);
    kernel.nl_family = AF_NETLINK;

    if (sendto(s->fd, req, len, 0, (struct sockaddr*)&kernel, sizeof kernel) <
        0)
        return XFRM_E_SYS;

    xfrm_buf r;
    for (;;) {
        ssize_t n = recv(s->fd, r.b, sizeof r.b, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return XFRM_E_SYS;
        }

        struct nlmsghdr* nh  = &r.h;
        size_t           rem = (size_t)n;
        for (; NLMSG_OK(nh, rem); nh = NLMSG_NEXT(nh, rem)) {
            if (nh->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr* e = (struct nlmsgerr*)NLMSG_DATA(nh);
                if (e->error == 0) return XFRM_OK;
                s->nl_errno = -e->error;
                return XFRM_E_ACK;
            }
            if (nh->nlmsg_type == NLMSG_DONE) return XFRM_OK;
        }
        /* nothing conclusive in this datagram; wait for more */
    }
}

/* Build with the given message type/flags, send, and advance the
 * sequence counter. */
static int run(xfrm_sock* s,
               int (*build)(uint8_t*, size_t, uint32_t, const void*),
               const void* arg)
{
    if (!s || s->fd < 0) return XFRM_E_INVAL;
    xfrm_buf m;
    int      len = build(m.b, sizeof m.b, s->seq, arg);
    if (len < 0) return len;
    int rc = transact(s, m.b, (size_t)len);
    s->seq++;
    return rc;
}

/* Thin adapters matching run()'s builder signature. */
static int build_sa_add(uint8_t* b, size_t c, uint32_t q, const void* a)
{
    return xfrm_sa_msg(b, c, q, (const xfrm_sa*)a);
}
static int build_sa_upd(uint8_t* b, size_t c, uint32_t q, const void* a)
{
    return sa_build(b, c, XFRM_MSG_UPDSA, NLM_F_REQUEST | NLM_F_ACK, q,
                    (const xfrm_sa*)a);
}
static int build_sa_del(uint8_t* b, size_t c, uint32_t q, const void* a)
{
    return xfrm_sa_del_msg(b, c, q, (const xfrm_sa_id*)a);
}
static int build_pol_add(uint8_t* b, size_t c, uint32_t q, const void* a)
{
    return xfrm_policy_msg(b, c, q, (const xfrm_policy*)a);
}
static int build_pol_upd(uint8_t* b, size_t c, uint32_t q, const void* a)
{
    return policy_build(b, c, XFRM_MSG_UPDPOLICY, NLM_F_REQUEST | NLM_F_ACK, q,
                        (const xfrm_policy*)a);
}
static int build_pol_del(uint8_t* b, size_t c, uint32_t q, const void* a)
{
    return xfrm_policy_del_msg(b, c, q, (const xfrm_policy_id*)a);
}

int xfrm_sa_add(xfrm_sock* s, const xfrm_sa* sa)
{
    return run(s, build_sa_add, sa);
}
int xfrm_sa_update(xfrm_sock* s, const xfrm_sa* sa)
{
    return run(s, build_sa_upd, sa);
}
int xfrm_sa_del(xfrm_sock* s, const xfrm_sa_id* id)
{
    return run(s, build_sa_del, id);
}
int xfrm_policy_add(xfrm_sock* s, const xfrm_policy* p)
{
    return run(s, build_pol_add, p);
}
int xfrm_policy_update(xfrm_sock* s, const xfrm_policy* p)
{
    return run(s, build_pol_upd, p);
}
int xfrm_policy_del(xfrm_sock* s, const xfrm_policy_id* id)
{
    return run(s, build_pol_del, id);
}

int xfrm_flush_sa(xfrm_sock* s, uint8_t proto)
{
    if (!s || s->fd < 0) return XFRM_E_INVAL;
    xfrm_buf m;
    int      len = xfrm_flush_sa_msg(m.b, sizeof m.b, s->seq, proto);
    if (len < 0) return len;
    int rc = transact(s, m.b, (size_t)len);
    s->seq++;
    return rc;
}

int xfrm_flush_policy(xfrm_sock* s)
{
    if (!s || s->fd < 0) return XFRM_E_INVAL;
    xfrm_buf m;
    int      len = xfrm_flush_policy_msg(m.b, sizeof m.b, s->seq);
    if (len < 0) return len;
    int rc = transact(s, m.b, (size_t)len);
    s->seq++;
    return rc;
}
