/* Interface address management over NETLINK_ROUTE. The message layout is
 * struct nlmsghdr + a struct ifaddrmsg + netlink attributes; the
 * attribute run is built with the shared TLV codec (task/inc/tlv.h) under
 * its netlink profile, exactly as the sibling xfrm module does, so this
 * module carries no attribute serializer of its own. */

#include "rtnl.h"
#include "tlv.h"

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <linux/if_addr.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

/* struct rtattr / nlattr layout: len(2) | type(2), host byte order,
 * length counts the 4-byte header, entries padded to 4. */
static const tlv_prof_t rtnl_nla = TLV_PROF_NETLINK;

/* A netlink buffer must be aligned for the widest field it carries, so
 * callers pass this union. */
#define RTNL_BUF_MAX 1024
typedef union {
    struct nlmsghdr h;
    uint64_t        align;
    uint8_t         b[RTNL_BUF_MAX];
} rtnl_buf;

static size_t align4(size_t n)
{
    return (n + 3u) & ~(size_t)3u;
}

/* Parse a literal address into raw network-byte-order bytes (as
 * inet_pton yields) and report its family and byte length. */
static int addr_pton(const char* s, uint8_t out[16], uint16_t* fam,
                     uint8_t* len)
{
    if (!s || !*s) return RTNL_E_INVAL;
    memset(out, 0, 16);
    if (inet_pton(AF_INET, s, out) == 1) {
        *fam = AF_INET;
        *len = 4;
        return RTNL_OK;
    }
    if (inet_pton(AF_INET6, s, out) == 1) {
        *fam = AF_INET6;
        *len = 16;
        return RTNL_OK;
    }
    return RTNL_E_INVAL;
}

/* Lay down the header and fixed payload, then point an attribute writer
 * at the aligned remainder. Returns the attribute base offset, or a
 * negative RTNL_E_* code. */
static int msg_begin(uint8_t* buf, size_t cap, uint16_t type, uint16_t flags,
                     uint32_t seq, const void* fixed, size_t fixed_len,
                     tlv_wbuf_t* w)
{
    const size_t base = align4(NLMSG_HDRLEN + fixed_len);
    if (base > cap) return RTNL_E_OVERFLOW;

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
    if (w->overflow) return RTNL_E_OVERFLOW;
    struct nlmsghdr* nh = (struct nlmsghdr*)buf;
    nh->nlmsg_len       = (uint32_t)((size_t)base + w->off);
    return (int)nh->nlmsg_len;
}

/* ---- message builders ---------------------------------------------- */

static int addr_build(uint8_t* buf, size_t cap, uint16_t type, uint16_t flags,
                      uint32_t seq, const rtnl_addr* a)
{
    if (!a || !a->addr || a->ifindex == 0) return RTNL_E_INVAL;

    uint8_t  raw[16];
    uint16_t fam;
    uint8_t  alen;
    int      rc = addr_pton(a->addr, raw, &fam, &alen);
    if (rc) return rc;
    if (a->prefixlen > (uint8_t)(alen * 8)) return RTNL_E_INVAL;

    struct ifaddrmsg ifa;
    memset(&ifa, 0, sizeof ifa);
    ifa.ifa_family    = (uint8_t)fam;
    ifa.ifa_prefixlen = a->prefixlen;
    ifa.ifa_scope     = a->scope;
    ifa.ifa_index     = a->ifindex;

    tlv_wbuf_t w;
    int base = msg_begin(buf, cap, type, flags, seq, &ifa, sizeof ifa, &w);
    if (base < 0) return base;

    /* IFA_ADDRESS is the interface address for both families; IPv4 also
     * carries IFA_LOCAL (the two differ only for a peer address, which we
     * do not set). The kernel keys RTM_DELADDR on the same attributes. */
    if (fam == AF_INET) tlv_put(&w, &rtnl_nla, IFA_LOCAL, 0, raw, alen);
    tlv_put(&w, &rtnl_nla, IFA_ADDRESS, 0, raw, alen);

    return msg_end(buf, base, &w);
}

int rtnl_addr_msg(uint8_t* buf, size_t cap, uint32_t seq, const rtnl_addr* a)
{
    return addr_build(buf, cap, RTM_NEWADDR,
                      NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
                      seq, a);
}

int rtnl_addr_del_msg(uint8_t* buf, size_t cap, uint32_t seq,
                      const rtnl_addr* a)
{
    return addr_build(buf, cap, RTM_DELADDR, NLM_F_REQUEST | NLM_F_ACK, seq, a);
}

/* ---- transactions -------------------------------------------------- */

int rtnl_open(rtnl_sock* s)
{
    if (!s) return RTNL_E_INVAL;
    s->fd       = -1;
    s->seq      = 1;
    s->portid   = 0;
    s->nl_errno = 0;

    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) return RTNL_E_SYS;

    struct sockaddr_nl local;
    memset(&local, 0, sizeof local);
    local.nl_family = AF_NETLINK;
    if (bind(fd, (struct sockaddr*)&local, sizeof local) < 0) {
        close(fd);
        return RTNL_E_SYS;
    }

    socklen_t sl = sizeof local;
    if (getsockname(fd, (struct sockaddr*)&local, &sl) == 0)
        s->portid = local.nl_pid;

    s->fd = fd;
    return RTNL_OK;
}

void rtnl_close(rtnl_sock* s)
{
    if (s && s->fd >= 0) {
        close(s->fd);
        s->fd = -1;
    }
}

/* Send one request and consume the kernel's ACK. Every builder sets
 * NLM_F_ACK, so the kernel always answers with an NLMSG_ERROR carrying
 * either 0 (success) or a negative errno. */
static int transact(rtnl_sock* s, const void* req, size_t len)
{
    struct sockaddr_nl kernel;
    memset(&kernel, 0, sizeof kernel);
    kernel.nl_family = AF_NETLINK;

    if (sendto(s->fd, req, len, 0, (struct sockaddr*)&kernel, sizeof kernel) <
        0)
        return RTNL_E_SYS;

    rtnl_buf r;
    for (;;) {
        ssize_t n = recv(s->fd, r.b, sizeof r.b, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return RTNL_E_SYS;
        }

        struct nlmsghdr* nh  = &r.h;
        size_t           rem = (size_t)n;
        for (; NLMSG_OK(nh, rem); nh = NLMSG_NEXT(nh, rem)) {
            if (nh->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr* e = (struct nlmsgerr*)NLMSG_DATA(nh);
                if (e->error == 0) return RTNL_OK;
                s->nl_errno = -e->error;
                return RTNL_E_ACK;
            }
            if (nh->nlmsg_type == NLMSG_DONE) return RTNL_OK;
        }
        /* nothing conclusive in this datagram; wait for more */
    }
}

/* Build with the given message type/flags, send, and advance the
 * sequence counter. */
static int run(rtnl_sock* s,
               int (*build)(uint8_t*, size_t, uint32_t, const rtnl_addr*),
               const rtnl_addr* a)
{
    if (!s || s->fd < 0) return RTNL_E_INVAL;
    rtnl_buf m;
    int      len = build(m.b, sizeof m.b, s->seq, a);
    if (len < 0) return len;
    int rc = transact(s, m.b, (size_t)len);
    s->seq++;
    return rc;
}

int rtnl_addr_add(rtnl_sock* s, const rtnl_addr* a)
{
    return run(s, rtnl_addr_msg, a);
}

int rtnl_addr_del(rtnl_sock* s, const rtnl_addr* a)
{
    return run(s, rtnl_addr_del_msg, a);
}
