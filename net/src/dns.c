#define _GNU_SOURCE
#include "net_dns.h"
#include "net_sock.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#define DNS_PORT     53
#define DNS_QRY_MAX  300 /* header + 255 qname + question + EDNS0 */
#define DNS_RSP_MAX  2048
#define DNS_EDNS     1232
#define DNS_TYPE_OPT 41

struct dnsq {
    struct dnsq* next;
    net_dns*     dns;
    uint16_t     id, qtype;
    int          tries;
    uint64_t     tmr;
    net_dns_f    cb;
    void*        ud;
    size_t       len; /* stored packet, resent verbatim on timeout */
    uint8_t      pkt[DNS_QRY_MAX];
    char         name[256];
};

struct net_dns {
    net_loop*    loop;
    net_sock     sock;
    net_addr     server;
    struct dnsq* qs;
    int          timeout_ms;
    int          tries;
    uint16_t     seq;
};

static uint16_t get16(const uint8_t* p)
{
    return (uint16_t)(p[0] << 8 | p[1]);
}
static uint32_t get32(const uint8_t* p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 |
           p[3];
}
static void put16(uint8_t* p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

/* Expand a (possibly compressed) domain name into out[256]; returns the
 * offset just past the name at its original position, or -1. */
static int dns_name(const uint8_t* p, size_t n, size_t off, char* out)
{
    size_t o = off, w = 0;
    int    jumps = 0, end = -1;
    for (;;) {
        if (o >= n) return -1;
        uint8_t l = p[o];
        if (!l) {
            if (end < 0) end = (int)o + 1;
            break;
        }
        if ((l & 0xC0) == 0xC0) {
            if (o + 1 >= n || ++jumps > 40) return -1;
            if (end < 0) end = (int)o + 2;
            o = (size_t)(l & 0x3F) << 8 | p[o + 1];
            continue;
        }
        if (l & 0xC0) return -1;
        if (o + 1 + l > n || w + l + 2 > 256) return -1;
        if (w) out[w++] = '.';
        memcpy(out + w, p + o + 1, l);
        w += l;
        o += 1u + l;
    }
    out[w] = 0;
    return end;
}

/* <character-string>: length byte + bytes, clamped to the field size. */
static int dns_cstr(const uint8_t* p, size_t n, size_t off, char* out,
                    size_t cap)
{
    if (off >= n || off + 1 + p[off] > n) return -1;
    size_t l = p[off];
    size_t c = l < cap ? l : cap - 1;
    memcpy(out, p + off + 1, c);
    out[c] = 0;
    return (int)(off + 1 + l);
}

static int dns_qname(uint8_t* out, const char* name)
{
    size_t w = 0;
    while (*name) {
        const char* dot = strchr(name, '.');
        size_t      l   = dot ? (size_t)(dot - name) : strlen(name);
        if (!l || l > 63 || w + l + 2 > 255) return -1;
        out[w++] = (uint8_t)l;
        memcpy(out + w, name, l);
        w += l;
        name += l + (dot ? 1 : 0);
    }
    out[w++] = 0;
    return (int)w;
}

static struct dnsq* dns_find(net_dns* d, uint16_t id)
{
    for (struct dnsq* q = d->qs; q; q = q->next)
        if (q->id == id) return q;
    return NULL;
}

static void dns_detach(net_dns* d, struct dnsq* q)
{
    for (struct dnsq** pp = &d->qs; *pp; pp = &(*pp)->next)
        if (*pp == q) {
            *pp = q->next;
            break;
        }
    if (q->tmr) net_loop_cancel(d->loop, q->tmr);
}

static void dns_send(net_dns* d, struct dnsq* q)
{
    net_udp_send(&d->sock, q->pkt, q->len, &d->server);
}

static void dns_timeo(void* ud)
{
    struct dnsq* q = ud;
    net_dns*     d = q->dns;
    q->tmr         = 0;
    if (++q->tries < d->tries) {
        dns_send(d, q);
        q->tmr = net_loop_after(d->loop, (uint64_t)d->timeout_ms << q->tries,
                                dns_timeo, q);
        return;
    }
    dns_detach(d, q);
    q->cb(q->ud, NET_TIMEOUT, NULL, 0);
    free(q);
}

static void dns_parse(net_dns* d, const uint8_t* p, size_t n)
{
    if (n < 12 || !(get16(p + 2) & 0x8000)) return;
    struct dnsq* q = dns_find(d, get16(p));
    if (!q) return;

    /* the question must echo ours; otherwise it is stale or forged */
    size_t   off = 12;
    char     qname[256];
    uint16_t qd = get16(p + 4);
    if (qd != 1) return;
    int o = dns_name(p, n, off, qname);
    if (o < 0 || (size_t)o + 4 > n) return;
    if (strcasecmp(qname, q->name) || get16(p + o) != q->qtype) return;
    off = (size_t)o + 4;

    dns_detach(d, q);
    int        rcode = get16(p + 2) & 0xF;
    net_dns_rr rr[NET_DNS_MAX];
    size_t     cnt = 0;

    for (uint16_t i = get16(p + 6); i && !rcode; i--) {
        char owner[256];
        o = dns_name(p, n, off, owner);
        if (o < 0 || (size_t)o + 10 > n) break;
        uint16_t type  = get16(p + o);
        uint32_t ttl   = get32(p + o + 4);
        size_t   rdlen = get16(p + o + 8);
        size_t   rd    = (size_t)o + 10;
        if (rd + rdlen > n) break;
        off = rd + rdlen;
        if (type != q->qtype || cnt == NET_DNS_MAX) continue; /* e.g. CNAMEs */

        net_dns_rr* r = &rr[cnt];
        memset(r, 0, sizeof *r);
        r->type = type;
        r->ttl  = ttl;
        switch (type) {
        case NET_DNS_A:
            if (rdlen != 4) continue;
            memcpy(&r->u.a, p + rd, 4);
            break;
        case NET_DNS_AAAA:
            if (rdlen != 16) continue;
            memcpy(&r->u.aaaa, p + rd, 16);
            break;
        case NET_DNS_SRV:
            if (rdlen < 7) continue;
            r->u.srv.prio   = get16(p + rd);
            r->u.srv.weight = get16(p + rd + 2);
            r->u.srv.port   = get16(p + rd + 4);
            if (dns_name(p, n, rd + 6, r->u.srv.target) < 0) continue;
            break;
        case NET_DNS_NAPTR: {
            if (rdlen < 7) continue;
            r->u.naptr.order = get16(p + rd);
            r->u.naptr.pref  = get16(p + rd + 2);
            int so           = dns_cstr(p, off, rd + 4, r->u.naptr.flags,
                                        sizeof r->u.naptr.flags);
            if (so < 0) continue;
            so = dns_cstr(p, off, (size_t)so, r->u.naptr.service,
                          sizeof r->u.naptr.service);
            if (so < 0) continue;
            so = dns_cstr(p, off, (size_t)so, r->u.naptr.regexp,
                          sizeof r->u.naptr.regexp);
            if (so < 0) continue;
            if (dns_name(p, n, (size_t)so, r->u.naptr.replace) < 0) continue;
            break;
        }
        default: continue;
        }
        cnt++;
    }

    q->cb(q->ud, rcode, cnt ? rr : NULL, cnt);
    free(q);
}

static void dns_readable(void* ud, int fd, unsigned ev)
{
    net_dns* d = ud;
    uint8_t  buf[DNS_RSP_MAX];
    (void)fd;
    (void)ev;
    for (;;) {
        ssize_t n = net_udp_recv(&d->sock, buf, sizeof buf, NULL, -1);
        if (n < 0) return; /* drained */
        dns_parse(d, buf, (size_t)n);
    }
}

static int dns_resolv_conf(net_addr* server)
{
    FILE* f = fopen("/etc/resolv.conf", "r");
    if (!f) return NET_ERR;
    char line[256], host[128];
    int  r = NET_ERR;
    while (fgets(line, sizeof line, f))
        if (sscanf(line, " nameserver %127s", host) == 1 &&
            net_addr_from(server, host, DNS_PORT) == NET_OK) {
            r = NET_OK;
            break;
        }
    fclose(f);
    return r;
}

net_dns* net_dns_new(net_loop* loop, const net_addr* server)
{
    net_dns* d = calloc(1, sizeof *d);
    if (!d) return NULL;
    d->loop       = loop;
    d->timeout_ms = 500;
    d->tries      = 3;

    int r = NET_OK;
    if (server) d->server = *server;
    else r = dns_resolv_conf(&d->server);
    net_addr any;
    if (r || net_addr_any(&any, d->server.sa.sa_family, 0) ||
        net_udp_open(&d->sock, &any, 0)) {
        free(d);
        return NULL;
    }
    if (net_loop_add(loop, d->sock.fd, NET_RD, dns_readable, d)) {
        net_sock_close(&d->sock);
        free(d);
        return NULL;
    }
    if (getentropy(&d->seq, sizeof d->seq)) d->seq = (uint16_t)net_now_ms();
    return d;
}

void net_dns_free(net_dns* d)
{
    if (!d) return;
    while (d->qs) {
        struct dnsq* q = d->qs;
        dns_detach(d, q);
        free(q);
    }
    net_loop_del(d->loop, d->sock.fd);
    net_sock_close(&d->sock);
    free(d);
}

void net_dns_conf(net_dns* d, int timeout_ms, int tries)
{
    if (timeout_ms > 0) d->timeout_ms = timeout_ms;
    if (tries > 0) d->tries = tries;
}

int net_dns_query(net_dns* d, const char* name, uint16_t type, net_dns_f cb,
                  void* ud)
{
    if (!cb || !name || strlen(name) > 255) return NET_ERR;
    struct dnsq* q = calloc(1, sizeof *q);
    if (!q) return NET_ERR;
    q->dns   = d;
    q->qtype = type;
    q->cb    = cb;
    q->ud    = ud;
    strcpy(q->name, name);
    do
        q->id = ++d->seq;
    while (dns_find(d, q->id));

    uint8_t* p = q->pkt;
    put16(p, q->id);
    put16(p + 2, 0x0100); /* RD */
    put16(p + 4, 1);      /* QD */
    put16(p + 6, 0);
    put16(p + 8, 0);
    put16(p + 10, 1); /* AR: EDNS0 OPT */
    int w = dns_qname(p + 12, name);
    if (w < 0) {
        free(q);
        return NET_ERR;
    }
    size_t o = 12 + (size_t)w;
    put16(p + o, type);
    put16(p + o + 2, 1); /* IN */
    o += 4;
    p[o] = 0; /* OPT: root, type 41, class = udp size */
    put16(p + o + 1, DNS_TYPE_OPT);
    put16(p + o + 3, DNS_EDNS);
    memset(p + o + 5, 0, 6);
    q->len = o + 11;

    q->next = d->qs;
    d->qs   = q;
    dns_send(d, q);
    q->tmr = net_loop_after(d->loop, (uint64_t)d->timeout_ms, dns_timeo, q);
    return NET_OK;
}
