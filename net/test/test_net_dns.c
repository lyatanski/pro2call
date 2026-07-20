#define _GNU_SOURCE
#include "net_dns.h"
#include "net_sock.h"
#include "test.h"

#include <arpa/inet.h>
#include <string.h>

/* --- in-process fake DNS server ---------------------------------------- */

static net_sock fake;
static int      fake_hits; /* queries received */
static int      fake_drop; /* swallow this many queries first */
static int      fake_rcode;
static uint16_t fake_an_type; /* answer RR type to emit, 0 = none */

static void put16(uint8_t* p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}
static void put32(uint8_t* p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static size_t put_name(uint8_t* p, const char* name)
{
    size_t w = 0;
    while (*name) {
        const char* d = strchr(name, '.');
        size_t      l = d ? (size_t)(d - name) : strlen(name);
        p[w++]        = (uint8_t)l;
        memcpy(p + w, name, l);
        w += l;
        name += l + (d ? 1 : 0);
    }
    p[w++] = 0;
    return w;
}

static size_t put_cstr(uint8_t* p, const char* s)
{
    size_t l = strlen(s);
    p[0]     = (uint8_t)l;
    memcpy(p + 1, s, l);
    return l + 1;
}

/* one answer RR: owner compressed to the qname at offset 12 */
static size_t put_rr_hdr(uint8_t* p, uint16_t type, uint32_t ttl)
{
    put16(p, 0xC00C);
    put16(p + 2, type);
    put16(p + 4, 1);
    put32(p + 6, ttl);
    return 10; /* caller writes rdlength at p+10 */
}

static void fake_reply(void* ud, int fd, unsigned ev)
{
    uint8_t  q[512], r[512];
    net_addr from;
    (void)ud;
    (void)fd;
    (void)ev;
    for (;;) {
        ssize_t n = net_udp_recv(&fake, q, sizeof q, &from, -1);
        if (n < 12) return;
        fake_hits++;
        if (fake_drop > 0) {
            fake_drop--;
            continue;
        }
        size_t qend = 12; /* skip qname + type + class */
        while (qend < (size_t)n && q[qend])
            qend += q[qend] + 1;
        qend += 5;
        memcpy(r, q, qend);
        put16(r + 2, (uint16_t)(0x8180 | fake_rcode));
        put16(r + 4, 1);
        put16(r + 8, 0);
        put16(r + 10, 0); /* EDNS OPT not echoed */
        size_t   w  = qend;
        uint16_t an = 0;

        if (!fake_rcode && fake_an_type == NET_DNS_A) {
            for (uint32_t i = 0; i < 2; i++) {
                w += put_rr_hdr(r + w, NET_DNS_A, 60);
                put16(r + w, 4);
                put32(r + w + 2, 0x0A000001u + i); /* 10.0.0.1, 10.0.0.2 */
                w += 6;
                an++;
            }
        } else if (!fake_rcode && fake_an_type == NET_DNS_AAAA) {
            w += put_rr_hdr(r + w, NET_DNS_AAAA, 60);
            put16(r + w, 16);
            memset(r + w + 2, 0, 16);
            r[w + 2]  = 0x20;
            r[w + 3]  = 0x01;
            r[w + 17] = 1; /* 2001::1 */
            w += 18;
            an++;
        } else if (!fake_rcode && fake_an_type == NET_DNS_SRV) {
            w += put_rr_hdr(r + w, NET_DNS_SRV, 60);
            size_t rd = w + 2;
            put16(r + rd, 10);
            put16(r + rd + 2, 60);
            put16(r + rd + 4, 5060);
            size_t tl = put_name(r + rd + 6, "pcscf1.ims.example.com");
            put16(r + w, (uint16_t)(6 + tl));
            w = rd + 6 + tl;
            an++;
        } else if (!fake_rcode && fake_an_type == NET_DNS_NAPTR) {
            w += put_rr_hdr(r + w, NET_DNS_NAPTR, 60);
            size_t rd = w + 2, o = rd;
            put16(r + o, 50);
            o += 2;
            put16(r + o, 100);
            o += 2;
            o += put_cstr(r + o, "s");
            o += put_cstr(r + o, "SIP+D2U");
            o += put_cstr(r + o, "");
            o += put_name(r + o, "_sip._udp.ims.example.com");
            put16(r + w, (uint16_t)(o - rd));
            w = o;
            an++;
        }
        put16(r + 6, an);
        net_udp_send(&fake, r, w, &from);
    }
}

/* --- capture callback --------------------------------------------------- */

static int        got_status;
static size_t     got_n;
static net_dns_rr got_rr[NET_DNS_MAX];

static void capture(void* ud, int status, const net_dns_rr* rr, size_t n)
{
    (void)ud;
    got_status = status;
    got_n      = n;
    if (n) memcpy(got_rr, rr, n * sizeof *rr);
}

static void ask(net_loop* l, net_dns* d, const char* name, uint16_t type)
{
    fake_an_type = type;
    got_status   = -100;
    got_n        = 0;
    net_dns_query(d, name, type, capture, NULL);
    for (int i = 0; i < 1000 && got_status == -100; i++)
        net_loop_step(l, 10);
}

spec ("net_dns") {
    net_loop* l = net_loop_new();
    net_addr  lo;
    net_addr_from(&lo, "127.0.0.1", 0);
    net_udp_open(&fake, &lo, 0);
    net_loop_add(l, fake.fd, NET_RD, fake_reply, NULL);
    net_dns* d = net_dns_new(l, &fake.local);

    context ("records") {
        it ("resolver comes up") {
            check(d != NULL);
        }

        it ("resolves A") {
            ask(l, d, "ims.example.com", NET_DNS_A);
            check(got_status == 0);
            check(got_n == 2);
            check(got_rr[0].type == NET_DNS_A);
            check(got_rr[0].ttl == 60);
            check(ntohl(got_rr[0].u.a.s_addr) == 0x0A000001);
            check(ntohl(got_rr[1].u.a.s_addr) == 0x0A000002);
        }

        it ("resolves AAAA") {
            ask(l, d, "ims.example.com", NET_DNS_AAAA);
            check(got_status == 0);
            check(got_n == 1);
            char ip[64];
            inet_ntop(AF_INET6, &got_rr[0].u.aaaa, ip, sizeof ip);
            check(!strcmp(ip, "2001::1"));
        }

        it ("resolves SRV") {
            ask(l, d, "_sip._udp.ims.example.com", NET_DNS_SRV);
            check(got_status == 0);
            check(got_n == 1);
            check(got_rr[0].u.srv.prio == 10);
            check(got_rr[0].u.srv.weight == 60);
            check(got_rr[0].u.srv.port == 5060);
            check(!strcmp(got_rr[0].u.srv.target, "pcscf1.ims.example.com"));
        }

        it ("resolves NAPTR") {
            ask(l, d, "ims.example.com", NET_DNS_NAPTR);
            check(got_status == 0);
            check(got_n == 1);
            check(got_rr[0].u.naptr.order == 50);
            check(got_rr[0].u.naptr.pref == 100);
            check(!strcmp(got_rr[0].u.naptr.flags, "s"));
            check(!strcmp(got_rr[0].u.naptr.service, "SIP+D2U"));
            check(!strcmp(got_rr[0].u.naptr.regexp, ""));
            check(!strcmp(got_rr[0].u.naptr.replace,
                          "_sip._udp.ims.example.com"));
        }
    }

    context ("failures") {
        it ("reports NXDOMAIN as rcode 3") {
            fake_rcode = 3;
            ask(l, d, "missing.example.com", NET_DNS_A);
            check(got_status == 3);
            check(got_n == 0);
            fake_rcode = 0;
        }

        it ("retransmits, then times out") {
            net_dns_conf(d, 20, 2);
            fake_hits = 0;
            fake_drop = 1000;
            ask(l, d, "silent.example.com", NET_DNS_A);
            check(got_status == NET_TIMEOUT);
            check(fake_hits == 2); /* original + one retry */
            fake_drop = 0;
        }

        it ("recovers when a retry is answered") {
            net_dns_conf(d, 20, 3);
            fake_hits = 0;
            fake_drop = 1;
            ask(l, d, "flaky.example.com", NET_DNS_A);
            check(got_status == 0);
            check(got_n == 2);
            check(fake_hits == 2);
        }
    }

    net_dns_free(d);
    net_loop_del(l, fake.fd);
    net_sock_close(&fake);
    net_loop_free(l);
}
