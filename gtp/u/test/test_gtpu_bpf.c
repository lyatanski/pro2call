#include "gtpu_ebpf.h"
#include "test.h"

#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>

#include <linux/pkt_cls.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

/* Datapath tests: crafted frames through the TC programs via
 * BPF_PROG_TEST_RUN (§13.7 baseline correctness). Needs CAP_BPF +
 * CAP_NET_ADMIN; every test skips cleanly without them (§13.2
 * capability fallback).
 *
 * Topology under test (we are the eNB side):
 *   outer  198.51.100.1 (us) <-> 198.51.100.2 / 2001:db8::2 (peer)
 *   inner  10.45.0.2 (UE)    <-> 203.0.113.10 (network host)
 * Bearer A (default):   local TEID 0x1001, remote 0x2002
 * Bearer B (peer stub): local TEID 0x2002 — decaps bearer A's output
 * Bearer C (dedicated): local TEID 0x1003, remote 0x2003,
 *                       TFT = {UDP, remote port 5004}
 * Bearer D (v6 outer):  UE 10.45.0.3, local 0x1004, remote 0x2004, QFI 9
 */

static const uint8_t UE[4]        = { 10, 45, 0, 2 };
static const uint8_t UE2[4]       = { 10, 45, 0, 3 };
static const uint8_t HOST[4]      = { 203, 0, 113, 10 };
static const uint8_t O_LOCAL[4]   = { 198, 51, 100, 1 };
static const uint8_t O_PEER[4]    = { 198, 51, 100, 2 };
static const uint8_t O_LOCAL6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                      0,    0,    0,    0,    0, 0, 0, 1 };
static const uint8_t O_PEER6[16]  = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                      0,    0,    0,    0,    0, 0, 0, 2 };

/* ---- wire builders (independent of the BPF code on purpose) ---- */

static void be16p(uint8_t* p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}
static void be32p(uint8_t* p, uint32_t v)
{
    be16p(p, (uint16_t)(v >> 16));
    be16p(p + 2, (uint16_t)v);
}
static uint16_t be16g(const uint8_t* p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t sum16(const uint8_t* p, size_t n, uint32_t s)
{
    size_t k = 0;
    for (; k + 1 < n; k += 2)
        s += (uint32_t)((p[k] << 8) | p[k + 1]);
    if (n & 1) s += (uint32_t)(p[n - 1] << 8);
    return s;
}

static uint16_t fold16(uint32_t s)
{
    while (s >> 16)
        s = (s & 0xffff) + (s >> 16);
    return (uint16_t)s;
}

static size_t eth_push(uint8_t* p, uint16_t proto)
{
    memset(p, 0xaa, 6);
    memset(p + 6, 0xbb, 6);
    be16p(p + 12, proto);
    return 14;
}

static size_t ipv4_push(uint8_t* p, const uint8_t src[4], const uint8_t dst[4],
                        uint8_t proto, uint16_t payload_len)
{
    memset(p, 0, 20);
    p[0] = 0x45;
    be16p(p + 2, (uint16_t)(20 + payload_len));
    p[8] = 64;
    p[9] = proto;
    memcpy(p + 12, src, 4);
    memcpy(p + 16, dst, 4);
    be16p(p + 10, (uint16_t)~fold16(sum16(p, 20, 0)));
    return 20;
}

static size_t udp_push(uint8_t* p, uint16_t sport, uint16_t dport,
                       uint16_t payload_len)
{
    be16p(p, sport);
    be16p(p + 2, dport);
    be16p(p + 4, (uint16_t)(8 + payload_len));
    be16p(p + 6, 0);
    return 8;
}

/* Inner IPv4/UDP packet as the UE would receive it (dst = UE). */
static size_t inner_udp4(uint8_t* p, const uint8_t dst[4], uint16_t sport,
                         uint16_t dport, const char* payload)
{
    size_t plen = strlen(payload);
    size_t off  = ipv4_push(p, HOST, dst, 17, (uint16_t)(8 + plen));
    off += udp_push(p + off, sport, dport, (uint16_t)plen);
    memcpy(p + off, payload, plen);
    return off + plen;
}

/* Full outer frame: Eth + IPv4 + UDP:2152 + GTP-U (+ PSC ext). */
static size_t gpdu4(uint8_t* p, uint8_t msg_type, uint32_t teid, int with_ext,
                    const uint8_t* inner, size_t inner_len)
{
    size_t gtpu_len = 8 + (with_ext ? 8 : 0);
    size_t off      = eth_push(p, 0x0800);
    off += ipv4_push(p + off, O_PEER, O_LOCAL, 17,
                     (uint16_t)(8 + gtpu_len + inner_len));
    off += udp_push(p + off, 2152, 2152, (uint16_t)(gtpu_len + inner_len));

    p[off]     = (uint8_t)(0x30 | (with_ext ? 0x04 : 0));
    p[off + 1] = msg_type;
    be16p(p + off + 2, (uint16_t)((with_ext ? 8 : 0) + inner_len));
    be32p(p + off + 4, teid);
    off += 8;
    if (with_ext) {
        p[off]     = 0;
        p[off + 1] = 0;
        p[off + 2] = 0;    /* seq, n-pdu */
        p[off + 3] = 0x85; /* next: PSC */
        p[off + 4] = 1;    /* ext length */
        p[off + 5] = 0x10; /* UL PSC */
        p[off + 6] = 9;    /* QFI */
        p[off + 7] = 0x00; /* no more ext */
        off += 8;
    }
    if (inner_len) memcpy(p + off, inner, inner_len);
    return off + inner_len;
}

static int run_prog(int fd, const uint8_t* in, size_t in_len, uint8_t* out,
                    size_t* out_len, uint32_t* retval)
{
    DECLARE_LIBBPF_OPTS(bpf_test_run_opts, o, .data_in = in,
                        .data_size_in = (uint32_t)in_len, .data_out = out,
                        .data_size_out = out ? 4096 : 0);
    int rc = bpf_prog_test_run_opts(fd, &o);
    if (rc) return rc;
    if (out_len) *out_len = o.data_size_out;
    if (retval) *retval = o.retval;
    return 0;
}

/* ---- event capture ---- */

static struct gtpu_event last_ev;
static int               ev_count;

static void on_ev(void* ctx, const struct gtpu_event* ev)
{
    (void)ctx;
    last_ev = *ev;
    ev_count++;
}

static void drain_events(gtpu_ebpf_t* g)
{
    while (gtpu_events_poll(g, 0, on_ev, NULL) > 0) {
    }
    ev_count = 0;
}

spec ("gtpu_bpf") {
    int          priv     = gtpu_ebpf_supported();
    gtpu_ebpf_t* g        = NULL;
    int          decap_fd = -1, encap_fd = -1;

    gtpu_tunnel_t bearer_a;
    memset(&bearer_a, 0, sizeof bearer_a);
    bearer_a.local_teid   = 0x1001;
    bearer_a.remote_teid  = 0x2002;
    bearer_a.ebi          = 5;
    bearer_a.inner_family = AF_INET;
    memcpy(bearer_a.inner_addr, UE, 4);
    bearer_a.outer_family = AF_INET;
    memcpy(bearer_a.remote_addr, O_PEER, 4);
    bearer_a.tx_ifindex = 1;
    bearer_a.static_mac = true;
    memcpy(bearer_a.dst_mac, (uint8_t[6]){ 2, 0, 0, 0, 0, 2 }, 6);
    memcpy(bearer_a.src_mac, (uint8_t[6]){ 2, 0, 0, 0, 0, 1 }, 6);

    context ("load and attachability") {
        it ("loads both TC programs through the verifier", priv) {
            gtpu_ebpf_cfg_t cfg;
            memset(&cfg, 0, sizeof cfg);
            cfg.pin_dir        = ""; /* anonymous maps for the test */
            cfg.max_bearers    = 1024;
            cfg.uplink_ifindex = 1;
            memcpy(cfg.local_v4, O_LOCAL, 4);
            memcpy(cfg.local_v6, O_LOCAL6, 16);

            check(gtpu_ebpf_open(&g, &cfg) == GTPU_OK);
            decap_fd = gtpu_ebpf_prog_fd(g, GTPU_PROG_DECAP);
            encap_fd = gtpu_ebpf_prog_fd(g, GTPU_PROG_ENCAP);
            check(decap_fd >= 0);
            check(encap_fd >= 0);
        }

        it ("installs default and dedicated bearers", !!g) {
            check(gtpu_teid_add(g, &bearer_a) == GTPU_OK);
            check(gtpu_teid_add(g, &bearer_a) == GTPU_E_EXIST);

            /* Peer stub that decaps bearer A's own output. */
            gtpu_tunnel_t b = bearer_a;
            b.local_teid    = 0x2002;
            b.remote_teid   = 0xdead;
            memset(b.inner_addr, 0, 16); /* no inner dst check */
            check(gtpu_teid_add(g, &b) == GTPU_OK);

            /* Dedicated bearer: UDP from remote port 5004 (RTP). */
            gtpu_tft_t f;
            memset(&f, 0, sizeof f);
            f.tunnel             = bearer_a;
            f.tunnel.local_teid  = 0x1003;
            f.tunnel.remote_teid = 0x2003;
            f.tunnel.ebi         = 6;
            f.proto              = 17;
            f.remote_port        = 5004;
            check(gtpu_tft_add(g, &f) == GTPU_OK);

            /* IPv6 outer + QFI for a second UE. */
            gtpu_tunnel_t d = bearer_a;
            d.local_teid    = 0x1004;
            d.remote_teid   = 0x2004;
            memcpy(d.inner_addr, UE2, 4);
            d.outer_family = AF_INET6;
            memcpy(d.remote_addr, O_PEER6, 16);
            d.has_qfi = true;
            d.qfi     = 9;
            check(gtpu_teid_add(g, &d) == GTPU_OK);
        }
    }

    context ("decapsulation (TC ingress)") {
        it ("strips outer headers from a G-PDU", !!g) {
            uint8_t inner[128], in[256], out[4096];
            size_t  ilen = inner_udp4(inner, UE, 5004, 40000, "downlink-1");
            size_t  ln   = gpdu4(in, GTPU_MT_GPDU, 0x1001, 0, inner, ilen);

            uint32_t ret;
            size_t   olen;
            check(run_prog(decap_fd, in, ln, out, &olen, &ret) == 0);
            check(ret == TC_ACT_OK); /* rx_ifindex 0 = to stack */
            check(olen == 14 + ilen);
            check(be16g(out + 12) == 0x0800); /* ethertype fixed up */
            check(memcmp(out + 14, inner, ilen) == 0);

            struct gtpu_stats st;
            check(gtpu_stats_read(g, 0x1001, &st) == GTPU_OK);
            check(st.rx_pkts == 1);
            check(st.rx_bytes == ilen);
        }

        it ("walks and strips the PDU Session Container chain", !!g) {
            uint8_t inner[128], in[256], out[4096];
            size_t  ilen = inner_udp4(inner, UE, 5004, 40000, "downlink-2");
            size_t  ln   = gpdu4(in, GTPU_MT_GPDU, 0x1001, 1, inner, ilen);

            uint32_t ret;
            size_t   olen;
            check(run_prog(decap_fd, in, ln, out, &olen, &ret) == 0);
            check(ret == TC_ACT_OK);
            check(olen == 14 + ilen);
            check(memcmp(out + 14, inner, ilen) == 0);
        }

        it ("reports unknown TEIDs and passes the frame on", !!g) {
            drain_events(g);
            uint8_t inner[128], in[256], out[4096];
            size_t  ilen = inner_udp4(inner, UE, 5004, 40000, "downlink-3");
            size_t  ln   = gpdu4(in, GTPU_MT_GPDU, 0xBEEF, 0, inner, ilen);

            uint32_t ret;
            size_t   olen;
            check(run_prog(decap_fd, in, ln, out, &olen, &ret) == 0);
            check(ret == TC_ACT_OK); /* userspace sends Error Indication */
            check(olen == ln);       /* untouched */
            check(memcmp(out, in, ln) == 0);

            check(gtpu_events_poll(g, 0, on_ev, NULL) >= 1);
            check(ev_count >= 1);
            check(last_ev.kind == GTPU_EV_UNKNOWN_TEID);
            check(last_ev.teid == 0xBEEF);
            check(last_ev.src_family == AF_INET);
            check(memcmp(last_ev.src_addr, O_PEER, 4) == 0);
            check(ntohs(last_ev.src_port) == 2152);

            struct gtpu_stats st;
            check(gtpu_stats_read(g, 0xBEEF, &st) == GTPU_OK);
            check(st.err_unknown_teid == 1);
        }

        it ("signals End Marker to the handover state machine", !!g) {
            drain_events(g);
            uint8_t in[256], out[4096];
            size_t  ln = gpdu4(in, GTPU_MT_END_MARKER, 0x1001, 0, NULL, 0);

            uint32_t ret;
            size_t   olen;
            check(run_prog(decap_fd, in, ln, out, &olen, &ret) == 0);
            check(ret == TC_ACT_OK);
            check(gtpu_events_poll(g, 0, on_ev, NULL) >= 1);
            check(last_ev.kind == GTPU_EV_END_MARKER);
            check(last_ev.teid == 0x1001);
        }

        it ("drops G-PDUs whose inner dst is not the bearer's UE", !!g) {
            uint8_t       inner[128], in[256];
            const uint8_t spoof[4] = { 10, 45, 0, 9 };
            size_t ilen = inner_udp4(inner, spoof, 5004, 40000, "spoofed");
            size_t ln   = gpdu4(in, GTPU_MT_GPDU, 0x1001, 0, inner, ilen);

            uint32_t ret;
            check(run_prog(decap_fd, in, ln, NULL, NULL, &ret) == 0);
            check(ret == TC_ACT_SHOT);

            struct gtpu_stats st;
            check(gtpu_stats_read(g, 0x1001, &st) == GTPU_OK);
            check(st.err_malformed == 1);
        }
    }

    context ("encapsulation (TC egress)") {
        it ("wraps default-bearer traffic via the LPM table", !!g) {
            uint8_t inner[128], in[256], out[4096];
            size_t  ilen = inner_udp4(inner, UE, 9999, 40000, "bulk");
            size_t  ln   = eth_push(in, 0x0800);
            memcpy(in + ln, inner, ilen);
            ln += ilen;

            uint32_t ret;
            size_t   olen;
            check(run_prog(encap_fd, in, ln, out, &olen, &ret) == 0);
            check(ret == TC_ACT_REDIRECT);
            check(olen == ln + 36); /* +IPv4 +UDP +GTP-U */

            check(memcmp(out, bearer_a.dst_mac, 6) == 0);
            check(memcmp(out + 6, bearer_a.src_mac, 6) == 0);
            check(be16g(out + 12) == 0x0800);

            const uint8_t* ip = out + 14;
            check(ip[0] == 0x45);
            check(be16g(ip + 2) == 20 + 8 + 8 + ilen);
            check(ip[9] == 17);
            check(memcmp(ip + 12, O_LOCAL, 4) == 0);
            check(memcmp(ip + 16, O_PEER, 4) == 0);
            check(fold16(sum16(ip, 20, 0)) == 0xffff); /* valid csum */

            const uint8_t* udp = ip + 20;
            check(be16g(udp) == 2152);
            check(be16g(udp + 2) == 2152);
            check(be16g(udp + 4) == 8 + 8 + ilen);

            const uint8_t* gtpu = udp + 8;
            check(gtpu[0] == 0x30);
            check(gtpu[1] == 0xff);
            check(be16g(gtpu + 2) == ilen);
            check(gtpu[4] == 0 && gtpu[5] == 0);
            check(be16g(gtpu + 6) == 0x2002); /* remote TEID on the wire */
            check(memcmp(gtpu + 8, inner, ilen) == 0);

            struct gtpu_stats st;
            check(gtpu_stats_read(g, 0x1001, &st) == GTPU_OK);
            check(st.tx_pkts == 1);
            check(st.tx_bytes == ilen);
        }

        it ("steers TFT matches onto the dedicated bearer", !!g) {
            uint8_t inner[128], in[256], out[4096];
            size_t  ilen = inner_udp4(inner, UE, 5004, 40000, "rtp");
            size_t  ln   = eth_push(in, 0x0800);
            memcpy(in + ln, inner, ilen);
            ln += ilen;

            uint32_t ret;
            size_t   olen;
            check(run_prog(encap_fd, in, ln, out, &olen, &ret) == 0);
            check(ret == TC_ACT_REDIRECT);
            const uint8_t* gtpu = out + 14 + 20 + 8;
            check(gtpu[4] == 0 && gtpu[5] == 0);
            check(be16g(gtpu + 6) == 0x2003); /* dedicated TEID */
        }

        it ("keeps non-matching traffic on the default bearer", !!g) {
            uint8_t inner[128], in[256], out[4096];
            size_t  ilen = inner_udp4(inner, UE, 9998, 40000, "other");
            size_t  ln   = eth_push(in, 0x0800);
            memcpy(in + ln, inner, ilen);
            ln += ilen;

            uint32_t ret;
            size_t   olen;
            check(run_prog(encap_fd, in, ln, out, &olen, &ret) == 0);
            check(ret == TC_ACT_REDIRECT);
            const uint8_t* gtpu = out + 14 + 20 + 8;
            check(be16g(gtpu + 6) == 0x2002); /* default TEID */
        }

        it ("passes non-tunnel traffic through unmodified", !!g) {
            uint8_t       inner[128], in[256], out[4096];
            const uint8_t other[4] = { 8, 8, 8, 8 };
            size_t        ilen     = inner_udp4(inner, other, 53, 53, "dns");
            size_t        ln       = eth_push(in, 0x0800);
            memcpy(in + ln, inner, ilen);
            ln += ilen;

            uint32_t ret;
            size_t   olen;
            check(run_prog(encap_fd, in, ln, out, &olen, &ret) == 0);
            check(ret == TC_ACT_OK);
            check(olen == ln);
            check(memcmp(out, in, ln) == 0);
        }

        it ("builds an IPv6 outer with valid UDP checksum and QFI", !!g) {
            uint8_t inner[128], in[256], out[4096];
            size_t  ilen = inner_udp4(inner, UE2, 9999, 40000, "v6-outer");
            size_t  ln   = eth_push(in, 0x0800);
            memcpy(in + ln, inner, ilen);
            ln += ilen;

            uint32_t ret;
            size_t   olen;
            check(run_prog(encap_fd, in, ln, out, &olen, &ret) == 0);
            check(ret == TC_ACT_REDIRECT);
            check(olen == ln + 40 + 8 + 16); /* IPv6 + UDP + GTP-U/PSC */
            check(be16g(out + 12) == 0x86dd);

            const uint8_t* ip6 = out + 14;
            check((ip6[0] >> 4) == 6);
            check(be16g(ip6 + 4) == 8 + 16 + ilen);
            check(ip6[6] == 17);
            check(memcmp(ip6 + 8, O_LOCAL6, 16) == 0);
            check(memcmp(ip6 + 24, O_PEER6, 16) == 0);

            /* RFC 2460 pseudo-header + UDP datagram must sum to 0xffff. */
            const uint8_t* udp     = ip6 + 40;
            uint16_t       udp_len = be16g(udp + 4);
            check(udp_len == 8 + 16 + ilen);
            check(be16g(udp + 6) != 0); /* v6: checksum is mandatory */
            uint32_t ph = sum16(ip6 + 8, 32, 0) + udp_len + 17;
            check(fold16(sum16(udp, udp_len, ph)) == 0xffff);

            const uint8_t* gtpu = udp + 8;
            check(gtpu[0] == 0x34); /* version 1, PT, E */
            check(be16g(gtpu + 2) == ilen + 8);
            check(be16g(gtpu + 6) == 0x2004);
            check(gtpu[11] == 0x85);               /* next ext: PSC */
            check(gtpu[12] == 1 && gtpu[14] == 9); /* len, QFI */
            check(memcmp(gtpu + 16, inner, ilen) == 0);
        }
    }

    context ("round trip") {
        it ("decap(encap(pkt)) returns the original packet", !!g) {
            uint8_t inner[128], in[256], mid[4096], out[4096];
            size_t  ilen = inner_udp4(inner, UE, 9999, 40000, "round-trip");
            size_t  ln   = eth_push(in, 0x0800);
            memcpy(in + ln, inner, ilen);
            ln += ilen;

            uint32_t ret;
            size_t   mlen, olen;
            check(run_prog(encap_fd, in, ln, mid, &mlen, &ret) == 0);
            check(ret == TC_ACT_REDIRECT);

            /* Bearer B (local TEID 0x2002) plays the receiving peer. */
            check(run_prog(decap_fd, mid, mlen, out, &olen, &ret) == 0);
            check(ret == TC_ACT_OK);
            check(olen == 14 + ilen);
            check(memcmp(out + 14, inner, ilen) == 0);
        }
    }

    context ("teardown") {
        it ("removes bearers and closes", !!g) {
            gtpu_tunnel_t b = bearer_a;
            check(gtpu_teid_del(g, &bearer_a) == GTPU_OK);
            check(gtpu_teid_del(g, &bearer_a) == GTPU_E_NOENT);
            b.local_teid  = 0x2002;
            b.remote_teid = 0xdead;
            memset(b.inner_addr, 0, 16);
            check(gtpu_teid_del(g, &b) == GTPU_OK);
            gtpu_ebpf_close(g);
            g = NULL;
        }
    }
}
