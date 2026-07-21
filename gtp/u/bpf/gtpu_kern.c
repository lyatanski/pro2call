// SPDX-License-Identifier: (BSD-2-Clause OR GPL-2.0)
/* GTP-U TC datapath — decap ingress and encap egress.
 * Both programs are BPF_PROG_TYPE_SCHED_CLS, attached to the
 * clsact qdisc by the userspace loader (src/gtpu_ebpf.c).
 *
 * Decap: outer Eth+IP+UDP:2152+GTP-U is parsed, the TEID looked up in
 * teid_rx_map, the outer headers stripped in-place with
 * bpf_skb_adjust_room, and the inner packet redirected. Unknown TEIDs,
 * End Markers and malformed inners are reported through the gtpu_events
 * ring buffer; anything that is not a G-PDU falls through with
 * TC_ACT_OK to the userspace socket (Echo, Error Indication, OAM).
 *
 * Encap: the inner packet is classified first against the dedicated-
 * bearer TFT filters (teid_tft_map, exact match with wildcard tiers),
 * then against the default-bearer LPM tries (teid_tx4/6_map). On a hit
 * the outer headers are built in-place and the frame redirected to the
 * uplink. Packets matching no tunnel pass through unmodified.
 *
 * Every packet-mutating path is copy-free: adjust_room + store_bytes.
 */

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "gtpu_abi.h"

#ifndef AF_INET
#define AF_INET  2
#define AF_INET6 10
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* ---- Maps (§13.5) — pinned under /sys/fs/bpf/gtpu by the loader ---- */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); /* local TEID, host order */
    __type(value, struct gtpu_rx_tun);
    __uint(max_entries, GTPU_MAX_BEARERS);
} teid_rx_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct gtpu_lpm4_key);
    __type(value, struct gtpu_tx_tun);
    __uint(max_entries, GTPU_MAX_BEARERS);
    __uint(map_flags, BPF_F_NO_PREALLOC); /* mandatory for LPM tries */
} teid_tx4_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct gtpu_lpm6_key);
    __type(value, struct gtpu_tx_tun);
    __uint(max_entries, GTPU_MAX_BEARERS);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} teid_tx6_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct gtpu_tft_key);
    __type(value, struct gtpu_tx_tun);
    __uint(max_entries, GTPU_MAX_TFT);
} teid_tft_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32); /* teid & GTPU_STATS_MASK */
    __type(value, struct gtpu_stats);
    __uint(max_entries, GTPU_STATS_ENTRIES);
} gtpu_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, GTPU_RINGBUF_SIZE);
} gtpu_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct gtpu_config);
    __uint(max_entries, 1);
} gtpu_config_map SEC(".maps");

/* ---- Shared helpers ---- */

static __always_inline struct gtpu_config* config_get(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&gtpu_config_map, &key);
}

/* Per-CPU slot: plain increments, no atomics needed (§13.3). */
static __always_inline struct gtpu_stats* stats_slot(__u32 teid)
{
    __u32 key = teid & GTPU_STATS_MASK;
    return bpf_map_lookup_elem(&gtpu_stats_map, &key);
}

static __always_inline void emit_event(__u32 kind, __u32 teid, __u8 family,
                                       const __u8* addr, __be16 port,
                                       struct gtpu_stats* st)
{
    struct gtpu_event* ev = bpf_ringbuf_reserve(&gtpu_events, sizeof *ev, 0);
    if (!ev) {
        if (st) st->err_ringbuf_full++;
        return;
    }
    ev->kind       = kind;
    ev->teid       = teid;
    ev->src_family = family;
    ev->pad        = 0;
    ev->src_port   = port;
    if (addr) __builtin_memcpy(ev->src_addr, addr, 16);
    else __builtin_memset(ev->src_addr, 0, 16);
    bpf_ringbuf_submit(ev, 0);
}

static __always_inline int addr16_is_zero(const __u8* a)
{
    __u64 lo, hi;
    __builtin_memcpy(&lo, a, 8);
    __builtin_memcpy(&hi, a + 8, 8);
    return (lo | hi) == 0;
}

static __always_inline int mac_is_zero(const __u8* m)
{
    return (m[0] | m[1] | m[2] | m[3] | m[4] | m[5]) == 0;
}

/* One's-complement sum of a small, in-stack buffer. Endian-neutral:
 * summing wire-order 16-bit pairs as host loads yields the checksum in
 * the same (wire) byte order. */
static __always_inline __u16 csum16(const void* buf, __u32 words, __u32 seed)
{
    const __u16* w = buf;
    __u32        s = seed;
    for (__u32 i = 0; i < words; i++)
        s += w[i];
    s = (s & 0xffff) + (s >> 16);
    s = (s & 0xffff) + (s >> 16);
    return (__u16)s;
}

/* =====================================================================
 * Ingress: GTP-U decapsulation (§13.3)
 * ===================================================================== */

SEC("tc")
int gtpu_decap(struct __sk_buff* skb)
{
    void* data     = (void*)(long)skb->data;
    void* data_end = (void*)(long)skb->data_end;

    /* Outer Ethernet: non-IP frames belong to the kernel. */
    struct ethhdr* eth = data;
    if ((void*)(eth + 1) > data_end) return TC_ACT_OK;

    __u32 udp_off;
    __u8  src_family;
    __u8  src_addr[16] = { 0 };

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr* ip = (void*)(eth + 1);
        if ((void*)(ip + 1) > data_end) return TC_ACT_OK;
        /* IP options on the GTP-U transport are pathological — leave
         * them to the kernel/userspace path rather than fight the
         * verifier over a variable-length checksum loop. */
        if (ip->version != 4 || ip->ihl != 5) return TC_ACT_OK;
        if (ip->protocol != IPPROTO_UDP) return TC_ACT_OK;
        /* Fragments: no UDP header in this frame; kernel reassembly
         * delivers them to the userspace socket instead. */
        if (ip->frag_off & bpf_htons(0x3fff)) return TC_ACT_OK;
        /* Header checksum must sum to 0xffff (checksum field included). */
        if (csum16(ip, 10, 0) != 0xffff) return TC_ACT_SHOT;
        src_family = AF_INET;
        __builtin_memcpy(src_addr, &ip->saddr, 4);
        udp_off = ETH_HLEN + sizeof *ip;
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr* ip6 = (void*)(eth + 1);
        if ((void*)(ip6 + 1) > data_end) return TC_ACT_OK;
        /* No extension header walk on the outer: transport-grade GTP-U
         * carries UDP directly; anything else goes to the stack. */
        if (ip6->nexthdr != IPPROTO_UDP) return TC_ACT_OK;
        src_family = AF_INET6;
        __builtin_memcpy(src_addr, &ip6->saddr, 16);
        udp_off = ETH_HLEN + sizeof *ip6;
    } else {
        return TC_ACT_OK;
    }

    /* Read the fixed 8-byte outer UDP header at its family-dependent
     * offset with load_bytes. Direct access (data + udp_off) adds a
     * *variable* scalar to the packet pointer — udp_off is 34 for IPv4,
     * 54 for IPv6 — which the verifier rejects unless the program is
     * loaded privileged (CAP_PERFMON: "prohibited for !root"). This
     * datapath is meant to load with only CAP_BPF + CAP_NET_ADMIN, so it
     * reads variable-offset headers by offset, never by pointer math. */
    struct udphdr udp;
    if (bpf_skb_load_bytes(skb, udp_off, &udp, sizeof udp)) return TC_ACT_OK;
    if (udp.dest != bpf_htons(GTPU_PORT)) return TC_ACT_OK;
    const __be16 src_port = udp.source;

    /* From here on this is GTP-U traffic addressed to us: refuse to
     * forward against a stale/absent map layout (§13.5 ABI check). */
    struct gtpu_config* cfg = config_get();
    if (!cfg || cfg->abi_version != GTPU_ABI_VERSION) {
        struct gtpu_stats* st = stats_slot(0);
        if (st) st->err_abi++;
        emit_event(GTPU_EV_ABI_MISMATCH, 0, src_family, src_addr, src_port, st);
        return TC_ACT_SHOT;
    }

    /* Mandatory GTP-U header, likewise read by offset (not data + off). */
    __u32           gtpu_off = udp_off + sizeof udp;
    struct gtpu_hdr g;
    if (bpf_skb_load_bytes(skb, gtpu_off, &g, sizeof g)) return TC_ACT_OK;
    if ((g.flags & 0xf0) != GTPU_F_VERSION_PT) /* version 1, PT=GTP only */
        return TC_ACT_OK;

    __u32              teid = bpf_ntohl(g.teid);
    struct gtpu_stats* st   = stats_slot(teid);

    if (g.msg_type == GTPU_MT_END_MARKER) {
        /* Handover state machine runs in userspace (§13.3). */
        emit_event(GTPU_EV_END_MARKER, teid, src_family, src_addr, src_port,
                   st);
        return TC_ACT_OK;
    }
    if (g.msg_type != GTPU_MT_GPDU)
        return TC_ACT_OK; /* Echo/Error Indication → userspace socket */

    /* Optional area + extension header chain (variable offsets: use
     * load_bytes, direct access would fight the verifier). */
    __u32 payload_off = gtpu_off + GTPU_HDR_MIN;
    if (g.flags & (GTPU_F_EXT | GTPU_F_SEQ | GTPU_F_NPDU)) {
        payload_off += GTPU_HDR_OPT;
        if (g.flags & GTPU_F_EXT) {
            __u8 next = 0;
            if (bpf_skb_load_bytes(skb, gtpu_off + 11, &next, 1))
                return TC_ACT_OK;
            for (int hop = 0; hop < GTPU_EXT_MAX_HOPS && next; hop++) {
                __u8 extlen = 0;
                if (bpf_skb_load_bytes(skb, payload_off, &extlen, 1))
                    return TC_ACT_OK;
                if (!extlen) return TC_ACT_OK; /* malformed chain → stack */
                payload_off += (__u32)extlen * 4;
                if (bpf_skb_load_bytes(skb, payload_off - 1, &next, 1))
                    return TC_ACT_OK;
            }
            if (next) return TC_ACT_OK; /* pathological chain (§13.3) */
        }
    }

    struct gtpu_rx_tun* tun = bpf_map_lookup_elem(&teid_rx_map, &teid);
    if (!tun) {
        if (st) st->err_unknown_teid++;
        /* Userspace answers with Error Indication (TS 29.281 §7.3.1). */
        emit_event(GTPU_EV_UNKNOWN_TEID, teid, src_family, src_addr, src_port,
                   st);
        return TC_ACT_OK;
    }

    /* Validate the inner packet before touching the skb. */
    if (payload_off >= skb->len) goto malformed;
    __u32 inner_len = skb->len - payload_off;

    __u8 inner_b0 = 0;
    if (bpf_skb_load_bytes(skb, payload_off, &inner_b0, 1)) goto malformed;
    __u8 inner_ver = inner_b0 >> 4;

    __be16 inner_proto;
    if (tun->inner_family == AF_INET) {
        if (inner_ver != 4 || inner_len < sizeof(struct iphdr)) goto malformed;
        inner_proto = bpf_htons(ETH_P_IP);
        if (!addr16_is_zero(tun->inner_addr)) {
            __u8 dst[4];
            if (bpf_skb_load_bytes(skb, payload_off + 16, dst, 4))
                goto malformed;
            if (__builtin_memcmp(dst, tun->inner_addr, 4))
                goto malformed; /* inner dst is not the expected UE */
        }
    } else {
        if (inner_ver != 6 || inner_len < sizeof(struct ipv6hdr))
            goto malformed;
        inner_proto = bpf_htons(ETH_P_IPV6);
        if (!addr16_is_zero(tun->inner_addr)) {
            __u8 dst[16];
            if (bpf_skb_load_bytes(skb, payload_off + 24, dst, 16))
                goto malformed;
            if (__builtin_memcmp(dst, tun->inner_addr, 16)) goto malformed;
        }
    }

    /* Strip IP+UDP+GTP-U in-place, keeping the Ethernet header (§0.2:
     * bpf_skb_adjust_room, no clones). */
    if (bpf_skb_adjust_room(skb, -(__s32)(payload_off - ETH_HLEN),
                            BPF_ADJ_ROOM_MAC, 0))
        goto malformed;

    /* The exposed inner packet rides the old Ethernet header: fix the
     * ethertype to match the inner family. */
    if (bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_proto), &inner_proto,
                            sizeof inner_proto, 0))
        return TC_ACT_SHOT;

    if (st) {
        st->rx_pkts++;
        st->rx_bytes += inner_len;
    }

    if (tun->ifindex) return bpf_redirect(tun->ifindex, 0);
    return TC_ACT_OK; /* ifindex 0: deliver to the local stack */

malformed:
    if (st) st->err_malformed++;
    emit_event(GTPU_EV_MALFORMED, teid, src_family, src_addr, src_port, st);
    return TC_ACT_SHOT;
}

/* =====================================================================
 * Egress: GTP-U encapsulation (§13.4)
 * ===================================================================== */

/* Bearer classification: dedicated-bearer TFT filters first (exact
 * match with wildcard tiers, see gtpu_abi.h), then the default-bearer
 * LPM trie for the inner family. Returns NULL when the packet belongs
 * to no tunnel. */
static __always_inline struct gtpu_tx_tun*
tx_classify(__u8 family, const __u8* ue_addr, __u8 proto, __be16 ue_port,
            __be16 remote_port)
{
    struct gtpu_tft_key k;
    __builtin_memset(&k, 0, sizeof k);
    k.family = family;
    k.proto  = proto;
    __builtin_memcpy(k.ue_addr, ue_addr, 16);

    struct gtpu_tx_tun* tun;

    k.ue_port     = ue_port;
    k.remote_port = remote_port;
    tun           = bpf_map_lookup_elem(&teid_tft_map, &k);
    if (tun) return tun;

    if (remote_port) {
        k.remote_port = 0;
        tun           = bpf_map_lookup_elem(&teid_tft_map, &k);
        if (tun) return tun;
    }
    if (ue_port) {
        k.ue_port     = 0;
        k.remote_port = remote_port;
        tun           = bpf_map_lookup_elem(&teid_tft_map, &k);
        if (tun) return tun;
    }
    if (ue_port || remote_port) {
        k.ue_port     = 0;
        k.remote_port = 0;
        tun           = bpf_map_lookup_elem(&teid_tft_map, &k);
        if (tun) return tun;
    }

    if (family == AF_INET) {
        struct gtpu_lpm4_key lk;
        lk.prefixlen = 32;
        __builtin_memcpy(lk.addr, ue_addr, 4);
        return bpf_map_lookup_elem(&teid_tx4_map, &lk);
    }
    struct gtpu_lpm6_key lk;
    lk.prefixlen = 128;
    __builtin_memcpy(lk.addr, ue_addr, 16);
    return bpf_map_lookup_elem(&teid_tx6_map, &lk);
}

/* IPv6 outer needs a real UDP checksum; payloads too large for the
 * bounded checksum loop fall back to the userspace path. The chunk is
 * kept at 128 (not 256) so csum_pkt_range's frame plus gtpu_encap's stay
 * within BPF's 512-byte combined call-stack limit; CSUM_CHUNKS is doubled
 * to keep the same total checksummable length. */
#define CSUM_CHUNK   128
#define CSUM_CHUNKS  16
#define CSUM_MAX_LEN (CSUM_CHUNK * CSUM_CHUNKS)

/* One's-complement sum over a packet byte range. A real BPF subprogram
 * (not inlined) so the chunk buffer lives in its own stack frame rather
 * than adding to the caller's; the two frames together must still fit
 * BPF's 512-byte combined-stack limit (hence CSUM_CHUNK = 128).
 * Returns the running 32-bit sum, or negative on a short packet. */
static __noinline __s64 csum_pkt_range(struct __sk_buff* skb, __u32 off,
                                       __u32 remain, __u64 seed)
{
    __s64 sum = (__s64)seed;
    __u8  chunk[CSUM_CHUNK];

    for (int i = 0; i < CSUM_CHUNKS && remain; i++) {
        __u32 n = remain > CSUM_CHUNK ? CSUM_CHUNK : remain;
        if (n < CSUM_CHUNK) __builtin_memset(chunk, 0, CSUM_CHUNK);
        if (bpf_skb_load_bytes(skb, off, chunk, n)) return -1;
        /* Zero padding is checksum-neutral: always sum the full chunk
         * so the size stays constant for the verifier. */
        sum = bpf_csum_diff(0, 0, (__be32*)chunk, CSUM_CHUNK, (__u32)sum);
        if (sum < 0) return -1;
        off += n;
        remain -= n;
    }
    return sum;
}

SEC("tc")
int gtpu_encap(struct __sk_buff* skb)
{
    void* data     = (void*)(long)skb->data;
    void* data_end = (void*)(long)skb->data_end;

    struct ethhdr* eth = data;
    if ((void*)(eth + 1) > data_end) return TC_ACT_OK;

    /* ---- Parse the inner packet for classification ---- */

    __u8  family;
    __u8  proto;
    __u8  ue_addr[16]     = { 0 }; /* inner destination */
    __u8  inner_saddr[16] = { 0 }; /* inner source, for the L4 pseudo-header */
    __u32 l4_off          = 0;     /* 0 = no L4 header in this frame */
    __u32 inner_l4_len    = 0;     /* L4 header + payload; 0 = do not checksum */

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr* ip = (void*)(eth + 1);
        if ((void*)(ip + 1) > data_end) return TC_ACT_OK;
        if (ip->version != 4 || ip->ihl < 5) return TC_ACT_OK;
        family = AF_INET;
        proto  = ip->protocol;
        __builtin_memcpy(ue_addr, &ip->daddr, 4);
        __builtin_memcpy(inner_saddr, &ip->saddr, 4);
        __u32 ihl_bytes = (__u32)ip->ihl * 4;
        /* Ports exist only in first fragments. */
        if (!(ip->frag_off & bpf_htons(0x1fff)))
            l4_off = ETH_HLEN + ihl_bytes;
        /* A complete L4 checksum only exists in a whole datagram (offset 0,
         * MF clear); leave fragments to the offloaded/partial checksum. */
        if (!(ip->frag_off & bpf_htons(0x3fff))) {
            __u32 tot = bpf_ntohs(ip->tot_len);
            if (tot > ihl_bytes) inner_l4_len = tot - ihl_bytes;
        }
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr* ip6 = (void*)(eth + 1);
        if ((void*)(ip6 + 1) > data_end) return TC_ACT_OK;
        family = AF_INET6;
        proto  = ip6->nexthdr; /* no ext walk: ports stay wildcard then */
        __builtin_memcpy(ue_addr, &ip6->daddr, 16);
        __builtin_memcpy(inner_saddr, &ip6->saddr, 16);
        inner_l4_len = bpf_ntohs(ip6->payload_len); /* no ext headers assumed */
        l4_off       = ETH_HLEN + sizeof *ip6;
    } else {
        return TC_ACT_OK;
    }

    /* TCP, UDP and SCTP all carry src/dst ports in the first 4 bytes. */
    __be16 remote_port = 0, ue_port = 0;
    if (l4_off && (proto == IPPROTO_TCP || proto == IPPROTO_UDP ||
                   proto == IPPROTO_SCTP)) {
        __be16 ports[2];
        if (!bpf_skb_load_bytes(skb, l4_off, ports, sizeof ports)) {
            remote_port = ports[0]; /* inner src = network side */
            ue_port     = ports[1]; /* inner dst = UE side */
        }
    }

    struct gtpu_tx_tun* tun =
        tx_classify(family, ue_addr, proto, ue_port, remote_port);
    if (!tun) return TC_ACT_OK; /* not tunnel traffic — pass through */

    struct gtpu_stats*  st  = stats_slot(tun->local_teid);
    struct gtpu_config* cfg = config_get();
    if (!cfg || cfg->abi_version != GTPU_ABI_VERSION) {
        if (st) st->err_abi++;
        emit_event(GTPU_EV_ABI_MISMATCH, tun->local_teid, 0, 0, 0, st);
        return TC_ACT_SHOT;
    }

    /* ---- Resolve outer MACs before mutating the packet ----
     * bpf_fib_lookup first (§13.4), static per-tunnel MACs as the
     * lab-topology fallback (or forced via GTPU_TXF_STATIC_MAC). */

    __u32 inner_len = skb->len - ETH_HLEN;
    __u32 oif       = tun->ifindex ? tun->ifindex : cfg->uplink_ifindex;
    __u8  smac[6], dmac[6];
    __builtin_memcpy(smac, tun->src_mac, 6);
    __builtin_memcpy(dmac, tun->dst_mac, 6);

    __u32 gtpu_len = GTPU_HDR_MIN;
    if (tun->flags & GTPU_TXF_QFI)
        gtpu_len += GTPU_HDR_OPT + 4; /* opt area + PDU Session Container */
    __u32 udp_len = sizeof(struct udphdr) + gtpu_len + inner_len;

    if (!(tun->flags & GTPU_TXF_STATIC_MAC)) {
        struct bpf_fib_lookup fib;
        __builtin_memset(&fib, 0, sizeof fib);
        fib.family  = tun->outer_family;
        fib.ifindex = oif ? oif : skb->ifindex;
        fib.tot_len = (__u16)(udp_len + (tun->outer_family == AF_INET
                                             ? sizeof(struct iphdr)
                                             : sizeof(struct ipv6hdr)));
        if (tun->outer_family == AF_INET) {
            __builtin_memcpy(&fib.ipv4_src, cfg->local_v4, 4);
            __builtin_memcpy(&fib.ipv4_dst, tun->remote_addr, 4);
        } else {
            __builtin_memcpy(fib.ipv6_src, cfg->local_v6, 16);
            __builtin_memcpy(fib.ipv6_dst, tun->remote_addr, 16);
        }
        if (bpf_fib_lookup(skb, &fib, sizeof fib, 0) ==
            BPF_FIB_LKUP_RET_SUCCESS) {
            __builtin_memcpy(smac, fib.smac, 6);
            __builtin_memcpy(dmac, fib.dmac, 6);
            oif = fib.ifindex;
        }
    }
    if (mac_is_zero(dmac) || !oif) {
        /* An established tunnel we cannot emit on: dropping loudly
         * beats leaking the inner packet unencapsulated. */
        if (st) st->err_tx_no_neigh++;
        return TC_ACT_SHOT;
    }

    const int v4 = tun->outer_family == AF_INET;
    if (!v4 && udp_len > CSUM_MAX_LEN)
        return TC_ACT_OK; /* userspace path computes the v6 checksum */

    __u32 outer_l3  = v4 ? sizeof(struct iphdr) : sizeof(struct ipv6hdr);
    __u32 outer_len = outer_l3 + sizeof(struct udphdr) + gtpu_len;

    /* ---- Grow the skb, then write each header from its own fixed stack
     * object with store_bytes ----
     *
     * Overlaying udp/g on one buffer at `hdr + outer_l3` is pointer
     * arithmetic with a per-path scalar (outer_l3 is 20 or 40), which the
     * verifier forbids unless the program is loaded privileged. Building
     * each header in its own object keeps every pointer offset constant;
     * the store_bytes *destination offset* may vary freely — it is a
     * helper argument, not pointer math. cfg/tun are map values and stay
     * valid across bpf_skb_adjust_room (only packet pointers are killed). */

    if (bpf_skb_adjust_room(skb, (__s32)outer_len, BPF_ADJ_ROOM_MAC,
                            BPF_F_ADJ_ROOM_FIXED_GSO))
        return TC_ACT_SHOT;

    struct ethhdr neweth;
    __builtin_memcpy(neweth.h_dest, dmac, 6);
    __builtin_memcpy(neweth.h_source, smac, 6);
    neweth.h_proto = v4 ? bpf_htons(ETH_P_IP) : bpf_htons(ETH_P_IPV6);
    if (bpf_skb_store_bytes(skb, 0, &neweth, sizeof neweth, 0))
        return TC_ACT_SHOT;

    /* Outer L3, built and written inside each family branch so the store
     * size is a compile-time constant. */
    if (v4) {
        struct iphdr ip = { 0 };
        ip.version  = 4;
        ip.ihl      = 5;
        ip.tot_len  = bpf_htons((__u16)(outer_l3 + udp_len));
        ip.ttl      = 64;
        ip.protocol = IPPROTO_UDP;
        __builtin_memcpy(&ip.saddr, cfg->local_v4, 4);
        __builtin_memcpy(&ip.daddr, tun->remote_addr, 4);
        ip.check = (__u16)~csum16(&ip, 10, 0);
        if (bpf_skb_store_bytes(skb, ETH_HLEN, &ip, sizeof ip, 0))
            return TC_ACT_SHOT;
    } else {
        struct ipv6hdr ip6 = { 0 };
        ip6.version     = 6;
        ip6.payload_len = bpf_htons((__u16)udp_len);
        ip6.nexthdr     = IPPROTO_UDP;
        ip6.hop_limit   = 64;
        __builtin_memcpy(&ip6.saddr, cfg->local_v6, 16);
        __builtin_memcpy(&ip6.daddr, tun->remote_addr, 16);
        if (bpf_skb_store_bytes(skb, ETH_HLEN, &ip6, sizeof ip6, 0))
            return TC_ACT_SHOT;
    }

    /* Outer UDP: fixed stack struct, written at the (variable) L3 offset. */
    struct udphdr udp = { 0 };
    udp.source = bpf_htons(GTPU_PORT);
    udp.dest   = tun->remote_port;
    udp.len    = bpf_htons((__u16)udp_len);
    udp.check  = 0; /* optional for IPv4 (§13.4); v6 computed below */
    if (bpf_skb_store_bytes(skb, ETH_HLEN + outer_l3, &udp, sizeof udp, 0))
        return TC_ACT_SHOT;

    /* GTP-U header (+ optional PDU Session Container) in a fixed buffer. */
    __u32            gtpu_hdr_off = ETH_HLEN + outer_l3 + sizeof(struct udphdr);
    __u8             gbuf[GTPU_HDR_MIN + GTPU_HDR_OPT + 4] = { 0 };
    struct gtpu_hdr* g                                     = (struct gtpu_hdr*)gbuf;
    g->msg_type                                            = GTPU_MT_GPDU;
    g->teid = bpf_htonl(tun->remote_teid);
    if (tun->flags & GTPU_TXF_QFI) {
        /* E flag; length counts the opt area and ext header too. */
        g->flags  = GTPU_F_VERSION_PT | GTPU_F_EXT;
        g->length = bpf_htons((__u16)(inner_len + GTPU_HDR_OPT + 4));
        gbuf[GTPU_HDR_MIN + 3] = GTPU_EXT_PDU_SESSION; /* seq/n-pdu stay zero */
        gbuf[GTPU_HDR_MIN + 4] = 1;                    /* ext length, 4-byte units */
        gbuf[GTPU_HDR_MIN + 5] = 0x00;                 /* PDU type 0 = DL PSC */
        gbuf[GTPU_HDR_MIN + 6] = tun->qfi & 0x3f;
        gbuf[GTPU_HDR_MIN + 7] = GTPU_EXT_NONE;
        if (bpf_skb_store_bytes(skb, gtpu_hdr_off, gbuf,
                                GTPU_HDR_MIN + GTPU_HDR_OPT + 4, 0))
            return TC_ACT_SHOT;
    } else {
        g->flags  = GTPU_F_VERSION_PT;
        g->length = bpf_htons((__u16)inner_len);
        if (bpf_skb_store_bytes(skb, gtpu_hdr_off, gbuf, GTPU_HDR_MIN, 0))
            return TC_ACT_SHOT;
    }

    if (!v4) {
        /* Mandatory IPv6 UDP checksum: pseudo-header sum plus a bounded
         * walk over the written UDP+GTP-U+inner bytes. (The plan's
         * bpf_l4_csum_replace only patches an existing checksum; a
         * from-scratch header needs the full sum.) */
        struct {
            __u8   src[16], dst[16];
            __be32 len;
            __u8   zero[3], nexthdr;
        } ph;
        __builtin_memcpy(ph.src, cfg->local_v6, 16);
        __builtin_memcpy(ph.dst, tun->remote_addr, 16);
        ph.len     = bpf_htonl(udp_len);
        ph.zero[0] = ph.zero[1] = ph.zero[2] = 0;
        ph.nexthdr                           = IPPROTO_UDP;

        __s64 sum = bpf_csum_diff(0, 0, (__be32*)&ph, sizeof ph, 0);
        if (sum < 0) return TC_ACT_SHOT;

        sum = csum_pkt_range(skb, ETH_HLEN + outer_l3, udp_len, (__u64)sum);
        if (sum < 0) return TC_ACT_SHOT;

        __u32 s     = (__u32)sum;
        s           = (s & 0xffff) + (s >> 16);
        s           = (s & 0xffff) + (s >> 16);
        __u16 check = (__u16)~s;
        if (!check) check = 0xffff; /* RFC 8200: zero means "no checksum" */
        if (bpf_skb_store_bytes(
                skb, ETH_HLEN + outer_l3 + offsetof(struct udphdr, check),
                &check, sizeof check, 0))
            return TC_ACT_SHOT;
    }

    /* ---- Finalize the INNER L4 checksum in software ----
     *
     * A locally-generated UDP/TCP datagram reaches this egress hook with
     * ip_summed == CHECKSUM_PARTIAL: the L4 checksum field holds only the
     * pseudo-header partial sum, to be completed by the NIC (or
     * skb_checksum_help) at transmit. But we prepend the outer headers and
     * bpf_redirect the frame, so that completion never runs — the peer UPF
     * then decapsulates and forwards the inner packet with a bogus checksum,
     * and the P-CSCF's kernel drops it before any socket sees it (tcpdump
     * still shows it arriving, which is exactly the "packet reaches the
     * container but is never processed" symptom).
     *
     * Recompute the checksum from scratch here: pseudo-header sum plus a
     * bounded walk over the L4 bytes with the check field zeroed. This is
     * idempotent for packets that already carry a correct checksum, so it is
     * safe to run unconditionally. The inner L4 sits at l4_off + outer_len
     * once the room has grown. SCTP (CRC32c, not the internet checksum) is
     * left to the stack; oversized inners keep the offloaded checksum (MTU
     * keeps SIP well within CSUM_MAX_LEN). */
    __u32 min_l4 = proto == IPPROTO_UDP ? sizeof(struct udphdr) : 20;
    if (l4_off && (proto == IPPROTO_UDP || proto == IPPROTO_TCP) &&
        inner_l4_len >= min_l4 && inner_l4_len <= CSUM_MAX_LEN) {
        __u32 l4  = l4_off + outer_len; /* inner L4 offset after the growth */
        __u32 ck  = l4 + (proto == IPPROTO_UDP ? offsetof(struct udphdr, check)
                                               : 16 /* TCP checksum field */);
        __u16 zero = 0;
        if (bpf_skb_store_bytes(skb, ck, &zero, sizeof zero, 0))
            return TC_ACT_SHOT;

        __s64 isum;
        if (family == AF_INET) {
            struct {
                __be32 src, dst;
                __u8   zero, proto;
                __be16 len;
            } ph4;
            __builtin_memcpy(&ph4.src, inner_saddr, 4);
            __builtin_memcpy(&ph4.dst, ue_addr, 4);
            ph4.zero  = 0;
            ph4.proto = proto;
            ph4.len   = bpf_htons((__u16)inner_l4_len);
            isum      = bpf_csum_diff(0, 0, (__be32*)&ph4, sizeof ph4, 0);
        } else {
            struct {
                __u8   src[16], dst[16];
                __be32 len;
                __u8   zero[3], nexthdr;
            } ph6;
            __builtin_memcpy(ph6.src, inner_saddr, 16);
            __builtin_memcpy(ph6.dst, ue_addr, 16);
            ph6.len     = bpf_htonl(inner_l4_len);
            ph6.zero[0] = ph6.zero[1] = ph6.zero[2] = 0;
            ph6.nexthdr                             = proto;
            isum        = bpf_csum_diff(0, 0, (__be32*)&ph6, sizeof ph6, 0);
        }
        if (isum < 0) return TC_ACT_SHOT;

        isum = csum_pkt_range(skb, l4, inner_l4_len, (__u64)isum);
        if (isum < 0) return TC_ACT_SHOT;

        __u32 s      = (__u32)isum;
        s            = (s & 0xffff) + (s >> 16);
        s            = (s & 0xffff) + (s >> 16);
        __u16 icheck = (__u16)~s;
        /* RFC 768: a computed 0 is transmitted as 0xffff so it is not read
         * as "no checksum". A genuine TCP checksum of 0 is left as is. */
        if (proto == IPPROTO_UDP && !icheck) icheck = 0xffff;
        if (bpf_skb_store_bytes(skb, ck, &icheck, sizeof icheck, 0))
            return TC_ACT_SHOT;
    }

    if (st) {
        st->tx_pkts++;
        st->tx_bytes += inner_len;
    }

    return bpf_redirect(oif, 0);
}
