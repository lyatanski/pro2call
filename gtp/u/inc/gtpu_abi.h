#ifndef GTPU_ABI_H
#define GTPU_ABI_H

#include <linux/types.h>

/* GTP-U eBPF datapath ABI — shared between the TC BPF programs
 * (bpf/gtpu_kern.c) and the userspace loader (src/gtpu_ebpf.c).
 *
 * Everything in this header is wire- or map-layout and must change in
 * lockstep on both sides; bump GTPU_ABI_VERSION on any layout change.
 * The loader refuses to attach against pinned maps written by a
 * different version, and the TC programs drop (with a ring buffer
 * event) if the config map disagrees with their compiled-in version.
 *
 * Byte-order convention: map keys and TEIDs are host order; fields that
 * are copied verbatim to/from the wire (ports, addresses) are network
 * order. Addresses are byte arrays, IPv4 in the first 4 bytes.
 */

#define GTPU_ABI_VERSION 1
#define GTPU_PIN_DIR     "/sys/fs/bpf/gtpu"

/* ---- GTP-U wire constants — TS 29.281 ---- */

#define GTPU_PORT 2152

#define GTPU_MT_ECHO_REQUEST  0x01
#define GTPU_MT_ECHO_RESPONSE 0x02
#define GTPU_MT_ERROR_IND     0x1A
#define GTPU_MT_END_MARKER    0xFE
#define GTPU_MT_GPDU          0xFF

/* Flags octet: version(3) | PT | spare | E | S | PN */
#define GTPU_F_VERSION_PT 0x30 /* version 1, PT = GTP */
#define GTPU_F_EXT        0x04
#define GTPU_F_SEQ        0x02
#define GTPU_F_NPDU       0x01

#define GTPU_HDR_MIN 8 /* mandatory header */
#define GTPU_HDR_OPT                                        \
    4 /* seq(2) + n-pdu(1) + next-ext(1), present if E|S|PN \
       */

/* Extension header types */
#define GTPU_EXT_NONE        0x00
#define GTPU_EXT_PDU_SESSION 0x85 /* PDU Session Container, TS 38.415 */
#define GTPU_EXT_MAX_HOPS    5    /* longer chains fall through to userspace */

/* Mandatory GTP-U header as it appears on the wire. */
struct gtpu_hdr {
    __u8   flags;
    __u8   msg_type;
    __be16 length; /* payload bytes after this header (opt area included) */
    __be32 teid;
};

/* ---- Map sizing ---- */

#define GTPU_MAX_BEARERS   (1u << 20) /* 1 M simultaneous bearers */
#define GTPU_MAX_TFT       (1u << 16)
#define GTPU_STATS_ENTRIES 4096 /* power of two; slot = teid & mask */
#define GTPU_STATS_MASK    (GTPU_STATS_ENTRIES - 1)
#define GTPU_RINGBUF_SIZE  (4u << 20)

/* ---- teid_rx_map: local TEID -> decap target (TC ingress) ---- */

struct gtpu_rx_tun {
    __u8 inner_family;   /* AF_INET / AF_INET6 expected inside the tunnel */
    __u8 ebi;            /* EPS bearer id (dedicated bearers), observability */
    __u8 inner_addr[16]; /* expected inner dst (UE addr); all-zero = no check */
    __u32 ifindex;       /* bpf_redirect target; 0 = pass to local stack */
};

/* ---- teid_tx4/6_map (LPM, default bearer) and teid_tft_map
 *      (exact match, dedicated bearer) share this tunnel value ---- */

#define GTPU_TXF_STATIC_MAC 0x01 /* skip bpf_fib_lookup, use *_mac below */
#define GTPU_TXF_QFI        0x02 /* emit PDU Session Container ext with qfi */

struct gtpu_tx_tun {
    __u8   outer_family;    /* AF_INET / AF_INET6 outer header */
    __u8   ebi;             /* EPS bearer id, observability */
    __u8   qfi;             /* 5G QoS flow id, used when GTPU_TXF_QFI */
    __u8   flags;           /* GTPU_TXF_* */
    __u8   remote_addr[16]; /* outer dst (network order) */
    __u8   dst_mac[6];      /* fallback when fib lookup fails or STATIC_MAC */
    __u8   src_mac[6];
    __be16 remote_port; /* outer UDP dst, network order */
    __u32  remote_teid; /* host order, written big-endian to the wire */
    __u32  local_teid;  /* host order; stats key and rx correlation */
    __u32  ifindex;     /* uplink redirect target; 0 = config uplink */
};

/* LPM trie keys, one map per inner address family. */
struct gtpu_lpm4_key {
    __u32 prefixlen;
    __u8  addr[4];
};
struct gtpu_lpm6_key {
    __u32 prefixlen;
    __u8  addr[16];
};

/* ---- teid_tft_map key: dedicated-bearer traffic filter ----
 *
 * Exact-match subset of a 3GPP TFT packet filter (TS 24.008 §10.5.6.12):
 * protocol id, single UE-side port, single remote port, all matched on
 * the inner header of the packet being encapsulated (dst = UE side).
 * 0 means wildcard; the TC egress program probes tiers in order
 *   {proto, ue_port, remote_port}, {proto, ue_port, 0},
 *   {proto, 0, remote_port},       {proto, 0, 0}
 * and falls back to the LPM default-bearer maps on miss. Port ranges
 * expand to multiple entries (control-plane concern, not datapath).
 */
struct gtpu_tft_key {
    __u8   family;      /* AF_INET / AF_INET6 of the inner packet */
    __u8   proto;       /* inner IPPROTO_* */
    __be16 ue_port;     /* inner dst port, network order; 0 = any */
    __be16 remote_port; /* inner src port, network order; 0 = any */
    __u16  pad;         /* zero */
    __u8   ue_addr[16]; /* inner dst address, full match */
};

/* ---- gtpu_stats_map: per-CPU array, slot = teid & GTPU_STATS_MASK ---- */

struct gtpu_stats {
    __u64 rx_pkts;
    __u64 rx_bytes; /* inner bytes after decap */
    __u64 tx_pkts;
    __u64 tx_bytes; /* inner bytes before encap */
    __u64 err_unknown_teid;
    __u64 err_malformed;
    __u64 err_tx_no_neigh; /* no fib result and no static MAC */
    __u64 err_ringbuf_full;
    __u64 err_abi;
};

/* ---- gtpu_events ring buffer records ---- */

enum gtpu_event_kind {
    GTPU_EV_UNKNOWN_TEID = 1, /* userspace sends Error Indication */
    GTPU_EV_END_MARKER   = 2, /* handover state machine input */
    GTPU_EV_MALFORMED    = 3, /* dropped in TC with TC_ACT_SHOT */
    GTPU_EV_ABI_MISMATCH = 4, /* config map vs compiled-in version */
};

struct gtpu_event {
    __u32  kind;       /* enum gtpu_event_kind */
    __u32  teid;       /* host order */
    __u8   src_family; /* outer source, AF_INET / AF_INET6 */
    __u8   pad;
    __be16 src_port; /* outer UDP source, network order */
    __u8   src_addr[16];
};

/* ---- gtpu_config_map: single-entry array, written by the loader ---- */

struct gtpu_config {
    __u32 abi_version;    /* GTPU_ABI_VERSION of the writing loader */
    __u32 uplink_ifindex; /* default egress redirect target */
    __u8  local_v4[4];    /* outer source addresses, network order */
    __u8  local_v6[16];
};

#endif /* GTPU_ABI_H */
