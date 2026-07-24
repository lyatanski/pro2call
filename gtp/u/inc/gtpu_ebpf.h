#ifndef GTPU_EBPF_H
#define GTPU_EBPF_H

#include <stdbool.h>
#include <stdint.h>

#include "gtpu_abi.h"

#ifndef API_EXPORT
#define API_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Userspace side of the GTP-U eBPF TC datapath — PLAN.md §13.2, §13.5,
 * §13.6.
 *
 * gtpu_ebpf_open() loads the TC programs (bpf/gtpu_kern.c) through a
 * libbpf skeleton, pins the maps under cfg->pin_dir so forwarding state
 * survives program reloads, and refuses to proceed when the pinned maps
 * were written by an incompatible loader (GTPU_ABI_VERSION mismatch).
 * gtpu_ebpf_attach() creates the clsact qdisc hooks and attaches decap
 * to ingress of the GTP-U-facing interface and encap to egress of the
 * inner-traffic-facing interface.
 *
 * The GTPv2-C control plane keeps the forwarding table in sync through
 * gtpu_teid_add/update/del (default bearer, one tunnel per UE prefix)
 * and gtpu_tft_add/del (dedicated bearers: a traffic filter plus its
 * own TEID pair). Delete-side draining (GTPU_TEID_DRAIN_MS) is the
 * caller's timer job; these calls take effect immediately.
 *
 * All calls returning int use gtpu_err_t codes. The datapath is
 * optional at runtime: without CAP_BPF/CAP_NET_ADMIN (or when built
 * without the BPF toolchain) gtpu_ebpf_open() returns
 * GTPU_E_UNSUPPORTED and the caller falls back to the userspace
 * sendmmsg/recvmmsg path (§0.2).
 */

typedef enum {
    GTPU_OK            = 0,
    GTPU_E_SYS         = -1, /* system/libbpf error, errno set */
    GTPU_E_UNSUPPORTED = -2, /* missing capabilities or non-eBPF build */
    GTPU_E_VERIFIER    = -3, /* program rejected; log dumped to stderr */
    GTPU_E_ABI         = -4, /* pinned maps from an incompatible loader */
    GTPU_E_INVAL       = -5, /* invalid argument */
    GTPU_E_NOENT       = -6, /* no such TEID / filter */
    GTPU_E_EXIST       = -7  /* TEID / filter already installed */
} gtpu_err_t;

typedef struct gtpu_ebpf gtpu_ebpf_t;

typedef struct {
    const char* pin_dir;        /* NULL = GTPU_PIN_DIR; "" = no pinning */
    uint32_t    max_bearers;    /* TEID table size; 0 = GTPU_MAX_BEARERS */
    uint32_t    uplink_ifindex; /* default encap redirect target */
    uint8_t     local_v4[4];    /* outer source addresses, network order */
    uint8_t     local_v6[16];
} gtpu_ebpf_cfg_t;

/* One bearer: a TEID pair plus addressing for both directions.
 * Addresses and MACs are network order / wire format; TEIDs and ports
 * are host order. */
typedef struct {
    uint32_t local_teid;  /* RX map key (this node allocated it) */
    uint32_t remote_teid; /* written to outgoing G-PDUs */
    uint8_t  ebi;         /* EPS bearer id, observability only */

    uint8_t inner_family; /* AF_INET / AF_INET6 — the UE address */
    uint8_t inner_addr[16];
    uint8_t inner_prefixlen; /* 0 = host route (/32 or /128) */

    uint8_t  outer_family; /* AF_INET / AF_INET6 — the peer */
    uint8_t  remote_addr[16];
    uint16_t remote_port; /* 0 = GTPU_PORT */

    uint32_t rx_ifindex; /* decap redirect target; 0 = local stack */
    uint32_t tx_ifindex; /* encap uplink; 0 = cfg->uplink_ifindex */

    uint8_t dst_mac[6]; /* outer L2; used when fib lookup fails */
    uint8_t src_mac[6];
    bool    static_mac; /* skip fib lookup, always use the above */

    bool    has_qfi; /* 5G: emit PDU Session Container ext */
    uint8_t qfi;
} gtpu_tunnel_t;

/* Dedicated bearer: its own TEID pair plus the traffic filter that
 * steers inner packets onto it (subset of a TS 24.008 TFT packet
 * filter — protocol and single ports, 0 = wildcard; ranges expand to
 * multiple filters). tunnel.inner_addr is the inner dst matched (for
 * uplink to a remote peer this is that peer, not the UE). inner_saddr,
 * when set, additionally matches the inner source, so several UEs to one
 * destination stay on their own bearers; all-zero = any source. */
typedef struct {
    gtpu_tunnel_t tunnel;
    uint8_t       proto;           /* inner IPPROTO_*; required */
    uint16_t      ue_port;         /* inner dst port; 0 = any */
    uint16_t      remote_port;     /* inner src port; 0 = any */
    uint8_t       inner_saddr[16]; /* inner src match; all-zero = any */
} gtpu_tft_t;

typedef void (*gtpu_event_cb_t)(void* ctx, const struct gtpu_event* ev);

/* True when the process holds CAP_NET_ADMIN plus CAP_BPF (or
 * CAP_SYS_ADMIN) — the §13.2 capability check. */
API_EXPORT bool gtpu_ebpf_supported(void);

/* Load + pin. *out is NULL on failure. */
API_EXPORT int gtpu_ebpf_open(gtpu_ebpf_t** out, const gtpu_ebpf_cfg_t* cfg);

/* Attach decap to clsact ingress of gtpu_ifindex and encap to clsact
 * egress of inner_ifindex (either may be 0 to skip that direction). */
API_EXPORT int gtpu_ebpf_attach(gtpu_ebpf_t*, uint32_t gtpu_ifindex,
                                uint32_t inner_ifindex);
API_EXPORT int gtpu_ebpf_detach(gtpu_ebpf_t*);

/* Detaches, unloads the programs and frees. Pinned maps stay: the next
 * open() reuses them, which is what makes reloads forwarding-state
 * lossless. Remove cfg->pin_dir to flush state. */
API_EXPORT void gtpu_ebpf_close(gtpu_ebpf_t*);

/* ---- Forwarding table (control plane -> datapath, §13.6) ---- */

API_EXPORT int gtpu_teid_add(gtpu_ebpf_t*, const gtpu_tunnel_t*);
API_EXPORT int gtpu_teid_update(gtpu_ebpf_t*, const gtpu_tunnel_t*);
API_EXPORT int gtpu_teid_del(gtpu_ebpf_t*, const gtpu_tunnel_t*);

API_EXPORT int gtpu_tft_add(gtpu_ebpf_t*, const gtpu_tft_t*);
API_EXPORT int gtpu_tft_del(gtpu_ebpf_t*, const gtpu_tft_t*);

/* ---- Observability ---- */

/* Sums the per-CPU slot for this TEID. Slots are teid & GTPU_STATS_MASK,
 * so distinct TEIDs may share counters (§13.5). */
API_EXPORT int gtpu_stats_read(gtpu_ebpf_t*, uint32_t teid,
                               struct gtpu_stats* out);

/* Drain pending ring buffer events; returns the number consumed or a
 * negative error. Pollable fd for event loop integration below. */
API_EXPORT int gtpu_events_poll(gtpu_ebpf_t*, int timeout_ms, gtpu_event_cb_t,
                                void* ctx);
API_EXPORT int gtpu_events_fd(gtpu_ebpf_t*);

/* ---- Introspection (tests, BPF_PROG_TEST_RUN harnesses) ---- */

typedef enum { GTPU_PROG_DECAP, GTPU_PROG_ENCAP } gtpu_prog_id_t;
typedef enum {
    GTPU_MAP_TEID_RX,
    GTPU_MAP_TEID_TX4,
    GTPU_MAP_TEID_TX6,
    GTPU_MAP_TEID_TFT,
    GTPU_MAP_STATS,
    GTPU_MAP_EVENTS,
    GTPU_MAP_CONFIG
} gtpu_map_id_t;

API_EXPORT int gtpu_ebpf_prog_fd(gtpu_ebpf_t*, gtpu_prog_id_t);
API_EXPORT int gtpu_ebpf_map_fd(gtpu_ebpf_t*, gtpu_map_id_t);

#ifdef __cplusplus
}
#endif

#endif /* GTPU_EBPF_H */
