#include "gtpu_ebpf.h"

#include "mesg.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

/* Built without the BPF toolchain: keep the API linkable, report the
 * datapath unsupported and let callers use the userspace path (§13.2). */
#ifdef GTPU_EBPF_DISABLED

bool gtpu_ebpf_supported(void)
{
    return false;
}

int gtpu_ebpf_open(gtpu_ebpf_t** out, const gtpu_ebpf_cfg_t* cfg)
{
    (void)cfg;
    if (out) *out = NULL;
    MESG_WARN("gtpu: %s", "built without eBPF support, using userspace path");
    return GTPU_E_UNSUPPORTED;
}

int gtpu_ebpf_attach(gtpu_ebpf_t* g, uint32_t rx, uint32_t tx)
{
    (void)g;
    (void)rx;
    (void)tx;
    return GTPU_E_UNSUPPORTED;
}
int gtpu_ebpf_detach(gtpu_ebpf_t* g)
{
    (void)g;
    return GTPU_E_UNSUPPORTED;
}
void gtpu_ebpf_close(gtpu_ebpf_t* g)
{
    (void)g;
}

int gtpu_teid_add(gtpu_ebpf_t* g, const gtpu_tunnel_t* t)
{
    (void)g;
    (void)t;
    return GTPU_E_UNSUPPORTED;
}
int gtpu_teid_update(gtpu_ebpf_t* g, const gtpu_tunnel_t* t)
{
    (void)g;
    (void)t;
    return GTPU_E_UNSUPPORTED;
}
int gtpu_teid_del(gtpu_ebpf_t* g, const gtpu_tunnel_t* t)
{
    (void)g;
    (void)t;
    return GTPU_E_UNSUPPORTED;
}
int gtpu_tft_add(gtpu_ebpf_t* g, const gtpu_tft_t* f)
{
    (void)g;
    (void)f;
    return GTPU_E_UNSUPPORTED;
}
int gtpu_tft_del(gtpu_ebpf_t* g, const gtpu_tft_t* f)
{
    (void)g;
    (void)f;
    return GTPU_E_UNSUPPORTED;
}

int gtpu_stats_read(gtpu_ebpf_t* g, uint32_t teid, struct gtpu_stats* out)
{
    (void)g;
    (void)teid;
    (void)out;
    return GTPU_E_UNSUPPORTED;
}
int gtpu_events_poll(gtpu_ebpf_t* g, int t, gtpu_event_cb_t cb, void* ctx)
{
    (void)g;
    (void)t;
    (void)cb;
    (void)ctx;
    return GTPU_E_UNSUPPORTED;
}
int gtpu_events_fd(gtpu_ebpf_t* g)
{
    (void)g;
    return GTPU_E_UNSUPPORTED;
}
int gtpu_ebpf_prog_fd(gtpu_ebpf_t* g, gtpu_prog_id_t p)
{
    (void)g;
    (void)p;
    return GTPU_E_UNSUPPORTED;
}
int gtpu_ebpf_map_fd(gtpu_ebpf_t* g, gtpu_map_id_t m)
{
    (void)g;
    (void)m;
    return GTPU_E_UNSUPPORTED;
}

#else /* eBPF build */

#include <pthread.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/capability.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "gtpu_kern.skel.h"

#ifndef CAP_BPF
#define CAP_BPF 39
#endif

struct gtpu_ebpf {
    struct gtpu_kern_bpf* skel;
    struct ring_buffer*   rb;
    pthread_mutex_t       lock; /* §13.6: rx+tx map writes atomic */

    bool     rx_attached, tx_attached;
    uint32_t rx_ifindex, tx_ifindex;
    uint32_t rx_handle, rx_priority;
    uint32_t tx_handle, tx_priority;

    gtpu_event_cb_t cb;
    void*           cb_ctx;
};

/* ---- Capability check (§13.2) ---- */

static bool cap_effective(int cap)
{
    struct __user_cap_header_struct h = { _LINUX_CAPABILITY_VERSION_3, 0 };
    struct __user_cap_data_struct   d[2];
    memset(d, 0, sizeof d);
    if (syscall(SYS_capget, &h, d)) return false;
    return d[cap >> 5].effective & (1u << (cap & 31));
}

bool gtpu_ebpf_supported(void)
{
    return cap_effective(CAP_NET_ADMIN) &&
           (cap_effective(CAP_BPF) || cap_effective(CAP_SYS_ADMIN));
}

/* ---- Error mapping ---- */

static int err_sys(int rc)
{
    if (rc >= 0) return GTPU_OK;
    errno = -rc;
    switch (-rc) {
    case EEXIST: return GTPU_E_EXIST;
    case ENOENT: return GTPU_E_NOENT;
    case EPERM:  return GTPU_E_UNSUPPORTED;
    default:     return GTPU_E_SYS;
    }
}

/* ---- Load, pin, ABI check ---- */

static int pin_maps(struct gtpu_kern_bpf* skel, const char* dir)
{
    if (mkdir(dir, 0755) && errno != EEXIST) return GTPU_E_SYS;

    struct bpf_map* map;
    bpf_object__for_each_map(map, skel->obj)
    {
        char path[256];
        snprintf(path, sizeof path, "%s/%s", dir, bpf_map__name(map));
        int rc = bpf_map__set_pin_path(map, path);
        if (rc) return err_sys(rc);
    }
    return GTPU_OK;
}

int gtpu_ebpf_open(gtpu_ebpf_t** out, const gtpu_ebpf_cfg_t* cfg)
{
    if (!out || !cfg) return GTPU_E_INVAL;
    *out = NULL;

    if (!gtpu_ebpf_supported()) {
        MESG_WARN("gtpu: %s",
                  "missing CAP_BPF/CAP_NET_ADMIN, using userspace path");
        return GTPU_E_UNSUPPORTED;
    }

    gtpu_ebpf_t* g = calloc(1, sizeof *g);
    if (!g) return GTPU_E_SYS;
    pthread_mutex_init(&g->lock, NULL);

    /* libbpf's default logger already dumps the full verifier log to
     * stderr when a program is rejected (§13.2). */
    g->skel = gtpu_kern_bpf__open();
    if (!g->skel) {
        free(g);
        return GTPU_E_SYS;
    }

    uint32_t bearers = cfg->max_bearers ? cfg->max_bearers : GTPU_MAX_BEARERS;
    bpf_map__set_max_entries(g->skel->maps.teid_rx_map, bearers);
    bpf_map__set_max_entries(g->skel->maps.teid_tx4_map, bearers);
    bpf_map__set_max_entries(g->skel->maps.teid_tx6_map, bearers);

    /* Pinning makes maps outlive the process: reloads and upgrades
     * keep forwarding state (§13.5). libbpf reuses a compatible pinned
     * map and fails the load on layout mismatch. */
    const char* dir = cfg->pin_dir ? cfg->pin_dir : GTPU_PIN_DIR;
    if (dir[0]) {
        int rc = pin_maps(g->skel, dir);
        if (rc) {
            gtpu_ebpf_close(g);
            return rc;
        }
    }

    int rc = gtpu_kern_bpf__load(g->skel);
    if (rc) {
        MESG_FAIL("gtpu: BPF load failed: %s", strerror(-rc));
        gtpu_ebpf_close(g);
        return -rc == EACCES ? GTPU_E_VERIFIER : err_sys(rc);
    }

    /* ABI check before anything can attach (§13.5): a previous loader
     * instance left its version in the pinned config map. */
    int                cfg_fd = bpf_map__fd(g->skel->maps.gtpu_config_map);
    uint32_t           key    = 0;
    struct gtpu_config kcfg;
    memset(&kcfg, 0, sizeof kcfg);
    if (!bpf_map_lookup_elem(cfg_fd, &key, &kcfg) && kcfg.abi_version &&
        kcfg.abi_version != GTPU_ABI_VERSION) {
        MESG_FAIL("gtpu: pinned maps have ABI v%u, this loader is v%u; "
                  "flush %s to proceed",
                  kcfg.abi_version, GTPU_ABI_VERSION, dir);
        gtpu_ebpf_close(g);
        return GTPU_E_ABI;
    }

    memset(&kcfg, 0, sizeof kcfg);
    kcfg.abi_version    = GTPU_ABI_VERSION;
    kcfg.uplink_ifindex = cfg->uplink_ifindex;
    memcpy(kcfg.local_v4, cfg->local_v4, 4);
    memcpy(kcfg.local_v6, cfg->local_v6, 16);
    rc = bpf_map_update_elem(cfg_fd, &key, &kcfg, BPF_ANY);
    if (rc) {
        gtpu_ebpf_close(g);
        return err_sys(rc);
    }

    *out = g;
    return GTPU_OK;
}

/* ---- TC attach/detach (§13.3, §13.4) ---- */

static int tc_attach_one(uint32_t ifindex, enum bpf_tc_attach_point ap,
                         struct bpf_program* prog, const char* what,
                         uint32_t* handle, uint32_t* priority)
{
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = (int)ifindex,
                        .attach_point = ap);
    int rc = bpf_tc_hook_create(&hook);
    if (rc && rc != -EEXIST) {
        MESG_FAIL("gtpu: clsact create on ifindex %u failed: %s", ifindex,
                  strerror(-rc));
        return err_sys(rc);
    }

    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .prog_fd = bpf_program__fd(prog));
    rc = bpf_tc_attach(&hook, &opts);
    if (rc) {
        MESG_FAIL("gtpu: %s attach on ifindex %u failed: %s", what, ifindex,
                  strerror(-rc));
        return err_sys(rc);
    }

    *handle   = opts.handle;
    *priority = opts.priority;
    MESG_INFO("gtpu: %s attached, ifindex %u prog id %u handle %u prio %u",
              what, ifindex, opts.prog_id, opts.handle, opts.priority);
    return GTPU_OK;
}

static void tc_detach_one(uint32_t ifindex, enum bpf_tc_attach_point ap,
                          uint32_t handle, uint32_t priority)
{
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = (int)ifindex,
                        .attach_point = ap);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .handle = handle,
                        .priority = priority);
    int rc = bpf_tc_detach(&hook, &opts);
    if (rc)
        MESG_WARN("gtpu: detach on ifindex %u failed: %s", ifindex,
                  strerror(-rc));
    /* The clsact qdisc is left in place: destroying it would tear down
     * any other filters on the interface. */
}

int gtpu_ebpf_attach(gtpu_ebpf_t* g, uint32_t gtpu_ifindex,
                     uint32_t inner_ifindex)
{
    if (!g) return GTPU_E_INVAL;

    if (gtpu_ifindex && !g->rx_attached) {
        int rc = tc_attach_one(gtpu_ifindex, BPF_TC_INGRESS,
                               g->skel->progs.gtpu_decap, "decap",
                               &g->rx_handle, &g->rx_priority);
        if (rc) return rc;
        g->rx_ifindex  = gtpu_ifindex;
        g->rx_attached = true;
    }
    if (inner_ifindex && !g->tx_attached) {
        int rc = tc_attach_one(inner_ifindex, BPF_TC_EGRESS,
                               g->skel->progs.gtpu_encap, "encap",
                               &g->tx_handle, &g->tx_priority);
        if (rc) return rc;
        g->tx_ifindex  = inner_ifindex;
        g->tx_attached = true;
    }
    return GTPU_OK;
}

int gtpu_ebpf_detach(gtpu_ebpf_t* g)
{
    if (!g) return GTPU_E_INVAL;
    if (g->rx_attached) {
        tc_detach_one(g->rx_ifindex, BPF_TC_INGRESS, g->rx_handle,
                      g->rx_priority);
        g->rx_attached = false;
    }
    if (g->tx_attached) {
        tc_detach_one(g->tx_ifindex, BPF_TC_EGRESS, g->tx_handle,
                      g->tx_priority);
        g->tx_attached = false;
    }
    return GTPU_OK;
}

void gtpu_ebpf_close(gtpu_ebpf_t* g)
{
    if (!g) return;
    gtpu_ebpf_detach(g);
    if (g->rb) ring_buffer__free(g->rb);
    if (g->skel) gtpu_kern_bpf__destroy(g->skel);
    pthread_mutex_destroy(&g->lock);
    free(g);
}

/* ---- Forwarding table (§13.6) ---- */

static int tun_check(const gtpu_tunnel_t* t)
{
    if (!t || !t->local_teid || !t->remote_teid) return GTPU_E_INVAL;
    if (t->inner_family != AF_INET && t->inner_family != AF_INET6)
        return GTPU_E_INVAL;
    if (t->outer_family != AF_INET && t->outer_family != AF_INET6)
        return GTPU_E_INVAL;
    uint8_t max = t->inner_family == AF_INET ? 32 : 128;
    if (t->inner_prefixlen > max) return GTPU_E_INVAL;
    return GTPU_OK;
}

static void tun_to_rx(const gtpu_tunnel_t* t, struct gtpu_rx_tun* rx)
{
    memset(rx, 0, sizeof *rx);
    rx->inner_family = t->inner_family;
    rx->ebi          = t->ebi;
    memcpy(rx->inner_addr, t->inner_addr, 16);
    rx->ifindex = t->rx_ifindex;
}

static void tun_to_tx(const gtpu_tunnel_t* t, struct gtpu_tx_tun* tx)
{
    memset(tx, 0, sizeof *tx);
    tx->outer_family = t->outer_family;
    tx->ebi          = t->ebi;
    tx->qfi          = t->qfi;
    if (t->static_mac) tx->flags |= GTPU_TXF_STATIC_MAC;
    if (t->has_qfi) tx->flags |= GTPU_TXF_QFI;
    memcpy(tx->remote_addr, t->remote_addr, 16);
    memcpy(tx->dst_mac, t->dst_mac, 6);
    memcpy(tx->src_mac, t->src_mac, 6);
    tx->remote_port = htons(t->remote_port ? t->remote_port : GTPU_PORT);
    tx->remote_teid = t->remote_teid;
    tx->local_teid  = t->local_teid;
    tx->ifindex     = t->tx_ifindex;
}

/* Fills the LPM key for the tunnel's inner prefix; returns the map fd.
 * A gtpu_lpm6_key buffer is large enough for either family. */
static int tun_lpm(gtpu_ebpf_t* g, const gtpu_tunnel_t* t, void* key)
{
    if (t->inner_family == AF_INET) {
        struct gtpu_lpm4_key* k = key;
        k->prefixlen            = t->inner_prefixlen ? t->inner_prefixlen : 32;
        memcpy(k->addr, t->inner_addr, 4);
        return bpf_map__fd(g->skel->maps.teid_tx4_map);
    }
    struct gtpu_lpm6_key* k = key;
    k->prefixlen            = t->inner_prefixlen ? t->inner_prefixlen : 128;
    memcpy(k->addr, t->inner_addr, 16);
    return bpf_map__fd(g->skel->maps.teid_tx6_map);
}

static int teid_write(gtpu_ebpf_t* g, const gtpu_tunnel_t* t, uint64_t flags)
{
    int rc = tun_check(t);
    if (rc) return rc;

    struct gtpu_rx_tun   rx;
    struct gtpu_tx_tun   tx;
    struct gtpu_lpm6_key lpm;
    tun_to_rx(t, &rx);
    tun_to_tx(t, &tx);
    int lpm_fd = tun_lpm(g, t, &lpm);
    int rx_fd  = bpf_map__fd(g->skel->maps.teid_rx_map);

    pthread_mutex_lock(&g->lock);
    rc = bpf_map_update_elem(rx_fd, &t->local_teid, &rx, flags);
    if (!rc) {
        rc = bpf_map_update_elem(lpm_fd, &lpm, &tx, flags);
        if (rc && flags == BPF_NOEXIST) /* keep add atomic: roll back */
            bpf_map_delete_elem(rx_fd, &t->local_teid);
    }
    pthread_mutex_unlock(&g->lock);

    if (rc && flags == BPF_EXIST && -rc == ENOENT)
        MESG_WARN("gtpu: update of TEID %u raced with delete", t->local_teid);
    return err_sys(rc);
}

int gtpu_teid_add(gtpu_ebpf_t* g, const gtpu_tunnel_t* t)
{
    if (!g) return GTPU_E_INVAL;
    return teid_write(g, t, BPF_NOEXIST);
}

/* BPF_EXIST so an update cannot resurrect an entry a concurrent delete
 * just removed (§13.6). */
int gtpu_teid_update(gtpu_ebpf_t* g, const gtpu_tunnel_t* t)
{
    if (!g) return GTPU_E_INVAL;
    return teid_write(g, t, BPF_EXIST);
}

int gtpu_teid_del(gtpu_ebpf_t* g, const gtpu_tunnel_t* t)
{
    if (!g) return GTPU_E_INVAL;
    int rc = tun_check(t);
    if (rc) return rc;

    struct gtpu_lpm6_key lpm;
    int                  lpm_fd = tun_lpm(g, t, &lpm);
    int                  rx_fd  = bpf_map__fd(g->skel->maps.teid_rx_map);

    pthread_mutex_lock(&g->lock);
    int rc1 = bpf_map_delete_elem(rx_fd, &t->local_teid);
    int rc2 = bpf_map_delete_elem(lpm_fd, &lpm);
    pthread_mutex_unlock(&g->lock);

    return err_sys(rc1 ? rc1 : rc2);
}

/* ---- Dedicated bearers (TFT filters) ---- */

static int tft_key_build(const gtpu_tft_t* f, struct gtpu_tft_key* k)
{
    if (!f || !f->proto) return GTPU_E_INVAL;
    int rc = tun_check(&f->tunnel);
    if (rc) return rc;

    memset(k, 0, sizeof *k);
    k->family      = f->tunnel.inner_family;
    k->proto       = f->proto;
    k->ue_port     = htons(f->ue_port);
    k->remote_port = htons(f->remote_port);
    memcpy(k->ue_addr, f->tunnel.inner_addr, 16);
    return GTPU_OK;
}

int gtpu_tft_add(gtpu_ebpf_t* g, const gtpu_tft_t* f)
{
    if (!g) return GTPU_E_INVAL;

    struct gtpu_tft_key k;
    int                 rc = tft_key_build(f, &k);
    if (rc) return rc;

    struct gtpu_rx_tun rx;
    struct gtpu_tx_tun tx;
    tun_to_rx(&f->tunnel, &rx);
    tun_to_tx(&f->tunnel, &tx);

    /* tunnel.inner_addr is the filter's inner-dst *classification* address
     * (teid_tft_map key ue_addr), which is not necessarily the bearer's own
     * UE address: a filter may steer uplink by its remote destination (the
     * TS 24.008 packet filter matches inner dst = the remote side), in which
     * case inner_addr is that remote address, not the UE. The decap rx entry
     * must therefore not gate the downlink on it — the downlink's inner dst
     * is the UE, which would mismatch and be dropped as malformed. The TEID
     * alone identifies the bearer on decap, so clear the rx inner-dst check
     * (all-zero = no check). A default-bearer tunnel (gtpu_teid_add), whose
     * inner_addr really is the UE, keeps its check. */
    memset(rx.inner_addr, 0, sizeof rx.inner_addr);

    int rx_fd  = bpf_map__fd(g->skel->maps.teid_rx_map);
    int tft_fd = bpf_map__fd(g->skel->maps.teid_tft_map);

    pthread_mutex_lock(&g->lock);
    rc = bpf_map_update_elem(rx_fd, &f->tunnel.local_teid, &rx, BPF_NOEXIST);
    if (!rc) {
        rc = bpf_map_update_elem(tft_fd, &k, &tx, BPF_NOEXIST);
        if (rc) bpf_map_delete_elem(rx_fd, &f->tunnel.local_teid);
    }
    pthread_mutex_unlock(&g->lock);
    return err_sys(rc);
}

int gtpu_tft_del(gtpu_ebpf_t* g, const gtpu_tft_t* f)
{
    if (!g) return GTPU_E_INVAL;

    struct gtpu_tft_key k;
    int                 rc = tft_key_build(f, &k);
    if (rc) return rc;

    int rx_fd  = bpf_map__fd(g->skel->maps.teid_rx_map);
    int tft_fd = bpf_map__fd(g->skel->maps.teid_tft_map);

    pthread_mutex_lock(&g->lock);
    int rc1 = bpf_map_delete_elem(tft_fd, &k);
    int rc2 = bpf_map_delete_elem(rx_fd, &f->tunnel.local_teid);
    pthread_mutex_unlock(&g->lock);
    return err_sys(rc1 ? rc1 : rc2);
}

/* ---- Observability ---- */

int gtpu_stats_read(gtpu_ebpf_t* g, uint32_t teid, struct gtpu_stats* out)
{
    if (!g || !out) return GTPU_E_INVAL;

    int ncpu = libbpf_num_possible_cpus();
    if (ncpu <= 0) return GTPU_E_SYS;

    struct gtpu_stats* per = calloc((size_t)ncpu, sizeof *per);
    if (!per) return GTPU_E_SYS;

    uint32_t key = teid & GTPU_STATS_MASK;
    int      rc = bpf_map_lookup_elem(bpf_map__fd(g->skel->maps.gtpu_stats_map),
                                      &key, per);
    if (rc) {
        free(per);
        return err_sys(rc);
    }

    memset(out, 0, sizeof *out);
    for (int c = 0; c < ncpu; c++) {
        out->rx_pkts += per[c].rx_pkts;
        out->rx_bytes += per[c].rx_bytes;
        out->tx_pkts += per[c].tx_pkts;
        out->tx_bytes += per[c].tx_bytes;
        out->err_unknown_teid += per[c].err_unknown_teid;
        out->err_malformed += per[c].err_malformed;
        out->err_tx_no_neigh += per[c].err_tx_no_neigh;
        out->err_ringbuf_full += per[c].err_ringbuf_full;
        out->err_abi += per[c].err_abi;
    }
    free(per);
    return GTPU_OK;
}

static int event_trampoline(void* ctx, void* data, size_t len)
{
    gtpu_ebpf_t* g = ctx;
    if (len >= sizeof(struct gtpu_event) && g->cb) g->cb(g->cb_ctx, data);
    return 0;
}

static int events_open(gtpu_ebpf_t* g)
{
    if (g->rb) return GTPU_OK;
    g->rb = ring_buffer__new(bpf_map__fd(g->skel->maps.gtpu_events),
                             event_trampoline, g, NULL);
    return g->rb ? GTPU_OK : GTPU_E_SYS;
}

int gtpu_events_poll(gtpu_ebpf_t* g, int timeout_ms, gtpu_event_cb_t cb,
                     void* ctx)
{
    if (!g || !cb) return GTPU_E_INVAL;
    int rc = events_open(g);
    if (rc) return rc;

    g->cb     = cb;
    g->cb_ctx = ctx;
    rc        = ring_buffer__poll(g->rb, timeout_ms);
    g->cb     = NULL;
    g->cb_ctx = NULL;
    return rc < 0 ? err_sys(rc) : rc;
}

int gtpu_events_fd(gtpu_ebpf_t* g)
{
    if (!g) return GTPU_E_INVAL;
    int rc = events_open(g);
    if (rc) return rc;
    return ring_buffer__epoll_fd(g->rb);
}

/* ---- Introspection ---- */

int gtpu_ebpf_prog_fd(gtpu_ebpf_t* g, gtpu_prog_id_t id)
{
    if (!g) return GTPU_E_INVAL;
    switch (id) {
    case GTPU_PROG_DECAP: return bpf_program__fd(g->skel->progs.gtpu_decap);
    case GTPU_PROG_ENCAP: return bpf_program__fd(g->skel->progs.gtpu_encap);
    }
    return GTPU_E_INVAL;
}

int gtpu_ebpf_map_fd(gtpu_ebpf_t* g, gtpu_map_id_t id)
{
    if (!g) return GTPU_E_INVAL;
    switch (id) {
    case GTPU_MAP_TEID_RX:  return bpf_map__fd(g->skel->maps.teid_rx_map);
    case GTPU_MAP_TEID_TX4: return bpf_map__fd(g->skel->maps.teid_tx4_map);
    case GTPU_MAP_TEID_TX6: return bpf_map__fd(g->skel->maps.teid_tx6_map);
    case GTPU_MAP_TEID_TFT: return bpf_map__fd(g->skel->maps.teid_tft_map);
    case GTPU_MAP_STATS:    return bpf_map__fd(g->skel->maps.gtpu_stats_map);
    case GTPU_MAP_EVENTS:   return bpf_map__fd(g->skel->maps.gtpu_events);
    case GTPU_MAP_CONFIG:   return bpf_map__fd(g->skel->maps.gtpu_config_map);
    }
    return GTPU_E_INVAL;
}

#endif /* GTPU_EBPF_DISABLED */
