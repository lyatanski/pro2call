/* gtp::UserPlane — facade over the gtp/u eBPF loader (gtpu_ebpf.h):
 * string addresses in, kernel forwarding-table entries out. */

#include "gtpxx_intl.hpp"

#include "gtpu_ebpf.h"

#include <cstring>
#include <exception>
#include <netinet/in.h>
#include <sys/socket.h>

namespace gtp
{

using namespace intl;

static void check(int rc, const char* doing)
{
    if (rc == GTPU_OK) return;
    const char* what;
    switch (rc) {
    case GTPU_E_SYS: what = "system/libbpf error"; break;
    case GTPU_E_UNSUPPORTED:
        what = "eBPF datapath unavailable "
               "(missing CAP_BPF/CAP_NET_ADMIN or non-eBPF build)";
        break;
    case GTPU_E_VERIFIER: what = "BPF program rejected by the verifier"; break;
    case GTPU_E_ABI:      what = "pinned maps from an incompatible loader"; break;
    case GTPU_E_INVAL:    what = "invalid argument"; break;
    case GTPU_E_NOENT:    what = "no such TEID/filter"; break;
    case GTPU_E_EXIST:    what = "TEID/filter already installed"; break;
    default:              what = "error"; break;
    }
    throw Error(std::string(doing) + ": " + what, rc);
}

/* Literal address -> (family, 16-byte buffer, IPv4 in the first 4). */
static uint8_t inner_addr_parse(const std::string& s, uint8_t out[16])
{
    std::memset(out, 0, 16);
    if (s.find(':') != std::string::npos) {
        addr6_parse(s, out);
        return AF_INET6;
    }
    addr4_parse(s, out);
    return AF_INET;
}

static gtpu_tunnel_t tunnel_to_c(const Tunnel& t)
{
    gtpu_tunnel_t c;
    std::memset(&c, 0, sizeof c);
    c.local_teid  = t.local_teid;
    c.remote_teid = t.remote_teid;
    c.ebi         = t.ebi;

    if (t.ue_addr.empty()) throw Error("tunnel needs ue_addr");
    if (t.remote_addr.empty()) throw Error("tunnel needs remote_addr");
    c.inner_family    = inner_addr_parse(t.ue_addr, c.inner_addr);
    c.inner_prefixlen = t.prefix_len;
    c.outer_family    = inner_addr_parse(t.remote_addr, c.remote_addr);
    c.remote_port     = t.remote_port;

    c.rx_ifindex = t.rx_ifindex;
    c.tx_ifindex = t.tx_ifindex;
    mac_parse(t.dst_mac, c.dst_mac);
    mac_parse(t.src_mac, c.src_mac);
    c.static_mac = t.static_mac;
    if (t.qfi >= 0) {
        c.has_qfi = true;
        c.qfi     = static_cast<uint8_t>(t.qfi);
    }
    return c;
}

static gtpu_tft_t tft_to_c(const TrafficFilter& f)
{
    gtpu_tft_t c;
    std::memset(&c, 0, sizeof c);
    if (f.proto == 0)
        throw Error("traffic filter needs proto (inner IPPROTO_*)");
    c.tunnel      = tunnel_to_c(f.tunnel);
    c.proto       = f.proto;
    c.ue_port     = f.ue_port;
    c.remote_port = f.remote_port;
    if (!f.ue_saddr.empty()) inner_addr_parse(f.ue_saddr, c.inner_saddr);
    return c;
}

bool UserPlane::supported()
{
    return gtpu_ebpf_supported();
}

UserPlane::UserPlane(const UserPlaneConfig& cfg) : bpf_(nullptr)
{
    gtpu_ebpf_cfg_t c;
    std::memset(&c, 0, sizeof c);
    c.pin_dir        = cfg.pin_dir.c_str(); /* "" = no pinning */
    c.max_bearers    = cfg.max_bearers;
    c.uplink_ifindex = cfg.uplink_ifindex;
    if (!cfg.local_v4.empty()) addr4_parse(cfg.local_v4, c.local_v4);
    if (!cfg.local_v6.empty()) addr6_parse(cfg.local_v6, c.local_v6);
    check(gtpu_ebpf_open(&bpf_, &c), "open GTP-U datapath");
}

UserPlane::~UserPlane()
{
    gtpu_ebpf_close(bpf_);
}

void UserPlane::attach(uint32_t gtpu_ifindex, uint32_t inner_ifindex)
{
    check(gtpu_ebpf_attach(bpf_, gtpu_ifindex, inner_ifindex), "attach");
}

void UserPlane::detach()
{
    check(gtpu_ebpf_detach(bpf_), "detach");
}

void UserPlane::add_tunnel(const Tunnel& t)
{
    gtpu_tunnel_t c = tunnel_to_c(t);
    check(gtpu_teid_add(bpf_, &c), "add tunnel");
}

void UserPlane::update_tunnel(const Tunnel& t)
{
    gtpu_tunnel_t c = tunnel_to_c(t);
    check(gtpu_teid_update(bpf_, &c), "update tunnel");
}

void UserPlane::del_tunnel(const Tunnel& t)
{
    gtpu_tunnel_t c = tunnel_to_c(t);
    check(gtpu_teid_del(bpf_, &c), "delete tunnel");
}

void UserPlane::add_filter(const TrafficFilter& f)
{
    gtpu_tft_t c = tft_to_c(f);
    check(gtpu_tft_add(bpf_, &c), "add traffic filter");
}

void UserPlane::del_filter(const TrafficFilter& f)
{
    gtpu_tft_t c = tft_to_c(f);
    check(gtpu_tft_del(bpf_, &c), "delete traffic filter");
}

TunnelStats UserPlane::stats(uint32_t local_teid)
{
    struct gtpu_stats s;
    std::memset(&s, 0, sizeof s);
    check(gtpu_stats_read(bpf_, local_teid, &s), "read stats");
    TunnelStats out;
    out.rx_pkts          = s.rx_pkts;
    out.rx_bytes         = s.rx_bytes;
    out.tx_pkts          = s.tx_pkts;
    out.tx_bytes         = s.tx_bytes;
    out.err_unknown_teid = s.err_unknown_teid;
    out.err_malformed    = s.err_malformed;
    out.err_tx_no_neigh  = s.err_tx_no_neigh;
    out.err_ringbuf_full = s.err_ringbuf_full;
    out.err_abi          = s.err_abi;
    return out;
}

int UserPlane::events_fd() const
{
    return gtpu_events_fd(bpf_);
}

namespace
{
struct EvCtx {
    UserPlaneEventHandler* h;
    std::exception_ptr     pending;
};
} /* anonymous namespace */

/* Handler exceptions must not unwind through libbpf's ring-buffer C
 * frames; capture and rethrow after gtpu_events_poll returns. */
static void ev_tramp(void* ud, const struct gtpu_event* ev)
{
    auto* ctx = static_cast<EvCtx*>(ud);
    if (ctx->pending) return; /* already failing; drain silently */
    try {
        std::string src;
        if (ev->src_family == AF_INET) src = addr4_format(ev->src_addr);
        else if (ev->src_family == AF_INET6) src = addr6_format(ev->src_addr);
        ctx->h->on_event(static_cast<int>(ev->kind), ev->teid, src,
                         ntohs(ev->src_port));
    } catch (...) {
        ctx->pending = std::current_exception();
    }
}

int UserPlane::poll_events(int timeout_ms, UserPlaneEventHandler* h)
{
    if (!h) throw Error("event handler is null");
    EvCtx ctx;
    ctx.h = h;
    int n = gtpu_events_poll(bpf_, timeout_ms, ev_tramp, &ctx);
    if (ctx.pending) std::rethrow_exception(ctx.pending);
    if (n < 0) check(n, "poll events");
    return n;
}

} /* namespace gtp */
