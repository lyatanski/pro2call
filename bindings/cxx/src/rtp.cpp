/* The RTP media session: sequencing on send, source/loss/jitter
 * tracking on receive, periodic compound RTCP and handler dispatch, on
 * top of net_loop + net_sock and the C codec.
 *
 * The loop is the netxx one (net::Loop::raw()/life(), exactly as the
 * gtp session layer uses it), so media shares the script's single
 * dispatcher with GTP-C and SIP. Handler callbacks may be Lua
 * trampolines; any exception they raise is deferred through the loop so
 * it never unwinds through net_loop's C frames, and rethrown from
 * Loop::step()/run(). */

#include "rtpxx.hpp"

#include "net_sock.h"

#include <arpa/inet.h>
#include <cstring>
#include <ctime>
#include <memory>

namespace rtp
{

/* ---- address helpers ---- */

static net_addr addr_of(const std::string& host, uint16_t port)
{
    net_addr a;
    if (net_addr_from(&a, host.empty() ? nullptr : host.c_str(), port) !=
        NET_OK)
        throw Error("bad address: " + host);
    return a;
}

static void addr_split(const net_addr& a, std::string& host, uint16_t& port)
{
    port                       = net_addr_port(&a);
    char buf[INET6_ADDRSTRLEN] = "";
    if (a.sa.sa_family == AF_INET) {
        inet_ntop(AF_INET, &a.v4.sin_addr, buf, sizeof buf);
    } else {
        const struct in6_addr* i6 = &a.v6.sin6_addr;
        if (IN6_IS_ADDR_V4MAPPED(i6))
            inet_ntop(AF_INET, &i6->s6_addr[12], buf, sizeof buf);
        else inet_ntop(AF_INET6, i6, buf, sizeof buf);
    }
    host = buf;
}

/* Non-cryptographic randomness for SSRC/seq/timestamp offsets. */
static uint32_t rnd32()
{
    static uint64_t state;
    if (!state) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        state = (uint64_t)ts.tv_nsec ^ ((uint64_t)ts.tv_sec << 20) ^
                (uintptr_t)&state;
    }
    state = state * 6364136223846793005ULL + 1442695040888963407ULL;
    return (uint32_t)(state >> 32);
}

/* ---- default (no-op) handler bodies ---- */

void StreamHandler::on_rtp(const Packet&, const std::string&, uint16_t)
{
}
void StreamHandler::on_sender_report(uint32_t, const SenderInfo&,
                                      const std::vector<ReportBlock>&)
{
}
void StreamHandler::on_receiver_report(uint32_t,
                                        const std::vector<ReportBlock>&)
{
}
void StreamHandler::on_bye(uint32_t, const std::string&)
{
}

/* ---- Packet codec ---- */

std::string Packet::encode() const
{
    if (csrc.size() > RTP_MAX_CSRC) throw Error("too many CSRCs", RTP_E_INVAL);

    rtp_pkt_t p;
    std::memset(&p, 0, sizeof p);
    p.marker = marker;
    p.pt     = (uint8_t)pt;
    p.seq    = (uint16_t)seq;
    p.ts     = ts;
    p.ssrc   = ssrc;
    p.cc     = (uint8_t)csrc.size();
    for (size_t i = 0; i < csrc.size(); i++)
        p.csrc[i] = csrc[i];
    p.has_ext     = has_ext;
    p.ext_profile = (uint16_t)ext_profile;
    p.ext         = reinterpret_cast<const uint8_t*>(ext.data());
    p.ext_len     = (uint32_t)ext.size();
    p.payload     = reinterpret_cast<const uint8_t*>(payload.data());
    p.payload_len = (uint32_t)payload.size();

    std::string out;
    out.resize(12 + csrc.size() * 4 + (has_ext ? 4 + ext.size() : 0) +
               payload.size());
    int n = rtp_pkt_encode(&p, &out[0], out.size());
    if (n < 0) throw Error("RTP encode failed", n);
    out.resize((size_t)n);
    return out;
}

static Packet packet_from(const rtp_pkt_t& p)
{
    Packet out;
    out.pt     = p.pt;
    out.marker = p.marker;
    out.seq    = p.seq;
    out.ts     = p.ts;
    out.ssrc   = p.ssrc;
    out.csrc.assign(p.csrc, p.csrc + p.cc);
    out.has_ext = p.has_ext;
    if (p.has_ext) {
        out.ext_profile = p.ext_profile;
        out.ext.assign(reinterpret_cast<const char*>(p.ext), p.ext_len);
    }
    out.payload.assign(reinterpret_cast<const char*>(p.payload), p.payload_len);
    return out;
}

Packet Packet::parse(const std::string& wire)
{
    rtp_pkt_t p;
    int       rc = rtp_pkt_parse(&p, wire.data(), wire.size());
    if (rc != RTP_OK) throw Error("RTP parse failed", rc);
    return packet_from(p);
}

/* ---- Stream ---- */

struct Stream::Impl {
    net::Loop*                 loop = nullptr;
    std::shared_ptr<net_loop*> loop_life;
    net_sock                   rtp_sock, rtcp_sock;

    bool     has_peer = false;
    net_addr peer_rtp, peer_rtcp;

    uint32_t    ssrc;
    uint16_t    seq;
    uint32_t    ts;
    int         pt         = RTP_PT_PCMU;
    unsigned    clock_rate = 8000;
    unsigned    rtcp_ms    = 5000;
    std::string cname;

    uint64_t timer_id   = 0;
    bool     reports_on = false;

    uint64_t tx_packets = 0, tx_octets = 0;
    bool     sent_since_report = false;

    bool         have_source = false;
    rtp_source_t source;
    uint64_t     rx_packets = 0, rx_octets = 0;
    uint32_t     last_sr_lsr     = 0; /* middle NTP bits of last SR */
    uint64_t     last_sr_arrival = 0; /* net_now_ms at its arrival  */
    double       rtt_ms          = -1;

    /* The loop through its liveness token, so a session outliving the
     * loop under a garbage collector unregisters nothing (see
     * net::Loop::life()). */
    net_loop* lp() const
    {
        return *loop_life;
    }

    static void rtp_tramp(void* ud, int, unsigned)
    {
        auto* s = static_cast<Stream*>(ud);
        try {
            s->on_rtp_readable();
        } catch (...) {
            s->impl_->loop->defer_exception();
        }
    }

    static void rtcp_tramp(void* ud, int, unsigned)
    {
        auto* s = static_cast<Stream*>(ud);
        try {
            s->on_rtcp_readable();
        } catch (...) {
            s->impl_->loop->defer_exception();
        }
    }

    static void timer_tramp(void* ud)
    {
        auto* s            = static_cast<Stream*>(ud);
        s->impl_->timer_id = 0;
        try {
            s->on_report_timer();
        } catch (...) {
            s->impl_->loop->defer_exception();
        }
    }
};

Stream::Stream(net::Loop& loop, const std::string& local_host,
                 uint16_t rtp_port, bool nonlocal_src)
    : impl_(new Impl)
{
    std::unique_ptr<Impl> guard(impl_);
    impl_->loop      = &loop;
    impl_->loop_life = loop.life();
    impl_->ssrc      = rnd32();
    impl_->seq       = (uint16_t)rnd32();
    impl_->ts        = rnd32();

    unsigned flags = NET_BOUND;
    if (nonlocal_src) flags |= NET_NONLOCAL_SRC;

    net_addr a  = addr_of(local_host, rtp_port);
    int      rc = net_udp_open(&impl_->rtp_sock, &a, flags);
    if (rc != NET_OK)
        throw Error(
            "cannot bind " + local_host + ":" + std::to_string(rtp_port), rc);

    /* RTCP on the next port (RFC 3550 §11); with an ephemeral RTP
     * port, next to whatever was assigned. */
    uint16_t rp = net_addr_port(&impl_->rtp_sock.local);
    net_addr b  = addr_of(local_host, (uint16_t)(rp + 1));
    rc          = net_udp_open(&impl_->rtcp_sock, &b, flags);
    if (rc != NET_OK) {
        net_sock_close(&impl_->rtp_sock);
        throw Error("cannot bind RTCP port " + std::to_string(rp + 1), rc);
    }

    if (net_loop_add(impl_->lp(), impl_->rtp_sock.fd, NET_RD, Impl::rtp_tramp,
                     this) != NET_OK ||
        net_loop_add(impl_->lp(), impl_->rtcp_sock.fd, NET_RD, Impl::rtcp_tramp,
                     this) != NET_OK) {
        net_loop_del(impl_->lp(), impl_->rtp_sock.fd);
        net_sock_close(&impl_->rtp_sock);
        net_sock_close(&impl_->rtcp_sock);
        throw Error("cannot register session with the loop");
    }

    impl_->cname = local_host + ":" + std::to_string(rp);
    guard.release();
}

Stream::~Stream()
{
    /* The loop may already be gone when a garbage collector tears the
     * two down in the wrong order; unregister only while it lives. */
    net_loop* l = *impl_->loop_life;
    if (l) {
        net_loop_del(l, impl_->rtp_sock.fd);
        net_loop_del(l, impl_->rtcp_sock.fd);
        if (impl_->timer_id) net_loop_cancel(l, impl_->timer_id);
    }
    net_sock_close(&impl_->rtp_sock);
    net_sock_close(&impl_->rtcp_sock);
    delete impl_;
}

void Stream::set_peer(const std::string& host, uint16_t rtp_port)
{
    impl_->peer_rtp   = addr_of(host, rtp_port);
    impl_->peer_rtcp  = addr_of(host, (uint16_t)(rtp_port + 1));
    impl_->has_peer   = true;
    impl_->reports_on = true;
    arm_timer();
}

void Stream::set_payload_type(int pt)
{
    if (pt < 0 || pt > 127)
        throw Error("payload type out of range", RTP_E_INVAL);
    impl_->pt = pt;
}

void Stream::set_clock_rate(unsigned hz)
{
    if (hz == 0) throw Error("clock rate is zero", RTP_E_INVAL);
    impl_->clock_rate = hz;
}

void Stream::set_cname(const std::string& cname)
{
    if (cname.size() > 255) throw Error("CNAME too long", RTP_E_INVAL);
    impl_->cname = cname;
}

void Stream::set_ssrc(uint32_t ssrc)
{
    impl_->ssrc = ssrc;
}
void Stream::set_rtcp_interval(unsigned ms)
{
    impl_->rtcp_ms = ms;
}

uint32_t Stream::ssrc() const
{
    return impl_->ssrc;
}
uint16_t Stream::rtp_port() const
{
    return net_addr_port(&impl_->rtp_sock.local);
}

std::string Stream::local_host() const
{
    std::string host;
    uint16_t    port;
    addr_split(impl_->rtp_sock.local, host, port);
    return host;
}

void Stream::send(const std::string& payload, uint32_t ts_step, bool marker)
{
    Packet p;
    p.pt      = impl_->pt;
    p.marker  = marker;
    p.seq     = impl_->seq;
    p.ts      = impl_->ts;
    p.ssrc    = impl_->ssrc;
    p.payload = payload;
    send_packet(p);
    impl_->seq = (uint16_t)(impl_->seq + 1);
    impl_->ts += ts_step;
}

void Stream::send_packet(const Packet& p)
{
    if (!impl_->has_peer) throw Error("no peer set");
    std::string wire = p.encode();
    ssize_t     n    = net_udp_send(&impl_->rtp_sock, wire.data(), wire.size(),
                                    &impl_->peer_rtp);
    if (n < 0) throw Error("RTP send failed", (int)n);
    impl_->tx_packets++;
    impl_->tx_octets += p.payload.size();
    impl_->sent_since_report = true;
}

void Stream::bye(const std::string& reason)
{
    if (reason.size() > 255) throw Error("BYE reason too long", RTP_E_INVAL);
    send_report(true, reason);
    impl_->reports_on = false;
    if (impl_->timer_id) {
        net_loop* l = *impl_->loop_life;
        if (l) net_loop_cancel(l, impl_->timer_id);
        impl_->timer_id = 0;
    }
}

Stats Stream::stats() const
{
    Stats s;
    s.local_ssrc = impl_->ssrc;
    s.tx_packets = impl_->tx_packets;
    s.tx_octets  = impl_->tx_octets;
    s.rx_packets = impl_->rx_packets;
    s.rx_octets  = impl_->rx_octets;
    s.rtt_ms     = impl_->rtt_ms;
    if (impl_->have_source) {
        const rtp_source_t* src = &impl_->source;
        s.remote_ssrc           = src->ssrc;
        uint32_t expected = src->cycles + src->max_seq - src->base_seq + 1;
        s.rx_lost         = (int)(expected - src->received);
        s.rx_jitter       = src->jitter >> 4;
    }
    return s;
}

/* ---- receive paths ---- */

void Stream::on_rtp_readable()
{
    uint8_t  buf[4096];
    net_addr from;
    for (;;) {
        ssize_t n = net_udp_recv(&impl_->rtp_sock, buf, sizeof buf, &from, -1);
        if (n < 0) break; /* drained (or transient error) */

        rtp_pkt_t p;
        if (rtp_pkt_parse(&p, buf, (size_t)n) != RTP_OK)
            continue; /* not RTP; drop */

        if (!impl_->have_source) {
            rtp_source_init(&impl_->source, p.ssrc, p.seq);
            impl_->have_source = true;
        }
        if (p.ssrc == impl_->source.ssrc &&
            rtp_source_update(&impl_->source, p.seq)) {
            uint32_t arrival =
                (uint32_t)(net_now_ms() * impl_->clock_rate / 1000);
            rtp_source_jitter(&impl_->source, p.ts, arrival);
        }
        impl_->rx_packets++;
        impl_->rx_octets += p.payload_len;

        if (handler_) {
            std::string host;
            uint16_t    port;
            addr_split(from, host, port);
            handler_->on_rtp(packet_from(p), host, port);
        }
    }
}

void Stream::on_rtcp_readable()
{
    uint8_t  buf[4096];
    net_addr from;
    for (;;) {
        ssize_t n = net_udp_recv(&impl_->rtcp_sock, buf, sizeof buf, &from, -1);
        if (n < 0) break;

        rtcp_iter_t it;
        rtcp_view_t v;
        rtcp_iter_init(&it, buf, (size_t)n);
        while (rtcp_iter_next(&it, &v) == 1) {
            rtcp_rep_t rep;
            switch (v.type) {
            case RTCP_SR:
                if (rtcp_sr_parse(&v, &rep) != RTP_OK) break;
                /* remember for the lsr/dlsr of our next report */
                impl_->last_sr_lsr = (rep.ntp_sec << 16) | (rep.ntp_frac >> 16);
                impl_->last_sr_arrival = net_now_ms();
                note_rtt(rep);
                if (handler_) {
                    SenderInfo si;
                    si.ntp_sec      = rep.ntp_sec;
                    si.ntp_frac     = rep.ntp_frac;
                    si.rtp_ts       = rep.rtp_ts;
                    si.packet_count = rep.pkt_count;
                    si.octet_count  = rep.octet_count;
                    handler_->on_sender_report(rep.ssrc, si,
                                               report_blocks(rep));
                }
                break;
            case RTCP_RR:
                if (rtcp_rr_parse(&v, &rep) != RTP_OK) break;
                note_rtt(rep);
                if (handler_)
                    handler_->on_receiver_report(rep.ssrc, report_blocks(rep));
                break;
            case RTCP_BYE: {
                rtcp_bye_t bye;
                if (rtcp_bye_parse(&v, &bye) != RTP_OK || bye.count == 0) break;
                if (handler_)
                    handler_->on_bye(
                        bye.ssrc[0],
                        std::string(bye.reason.p ? bye.reason.p : "",
                                    bye.reason.len));
                break;
            }
            default: /* SDES/APP/unknown: ignore */ break;
            }
        }
    }
}

/* Round-trip time from a report block the peer wrote about us (RFC 3550
 * §6.4.1): it echoes the middle 32 NTP bits of the last SR it had from
 * us (lsr) and how long it then held the report (dlsr), so
 *
 *     RTT = now_ntp - lsr - dlsr
 *
 * all in 1/65536 s. A zero lsr means the peer had never heard an SR from
 * us when it wrote the block — no measurement, leave the last one alone.
 * Blocks about any other source are somebody else's round trip. */
void Stream::note_rtt(const rtcp_rep_t& rep)
{
    uint32_t sec, frac;
    rtp_ntp_now(&sec, &frac);
    uint32_t now = (sec << 16) | (frac >> 16);

    for (unsigned i = 0; i < rep.count; i++) {
        const rtcp_report_t* r = &rep.reports[i];
        if (r->ssrc != impl_->ssrc || r->lsr == 0) continue;
        uint32_t delay = now - r->lsr - r->dlsr; /* wraps modulo 2^32 */
        impl_->rtt_ms  = (double)delay * 1000.0 / 65536.0;
    }
}

std::vector<ReportBlock> Stream::report_blocks(const rtcp_rep_t& rep)
{
    std::vector<ReportBlock> out(rep.count);
    for (unsigned i = 0; i < rep.count; i++) {
        const rtcp_report_t* r = &rep.reports[i];
        out[i].ssrc            = r->ssrc;
        out[i].fraction_lost   = r->fraction;
        out[i].packets_lost    = r->lost;
        out[i].highest_seq     = r->last_seq;
        out[i].jitter          = r->jitter;
        out[i].lsr             = r->lsr;
        out[i].dlsr            = r->dlsr;
    }
    return out;
}

/* ---- periodic reports ---- */

void Stream::arm_timer()
{
    if (impl_->timer_id || !impl_->reports_on || impl_->rtcp_ms == 0) return;
    net_loop* l = impl_->lp();
    if (!l) return; /* the loop is gone; nothing left to report to */
    impl_->timer_id =
        net_loop_after(l, impl_->rtcp_ms, Impl::timer_tramp, this);
    if (impl_->timer_id == 0) throw Error("net_loop_after failed");
}

void Stream::on_report_timer()
{
    send_report(false, "");
    arm_timer();
}

void Stream::send_report(bool with_bye, const std::string& reason)
{
    if (!impl_->has_peer) return;

    rtcp_report_t rb;
    unsigned      nrb = 0;
    if (impl_->have_source && impl_->source.received > 0) {
        rtp_source_report(&impl_->source, &rb);
        rb.lsr = impl_->last_sr_lsr;
        if (impl_->last_sr_arrival)
            rb.dlsr = (uint32_t)((net_now_ms() - impl_->last_sr_arrival) *
                                 65536 / 1000);
        nrb = 1;
    }

    uint8_t     buf[512];
    rtcp_wbuf_t w;
    rtcp_wbuf_init(&w, buf, sizeof buf);

    if (impl_->sent_since_report) {
        uint32_t sec, frac;
        rtp_ntp_now(&sec, &frac);
        rtcp_put_sr(&w, impl_->ssrc, sec, frac, impl_->ts,
                    (uint32_t)impl_->tx_packets, (uint32_t)impl_->tx_octets,
                    nrb ? &rb : nullptr, nrb);
    } else {
        rtcp_put_rr(&w, impl_->ssrc, nrb ? &rb : nullptr, nrb);
    }
    rtcp_put_sdes_cname(&w, impl_->ssrc, impl_->cname.data(),
                        impl_->cname.size());
    if (with_bye)
        rtcp_put_bye(&w, &impl_->ssrc, 1, reason.data(), reason.size());

    int n = rtcp_end(&w);
    if (n < 0) throw Error("RTCP compound too large", n);

    ssize_t sent =
        net_udp_send(&impl_->rtcp_sock, buf, (size_t)n, &impl_->peer_rtcp);
    if (sent < 0) throw Error("RTCP send failed", (int)sent);
    impl_->sent_since_report = false;
}

} /* namespace rtp */
