#ifndef RTPXX_HPP
#define RTPXX_HPP

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "netxx.hpp" /* net::Loop — the transport the media session runs on */
#include "rtp.h"

/* rtpxx — C++ facade over the C RTP/RTCP codec (rtp/inc/rtp.h),
 * written to be wrapped by SWIG (bindings/swig/rtp.i) and driven from
 * a scripting language. It follows the same rules as the other
 * facades:
 *
 *   - value types: Packet and the report structs own copies of
 *     everything, so no lifetime coupling to receive buffers;
 *   - callbacks are virtual methods on handler classes, bridged to
 *     Lua tables/functions by the SWIG layer;
 *   - errors are exceptions (rtp::Error), never return codes.
 *
 * The media layer (Stream — see bindings/swig/rtp.i for why it is not
 * called Session) drives one RTP stream over a pair of
 * net_loop-registered UDP sockets (RTP on the given port, RTCP on
 * port + 1, per RFC 3550 §11): sequencing and timestamps on send,
 * source validation / loss / jitter tracking on receive (the
 * appendix-A algorithms in the C library), and periodic compound
 * RTCP — SR when we sent since the last report, else RR, plus SDES
 * CNAME — with incoming SR/RR/BYE surfaced through StreamHandler.
 *
 * The event loop is net::Loop from the netxx facade (as the gtp
 * session layer's is), not a private one: a script that already runs
 * GTP-C and SIP on one net.Loop gives its media sessions the same
 * loop, and one loop:run() drives signalling and media together. */

namespace rtp
{

/* Every failure surfaces as one of these; code() keeps the underlying
 * rtp_err_t / NET_* value when there is one. */
class Error : public std::runtime_error
{
  public:
    explicit Error(const std::string& what, int code = 0)
        : std::runtime_error(what), code_(code)
    {
    }
    int code() const
    {
        return code_;
    }

  private:
    int code_;
};

/* Static payload types (RFC 3551 §6); >= PT_DYNAMIC is bound by SDP. */
enum Pt {
    PT_PCMU    = RTP_PT_PCMU,
    PT_GSM     = RTP_PT_GSM,
    PT_G723    = RTP_PT_G723,
    PT_PCMA    = RTP_PT_PCMA,
    PT_G722    = RTP_PT_G722,
    PT_L16_2CH = RTP_PT_L16_2CH,
    PT_L16     = RTP_PT_L16,
    PT_G728    = RTP_PT_G728,
    PT_G729    = RTP_PT_G729,
    PT_DYNAMIC = RTP_PT_DYNAMIC
};

/* ---- value types ---- */

/* One RTP packet. payload (and ext) are byte strings. On send through
 * Stream::send_packet() every field is used as given. */
struct Packet {
    int                   pt     = 0;
    bool                  marker = false;
    unsigned              seq    = 0;
    uint32_t              ts     = 0;
    uint32_t              ssrc   = 0;
    std::vector<uint32_t> csrc;
    bool                  has_ext     = false;
    int                   ext_profile = 0;
    std::string           ext; /* multiple of 4 bytes */
    std::string           payload;

    std::string   encode() const;
    static Packet parse(const std::string& wire);
};

/* Sender info from an SR (RFC 3550 §6.4.1). */
struct SenderInfo {
    uint32_t ntp_sec = 0, ntp_frac = 0;
    uint32_t rtp_ts       = 0;
    uint32_t packet_count = 0, octet_count = 0;
};

/* One reception report block from an SR/RR. */
struct ReportBlock {
    uint32_t ssrc          = 0;
    int      fraction_lost = 0; /* since last report, /256 */
    int      packets_lost  = 0; /* cumulative             */
    uint32_t highest_seq   = 0; /* extended               */
    uint32_t jitter        = 0; /* timestamp units        */
    uint32_t lsr = 0, dlsr = 0;
};

/* Stream counters; the rx_* side tracks the first remote SSRC seen.
 *
 * rx_* is what WE see of the inbound stream; the outbound direction can
 * only be measured by the peer, which reports it back in an RTCP report
 * block (StreamHandler::on_receiver_report). rtt_ms is the one figure
 * derived from such a block here, since it needs a clock reading at
 * arrival: negative until a block about our SSRC carrying a non-zero
 * lsr arrives. */
struct Stats {
    uint32_t local_ssrc  = 0;
    uint32_t remote_ssrc = 0; /* 0 until a source is seen */
    uint64_t tx_packets = 0, tx_octets = 0;
    uint64_t rx_packets = 0, rx_octets = 0;
    int      rx_lost   = 0;  /* cumulative, may be negative */
    uint32_t rx_jitter = 0;  /* timestamp units */
    double   rtt_ms    = -1; /* last RTT, < 0 = not measured yet */
};

/* ---- media stream ---- */

/* Subclass this and pass it to Stream::set_handler(). All methods
 * default to no-ops. */
class StreamHandler
{
  public:
    virtual ~StreamHandler() = default;

    /* One RTP packet arrived (already validated by the codec). */
    virtual void on_rtp(const Packet& p, const std::string& host,
                        uint16_t port);

    /* Incoming RTCP. ssrc is the report's sender. */
    virtual void on_sender_report(uint32_t ssrc, const SenderInfo& si,
                                  const std::vector<ReportBlock>& reports);
    virtual void on_receiver_report(uint32_t                        ssrc,
                                    const std::vector<ReportBlock>& reports);
    virtual void on_bye(uint32_t ssrc, const std::string& reason);
};

/* One RTP stream endpoint: binds rtp_port and rtp_port + 1 (RTCP) on
 * local_host and registers both with the loop. Sending needs a peer
 * (set_peer); the peer's RTCP port is its RTP port + 1. Periodic
 * compound reports start with set_peer() and stop at bye().
 *
 * nonlocal_src sets IP_FREEBIND + IP_TRANSPARENT (net_sock.h's
 * NET_NONLOCAL_SRC, as net::UdpSocket's own flag does) so the pair can
 * bind and send from an address this host does not own — a simulated
 * UE's PDN address, whose media must leave with the PAA as its source.
 * Needs CAP_NET_ADMIN. */
class Stream
{
  public:
    Stream(net::Loop& loop, const std::string& local_host, uint16_t rtp_port,
           bool nonlocal_src = false);
    ~Stream();
    Stream(const Stream&)            = delete;
    Stream& operator=(const Stream&) = delete;

    void set_handler(StreamHandler* h)
    {
        handler_ = h;
    }
    void set_peer(const std::string& host, uint16_t rtp_port);

    /* Stream parameters; defaults are G.711 mu-law telephony. */
    void set_payload_type(int pt);
    void set_clock_rate(unsigned hz);         /* jitter units, 8000 */
    void set_cname(const std::string& cname); /* SDES CNAME         */
    void set_ssrc(uint32_t ssrc);             /* default random     */
    void set_rtcp_interval(unsigned ms);      /* default 5000       */

    uint32_t    ssrc() const;
    uint16_t    rtp_port() const;
    std::string local_host() const;

    /* Send one payload as the next packet in the stream: seq
     * increments, the timestamp advances by ts_step *after* this
     * packet (so ts_step is the samples-per-packet of the payload). */
    void send(const std::string& payload, uint32_t ts_step,
              bool marker = false);

    /* Full control: every header field is taken from p as given. */
    void send_packet(const Packet& p);

    /* Send the closing compound (report + SDES + BYE) and stop the
     * periodic reports. The stream can still receive. */
    void bye(const std::string& reason = "");

    Stats stats() const;

  private:
    struct Impl;
    Impl*          impl_;
    StreamHandler* handler_ = nullptr;

    void on_rtp_readable();
    void on_rtcp_readable();
    void on_report_timer();
    void send_report(bool with_bye, const std::string& reason);
    void arm_timer();
    /* RTT from a report block about us: now_ntp - lsr - dlsr (§6.4.1). */
    void                            note_rtt(const rtcp_rep_t& rep);
    static std::vector<ReportBlock> report_blocks(const rtcp_rep_t& rep);
};

} /* namespace rtp */

#endif /* RTPXX_HPP */
