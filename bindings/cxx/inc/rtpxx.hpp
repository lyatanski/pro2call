#ifndef RTPXX_HPP
#define RTPXX_HPP

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "net_loop.h"
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
 * The media layer (Session) drives one RTP stream over a pair of
 * net_loop-registered UDP sockets (RTP on the given port, RTCP on
 * port + 1, per RFC 3550 §11): sequencing and timestamps on send,
 * source validation / loss / jitter tracking on receive (the
 * appendix-A algorithms in the C library), and periodic compound
 * RTCP — SR when we sent since the last report, else RR, plus SDES
 * CNAME — with incoming SR/RR/BYE surfaced through SessionHandler. */

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
 * Session::send_packet() every field is used as given. */
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

/* Session counters; the rx_* side tracks the first remote SSRC seen. */
struct Stats {
    uint32_t local_ssrc  = 0;
    uint32_t remote_ssrc = 0; /* 0 until a source is seen */
    uint64_t tx_packets = 0, tx_octets = 0;
    uint64_t rx_packets = 0, rx_octets = 0;
    int      rx_lost   = 0; /* cumulative, may be negative */
    uint32_t rx_jitter = 0; /* timestamp units */
};

/* ---- event loop ---- */

class TimerHandler
{
  public:
    virtual ~TimerHandler() = default;
    virtual void on_timer() = 0;
};

class IoHandler
{
  public:
    virtual ~IoHandler()                        = default;
    virtual void on_io(int fd, unsigned events) = 0; /* NET_RD/NET_WR/NET_ER */
};

/* Wraps net_loop (net/inc/net_loop.h), exactly like net::Loop: the
 * single-threaded epoll dispatcher every session registers with.
 * Handlers are borrowed — the caller keeps them alive (the Lua layer
 * pins them in registries). Exceptions thrown by handlers never
 * unwind through the C dispatcher: they are captured, the loop is
 * stopped, and step()/run() rethrows. */
class Loop
{
  public:
    Loop();
    ~Loop();
    Loop(const Loop&)            = delete;
    Loop& operator=(const Loop&) = delete;

    /* One poll iteration; timeout_ms < 0 waits for the next event or
     * timer. Returns the number of fd events dispatched. */
    int  step(int timeout_ms = -1);
    void run(); /* step until stop() */
    void stop();

    /* One-shot timer; returns a cancellation id. */
    uint64_t after(uint64_t ms, TimerHandler* h);
    void     cancel(uint64_t timer_id);

    /* Register an arbitrary fd (integration point for other stacks). */
    void add_fd(int fd, unsigned events, IoHandler* h);
    void mod_fd(int fd, unsigned events);
    void del_fd(int fd);

    net_loop* raw() const
    {
        return l_;
    }

    /* Internal (used by callback trampolines): capture the in-flight
     * exception, stop the loop, and rethrow it from step()/run(). */
    void defer_exception();
    void rethrow_pending();

  private:
    friend class Session;
    struct Impl;
    Impl*     impl_;
    net_loop* l_;
    /* Liveness token: nulled by ~Loop so dependents destroyed after
     * the loop (garbage collectors order teardown freely) skip their
     * unregistration instead of touching a freed net_loop. */
    std::shared_ptr<net_loop*> life_;
};

/* ---- media session ---- */

/* Subclass this and pass it to Session::set_handler(). All methods
 * default to no-ops. */
class SessionHandler
{
  public:
    virtual ~SessionHandler() = default;

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
 * local_host and registers both with the Loop. Sending needs a peer
 * (set_peer); the peer's RTCP port is its RTP port + 1. Periodic
 * compound reports start with set_peer() and stop at bye(). */
class Session
{
  public:
    Session(Loop& loop, const std::string& local_host, uint16_t rtp_port);
    ~Session();
    Session(const Session&)            = delete;
    Session& operator=(const Session&) = delete;

    void set_handler(SessionHandler* h)
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
     * periodic reports. The session can still receive. */
    void bye(const std::string& reason = "");

    Stats stats() const;

  private:
    struct Impl;
    Impl*           impl_;
    SessionHandler* handler_ = nullptr;

    void on_rtp_readable();
    void on_rtcp_readable();
    void on_report_timer();
    void send_report(bool with_bye, const std::string& reason);
    void arm_timer();
    static std::vector<ReportBlock> report_blocks(const rtcp_rep_t& rep);
};

} /* namespace rtp */

#endif /* RTPXX_HPP */
