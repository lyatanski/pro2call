#ifndef RTP_H
#define RTP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RTP/RTCP codec — RFC 3550 (profile constants from RFC 3551).
 *
 * Decode is zero-copy: rtp_pkt_parse() fills an rtp_pkt_t whose
 * payload and header-extension fields point into the caller's buffer.
 * Nothing is allocated and nothing is copied; the buffer must remain
 * valid while the packet is in use. RTCP compound packets are walked
 * with an iterator (rtcp_iter_*) yielding one view per packet, and the
 * per-type parsers (SR/RR/SDES/BYE) fill fixed-size structs from a
 * view — again without copying variable-length data.
 *
 * Encode writes directly into a caller-supplied buffer. The RTCP
 * writer is sticky on overflow: once any put exceeds capacity every
 * subsequent call fails, so return codes can be chained and checked
 * once at rtcp_end() (mirrors sip_wbuf_t in sip/inc/sip.h).
 *
 * The rtp_source_t tracker implements the receiver-side algorithms of
 * RFC 3550 appendix A: sequence-number validation with probation
 * (A.1), extended-sequence/loss bookkeeping (A.3), interarrival jitter
 * (A.8) and the fraction-lost computation for report blocks. It is
 * pure computation — the transport and RTCP scheduling live above
 * (bindings/cxx/inc/rtpxx.hpp drives both over net_loop).
 *
 * Wire layout reference (RFC 3550 §5.1):
 *   RTP  : V(2) P X CC | M PT(7) | sequence, timestamp, SSRC,
 *          CC * CSRC, [extension: profile(16) len(16) data], payload
 *   RTCP : compound of packets, each V(2) P C(5) | PT(8) | len(16)
 *          where len is in 32-bit words minus one
 */

/* Borrowed view into a buffer owned by someone else. Never
 * NUL-terminated; print with printf("%.*s", RTP_STR_ARG(s)). */
typedef struct {
    const char* p;
    uint32_t    len;
} rtp_str_t;

#define RTP_STR_ARG(s) (int)(s).len, (s).p

typedef enum {
    RTP_OK         = 0,
    RTP_E_SHORT    = -1, /* buffer smaller than the encoded lengths claim */
    RTP_E_VERSION  = -2, /* version is not 2                              */
    RTP_E_FORMAT   = -3, /* malformed packet (padding, counts, lengths)   */
    RTP_E_OVERFLOW = -4, /* write buffer too small                        */
    RTP_E_INVAL    = -5  /* invalid argument                              */
} rtp_err_t;

enum { RTP_VERSION = 2 };

/* Static payload types — RFC 3551 §6. Everything >= 96 is dynamic,
 * bound by SDP (a=rtpmap). */
typedef enum {
    RTP_PT_PCMU    = 0, /* G.711 mu-law, 8000 Hz */
    RTP_PT_GSM     = 3,
    RTP_PT_G723    = 4,
    RTP_PT_PCMA    = 8, /* G.711 A-law, 8000 Hz  */
    RTP_PT_G722    = 9,
    RTP_PT_L16_2CH = 10, /* 44100 Hz stereo       */
    RTP_PT_L16     = 11, /* 44100 Hz mono         */
    RTP_PT_G728    = 15,
    RTP_PT_G729    = 18,
    RTP_PT_DYNAMIC = 96 /* first dynamic type    */
} rtp_pt_t;

/* ---- RTP packets ---- */

#define RTP_MAX_CSRC 15

/* Parsed packet — payload/ext point into the caller's input buffer.
 * On encode the same struct is the source: set the fields, point
 * payload at the data (ext only when has_ext). */
typedef struct {
    bool           marker;
    uint8_t        pt; /* payload type, 0..127     */
    uint16_t       seq;
    uint32_t       ts;
    uint32_t       ssrc;
    uint8_t        cc; /* CSRC count               */
    uint32_t       csrc[RTP_MAX_CSRC];
    bool           has_ext; /* RFC 3550 §5.3.1          */
    uint16_t       ext_profile;
    const uint8_t* ext;     /* extension words          */
    uint32_t       ext_len; /* bytes, multiple of 4     */
    const uint8_t* payload;
    uint32_t       payload_len;
} rtp_pkt_t;

/* Parse one packet. Padding (P bit) is stripped from the payload.
 * Returns RTP_OK or a negative rtp_err_t. The buffer must stay valid
 * while the packet is in use. */
API_EXPORT int rtp_pkt_parse(rtp_pkt_t* p, const void* buf, size_t len);

/* Encode into buf. Never writes padding. Returns the total length or
 * a negative rtp_err_t (RTP_E_INVAL when cc > RTP_MAX_CSRC, pt > 127
 * or ext_len is not a multiple of 4). */
API_EXPORT int rtp_pkt_encode(const rtp_pkt_t* p, void* buf, size_t cap);

/* ---- RTCP packets ---- */

typedef enum {
    RTCP_SR   = 200,
    RTCP_RR   = 201,
    RTCP_SDES = 202,
    RTCP_BYE  = 203,
    RTCP_APP  = 204
} rtcp_type_t;

/* SDES item types — RFC 3550 §6.5. */
typedef enum {
    RTCP_SDES_END   = 0,
    RTCP_SDES_CNAME = 1,
    RTCP_SDES_NAME  = 2,
    RTCP_SDES_EMAIL = 3,
    RTCP_SDES_PHONE = 4,
    RTCP_SDES_LOC   = 5,
    RTCP_SDES_TOOL  = 6,
    RTCP_SDES_NOTE  = 7,
    RTCP_SDES_PRIV  = 8
} rtcp_sdes_item_t;

#define RTCP_MAX_REPORTS 31 /* 5-bit count field */

/* One reception report block — RFC 3550 §6.4.1. */
typedef struct {
    uint32_t ssrc;     /* source this report is about               */
    uint8_t  fraction; /* fraction lost since last report, /256     */
    int32_t  lost;     /* cumulative packets lost (24-bit signed)   */
    uint32_t last_seq; /* extended highest sequence number received */
    uint32_t jitter;   /* interarrival jitter, timestamp units      */
    uint32_t lsr;      /* last SR: middle 32 bits of its NTP stamp  */
    uint32_t dlsr;     /* delay since last SR, 1/65536 s            */
} rtcp_report_t;

/* SR/RR contents — §6.4.1/§6.4.2. For an RR the sender-info block
 * (ntp_*, rtp_ts, pkt_count, octet_count) is zero. */
typedef struct {
    uint32_t      ssrc;
    uint32_t      ntp_sec, ntp_frac;
    uint32_t      rtp_ts;
    uint32_t      pkt_count, octet_count;
    uint8_t       count; /* report blocks */
    rtcp_report_t reports[RTCP_MAX_REPORTS];
} rtcp_rep_t;

/* BYE contents — §6.6. */
typedef struct {
    uint8_t   count;
    uint32_t  ssrc[RTCP_MAX_REPORTS];
    rtp_str_t reason; /* empty if absent */
} rtcp_bye_t;

/* One packet of a compound, as yielded by the iterator. body excludes
 * the 4-byte header; count is the 5-bit RC/SC (subtype for APP). */
typedef struct {
    uint8_t        type; /* rtcp_type_t (or anything else)  */
    uint8_t        count;
    const uint8_t* body;
    uint32_t       body_len; /* padding already stripped        */
} rtcp_view_t;

typedef struct {
    const uint8_t* p;
    size_t         len;
} rtcp_iter_t;

/* Walk a compound datagram. next returns 1 with *v filled, 0 at the
 * end, or a negative rtp_err_t on a malformed packet. Unknown packet
 * types are yielded, not skipped — callers ignore what they do not
 * know (§6.1). */
API_EXPORT void rtcp_iter_init(rtcp_iter_t* it, const void* buf, size_t len);
API_EXPORT int  rtcp_iter_next(rtcp_iter_t* it, rtcp_view_t* v);

/* Per-type parsers; the view must carry the matching type. */
API_EXPORT int rtcp_sr_parse(const rtcp_view_t* v, rtcp_rep_t* out);
API_EXPORT int rtcp_rr_parse(const rtcp_view_t* v, rtcp_rep_t* out);
API_EXPORT int rtcp_bye_parse(const rtcp_view_t* v, rtcp_bye_t* out);

/* SDES items, iterated across all chunks: next returns 1 with the
 * owning chunk's *ssrc, the *item type and its *value, 0 at the end,
 * or a negative rtp_err_t. */
typedef struct {
    const uint8_t* p;
    uint32_t       len;
    uint32_t       ssrc;
    uint8_t        chunks_left;
    bool           in_chunk;
} rtcp_sdes_iter_t;

API_EXPORT int rtcp_sdes_init(const rtcp_view_t* v, rtcp_sdes_iter_t* it);
API_EXPORT int rtcp_sdes_next(rtcp_sdes_iter_t* it, uint32_t* ssrc,
                              uint8_t* item, rtp_str_t* value);

/* ---- RTCP write (encode into caller's buffer) ---- */

/* Write buffer; overflow is sticky. off is the running length. */
typedef struct {
    uint8_t* buf;
    size_t   cap;
    size_t   off;
    bool     overflow;
} rtcp_wbuf_t;

API_EXPORT void rtcp_wbuf_init(rtcp_wbuf_t* w, void* buf, size_t cap);

/* Every put appends one complete RTCP packet and returns 0 or a
 * negative rtp_err_t; after an overflow all further puts return
 * RTP_E_OVERFLOW. lsr/dlsr of each report come from the struct. */
API_EXPORT int rtcp_put_sr(rtcp_wbuf_t* w, uint32_t ssrc, uint32_t ntp_sec,
                           uint32_t ntp_frac, uint32_t rtp_ts,
                           uint32_t pkt_count, uint32_t octet_count,
                           const rtcp_report_t* reports, unsigned n);
API_EXPORT int rtcp_put_rr(rtcp_wbuf_t* w, uint32_t ssrc,
                           const rtcp_report_t* reports, unsigned n);

/* One-chunk SDES carrying a single CNAME item (§6.5: every compound
 * must include one). */
API_EXPORT int rtcp_put_sdes_cname(rtcp_wbuf_t* w, uint32_t ssrc,
                                   const char* cname, size_t len);

API_EXPORT int rtcp_put_bye(rtcp_wbuf_t* w, const uint32_t* ssrc, unsigned n,
                            const char* reason, size_t len);

/* Finish: returns the total compound length, or RTP_E_OVERFLOW. */
API_EXPORT int rtcp_end(rtcp_wbuf_t* w);

/* ---- Receiver-side source statistics (RFC 3550 appendix A) ---- */

/* Per-sender reception state. Sequence validation runs the probation
 * scheme of A.1: a new source is not counted until RTP_MIN_SEQUENTIAL
 * packets arrive in order. */
#ifndef RTP_MIN_SEQUENTIAL
#define RTP_MIN_SEQUENTIAL 2
#endif

typedef struct {
    uint32_t ssrc;
    uint16_t max_seq; /* highest seq seen                    */
    uint32_t cycles;  /* shifted count of seq wraps          */
    uint32_t base_seq;
    uint32_t bad_seq;
    uint32_t probation; /* sequential packets until valid      */
    uint32_t received;
    uint32_t expected_prior; /* snapshot at last report             */
    uint32_t received_prior;
    bool     has_transit; /* first sample only seeds transit     */
    uint32_t transit;     /* last relative transit time          */
    uint32_t jitter;      /* estimator, scaled by 16 (A.8)       */
} rtp_source_t;

API_EXPORT void rtp_source_init(rtp_source_t* s, uint32_t ssrc, uint16_t seq);

/* Sequence-number update (A.1). Returns 1 when the packet counts as
 * received, 0 while in probation or when the jump is too large. */
API_EXPORT int rtp_source_update(rtp_source_t* s, uint16_t seq);

/* Jitter update (A.8): rtp_ts from the packet, arrival in the same
 * timestamp units (wall-clock ms * clock_rate / 1000). */
API_EXPORT void rtp_source_jitter(rtp_source_t* s, uint32_t rtp_ts,
                                  uint32_t arrival);

/* Fill a report block about this source (A.3): fraction/cumulative
 * lost, extended highest sequence, jitter. Snapshot-resets the
 * per-interval counters; lsr/dlsr are left zero for the caller. */
API_EXPORT void rtp_source_report(rtp_source_t* s, rtcp_report_t* out);

/* ---- NTP wallclock (for SR sender info) ---- */

/* Current NTP timestamp (seconds since 1900 + 2^-32 fraction). */
API_EXPORT void rtp_ntp_now(uint32_t* sec, uint32_t* frac);

#ifdef __cplusplus
}
#endif

#endif /* RTP_H */
