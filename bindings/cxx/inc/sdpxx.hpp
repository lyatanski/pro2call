#ifndef SDPXX_HPP
#define SDPXX_HPP

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "sdp.h"

/* sdpxx — C++ facade over the C SDP codec (sdp/inc/sdp.h), written to
 * be wrapped by SWIG (bindings/swig/sdp.i) and driven from a scripting
 * language. Same rules as the other facades:
 *
 *   - value types: Msg/Media/Attr own copies of everything, so no
 *     lifetime coupling to the body buffer (the C layer's zero-copy
 *     slices are materialized exactly once, here);
 *   - enums, not strings: media types, transport protocols, attribute
 *     names and directions keep the C library's numeric ids, so a
 *     script writes sdp.M_AUDIO / sdp.A_RTPMAP / sdp.DIR_SENDRECV
 *     instead of matching text;
 *   - errors are exceptions (sdp::Error), never return codes.
 *
 * Two things an SDP consumer gets wrong exactly once are resolved here
 * rather than at every call site, because getting either wrong sends
 * media to the wrong place and looks like a network fault:
 *
 *   - a media-level c= overrides the session-level one (RFC 8866 §5.7);
 *     rtpengine emits both, so Media::addr is the resolved one;
 *   - m= port 0 means the stream was rejected (RFC 3264 §6), which is
 *     Media::rejected() rather than a parse error or a silent zero.
 *
 * Media::dir is resolved the same way: the section's own direction
 * attribute, else the session's, else sendrecv.
 */

namespace sdp
{

/* Every failure surfaces as one of these; code() keeps the SDP_E_*
 * value that caused it. */
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

/* Attribute ids — mirrored from sdp.h so scripts get named constants
 * (sdp.A_RTPMAP, sdp.A_PTIME, ...). Extensions are A_OTHER and are
 * matched by name instead. */
enum AttrId {
    A_OTHER       = SDP_A_OTHER,
    A_CANDIDATE   = SDP_A_CANDIDATE,
    A_CRYPTO      = SDP_A_CRYPTO,
    A_EXTMAP      = SDP_A_EXTMAP,
    A_FINGERPRINT = SDP_A_FINGERPRINT,
    A_FMTP        = SDP_A_FMTP,
    A_GROUP       = SDP_A_GROUP,
    A_ICE_LITE    = SDP_A_ICE_LITE,
    A_ICE_OPTIONS = SDP_A_ICE_OPTIONS,
    A_ICE_PWD     = SDP_A_ICE_PWD,
    A_ICE_UFRAG   = SDP_A_ICE_UFRAG,
    A_INACTIVE    = SDP_A_INACTIVE,
    A_MAXPTIME    = SDP_A_MAXPTIME,
    A_MID         = SDP_A_MID,
    A_MSID        = SDP_A_MSID,
    A_PTIME       = SDP_A_PTIME,
    A_RECVONLY    = SDP_A_RECVONLY,
    A_RTCP        = SDP_A_RTCP,
    A_RTCP_FB     = SDP_A_RTCP_FB,
    A_RTCP_MUX    = SDP_A_RTCP_MUX,
    A_RTPMAP      = SDP_A_RTPMAP,
    A_SENDONLY    = SDP_A_SENDONLY,
    A_SENDRECV    = SDP_A_SENDRECV,
    A_SETUP       = SDP_A_SETUP,
    A_SSRC        = SDP_A_SSRC,
    A_SSRC_GROUP  = SDP_A_SSRC_GROUP
};

enum MediaType {
    M_OTHER       = SDP_M_OTHER,
    M_AUDIO       = SDP_M_AUDIO,
    M_VIDEO       = SDP_M_VIDEO,
    M_TEXT        = SDP_M_TEXT,
    M_APPLICATION = SDP_M_APPLICATION,
    M_MESSAGE     = SDP_M_MESSAGE,
    M_IMAGE       = SDP_M_IMAGE
};

enum Proto {
    P_OTHER             = SDP_P_OTHER,
    P_RTP_AVP           = SDP_P_RTP_AVP,
    P_RTP_AVPF          = SDP_P_RTP_AVPF,
    P_RTP_SAVP          = SDP_P_RTP_SAVP,
    P_RTP_SAVPF         = SDP_P_RTP_SAVPF,
    P_UDP_TLS_RTP_SAVP  = SDP_P_UDP_TLS_RTP_SAVP,
    P_UDP_TLS_RTP_SAVPF = SDP_P_UDP_TLS_RTP_SAVPF,
    P_UDP_DTLS_SCTP     = SDP_P_UDP_DTLS_SCTP,
    P_UDPTL             = SDP_P_UDPTL,
    P_UDP               = SDP_P_UDP,
    P_TCP               = SDP_P_TCP
};

enum Dir {
    DIR_SENDRECV = SDP_DIR_SENDRECV,
    DIR_SENDONLY = SDP_DIR_SENDONLY,
    DIR_RECVONLY = SDP_DIR_RECVONLY,
    DIR_INACTIVE = SDP_DIR_INACTIVE
};

/* One a= line. id is an AttrId; A_OTHER for extensions, which are
 * matched by name instead. A flag attribute (a=sendrecv) has an
 * empty value. */
struct Attr {
    int         id = A_OTHER;
    std::string name; /* as it appeared on the wire */
    std::string value;
};

/* o= — RFC 8866 §5.2. A peer that emits a non-numeric sess-id (the RFC
 * calls for a numeric string) is not rejected; the id comes out 0. */
struct Origin {
    std::string username;
    uint64_t    sess_id      = 0;
    uint64_t    sess_version = 0;
    std::string nettype;
    std::string addrtype;
    std::string addr;
};

/* c= — RFC 8866 §5.7. */
struct Conn {
    std::string nettype;
    std::string addrtype;
    std::string addr;
};

/* b=<bwtype>:<kilobits> */
struct Bw {
    std::string bwtype;
    uint64_t    value = 0;
};

/* a=rtpmap:<pt> <encoding>/<clock>[/<params>] */
struct Rtpmap {
    int         pt = -1;
    std::string enc;
    unsigned    clock = 0;
    std::string params; /* channels for audio; empty if absent */
};

/* One m= section, with everything that belongs to it — its attributes,
 * its format list, its bandwidth lines — copied in, so a Media outlives
 * the Msg it came from and the body it was parsed out of. */
class Media
{
  public:
    int         type = M_OTHER; /* MediaType                     */
    std::string type_name;      /* raw token, set even for OTHER */
    int         port   = 0;
    int         nports = 1;
    int         proto  = P_OTHER; /* Proto                         */
    std::string proto_name;
    std::string title; /* i=, empty if absent           */

    /* Resolved at parse: this section's c= if it has one, else the
     * session-level one; both empty when the description carries
     * neither. dir is resolved the same way, defaulting to sendrecv. */
    std::string addr;
    std::string addrtype;
    int         dir = DIR_SENDRECV; /* Dir */

    /* RFC 3264 §6: port 0 is an offer/answer rejection, not an error. */
    bool rejected() const
    {
        return port == 0;
    }

    /* Format list as it appeared (payload type numbers for the RTP
     * profiles, opaque tokens otherwise). */
    int         format_count() const;
    std::string format_at(int i) const; /* throws on range */

    /* The same list read as payload types: pt_at() is -1 for a format
     * that is not a number, so an m=application section does not turn
     * into a pile of zeros. */
    int  pt_count() const;
    int  pt_at(int i) const; /* throws on range */
    bool has_pt(int pt) const;

    bool   has_rtpmap(int pt) const;
    Rtpmap rtpmap(int pt) const; /* throws when absent   */
    /* a=fmtp parameters for a payload type; "" when absent. */
    std::string fmtp(int pt) const;

    /* a=ptime / a=maxptime in milliseconds; 0 when absent. */
    int ptime() const;
    int maxptime() const;

    int         attr_count() const;
    Attr        attr_at(int i) const; /* throws on range      */
    bool        has_attr(int id) const;
    std::string attr(int id) const; /* first value, "" if none */
    std::string attr_name(const std::string& aname) const;

    int      bw_count() const;
    Bw       bw_at(int i) const; /* throws on range      */
    uint64_t bw(const std::string& bwtype) const;

    /* Hidden from scripts; the accessors above are the interface. */
    std::vector<Attr>        attrs;
    std::vector<std::string> fmts;
    std::vector<Bw>          bws;
};

/* A parsed description. Field access never throws; the lookups that
 * can fail say so (has_audio() before audio(), has_media() before
 * media()). */
class Msg
{
  public:
    int         version    = 0;
    bool        has_origin = false;
    Origin      origin;
    std::string name; /* s= */
    std::string info; /* i= */
    std::string uri;  /* u= */
    bool        has_conn = false;
    Conn        conn;
    bool        has_time = false;
    uint64_t    t_start  = 0;
    uint64_t    t_stop   = 0;
    int         dir      = DIR_SENDRECV; /* session-level direction */

    int   media_count() const;
    Media media_at(int i) const; /* throws on range */

    /* First section of a media type, in wire order. */
    bool  has_media(int type) const;
    Media media(int type) const; /* throws when absent */

    bool has_audio() const
    {
        return has_media(M_AUDIO);
    }
    Media audio() const
    {
        return media(M_AUDIO);
    }

    /* Session-level attributes and bandwidth lines. */
    int         attr_count() const;
    Attr        attr_at(int i) const;
    bool        has_attr(int id) const;
    std::string attr(int id) const;
    std::string attr_name(const std::string& aname) const;
    int         bw_count() const;
    Bw          bw_at(int i) const;
    uint64_t    bw(const std::string& bwtype) const;

    /* Hidden from scripts. */
    std::vector<Media> medias;
    std::vector<Attr>  attrs;
    std::vector<Bw>    bws;
};

/* Parse one session description (a SIP application/sdp body). Throws
 * Error on anything the codec refuses: no v=0, a malformed o=/c=/b=/t=
 * or m= line, or a pool bound exceeded. Line terminators may be CRLF
 * or bare LF and the last line need not have one. */
Msg parse(const std::string& body);

/* Name tables, for pretty-printing in scripts. */
std::string attr_name(int id);
std::string mtype_name(int type);
std::string proto_name(int proto);
std::string dir_name(int dir);

/* RFC 3551 §6 static payload type assignments — the encoding name and
 * clock rate a static type implies, so an offer for one does not have
 * to spell them out. "" / 0 for a dynamic or unassigned type. */
std::string pt_encoding(int pt);
int         pt_clock(int pt);

/* Builds one description into an internal fixed buffer; done() returns
 * the bytes. The buffer is allocated once and never zeroed, so reusing
 * one Builder costs no allocation at all.
 *
 * Line order is the caller's: RFC 8866 §5 fixes it (v= o= s= i= u= c=
 * b= t= a=, then each m= with its own i= c= b= a=) and a writer that
 * silently reordered would only hide the mistake. version() resets the
 * buffer, so a build that throws part-way cannot leak stale bytes into
 * the next description; done() resets it too.
 *
 * Calls chain: Builder():version():origin(...):media(...):done(). */
class Builder
{
  public:
    enum { DEFAULT_CAP = 4 * 1024 };

    explicit Builder(size_t cap = DEFAULT_CAP);

    Builder& version(); /* v=0; resets the buffer */
    Builder& origin(const std::string& user, uint64_t sess_id,
                    uint64_t sess_version, const std::string& addr,
                    const std::string& addrtype = "IP4");
    Builder& name(const std::string& n);
    Builder& conn(const std::string& addr, const std::string& addrtype = "IP4");
    Builder& bw(const std::string& bwtype, uint64_t value);
    Builder& time(uint64_t start = 0, uint64_t stop = 0);

    /* m=; fmts is the pre-joined format list ("0 101"), empty for a
     * rejected stream. */
    Builder& media(int type, int port, int proto, const std::string& fmts = "");
    Builder& media_name(const std::string& type, int port,
                        const std::string& proto, const std::string& fmts = "");

    /* a=; an empty value writes a flag attribute (a=sendrecv). */
    Builder& attr(int id, const std::string& value = "");
    Builder& attr_name(const std::string& name, const std::string& value = "");
    /* Escape hatch for a line type this module does not model (e=, k=,
     * r=, z=); type is one lowercase letter. */
    Builder& line(const std::string& type, const std::string& value);

    std::string done();

    size_t capacity() const
    {
        return cap_;
    }

  private:
    void reset()
    {
        sdp_wbuf_init(&w_, buf_.get(), cap_);
    }

    /* Raw array, not std::vector<char>: vector value-initializes, which
     * costs a full memset of the capacity on every construction. */
    std::unique_ptr<char[]> buf_;
    size_t                  cap_;
    sdp_wbuf_t              w_;
};

/* The one description a UE placing a call actually needs: one audio
 * stream, one payload type, our own address and port. Everything but
 * addr/port has a working default, so the common case is
 *
 *   sdp::Offer o; o.addr = paa; o.port = 40000;
 *   std::string body = sdp::offer(o);
 *
 * and in Lua, sdp.offer{ addr = paa, port = 40000 }. */
struct Offer {
    std::string addr;     /* required: where WE receive RTP       */
    int         port = 0; /* required: our RTP port               */
    int         pt   = 0; /* payload type; 0 = G.711 PCMU         */
    /* Encoding name and clock rate for a=rtpmap. Empty/0 take the
     * RFC 3551 static assignment for pt, so an offer for a dynamic
     * type must name its codec rather than silently claim PCMU. */
    std::string codec;
    int         rate  = 0;
    int         ptime = 20; /* a=ptime, milliseconds; 0 omits it */
    int         dir   = DIR_SENDRECV;
    /* 0 = a fresh session id, unique per Offer from this process
     * (RFC 8866 §5.2 suggests an NTP-style timestamp). */
    uint64_t    id       = 0;
    uint64_t    version  = 1;
    std::string user     = "-";
    std::string name     = "-";
    std::string addrtype = "IP4";
};

std::string offer(const Offer& o);

} // namespace sdp

#endif /* SDPXX_HPP */
