#include "sdpxx.hpp"

#include <cstring>
#include <ctime>
#include <string>

namespace sdp
{

namespace
{

[[noreturn]] void fail(const char* what, int code)
{
    std::string m = what;
    switch (code) {
    case SDP_E_LINE:     m += ": malformed line"; break;
    case SDP_E_VERSION:  m += ": not a session description (no v=0)"; break;
    case SDP_E_MEDIA:    m += ": too many media sections"; break;
    case SDP_E_ATTRS:    m += ": too many attributes"; break;
    case SDP_E_FMTS:     m += ": too many media formats"; break;
    case SDP_E_BWS:      m += ": too many bandwidth lines"; break;
    case SDP_E_OVERFLOW: m += ": buffer too small"; break;
    case SDP_E_INVAL:    m += ": invalid argument"; break;
    case SDP_E_MISSING:  m += ": not present"; break;
    default:             m += ": failed"; break;
    }
    throw Error(m, code);
}

/* Each put returns the offending error the moment it fails, so a
 * description is never silently truncated. */
void check(int rc, const char* what)
{
    if (rc != SDP_OK) fail(what, rc);
}

std::string str(sdp_str_t s)
{
    return (s.p && s.len) ? std::string(s.p, s.len) : std::string();
}

/* A slice read as an unsigned decimal, or -1 when it is not one. */
int as_int(const std::string& s)
{
    if (s.empty() || s.size() > 9) return -1;
    int v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return -1;
        v = v * 10 + (c - '0');
    }
    return v;
}

/* One attribute pool run copied out as owned values. */
std::vector<Attr> copy_attrs(const sdp_msg_t& m, unsigned off, unsigned count)
{
    std::vector<Attr> out;
    out.reserve(count);
    for (unsigned i = off; i < off + count; i++) {
        Attr a;
        a.id    = m.attrs[i].id;
        a.name  = str(m.attrs[i].name);
        a.value = str(m.attrs[i].value);
        out.push_back(std::move(a));
    }
    return out;
}

std::vector<Bw> copy_bws(const sdp_msg_t& m, unsigned off, unsigned count)
{
    std::vector<Bw> out;
    out.reserve(count);
    for (unsigned i = off; i < off + count; i++)
        out.push_back(Bw{ str(m.bws[i].bwtype), m.bws[i].value });
    return out;
}

/* Shared by Msg and Media — the attribute lookups are identical, only
 * the vector differs. */
const Attr* find_attr(const std::vector<Attr>& v, int id)
{
    if (id == A_OTHER) return nullptr;
    for (const Attr& a : v)
        if (a.id == id) return &a;
    return nullptr;
}

bool ieq(const std::string& a, const std::string& b)
{
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++)
        if ((a[i] | 0x20) != (b[i] | 0x20)) return false;
    return true;
}

const Attr* find_attr_name(const std::vector<Attr>& v, const std::string& name)
{
    sdp_attr_id_t id = sdp_attr_from(name.c_str(), name.size());
    if (id != SDP_A_OTHER) return find_attr(v, id);
    for (const Attr& a : v)
        if (a.id == A_OTHER && ieq(a.name, name)) return &a;
    return nullptr;
}

/* An attribute whose value is a plain millisecond count (ptime,
 * maxptime); 0 when absent or unreadable. */
int attr_ms(const std::vector<Attr>& v, int id)
{
    const Attr* a = find_attr(v, id);
    if (a == nullptr) return 0;
    int n = as_int(a->value);
    return n < 0 ? 0 : n;
}

/* RFC 3551 §6: the static payload type assignments still seen on a
 * telephony leg. Dynamic types (96..127) are the caller's to name. */
struct StaticPt {
    int         pt;
    const char* enc;
    int         clock;
};
const StaticPt k_static[] = {
    { 0, "PCMU", 8000 },   { 3, "GSM", 8000 },    { 4, "G723", 8000 },
    { 5, "DVI4", 8000 },   { 6, "DVI4", 16000 },  { 7, "LPC", 8000 },
    { 8, "PCMA", 8000 },   { 9, "G722", 8000 },   { 10, "L16", 44100 },
    { 11, "L16", 44100 },  { 12, "QCELP", 8000 }, { 13, "CN", 8000 },
    { 14, "MPA", 90000 },  { 15, "G728", 8000 },  { 16, "DVI4", 11025 },
    { 17, "DVI4", 22050 }, { 18, "G729", 8000 }
};

const StaticPt* static_pt(int pt)
{
    for (const StaticPt& e : k_static)
        if (e.pt == pt) return &e;
    return nullptr;
}

} // namespace

/* ---- Media ---- */

int Media::format_count() const
{
    return (int)fmts.size();
}

std::string Media::format_at(int i) const
{
    if (i < 0 || (size_t)i >= fmts.size()) fail("format_at", SDP_E_INVAL);
    return fmts[(size_t)i];
}

int Media::pt_count() const
{
    return (int)fmts.size();
}

int Media::pt_at(int i) const
{
    if (i < 0 || (size_t)i >= fmts.size()) fail("pt_at", SDP_E_INVAL);
    return as_int(fmts[(size_t)i]);
}

bool Media::has_pt(int pt) const
{
    for (const std::string& f : fmts)
        if (as_int(f) == pt) return true;
    return false;
}

bool Media::has_rtpmap(int pt) const
{
    for (const Attr& a : attrs) {
        if (a.id != A_RTPMAP) continue;
        sdp_rtpmap_t r;
        sdp_str_t    v{ a.value.data(), (uint32_t)a.value.size() };
        if (sdp_rtpmap_parse(v, &r) == SDP_OK && r.pt == pt) return true;
    }
    return false;
}

Rtpmap Media::rtpmap(int pt) const
{
    for (const Attr& a : attrs) {
        if (a.id != A_RTPMAP) continue;
        sdp_rtpmap_t r;
        sdp_str_t    v{ a.value.data(), (uint32_t)a.value.size() };
        if (sdp_rtpmap_parse(v, &r) != SDP_OK || r.pt != pt) continue;
        Rtpmap out;
        out.pt     = r.pt;
        out.enc    = str(r.enc);
        out.clock  = r.clock;
        out.params = str(r.params);
        return out;
    }
    fail("rtpmap", SDP_E_MISSING);
}

std::string Media::fmtp(int pt) const
{
    for (const Attr& a : attrs) {
        if (a.id != A_FMTP) continue;
        sdp_fmtp_t f;
        sdp_str_t  v{ a.value.data(), (uint32_t)a.value.size() };
        if (sdp_fmtp_parse(v, &f) == SDP_OK && as_int(str(f.fmt)) == pt)
            return str(f.params);
    }
    return std::string();
}

int Media::ptime() const
{
    return attr_ms(attrs, A_PTIME);
}

int Media::maxptime() const
{
    return attr_ms(attrs, A_MAXPTIME);
}

int Media::attr_count() const
{
    return (int)attrs.size();
}

Attr Media::attr_at(int i) const
{
    if (i < 0 || (size_t)i >= attrs.size()) fail("attr_at", SDP_E_INVAL);
    return attrs[(size_t)i];
}

bool Media::has_attr(int id) const
{
    return find_attr(attrs, id) != nullptr;
}

std::string Media::attr(int id) const
{
    const Attr* a = find_attr(attrs, id);
    return a ? a->value : std::string();
}

std::string Media::attr_name(const std::string& aname) const
{
    const Attr* a = find_attr_name(attrs, aname);
    return a ? a->value : std::string();
}

int Media::bw_count() const
{
    return (int)bws.size();
}

Bw Media::bw_at(int i) const
{
    if (i < 0 || (size_t)i >= bws.size()) fail("bw_at", SDP_E_INVAL);
    return bws[(size_t)i];
}

uint64_t Media::bw(const std::string& bwtype) const
{
    for (const Bw& b : bws)
        if (ieq(b.bwtype, bwtype)) return b.value;
    return 0;
}

/* ---- Msg ---- */

int Msg::media_count() const
{
    return (int)medias.size();
}

Media Msg::media_at(int i) const
{
    if (i < 0 || (size_t)i >= medias.size()) fail("media_at", SDP_E_INVAL);
    return medias[(size_t)i];
}

bool Msg::has_media(int type) const
{
    for (const Media& m : medias)
        if (m.type == type) return true;
    return false;
}

Media Msg::media(int type) const
{
    for (const Media& m : medias)
        if (m.type == type) return m;
    fail("media", SDP_E_MISSING);
}

int Msg::attr_count() const
{
    return (int)attrs.size();
}

Attr Msg::attr_at(int i) const
{
    if (i < 0 || (size_t)i >= attrs.size()) fail("attr_at", SDP_E_INVAL);
    return attrs[(size_t)i];
}

bool Msg::has_attr(int id) const
{
    return find_attr(attrs, id) != nullptr;
}

std::string Msg::attr(int id) const
{
    const Attr* a = find_attr(attrs, id);
    return a ? a->value : std::string();
}

std::string Msg::attr_name(const std::string& aname) const
{
    const Attr* a = find_attr_name(attrs, aname);
    return a ? a->value : std::string();
}

int Msg::bw_count() const
{
    return (int)bws.size();
}

Bw Msg::bw_at(int i) const
{
    if (i < 0 || (size_t)i >= bws.size()) fail("bw_at", SDP_E_INVAL);
    return bws[(size_t)i];
}

uint64_t Msg::bw(const std::string& bwtype) const
{
    for (const Bw& b : bws)
        if (ieq(b.bwtype, bwtype)) return b.value;
    return 0;
}

/* ---- parse ---- */

Msg parse(const std::string& body)
{
    /* ~6 KiB; on the stack exactly as the C header intends, so a parse
     * costs no allocation beyond the strings it materializes. */
    sdp_msg_t c;
    int       rc = sdp_msg_parse(&c, body.data(), body.size());
    if (rc != SDP_OK) fail("parse", rc);

    Msg m;
    m.version    = c.version;
    m.has_origin = c.has_origin;
    if (c.has_origin) {
        m.origin.username     = str(c.origin.username);
        m.origin.sess_id      = c.origin.sess_id;
        m.origin.sess_version = c.origin.sess_version;
        m.origin.nettype      = str(c.origin.nettype);
        m.origin.addrtype     = str(c.origin.addrtype);
        m.origin.addr         = str(c.origin.addr);
    }
    m.name     = str(c.name);
    m.info     = str(c.info);
    m.uri      = str(c.uri);
    m.has_conn = c.has_conn;
    if (c.has_conn) {
        m.conn.nettype  = str(c.conn.nettype);
        m.conn.addrtype = str(c.conn.addrtype);
        m.conn.addr     = str(c.conn.addr);
    }
    m.has_time = c.has_time;
    m.t_start  = c.t_start;
    m.t_stop   = c.t_stop;
    m.dir      = sdp_media_dir(&c, nullptr);
    m.attrs    = copy_attrs(c, 0, c.attr_count);
    m.bws      = copy_bws(c, 0, c.bw_count);

    m.medias.reserve(c.media_count);
    for (unsigned i = 0; i < c.media_count; i++) {
        const sdp_media_t& s = c.media[i];
        Media              d;
        d.type       = s.type;
        d.type_name  = str(s.type_name);
        d.port       = s.port;
        d.nports     = s.nports;
        d.proto      = s.proto;
        d.proto_name = str(s.proto_name);
        d.title      = str(s.title);
        /* Resolved once, here: media-level c= over session-level, and
         * the section's direction over the session's. */
        if (const sdp_conn_t* cc = sdp_media_conn(&c, &s)) {
            d.addr     = str(cc->addr);
            d.addrtype = str(cc->addrtype);
        }
        d.dir   = sdp_media_dir(&c, &s);
        d.attrs = copy_attrs(c, s.attr_off, s.attr_count);
        d.bws   = copy_bws(c, s.bw_off, s.bw_count);
        d.fmts.reserve(s.fmt_count);
        for (unsigned f = s.fmt_off; f < (unsigned)(s.fmt_off + s.fmt_count);
             f++)
            d.fmts.push_back(str(c.fmts[f]));
        m.medias.push_back(std::move(d));
    }
    return m;
}

/* ---- name tables ---- */

std::string attr_name(int id)
{
    return sdp_attr_name((sdp_attr_id_t)id);
}

std::string mtype_name(int type)
{
    return sdp_mtype_name((sdp_mtype_t)type);
}

std::string proto_name(int proto)
{
    return sdp_proto_name((sdp_proto_t)proto);
}

std::string dir_name(int dir)
{
    return sdp_dir_name((sdp_dir_t)dir);
}

std::string pt_encoding(int pt)
{
    const StaticPt* e = static_pt(pt);
    return e ? e->enc : "";
}

int pt_clock(int pt)
{
    const StaticPt* e = static_pt(pt);
    return e ? e->clock : 0;
}

/* ---- Builder ---- */

Builder::Builder(size_t cap) : buf_(new char[cap]), cap_(cap)
{
    reset();
}

Builder& Builder::version()
{
    reset();
    check(sdp_put_version(&w_), "version");
    return *this;
}

Builder& Builder::origin(const std::string& user, uint64_t sess_id,
                         uint64_t sess_version, const std::string& addr,
                         const std::string& addrtype)
{
    check(sdp_put_origin(&w_, user.data(), user.size(), sess_id, sess_version,
                         addrtype.data(), addrtype.size(), addr.data(),
                         addr.size()),
          "origin");
    return *this;
}

Builder& Builder::name(const std::string& n)
{
    check(sdp_put_name(&w_, n.data(), n.size()), "name");
    return *this;
}

Builder& Builder::conn(const std::string& addr, const std::string& addrtype)
{
    check(sdp_put_conn(&w_, addrtype.data(), addrtype.size(), addr.data(),
                       addr.size()),
          "conn");
    return *this;
}

Builder& Builder::bw(const std::string& bwtype, uint64_t value)
{
    check(sdp_put_bw(&w_, bwtype.data(), bwtype.size(), value), "bw");
    return *this;
}

Builder& Builder::time(uint64_t start, uint64_t stop)
{
    check(sdp_put_time(&w_, start, stop), "time");
    return *this;
}

Builder& Builder::media(int type, int port, int proto, const std::string& fmts)
{
    if (port < 0 || port > 65535) fail("media", SDP_E_INVAL);
    check(sdp_put_media(&w_, (sdp_mtype_t)type, (uint16_t)port, 1,
                        (sdp_proto_t)proto, fmts.data(), fmts.size()),
          "media");
    return *this;
}

Builder& Builder::media_name(const std::string& type, int port,
                             const std::string& proto, const std::string& fmts)
{
    if (port < 0 || port > 65535) fail("media_name", SDP_E_INVAL);
    check(sdp_put_media_name(&w_, type.data(), type.size(), (uint16_t)port, 1,
                             proto.data(), proto.size(), fmts.data(),
                             fmts.size()),
          "media_name");
    return *this;
}

Builder& Builder::attr(int id, const std::string& value)
{
    check(sdp_put_attr(&w_, (sdp_attr_id_t)id, value.data(), value.size()),
          "attr");
    return *this;
}

Builder& Builder::attr_name(const std::string& name, const std::string& value)
{
    check(sdp_put_attr_name(&w_, name.data(), name.size(), value.data(),
                            value.size()),
          "attr_name");
    return *this;
}

Builder& Builder::line(const std::string& type, const std::string& value)
{
    if (type.size() != 1) fail("line", SDP_E_INVAL);
    check(sdp_put_line(&w_, type[0], value.data(), value.size()), "line");
    return *this;
}

std::string Builder::done()
{
    int n = sdp_end(&w_);
    if (n < 0) fail("done", n);
    std::string out(buf_.get(), (size_t)n);
    reset();
    return out;
}

/* ---- offer ---- */

std::string offer(const Offer& o)
{
    if (o.addr.empty())
        fail("offer: addr (our own media address)", SDP_E_INVAL);
    /* Port 0 is how an ANSWER rejects a stream (RFC 3264 §6); an offer
     * that carried it would be asking for no media at all, which is
     * never what a UE placing a call meant to say. */
    if (o.port <= 0 || o.port > 65535)
        fail("offer: port (our own RTP port)", SDP_E_INVAL);
    if (o.pt < 0 || o.pt > 127) fail("offer: pt", SDP_E_INVAL);

    std::string codec = o.codec;
    int         rate  = o.rate;
    if (codec.empty()) {
        codec = pt_encoding(o.pt);
        /* A dynamic payload type has no name to borrow; claiming PCMU
         * for it would produce an offer that negotiates and then plays
         * noise, so say what is missing instead. */
        if (codec.empty())
            fail("offer: payload type is not a static one, set codec",
                 SDP_E_INVAL);
    }
    if (rate <= 0) {
        rate = pt_clock(o.pt);
        if (rate <= 0)
            fail("offer: set rate for this payload type", SDP_E_INVAL);
    }

    /* RFC 8866 §5.2 wants a session id unique per session from this
     * originator; seed from the wall clock so two runs of a tool never
     * collide, then count up. */
    static uint64_t next_id = (uint64_t)std::time(nullptr);
    uint64_t        id      = o.id ? o.id : ++next_id;

    std::string pt = std::to_string(o.pt);
    Builder     b(1024);
    b.version()
        .origin(o.user, id, o.version, o.addr, o.addrtype)
        .name(o.name)
        .conn(o.addr, o.addrtype)
        .time(0, 0)
        .media(M_AUDIO, o.port, P_RTP_AVP, pt)
        .attr(A_RTPMAP, pt + " " + codec + "/" + std::to_string(rate));
    if (o.ptime > 0) b.attr(A_PTIME, std::to_string(o.ptime));
    b.attr(o.dir == DIR_SENDONLY   ? A_SENDONLY
           : o.dir == DIR_RECVONLY ? A_RECVONLY
           : o.dir == DIR_INACTIVE ? A_INACTIVE
                                   : A_SENDRECV);
    return b.done();
}

} // namespace sdp
