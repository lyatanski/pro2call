#include <limits.h>
#include <string.h>

#include "sdp.h"
#include "sdp_intl.h"

/* ---- name tables ---- */

typedef struct {
    const char* name;
    uint8_t     len;
} name_len_t;

static const name_len_t k_attr[SDP_A_MAX] = {
    [SDP_A_OTHER]       = { "", 0 },
    [SDP_A_CANDIDATE]   = { "candidate", 9 },
    [SDP_A_CRYPTO]      = { "crypto", 6 },
    [SDP_A_EXTMAP]      = { "extmap", 6 },
    [SDP_A_FINGERPRINT] = { "fingerprint", 11 },
    [SDP_A_FMTP]        = { "fmtp", 4 },
    [SDP_A_GROUP]       = { "group", 5 },
    [SDP_A_ICE_LITE]    = { "ice-lite", 8 },
    [SDP_A_ICE_OPTIONS] = { "ice-options", 11 },
    [SDP_A_ICE_PWD]     = { "ice-pwd", 7 },
    [SDP_A_ICE_UFRAG]   = { "ice-ufrag", 9 },
    [SDP_A_INACTIVE]    = { "inactive", 8 },
    [SDP_A_MAXPTIME]    = { "maxptime", 8 },
    [SDP_A_MID]         = { "mid", 3 },
    [SDP_A_MSID]        = { "msid", 4 },
    [SDP_A_PTIME]       = { "ptime", 5 },
    [SDP_A_RECVONLY]    = { "recvonly", 8 },
    [SDP_A_RTCP]        = { "rtcp", 4 },
    [SDP_A_RTCP_FB]     = { "rtcp-fb", 7 },
    [SDP_A_RTCP_MUX]    = { "rtcp-mux", 8 },
    [SDP_A_RTPMAP]      = { "rtpmap", 6 },
    [SDP_A_SENDONLY]    = { "sendonly", 8 },
    [SDP_A_SENDRECV]    = { "sendrecv", 8 },
    [SDP_A_SETUP]       = { "setup", 5 },
    [SDP_A_SSRC]        = { "ssrc", 4 },
    [SDP_A_SSRC_GROUP]  = { "ssrc-group", 10 }
};

/* The enum is alphabetical, so each first letter owns a contiguous id
 * range; lookup walks only that bucket. lo == 0 means no such names.
 * A name that is another's prefix ("rtcp" before "rtcp-fb") is safe in
 * either order because the scan compares the length first. */
static const struct {
    uint8_t lo, hi;
} k_attr_bucket[26] = { ['c' - 'a'] = { SDP_A_CANDIDATE, SDP_A_CRYPTO },
                        ['e' - 'a'] = { SDP_A_EXTMAP, SDP_A_EXTMAP },
                        ['f' - 'a'] = { SDP_A_FINGERPRINT, SDP_A_FMTP },
                        ['g' - 'a'] = { SDP_A_GROUP, SDP_A_GROUP },
                        ['i' - 'a'] = { SDP_A_ICE_LITE, SDP_A_INACTIVE },
                        ['m' - 'a'] = { SDP_A_MAXPTIME, SDP_A_MSID },
                        ['p' - 'a'] = { SDP_A_PTIME, SDP_A_PTIME },
                        ['r' - 'a'] = { SDP_A_RECVONLY, SDP_A_RTPMAP },
                        ['s' - 'a'] = { SDP_A_SENDONLY, SDP_A_SSRC_GROUP } };

static const name_len_t k_mtype[SDP_M_MAX] = {
    [SDP_M_OTHER]       = { "", 0 },
    [SDP_M_AUDIO]       = { "audio", 5 },
    [SDP_M_VIDEO]       = { "video", 5 },
    [SDP_M_TEXT]        = { "text", 4 },
    [SDP_M_APPLICATION] = { "application", 11 },
    [SDP_M_MESSAGE]     = { "message", 7 },
    [SDP_M_IMAGE]       = { "image", 5 }
};

/* Case matters: "udp" and "udptl" are registered lowercase, the
 * RTP profiles and "TCP" uppercase. */
static const name_len_t k_proto[SDP_P_MAX] = {
    [SDP_P_OTHER]             = { "", 0 },
    [SDP_P_RTP_AVP]           = { "RTP/AVP", 7 },
    [SDP_P_RTP_AVPF]          = { "RTP/AVPF", 8 },
    [SDP_P_RTP_SAVP]          = { "RTP/SAVP", 8 },
    [SDP_P_RTP_SAVPF]         = { "RTP/SAVPF", 9 },
    [SDP_P_UDP_TLS_RTP_SAVP]  = { "UDP/TLS/RTP/SAVP", 16 },
    [SDP_P_UDP_TLS_RTP_SAVPF] = { "UDP/TLS/RTP/SAVPF", 17 },
    [SDP_P_UDP_DTLS_SCTP]     = { "UDP/DTLS/SCTP", 13 },
    [SDP_P_UDPTL]             = { "udptl", 5 },
    [SDP_P_UDP]               = { "udp", 3 },
    [SDP_P_TCP]               = { "TCP", 3 }
};

static const name_len_t k_dir[4] = {
    { "sendrecv", 8 }, { "sendonly", 8 }, { "recvonly", 8 }, { "inactive", 8 }
};

const char* sdp_attr_name(sdp_attr_id_t id)
{
    return ((unsigned)id < SDP_A_MAX) ? k_attr[id].name : "";
}

sdp_attr_id_t sdp_attr_from(const char* name, size_t len)
{
    /* "mid" is the shortest, "fingerprint"/"ice-options" the longest. */
    if (SDP_UNLIKELY(name == NULL || len < 3 || len > 11)) return SDP_A_OTHER;
    char c = sdp_lc(name[0]);
    if (c < 'a' || c > 'z') return SDP_A_OTHER;
    uint8_t hi = k_attr_bucket[c - 'a'].hi;
    for (uint8_t id = k_attr_bucket[c - 'a'].lo; id && id <= hi; id++)
        if (k_attr[id].len == len && sdp_ieq2(name, k_attr[id].name, len))
            return (sdp_attr_id_t)id;
    return SDP_A_OTHER;
}

const char* sdp_mtype_name(sdp_mtype_t t)
{
    return ((unsigned)t < SDP_M_MAX) ? k_mtype[t].name : "";
}

sdp_mtype_t sdp_mtype_from(const char* name, size_t len)
{
    if (SDP_UNLIKELY(name == NULL)) return SDP_M_OTHER;
    for (uint8_t id = 1; id < SDP_M_MAX; id++)
        if (k_mtype[id].len == len && memcmp(name, k_mtype[id].name, len) == 0)
            return (sdp_mtype_t)id;
    return SDP_M_OTHER;
}

const char* sdp_proto_name(sdp_proto_t p)
{
    return ((unsigned)p < SDP_P_MAX) ? k_proto[p].name : "";
}

sdp_proto_t sdp_proto_from(const char* name, size_t len)
{
    if (SDP_UNLIKELY(name == NULL)) return SDP_P_OTHER;
    for (uint8_t id = 1; id < SDP_P_MAX; id++)
        if (k_proto[id].len == len && memcmp(name, k_proto[id].name, len) == 0)
            return (sdp_proto_t)id;
    return SDP_P_OTHER;
}

const char* sdp_dir_name(sdp_dir_t d)
{
    return ((unsigned)d < 4) ? k_dir[d].name : "";
}

/* ---- message parse ----
 *
 * Liberal in, strict out, but not liberal about anything that would
 * make us send media to the wrong place: a malformed v=, o=, c=, b=,
 * t= or m= fails the parse, because silently using a half-read c= is
 * worse than reporting that the description is broken. Lines whose
 * type letter the module has no use for (e=, p=, k=, r=, z=) and lines
 * with an unrecognized letter are skipped, as RFC 8866 §5 requires,
 * and an unknown a= comes back as SDP_A_OTHER rather than an error. */

/* Locate the terminator of the line starting at p: *eol is set to the
 * first byte of the CRLF (or bare LF), the return value is the start of
 * the following line. A final line with no terminator ends at the
 * buffer end, which also ends the scan. */
static const char* line_end(const char* p, const char* end, const char** eol)
{
    const char* nl = memchr(p, '\n', (size_t)(end - p));
    if (nl == NULL) {
        *eol = end;
        return end;
    }
    *eol = (nl > p && nl[-1] == '\r') ? nl - 1 : nl;
    return nl + 1;
}

/* Next whitespace-delimited field in [*p, end): the slice, with *p
 * advanced past it. An empty slice means the line is exhausted. */
static sdp_str_t field(const char** p, const char* end)
{
    const char* s = *p;
    while (s < end && sdp_is_ws(*s))
        s++;
    const char* q = s;
    while (q < end && !sdp_is_ws(*q))
        q++;
    *p = q;
    return (sdp_str_t){ s, (uint32_t)(q - s) };
}

/* o=<username> <sess-id> <sess-version> <nettype> <addrtype> <address>
 *
 * The RFC calls sess-id/sess-version numeric strings; a peer that emits
 * something else still describes usable media, and the struct has no
 * place to keep a non-numeric one, so those come out as 0 rather than
 * failing the description. A missing field does fail it. */
static int parse_origin(sdp_origin_t* o, const char* p, const char* end)
{
    sdp_str_t f[6];
    for (int i = 0; i < 6; i++) {
        f[i] = field(&p, end);
        if (SDP_UNLIKELY(f[i].len == 0)) return SDP_E_LINE;
    }
    o->username = f[0];
    if (!sdp_parse_u64(f[1].p, f[1].len, &o->sess_id)) o->sess_id = 0;
    if (!sdp_parse_u64(f[2].p, f[2].len, &o->sess_version)) o->sess_version = 0;
    o->nettype  = f[3];
    o->addrtype = f[4];
    o->addr     = f[5];
    return SDP_OK;
}

/* c=<nettype> <addrtype> <connection-address> */
static int parse_conn(sdp_conn_t* c, const char* p, const char* end)
{
    sdp_str_t f[3];
    for (int i = 0; i < 3; i++) {
        f[i] = field(&p, end);
        if (SDP_UNLIKELY(f[i].len == 0)) return SDP_E_LINE;
    }
    c->nettype  = f[0];
    c->addrtype = f[1];
    c->addr     = f[2];
    return SDP_OK;
}

/* m=<media> <port>[/<n>] <proto> <fmt> ... — the format list may be
 * empty (the RFC wants one, and a rejected stream often has none). */
static int parse_media(sdp_msg_t* m, sdp_media_t* md, const char* p,
                       const char* end, uint16_t* nfmt)
{
    sdp_str_t type = field(&p, end);
    sdp_str_t port = field(&p, end);
    sdp_str_t prot = field(&p, end);
    if (SDP_UNLIKELY(type.len == 0 || port.len == 0 || prot.len == 0))
        return SDP_E_LINE;

    /* <port>/<n>: a hierarchical stream count, absent in unicast VoIP. */
    const char* slash = memchr(port.p, '/', port.len);
    uint32_t    plen  = slash ? (uint32_t)(slash - port.p) : port.len;
    if (SDP_UNLIKELY(!sdp_parse_u16(port.p, plen, &md->port)))
        return SDP_E_LINE;
    md->nports = 1;
    if (slash) {
        uint32_t nlen = port.len - plen - 1;
        if (SDP_UNLIKELY(!sdp_parse_u16(slash + 1, nlen, &md->nports)))
            return SDP_E_LINE;
    }

    md->type       = (uint8_t)sdp_mtype_from(type.p, type.len);
    md->type_name  = type;
    md->proto      = (uint8_t)sdp_proto_from(prot.p, prot.len);
    md->proto_name = prot;
    md->fmt_off    = *nfmt;
    for (;;) {
        sdp_str_t f = field(&p, end);
        if (f.len == 0) break;
        if (SDP_UNLIKELY(*nfmt >= SDP_MAX_FMTS)) return SDP_E_FMTS;
        m->fmts[(*nfmt)++] = f;
        md->fmt_count++;
    }
    return SDP_OK;
}

int sdp_msg_parse(sdp_msg_t* m, const char* buf, size_t len)
{
    if (SDP_UNLIKELY(m == NULL || buf == NULL || len > (size_t)INT_MAX))
        return SDP_E_INVAL;

    /* The pools are left alone: only the counted prefix of each is ever
     * read, so zeroing 6 KiB on every parse would be pure waste. The
     * scalars and the two optional structs are cleared, so a caller that
     * reads origin/conn without checking has_* sees zeros, not the
     * previous message's slices. */
    m->version    = 0;
    m->has_origin = false;
    memset(&m->origin, 0, sizeof m->origin);
    m->name     = (sdp_str_t){ NULL, 0 };
    m->info     = (sdp_str_t){ NULL, 0 };
    m->uri      = (sdp_str_t){ NULL, 0 };
    m->has_conn = false;
    memset(&m->conn, 0, sizeof m->conn);
    m->has_time    = false;
    m->t_start     = 0;
    m->t_stop      = 0;
    m->bw_count    = 0;
    m->attr_count  = 0;
    m->media_count = 0;

    const char* p   = buf;
    const char* end = buf + len;

    /* Running pool totals; each section's run is [*_off, *_off + count). */
    uint16_t nattr = 0, nfmt = 0, nbw = 0;
    /* The section attributes/bandwidth/c=/i= currently belong to, NULL
     * while still at session level. */
    sdp_media_t* cur   = NULL;
    bool         got_v = false;

    while (p < end) {
        const char* eol;
        const char* next = line_end(p, end, &eol);

        /* A body may carry a trailing blank line; the RFC has no empty
         * lines, so skipping is the only sane reading. */
        if (eol == p) {
            p = next;
            continue;
        }
        if (SDP_UNLIKELY(eol - p < 2 || p[1] != '=')) return SDP_E_LINE;

        char        type = p[0];
        const char* v    = p + 2;
        /* Trailing whitespace is not part of any value. */
        while (eol > v && sdp_is_ws(eol[-1]))
            eol--;

        if (SDP_UNLIKELY(!got_v)) {
            if (type != 'v') return SDP_E_VERSION;
            if (eol - v != 1 || *v != '0') return SDP_E_VERSION;
            m->version = 0;
            got_v      = true;
            p          = next;
            continue;
        }

        switch (type) {
        case 'v': /* a second v= is not a description we understand */
            return SDP_E_VERSION;

        case 'o': {
            int rc = parse_origin(&m->origin, v, eol);
            if (SDP_UNLIKELY(rc != SDP_OK)) return rc;
            m->has_origin = true;
            break;
        }

        case 's': m->name = (sdp_str_t){ v, (uint32_t)(eol - v) }; break;

        case 'i': {
            sdp_str_t s = { v, (uint32_t)(eol - v) };
            if (cur) cur->title = s;
            else m->info = s;
            break;
        }

        case 'u': m->uri = (sdp_str_t){ v, (uint32_t)(eol - v) }; break;

        case 'c': {
            /* RFC 8866 §5.7: a media-level c= overrides the session
             * one for that stream. rtpengine emits both, and reading
             * the wrong one sends media to the wrong host — which is
             * why this is resolved here once, by sdp_media_conn(),
             * rather than at every call site. */
            sdp_conn_t* dst  = cur ? &cur->conn : &m->conn;
            bool*       flag = cur ? &cur->has_conn : &m->has_conn;
            if (*flag) break; /* first c= of the section wins */
            int rc = parse_conn(dst, v, eol);
            if (SDP_UNLIKELY(rc != SDP_OK)) return rc;
            *flag = true;
            break;
        }

        case 'b': {
            const char* colon = memchr(v, ':', (size_t)(eol - v));
            if (SDP_UNLIKELY(colon == NULL || colon == v)) return SDP_E_LINE;
            if (SDP_UNLIKELY(nbw >= SDP_MAX_BWS)) return SDP_E_BWS;
            sdp_bw_t* b = &m->bws[nbw];
            b->bwtype   = (sdp_str_t){ v, (uint32_t)(colon - v) };
            if (SDP_UNLIKELY(!sdp_parse_u64(
                    colon + 1, (size_t)(eol - colon - 1), &b->value)))
                return SDP_E_LINE;
            nbw++;
            if (cur) cur->bw_count++;
            else m->bw_count++;
            break;
        }

        case 't': {
            /* Repeat descriptors (r=) and later t= lines describe a
             * schedule no VoIP session has; the first t= is enough. */
            if (m->has_time) break;
            const char* q     = v;
            sdp_str_t   start = field(&q, eol);
            sdp_str_t   stop  = field(&q, eol);
            if (SDP_UNLIKELY(start.len == 0 || stop.len == 0))
                return SDP_E_LINE;
            if (SDP_UNLIKELY(!sdp_parse_u64(start.p, start.len, &m->t_start) ||
                             !sdp_parse_u64(stop.p, stop.len, &m->t_stop)))
                return SDP_E_LINE;
            m->has_time = true;
            break;
        }

        case 'm': {
            if (SDP_UNLIKELY(m->media_count >= SDP_MAX_MEDIA))
                return SDP_E_MEDIA;
            cur  = &m->media[m->media_count];
            *cur = (sdp_media_t){ 0 };
            /* The runs start empty at the current pool tops; attributes
             * and bandwidth lines below this m= append to them. */
            cur->bw_off   = nbw;
            cur->attr_off = nattr;
            int rc        = parse_media(m, cur, v, eol, &nfmt);
            if (SDP_UNLIKELY(rc != SDP_OK)) return rc;
            m->media_count++;
            break;
        }

        case 'a': {
            if (SDP_UNLIKELY(nattr >= SDP_MAX_ATTRS)) return SDP_E_ATTRS;
            const char* colon = memchr(v, ':', (size_t)(eol - v));
            const char* ne    = colon ? colon : eol;
            sdp_attr_t* a     = &m->attrs[nattr];
            a->name           = (sdp_str_t){ v, (uint32_t)(ne - v) };
            a->id             = (uint8_t)sdp_attr_from(v, (size_t)(ne - v));
            if (colon) {
                const char* av = colon + 1;
                while (av < eol && sdp_is_ws(*av))
                    av++;
                a->value = (sdp_str_t){ av, (uint32_t)(eol - av) };
            } else {
                a->value = (sdp_str_t){ NULL, 0 };
            }
            nattr++;
            if (cur) cur->attr_count++;
            else m->attr_count++;
            break;
        }

        default: /* e= p= k= r= z= and anything unregistered */ break;
        }

        p = next;
    }

    if (SDP_UNLIKELY(!got_v)) return SDP_E_VERSION;
    return SDP_OK;
}

/* ---- attribute access ---- */

static void attr_range(const sdp_msg_t* m, const sdp_media_t* media,
                       uint16_t* lo, uint16_t* hi)
{
    if (media == NULL) {
        *lo = 0;
        *hi = m->attr_count;
    } else {
        *lo = media->attr_off;
        *hi = (uint16_t)(media->attr_off + media->attr_count);
    }
}

const sdp_attr_t* sdp_attr_find(const sdp_msg_t* m, const sdp_media_t* media,
                                sdp_attr_id_t id)
{
    if (SDP_UNLIKELY(m == NULL || id == SDP_A_OTHER)) return NULL;
    uint16_t lo, hi;
    attr_range(m, media, &lo, &hi);
    for (uint16_t i = lo; i < hi; i++)
        if (m->attrs[i].id == (uint8_t)id) return &m->attrs[i];
    return NULL;
}

const sdp_attr_t* sdp_attr_next(const sdp_msg_t* m, const sdp_media_t* media,
                                const sdp_attr_t* prev)
{
    if (SDP_UNLIKELY(m == NULL || prev == NULL)) return NULL;
    uint16_t lo, hi;
    attr_range(m, media, &lo, &hi);
    if (SDP_UNLIKELY(prev < m->attrs + lo || prev >= m->attrs + hi))
        return NULL;
    for (const sdp_attr_t* a = prev + 1; a < m->attrs + hi; a++) {
        if (a->id != prev->id) continue;
        /* Extensions share one id, so they are matched by name. */
        if (a->id != SDP_A_OTHER) return a;
        if (a->name.len == prev->name.len &&
            sdp_ieq2(a->name.p, prev->name.p, a->name.len))
            return a;
    }
    return NULL;
}

const sdp_attr_t* sdp_attr_find_name(const sdp_msg_t*   m,
                                     const sdp_media_t* media, const char* name)
{
    if (SDP_UNLIKELY(m == NULL || name == NULL)) return NULL;
    size_t        n  = strlen(name);
    sdp_attr_id_t id = sdp_attr_from(name, n);
    if (id != SDP_A_OTHER) return sdp_attr_find(m, media, id);
    uint16_t lo, hi;
    attr_range(m, media, &lo, &hi);
    for (uint16_t i = lo; i < hi; i++)
        if (m->attrs[i].id == SDP_A_OTHER && m->attrs[i].name.len == n &&
            sdp_ieq2(m->attrs[i].name.p, name, n))
            return &m->attrs[i];
    return NULL;
}

/* One direction attribute in a section, or -1 when it carries none. */
static int section_dir(const sdp_msg_t* m, const sdp_media_t* media)
{
    uint16_t lo, hi;
    attr_range(m, media, &lo, &hi);
    for (uint16_t i = lo; i < hi; i++)
        switch (m->attrs[i].id) {
        case SDP_A_SENDRECV: return SDP_DIR_SENDRECV;
        case SDP_A_SENDONLY: return SDP_DIR_SENDONLY;
        case SDP_A_RECVONLY: return SDP_DIR_RECVONLY;
        case SDP_A_INACTIVE: return SDP_DIR_INACTIVE;
        default:             break;
        }
    return -1;
}

sdp_dir_t sdp_media_dir(const sdp_msg_t* m, const sdp_media_t* media)
{
    if (SDP_UNLIKELY(m == NULL)) return SDP_DIR_SENDRECV;
    int d = section_dir(m, media);
    if (d < 0 && media != NULL) d = section_dir(m, NULL);
    return (d < 0) ? SDP_DIR_SENDRECV : (sdp_dir_t)d;
}

const sdp_conn_t* sdp_media_conn(const sdp_msg_t* m, const sdp_media_t* media)
{
    if (SDP_UNLIKELY(m == NULL)) return NULL;
    if (media != NULL && media->has_conn) return &media->conn;
    return m->has_conn ? &m->conn : NULL;
}

/* ---- deep parsers ---- */

int sdp_rtpmap_parse(sdp_str_t value, sdp_rtpmap_t* out)
{
    if (SDP_UNLIKELY(out == NULL || value.p == NULL)) return SDP_E_INVAL;

    const char* p    = value.p;
    const char* end  = value.p + value.len;
    sdp_str_t   pt   = field(&p, end);
    sdp_str_t   rest = field(&p, end);
    if (SDP_UNLIKELY(pt.len == 0 || rest.len == 0)) return SDP_E_LINE;

    uint32_t n;
    if (SDP_UNLIKELY(!sdp_parse_u32(pt.p, pt.len, &n) || n > 127))
        return SDP_E_LINE;
    out->pt = (uint8_t)n;

    /* <encoding>/<clock rate>[/<encoding parameters>] */
    const char* s1 = memchr(rest.p, '/', rest.len);
    if (SDP_UNLIKELY(s1 == NULL || s1 == rest.p)) return SDP_E_LINE;
    const char* rend = rest.p + rest.len;
    const char* s2   = memchr(s1 + 1, '/', (size_t)(rend - s1 - 1));
    const char* cend = s2 ? s2 : rend;
    if (SDP_UNLIKELY(
            !sdp_parse_u32(s1 + 1, (size_t)(cend - s1 - 1), &out->clock)))
        return SDP_E_LINE;

    out->enc    = (sdp_str_t){ rest.p, (uint32_t)(s1 - rest.p) };
    out->params = s2 ? (sdp_str_t){ s2 + 1, (uint32_t)(rend - s2 - 1) }
                     : (sdp_str_t){ NULL, 0 };
    return SDP_OK;
}

int sdp_fmtp_parse(sdp_str_t value, sdp_fmtp_t* out)
{
    if (SDP_UNLIKELY(out == NULL || value.p == NULL)) return SDP_E_INVAL;

    const char* p   = value.p;
    const char* end = value.p + value.len;
    sdp_str_t   fmt = field(&p, end);
    if (SDP_UNLIKELY(fmt.len == 0)) return SDP_E_LINE;
    while (p < end && sdp_is_ws(*p))
        p++;
    out->fmt    = fmt;
    out->params = (sdp_str_t){ p, (uint32_t)(end - p) };
    return SDP_OK;
}

/* Does this slice spell exactly the decimal `pt`? Compared numerically,
 * so "08" and "8" are the same payload type. */
static bool is_pt(sdp_str_t s, unsigned pt)
{
    uint32_t v;
    return sdp_parse_u32(s.p, s.len, &v) && v == pt;
}

int sdp_rtpmap_find(const sdp_msg_t* m, const sdp_media_t* media, unsigned pt,
                    sdp_rtpmap_t* out)
{
    if (SDP_UNLIKELY(m == NULL || out == NULL)) return SDP_E_INVAL;
    for (const sdp_attr_t* a = sdp_attr_find(m, media, SDP_A_RTPMAP); a;
         a                   = sdp_attr_next(m, media, a)) {
        sdp_rtpmap_t r;
        if (sdp_rtpmap_parse(a->value, &r) == SDP_OK && r.pt == pt) {
            *out = r;
            return SDP_OK;
        }
    }
    return SDP_E_MISSING;
}

int sdp_fmtp_find(const sdp_msg_t* m, const sdp_media_t* media, unsigned pt,
                  sdp_str_t* params)
{
    if (SDP_UNLIKELY(m == NULL || params == NULL)) return SDP_E_INVAL;
    for (const sdp_attr_t* a = sdp_attr_find(m, media, SDP_A_FMTP); a;
         a                   = sdp_attr_next(m, media, a)) {
        sdp_fmtp_t f;
        if (sdp_fmtp_parse(a->value, &f) == SDP_OK && is_pt(f.fmt, pt)) {
            *params = f.params;
            return SDP_OK;
        }
    }
    return SDP_E_MISSING;
}
