#include <string.h>

#include "sms.h"
#include "sms_intl.h"

/* Data coding schemes, the GSM 7-bit default alphabet, septet packing
 * and everything built on them (TP-UD <-> UTF-8, the user data header,
 * concatenation) — TS 23.038 §4 and §6.2.1, TS 23.040 §9.2.3.16 and
 * §9.2.3.24.
 *
 * On the alphabet tables being hand-written: they were transcribed from
 * TS 23.038 table 6.2.1.1 and checked against it cell by cell. A
 * generator over the spec .docx was considered and rejected — see
 * sms/README.md; the short version is that the document encodes the ten
 * Greek letters as Word SYMBOL field codes and the escape position as a
 * footnote marker, so an extractor would need its own hand-written
 * Symbol-font table to produce this one. The tests carry the
 * verification instead: every septet round-trips, and the published
 * PDU vectors in sms/test decode byte for byte. */

/* ---- DCS (TS 23.038 §4) ---- */

void sms_dcs_decode(uint8_t dcs, sms_dcs_t* out)
{
    if (out == NULL) return;
    memset(out, 0, sizeof *out);
    out->alphabet = SMS_ALPHA_GSM7;

    unsigned group = (unsigned)(dcs >> 4);
    if (group <= 0x7) {
        /* 0000..0011 general data coding; 0100..0111 the same layout,
         * but the message is marked for automatic deletion. */
        out->auto_delete = group >= 0x4;
        out->compressed  = (dcs & 0x20) != 0;
        out->has_class   = (dcs & 0x10) != 0;
        out->cls         = (uint8_t)(dcs & 0x03);
        out->alphabet    = (uint8_t)((dcs >> 2) & 0x03);
        /* A compressed body is not text this codec can read, whatever
         * the alphabet bits claim. */
        if (out->compressed) out->alphabet = SMS_ALPHA_RESERVED;
    } else if (group >= 0xC && group <= 0xE) {
        out->mwi         = true;
        out->mwi_discard = group == 0xC;
        out->mwi_active  = (dcs & 0x08) != 0;
        out->mwi_type    = (uint8_t)(dcs & 0x03);
        /* 1100 and 1101 are GSM 7-bit, 1110 is UCS2. */
        out->alphabet = group == 0xE ? SMS_ALPHA_UCS2 : SMS_ALPHA_GSM7;
    } else if (group == 0xF) {
        out->has_class = true;
        out->cls       = (uint8_t)(dcs & 0x03);
        out->alphabet  = (dcs & 0x04) ? SMS_ALPHA_8BIT : SMS_ALPHA_GSM7;
    } else {
        /* 1000..1011 reserved. Reading it as GSM 7-bit is what handsets
         * do, but saying "reserved" keeps a caller from believing the
         * text. */
        out->alphabet = SMS_ALPHA_RESERVED;
    }
}

uint8_t sms_dcs_make(int alphabet, int cls)
{
    uint8_t dcs = 0;
    switch (alphabet) {
    case SMS_ALPHA_8BIT: dcs = 0x04; break;
    case SMS_ALPHA_UCS2: dcs = 0x08; break;
    default:             dcs = 0x00; break; /* GSM 7-bit */
    }
    if (cls >= 0 && cls <= 3) dcs |= (uint8_t)(0x10 | (unsigned)cls);
    return dcs;
}

int sms_dcs_alphabet(uint8_t dcs)
{
    sms_dcs_t d;
    sms_dcs_decode(dcs, &d);
    return d.alphabet;
}

/* ---- GSM 7-bit default alphabet (TS 23.038 §6.2.1) ----
 *
 * Table 6.2.1.1 read column by column: entry [i] is the Unicode code
 * point of septet i. 0x1B is the escape into the extension table and
 * has no character of its own. */
static const uint16_t gsm7_basic[128] = {
    /* 0x00 */ 0x0040,
    0x00A3,
    0x0024,
    0x00A5,
    0x00E8,
    0x00E9,
    0x00F9,
    0x00EC,
    /* 0x08 */ 0x00F2,
    0x00C7,
    0x000A,
    0x00D8,
    0x00F8,
    0x000D,
    0x00C5,
    0x00E5,
    /* 0x10 */ 0x0394,
    0x005F,
    0x03A6,
    0x0393,
    0x039B,
    0x03A9,
    0x03A0,
    0x03A8,
    /* 0x18 */ 0x03A3,
    0x0398,
    0x039E,
    0x001B,
    0x00C6,
    0x00E6,
    0x00DF,
    0x00C9,
    /* 0x20 */ 0x0020,
    0x0021,
    0x0022,
    0x0023,
    0x00A4,
    0x0025,
    0x0026,
    0x0027,
    /* 0x28 */ 0x0028,
    0x0029,
    0x002A,
    0x002B,
    0x002C,
    0x002D,
    0x002E,
    0x002F,
    /* 0x30 */ 0x0030,
    0x0031,
    0x0032,
    0x0033,
    0x0034,
    0x0035,
    0x0036,
    0x0037,
    /* 0x38 */ 0x0038,
    0x0039,
    0x003A,
    0x003B,
    0x003C,
    0x003D,
    0x003E,
    0x003F,
    /* 0x40 */ 0x00A1,
    0x0041,
    0x0042,
    0x0043,
    0x0044,
    0x0045,
    0x0046,
    0x0047,
    /* 0x48 */ 0x0048,
    0x0049,
    0x004A,
    0x004B,
    0x004C,
    0x004D,
    0x004E,
    0x004F,
    /* 0x50 */ 0x0050,
    0x0051,
    0x0052,
    0x0053,
    0x0054,
    0x0055,
    0x0056,
    0x0057,
    /* 0x58 */ 0x0058,
    0x0059,
    0x005A,
    0x00C4,
    0x00D6,
    0x00D1,
    0x00DC,
    0x00A7,
    /* 0x60 */ 0x00BF,
    0x0061,
    0x0062,
    0x0063,
    0x0064,
    0x0065,
    0x0066,
    0x0067,
    /* 0x68 */ 0x0068,
    0x0069,
    0x006A,
    0x006B,
    0x006C,
    0x006D,
    0x006E,
    0x006F,
    /* 0x70 */ 0x0070,
    0x0071,
    0x0072,
    0x0073,
    0x0074,
    0x0075,
    0x0076,
    0x0077,
    /* 0x78 */ 0x0078,
    0x0079,
    0x007A,
    0x00E4,
    0x00F6,
    0x00F1,
    0x00FC,
    0x00E0,
};

/* Extension table (§6.2.1.1): the ten positions reachable as
 * ESC (0x1B) followed by the septet. Everything else after an escape
 * "shall be treated as an unknown character" and displays as a space,
 * which is what the decoder does. */
static const struct {
    uint8_t  septet;
    uint16_t ucs;
} gsm7_ext[] = {
    { 0x0A, 0x000C }, /* form feed */
    { 0x14, 0x005E }, /* ^         */
    { 0x28, 0x007B }, /* {         */
    { 0x29, 0x007D }, /* }         */
    { 0x2F, 0x005C }, /* backslash */
    { 0x3C, 0x005B }, /* [         */
    { 0x3D, 0x007E }, /* ~         */
    { 0x3E, 0x005D }, /* ]         */
    { 0x40, 0x007C }, /* |         */
    { 0x65, 0x20AC }, /* euro sign */
};

#define GSM7_EXT_N ((int)(sizeof gsm7_ext / sizeof gsm7_ext[0]))

int32_t sms_gsm7_to_ucs(uint8_t septet)
{
    if (septet > 0x7F) return -1;
    if (septet == 0x1B) return -1; /* escape, not a character */
    return (int32_t)gsm7_basic[septet];
}

int32_t sms_gsm7_from_ucs(uint32_t ucs)
{
    /* ASCII is the common case and is identity for most of the range,
     * but not all of it: 0x24 is the generic currency sign, 0x40 is an
     * inverted exclamation mark, 0x5B..0x5E and 0x60 and 0x7B..0x7E are
     * accented letters, and '$' lives at 0x02. Table lookup, no
     * shortcuts — the shortcuts are where the mojibake comes from. */
    for (unsigned i = 0; i < 128; i++) {
        if (i == 0x1B) continue;
        if (gsm7_basic[i] == ucs) return (int32_t)i;
    }
    for (int i = 0; i < GSM7_EXT_N; i++)
        if (gsm7_ext[i].ucs == ucs)
            return (int32_t)(0x1B00 | gsm7_ext[i].septet);
    return -1;
}

static int32_t ext_to_ucs(uint8_t septet)
{
    for (int i = 0; i < GSM7_EXT_N; i++)
        if (gsm7_ext[i].septet == septet) return (int32_t)gsm7_ext[i].ucs;
    return -1;
}

int sms_gsm7_from_utf8(const char* s, size_t n, uint8_t* septets, size_t cap)
{
    if (s == NULL || septets == NULL) return SMS_E_INVAL;
    size_t i = 0, k = 0;
    while (i < n) {
        int32_t c = sms_utf8_next(s, n, &i);
        if (c < 0) return SMS_E_INVAL;
        int32_t g = sms_gsm7_from_ucs((uint32_t)c);
        if (g < 0) return SMS_E_ALPHABET;
        if (g & 0x1B00) {
            if (k + 2 > cap) return SMS_E_OVERFLOW;
            septets[k++] = 0x1B;
            septets[k++] = (uint8_t)(g & 0x7F);
        } else {
            if (k + 1 > cap) return SMS_E_OVERFLOW;
            septets[k++] = (uint8_t)g;
        }
    }
    return (int)k;
}

int sms_gsm7_septets(const char* s, size_t n)
{
    if (s == NULL) return SMS_E_INVAL;
    size_t i = 0, k = 0;
    while (i < n) {
        int32_t c = sms_utf8_next(s, n, &i);
        if (c < 0) return SMS_E_INVAL;
        int32_t g = sms_gsm7_from_ucs((uint32_t)c);
        if (g < 0) return SMS_E_ALPHABET;
        k += (g & 0x1B00) ? 2u : 1u;
    }
    return (int)k;
}

int sms_gsm7_to_utf8(const uint8_t* septets, size_t n, char* out, size_t cap)
{
    if (septets == NULL || out == NULL || cap == 0) return SMS_E_INVAL;
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        uint32_t ucs;
        if (septets[i] == 0x1B) {
            /* A trailing escape with nothing after it, and an escape
             * onto an undefined position, both render as a space
             * (§6.2.1.1) rather than dropping a character and shifting
             * everything after it. */
            int32_t e = i + 1 < n ? ext_to_ucs(septets[i + 1]) : -1;
            if (i + 1 < n) i++;
            ucs = e < 0 ? 0x20u : (uint32_t)e;
        } else if (septets[i] > 0x7F) {
            return SMS_E_INVAL;
        } else {
            ucs = gsm7_basic[septets[i]];
        }
        if (k + 1 >= cap) return SMS_E_OVERFLOW; /* room for a byte + NUL */
        size_t w = sms_utf8_put(out + k, cap - 1 - k, ucs);
        if (w == 0) return SMS_E_OVERFLOW;
        k += w;
    }
    out[k] = '\0';
    return (int)k;
}

/* ---- septet packing (TS 23.040 §9.2.3.24) ---- */

size_t sms_gsm7_septet_off(size_t udh_len)
{
    /* The text starts at the first septet boundary at or after the end
     * of the header, so the 0..6 bits in between are fill. */
    return (udh_len * 8 + 6) / 7;
}

int sms_gsm7_pack(const uint8_t* septets, size_t n, size_t septet_off,
                  uint8_t* out, size_t cap)
{
    if (septets == NULL || out == NULL) return SMS_E_INVAL;
    size_t total = ((septet_off + n) * 7 + 7) / 8;
    if (total > cap) return SMS_E_OVERFLOW;

    for (size_t i = 0; i < n; i++) {
        if (septets[i] > 0x7F) return SMS_E_INVAL;
        size_t   bit = (septet_off + i) * 7;
        size_t   o   = bit / 8;
        unsigned sh  = (unsigned)(bit % 8);
        /* Preserve whatever is below the write position — for the first
         * septet after a header that is the header's last octet and its
         * fill bits. */
        out[o] = (uint8_t)((out[o] & ((1u << sh) - 1u)) |
                           ((unsigned)septets[i] << sh));
        if (sh > 1) {
            /* The septet straddles into the next octet; it starts a new
             * octet, so overwrite rather than OR. */
            out[o + 1] = (uint8_t)((unsigned)septets[i] >> (8u - sh));
        }
    }
    /* A run whose last septet ends on an octet boundary leaves nothing
     * to pad; otherwise the spare high bits are already zero from the
     * shift above, except when n == 0 and the caller only has a header.
     * Nothing to do either way. */
    return (int)total;
}

int sms_gsm7_unpack(const uint8_t* in, size_t n, size_t septet_off,
                    size_t count, uint8_t* out, size_t cap)
{
    if (out == NULL) return SMS_E_INVAL;
    /* An empty run is a legitimate one — a message whose TP-UDL is 0 has
     * no TP-UD pointer at all — so NULL is only wrong when there are
     * septets to read out of it. */
    if (count == 0) return 0;
    if (in == NULL) return SMS_E_INVAL;
    if (count > cap) return SMS_E_OVERFLOW;
    if ((septet_off + count) * 7 > n * 8) return SMS_E_LENGTH;

    for (size_t i = 0; i < count; i++) {
        size_t   bit = (septet_off + i) * 7;
        size_t   o   = bit / 8;
        unsigned sh  = (unsigned)(bit % 8);
        unsigned v   = (unsigned)in[o] >> sh;
        if (sh > 1) v |= (unsigned)in[o + 1] << (8u - sh);
        out[i] = (uint8_t)(v & 0x7F);
    }
    return (int)count;
}

/* ---- user data header ---- */

size_t sms_udh_len(const uint8_t* ud, size_t ud_len)
{
    if (ud == NULL || ud_len == 0) return 0;
    size_t udhl = ud[0];
    if (udhl + 1 > ud_len) return 0; /* claims more than there is */
    return udhl + 1;
}

bool sms_udh_begin(sms_udh_iter_t* it, const uint8_t* ud, size_t ud_len)
{
    if (it == NULL) return false;
    size_t n = sms_udh_len(ud, ud_len);
    it
        ->p = ud;
    it
        ->end = n;
    it
        ->off = 1;
    return n > 1;
}

bool sms_udh_next(sms_udh_iter_t* it, sms_udh_ie_t* out)
{
    if (it == NULL || out == NULL) return false;
    /* An IE needs its two header octets and its declared length; a
     * header that runs off the end stops the walk rather than reading
     * past it. */
    if (it->off + 2 > it->end) return false;
    uint8_t iei = it->p[it->off];
    uint8_t len = it->p[it->off + 1];
    if (it->off + 2 + len > it->end) return false;
    out->iei  = iei;
    out->len  = len;
    out->data = len ? it->p + it->off + 2 : NULL;
    it
        ->off += 2u + len;
    return true;
}

/* ---- concatenation ---- */

bool sms_concat_get(const uint8_t* ud, size_t ud_len, sms_concat_t* out)
{
    sms_udh_iter_t it;
    sms_udh_ie_t ie;
    if (out == NULL) return false;
    if (!sms_udh_begin(&it, ud, ud_len)) return false;
    while (sms_udh_next(&it, &ie)) {
        if (ie.iei == SMS_UDH_CONCAT8 && ie.len == 3) {
            out->ref   = ie.data[0];
            out->total = ie.data[1];
            out->seq   = ie.data[2];
            out->ref16 = false;
            return true;
        }
        if (ie.iei == SMS_UDH_CONCAT16 && ie.len == 4) {
            out->ref   = (uint16_t)((ie.data[0] << 8) | ie.data[1]);
            out->total = ie.data[2];
            out->seq   = ie.data[3];
            out->ref16 = true;
            return true;
        }
    }
    return false;
}

int sms_concat_udh(uint8_t* out, size_t cap, const sms_concat_t* c)
{
    if (out == NULL || c == NULL) return SMS_E_INVAL;
    if (c->total == 0 || c->seq == 0 || c->seq > c->total) return SMS_E_INVAL;
    if (c->ref16) {
        if (cap < 7) return SMS_E_OVERFLOW;
        out[0] = 6; /* UDHL */
        out[1] = SMS_UDH_CONCAT16;
        out[2] = 4;
        out[3] = (uint8_t)(c->ref >> 8);
        out[4] = (uint8_t)(c->ref & 0xFF);
        out[5] = c->total;
        out[6] = c->seq;
        return 7;
    }
    if (cap < 6) return SMS_E_OVERFLOW;
    out[0] = 5;
    out[1] = SMS_UDH_CONCAT8;
    out[2] = 3;
    out[3] = (uint8_t)(c->ref & 0xFF);
    out[4] = c->total;
    out[5] = c->seq;
    return 6;
}

/* ---- TP-UD <-> UTF-8 ---- */

int sms_ud_to_utf8(uint8_t dcs, bool udhi, const uint8_t* ud, size_t ud_len,
                   uint8_t udl, char* out, size_t cap)
{
    if (out == NULL || cap == 0) return SMS_E_INVAL;
    if (ud == NULL && ud_len != 0) return SMS_E_INVAL;
    out[0] = '\0';

    size_t udhl = udhi ? sms_udh_len(ud, ud_len) : 0;
    if (udhi && udhl == 0) return SMS_E_LENGTH;
    /* A message with an empty body is legal and common (a "type 0" ping,
     * or the RP-ACK report), and its TP-UD pointer may be NULL. Answer
     * before any of the per-alphabet paths dereferences it. */
    if (udl == 0) return 0;

    int alpha = sms_dcs_alphabet(dcs);
    switch (alpha) {
    case SMS_ALPHA_GSM7: {
        /* TP-UDL counts septets, the header's septet-equivalent
         * included, so the text is what is left after the alignment. */
        size_t off = sms_gsm7_septet_off(udhl);
        if (udl < off) return SMS_E_LENGTH;
        size_t  count = (size_t)udl - off;
        uint8_t sep[SMS_UD_MAX * 8 / 7 + 2];
        if (count > sizeof sep) return SMS_E_LENGTH;
        int got = sms_gsm7_unpack(ud, ud_len, off, count, sep, sizeof sep);
        if (got < 0) return got;
        return sms_gsm7_to_utf8(sep, (size_t)got, out, cap);
    }
    case SMS_ALPHA_UCS2: {
        /* UCS2 here means UTF-16BE in practice (TS 23.038 §6.1 names
         * ISO/IEC 10646; handsets emit surrogate pairs for anything
         * past the BMP, and an emoji is exactly that), so decode
         * surrogates rather than emitting two broken code points. */
        if (udl > ud_len || udl < udhl) return SMS_E_LENGTH;
        size_t         n = (size_t)udl - udhl;
        const uint8_t* p = ud + udhl;
        size_t         k = 0;
        for (size_t i = 0; i + 1 < n; i += 2) {
            uint32_t u = (uint32_t)((p[i] << 8) | p[i + 1]);
            if (u >= 0xD800 && u <= 0xDBFF && i + 3 < n) {
                uint32_t lo = (uint32_t)((p[i + 2] << 8) | p[i + 3]);
                if (lo >= 0xDC00 && lo <= 0xDFFF) {
                    u = 0x10000u + ((u - 0xD800u) << 10) + (lo - 0xDC00u);
                    i += 2;
                }
            }
            if (u >= 0xD800 && u <= 0xDFFF) u = 0xFFFD; /* lone surrogate */
            if (k + 1 >= cap) return SMS_E_OVERFLOW;
            size_t w = sms_utf8_put(out + k, cap - 1 - k, u);
            if (w == 0) return SMS_E_OVERFLOW;
            k += w;
        }
        out[k] = '\0';
        return (int)k;
    }
    case SMS_ALPHA_8BIT: {
        /* 8-bit data is not text and has no charset; hand it back
         * verbatim so a caller can look at it, and let the caller
         * decide what it means. */
        if (udl > ud_len || udl < udhl) return SMS_E_LENGTH;
        size_t n = (size_t)udl - udhl;
        if (n + 1 > cap) return SMS_E_OVERFLOW;
        if (n) memcpy(out, ud + udhl, n);
        out[n] = '\0';
        return (int)n;
    }
    default: return SMS_E_ALPHABET;
    }
}

int sms_ud_from_utf8(const char* s, size_t n, int alphabet, const uint8_t* udh,
                     size_t udh_len, uint8_t* out, size_t cap, uint8_t* udl_out,
                     uint8_t* dcs_out)
{
    if (s == NULL || out == NULL || udl_out == NULL || dcs_out == NULL)
        return SMS_E_INVAL;
    if (udh_len && (udh == NULL || udh[0] + 1u != udh_len))
        return SMS_E_INVAL; /* UDHL must agree with the run handed in */
    if (udh_len > SMS_UD_MAX) return SMS_E_LENGTH;

    if (alphabet == SMS_ALPHA_AUTO) {
        int septets = sms_gsm7_septets(s, n);
        alphabet    = septets >= 0 ? SMS_ALPHA_GSM7 : SMS_ALPHA_UCS2;
    }

    if (udh_len && cap < udh_len) return SMS_E_OVERFLOW;
    if (udh_len) memcpy(out, udh, udh_len);

    switch (alphabet) {
    case SMS_ALPHA_GSM7: {
        /* 160 septets is the most one message can hold, so a text that
         * overruns this buffer is too long for a message — report that,
         * not an overflow of the caller's buffer, which is what
         * SMS_E_OVERFLOW means everywhere else in the API. */
        uint8_t sep[SMS_UD_MAX * 8 / 7 + 2];
        int     ns = sms_gsm7_from_utf8(s, n, sep, sizeof sep);
        if (ns == SMS_E_OVERFLOW) return SMS_E_LENGTH;
        if (ns < 0) return ns;
        size_t off   = sms_gsm7_septet_off(udh_len);
        size_t total = off + (size_t)ns;
        if (total > 255) return SMS_E_LENGTH;
        size_t octets = (total * 7 + 7) / 8;
        if (octets > SMS_UD_MAX) return SMS_E_LENGTH;
        if (octets > cap) return SMS_E_OVERFLOW;
        /* Zero from the header's last octet on, so the fill bits are
         * fill and pack() has clean bits to OR into. */
        memset(out + udh_len, 0, octets - udh_len);
        int rc = sms_gsm7_pack(sep, (size_t)ns, off, out, cap);
        if (rc < 0) return rc;
        *udl_out = (uint8_t)total;
        *dcs_out = sms_dcs_make(SMS_ALPHA_GSM7, -1);
        return rc;
    }
    case SMS_ALPHA_UCS2: {
        size_t i = 0, k = udh_len;
        while (i < n) {
            int32_t c = sms_utf8_next(s, n, &i);
            if (c < 0) return SMS_E_INVAL;
            uint32_t u = (uint32_t)c;
            if (u < 0x10000) {
                if (k + 2 > cap) return SMS_E_OVERFLOW;
                if (k + 2 > SMS_UD_MAX) return SMS_E_LENGTH;
                out[k++] = (uint8_t)(u >> 8);
                out[k++] = (uint8_t)(u & 0xFF);
            } else {
                uint32_t v  = u - 0x10000u;
                uint32_t hi = 0xD800u + (v >> 10);
                uint32_t lo = 0xDC00u + (v & 0x3FF);
                if (k + 4 > cap) return SMS_E_OVERFLOW;
                if (k + 4 > SMS_UD_MAX) return SMS_E_LENGTH;
                out[k++] = (uint8_t)(hi >> 8);
                out[k++] = (uint8_t)(hi & 0xFF);
                out[k++] = (uint8_t)(lo >> 8);
                out[k++] = (uint8_t)(lo & 0xFF);
            }
        }
        *udl_out = (uint8_t)k; /* octets, header included */
        *dcs_out = sms_dcs_make(SMS_ALPHA_UCS2, -1);
        return (int)k;
    }
    case SMS_ALPHA_8BIT: {
        if (udh_len + n > SMS_UD_MAX) return SMS_E_LENGTH;
        if (udh_len + n > cap) return SMS_E_OVERFLOW;
        memcpy(out + udh_len, s, n);
        *udl_out = (uint8_t)(udh_len + n);
        *dcs_out = sms_dcs_make(SMS_ALPHA_8BIT, -1);
        return (int)(udh_len + n);
    }
    default: return SMS_E_ALPHABET;
    }
}

/* ---- split ---- */

/* Where the next part ends, given the per-part budget. Returns the byte
 * offset into s[] just past the last character that fits, or a negative
 * sms_err_t. Never splits a GSM 7-bit escape pair or a UTF-16 surrogate
 * pair, because half of either decodes as a different character. */
static int split_at(const char* s, size_t n, size_t from, int alphabet,
                    size_t budget, size_t* end)
{
    size_t i = from, used = 0;
    if (alphabet == SMS_ALPHA_8BIT) {
        size_t take = n - i < budget ? n - i : budget;
        *end        = i + take;
        return take > 0 ? SMS_OK : SMS_E_LENGTH;
    }
    while (i < n) {
        size_t  j  = i;
        int32_t cp = sms_utf8_next(s, n, &j);
        if (cp < 0) return SMS_E_INVAL;
        size_t w;
        if (alphabet == SMS_ALPHA_GSM7) {
            int32_t g = sms_gsm7_from_ucs((uint32_t)cp);
            if (g < 0) return SMS_E_ALPHABET;
            w = (g & 0x1B00) ? 2u : 1u; /* escape pair counts two */
        } else {
            w = cp < 0x10000 ? 2u : 4u; /* surrogate pair counts four */
        }
        if (used + w > budget) break;
        used += w;
        i = j;
    }
    *end = i;
    /* A budget that cannot hold even one character would loop forever. */
    return used > 0 ? SMS_OK : SMS_E_LENGTH;
}

/* Wire units the whole text needs under `alphabet`: septets for GSM
 * 7-bit, octets otherwise. Negative sms_err_t when the alphabet cannot
 * hold it. Measuring separately from encoding is what lets the split
 * decide "one message or many" without needing a buffer big enough for
 * the whole text. */
static int wire_units(const char* s, size_t n, int alphabet)
{
    if (alphabet == SMS_ALPHA_GSM7) return sms_gsm7_septets(s, n);
    if (alphabet == SMS_ALPHA_8BIT)
        return n > 0x7FFFFFFFu ? SMS_E_LENGTH : (int)n;
    size_t i = 0, k = 0;
    while (i < n) {
        int32_t cp = sms_utf8_next(s, n, &i);
        if (cp < 0) return SMS_E_INVAL;
        k += cp < 0x10000 ? 2u : 4u; /* surrogate pair is four octets */
    }
    return k > 0x7FFFFFFFu ? SMS_E_LENGTH : (int)k;
}

int sms_concat_split(const char* s, size_t n, int alphabet, uint16_t ref,
                     bool ref16, sms_part_t* parts, int max)
{
    if (s == NULL || parts == NULL || max <= 0) return SMS_E_INVAL;

    if (alphabet == SMS_ALPHA_AUTO) {
        int septets = sms_gsm7_septets(s, n);
        alphabet    = septets >= 0 ? SMS_ALPHA_GSM7 : SMS_ALPHA_UCS2;
    }
    if (alphabet != SMS_ALPHA_GSM7 && alphabet != SMS_ALPHA_UCS2 &&
        alphabet != SMS_ALPHA_8BIT)
        return SMS_E_ALPHABET;

    int units = wire_units(s, n, alphabet);
    if (units < 0) return units;
    size_t one_octets = alphabet == SMS_ALPHA_GSM7 ? ((size_t)units * 7 + 7) / 8
                                                   : (size_t)units;

    /* One message with no concatenation header, when the text fits. A
     * single part wrapped in a concatenation IE is legal but wasteful,
     * and some handsets render it as "1/1" clutter. */
    if (one_octets <= SMS_UD_MAX) {
        memset(&parts[0], 0, sizeof parts[0]);
        int one =
            sms_ud_from_utf8(s, n, alphabet, NULL, 0, parts[0].ud,
                             sizeof parts[0].ud, &parts[0].udl, &parts[0].dcs);
        if (one < 0) return one;
        parts[0].ud_len = (uint8_t)one;
        parts[0].seq    = 1;
        parts[0].total  = 1;
        return 1;
    }

    /* The header eats from the same 140 octets as the text, which is
     * why a concatenated 7-bit part carries 153 septets, not 160. */
    size_t udh_len = ref16 ? 7u : 6u;
    size_t budget  = alphabet == SMS_ALPHA_GSM7
                         ? ((SMS_UD_MAX * 8) / 7) - sms_gsm7_septet_off(udh_len)
                         : SMS_UD_MAX - udh_len;

    /* Count first: `total` goes into every part's header, so it has to
     * be known before the first one is built. The boundaries are a pure
     * function of (text, budget), so the second walk reproduces them. */
    int    count = 0;
    size_t i     = 0;
    while (i < n) {
        size_t end;
        int    rc = split_at(s, n, i, alphabet, budget, &end);
        if (rc < 0) return rc;
        i = end;
        if (++count > max || count > 255) return SMS_E_LENGTH;
    }

    sms_concat_t c = { ref, (uint8_t)count, 0, ref16 };
    i              = 0;
    for (int part = 1; part <= count; part++) {
        size_t end;
        int    rc = split_at(s, n, i, alphabet, budget, &end);
        if (rc < 0) return rc;

        uint8_t udh[7];
        c.seq = (uint8_t)part;
        int h = sms_concat_udh(udh, sizeof udh, &c);
        if (h < 0) return h;

        sms_part_t* p = &parts[part - 1];
        memset(p, 0, sizeof *p);
        rc = sms_ud_from_utf8(s + i, end - i, alphabet, udh, (size_t)h, p->ud,
                              sizeof p->ud, &p->udl, &p->dcs);
        if (rc < 0) return rc;
        p->ud_len = (uint8_t)rc;
        p->seq    = (uint8_t)part;
        p->total  = (uint8_t)count;
        i         = end;
    }
    return count;
}
