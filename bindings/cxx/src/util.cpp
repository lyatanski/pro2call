/* String/wire conversions: TBCD digits, APN labels, addresses, and the
 * sub-IE struct translations shared by the message codecs. */

#include "gtpxx_intl.hpp"

#include <arpa/inet.h>
#include <cstdio>
#include <cstring>

namespace gtp
{

Bytes bcd_encode(const std::string& digits)
{
    Bytes out;
    out.reserve((digits.size() + 1) / 2);
    for (size_t i = 0; i < digits.size(); i += 2) {
        char lo = digits[i];
        if (lo < '0' || lo > '9') throw Error("BCD: non-digit character");
        uint8_t b = static_cast<uint8_t>(lo - '0');
        if (i + 1 < digits.size()) {
            char hi = digits[i + 1];
            if (hi < '0' || hi > '9') throw Error("BCD: non-digit character");
            b |= static_cast<uint8_t>((hi - '0') << 4);
        } else {
            b |= 0xF0; /* odd digit count: pad the high nibble */
        }
        out.push_back(b);
    }
    return out;
}

std::string bcd_decode(const Bytes& bcd)
{
    std::string out;
    out.reserve(bcd.size() * 2);
    for (uint8_t b : bcd) {
        uint8_t lo = b & 0x0F, hi = b >> 4;
        if (lo > 9) break;
        out.push_back(static_cast<char>('0' + lo));
        if (hi > 9) break; /* 0xF pad ends the string */
        out.push_back(static_cast<char>('0' + hi));
    }
    return out;
}

Bytes apn_encode(const std::string& dotted)
{
    Bytes out;
    out.reserve(dotted.size() + 1);
    size_t start = 0;
    while (start <= dotted.size()) {
        size_t dot = dotted.find('.', start);
        size_t end = (dot == std::string::npos) ? dotted.size() : dot;
        size_t n   = end - start;
        if (n == 0 || n > 63) throw Error("APN: label length must be 1..63");
        out.push_back(static_cast<uint8_t>(n));
        out.insert(out.end(), dotted.begin() + static_cast<long>(start),
                   dotted.begin() + static_cast<long>(end));
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    return out;
}

std::string apn_decode(const Bytes& labels)
{
    std::string out;
    size_t      off = 0;
    while (off < labels.size()) {
        size_t n = labels[off++];
        if (n == 0 || off + n > labels.size())
            throw Error("APN: malformed label encoding");
        if (!out.empty()) out.push_back('.');
        out.append(reinterpret_cast<const char*>(labels.data() + off), n);
        off += n;
    }
    return out;
}

/* One digit of a digit string, or throw. */
static uint8_t plmn_digit(char c)
{
    if (c < '0' || c > '9') throw Error("PLMN: non-digit character");
    return static_cast<uint8_t>(c - '0');
}

Bytes plmn_encode(const std::string& mcc, const std::string& mnc)
{
    if (mcc.size() != 3 || (mnc.size() != 2 && mnc.size() != 3))
        throw Error("PLMN: MCC must be 3 digits and MNC 2 or 3");
    const uint8_t n3 = (mnc.size() == 3) ? plmn_digit(mnc[2]) : 0x0f;
    /* Nibble layout of TS 24.008 §10.5.1.3: octet 2's high nibble is the
     * third MNC digit (0xF when the MNC has only two). */
    return Bytes{
        static_cast<uint8_t>(plmn_digit(mcc[1]) << 4 | plmn_digit(mcc[0])),
        static_cast<uint8_t>(n3 << 4 | plmn_digit(mcc[2])),
        static_cast<uint8_t>(plmn_digit(mnc[1]) << 4 | plmn_digit(mnc[0])),
    };
}

Bytes uli_tai_ecgi(const std::string& mcc, const std::string& mnc,
                   uint16_t tac, uint32_t eci)
{
    const Bytes pl = plmn_encode(mcc, mnc);
    Bytes       out;
    out.reserve(1 + 3 + 2 + 3 + 4);
    out.push_back(0x18); /* flags: TAI (bit 3) + ECGI (bit 4) */
    out.insert(out.end(), pl.begin(), pl.end());
    out.push_back(static_cast<uint8_t>(tac >> 8));
    out.push_back(static_cast<uint8_t>(tac));
    out.insert(out.end(), pl.begin(), pl.end());
    out.push_back(static_cast<uint8_t>(eci >> 24 & 0x0f)); /* 4 spare high bits */
    out.push_back(static_cast<uint8_t>(eci >> 16));
    out.push_back(static_cast<uint8_t>(eci >> 8));
    out.push_back(static_cast<uint8_t>(eci));
    return out;
}

std::string pco_pcscf_v4(const Bytes& pco)
{
    if (pco.size() < 4) return "";
    size_t i = 1; /* skip the configuration-protocol/flags octet */
    while (i + 2 < pco.size()) {
        const uint16_t id  = static_cast<uint16_t>(pco[i] << 8 | pco[i + 1]);
        const uint8_t  len = pco[i + 2];
        const size_t   body = i + 3;
        if (body + len > pco.size()) break; /* truncated container */
        if (id == 0x000c && len >= 4) {
            char b[INET_ADDRSTRLEN];
            std::snprintf(b, sizeof b, "%u.%u.%u.%u", pco[body], pco[body + 1],
                          pco[body + 2], pco[body + 3]);
            return b;
        }
        i = body + len;
    }
    return "";
}

Bytes pco_request_pcscf()
{
    /* Configuration-protocol octet 0x80, then one empty P-CSCF IPv4
     * Address Request container (id 0x000C, length 0). */
    return Bytes{ 0x80, 0x00, 0x0c, 0x00 };
}

namespace intl
{

void addr4_parse(const std::string& s, uint8_t out[4])
{
    if (inet_pton(AF_INET, s.c_str(), out) != 1)
        throw Error("bad IPv4 address: " + s);
}

void addr6_parse(const std::string& s, uint8_t out[16])
{
    if (inet_pton(AF_INET6, s.c_str(), out) != 1)
        throw Error("bad IPv6 address: " + s);
}

std::string addr4_format(const uint8_t a[4])
{
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, a, buf, sizeof buf);
    return buf;
}

std::string addr6_format(const uint8_t a[16])
{
    char buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, a, buf, sizeof buf);
    return buf;
}

void mac_parse(const std::string& s, uint8_t out[6])
{
    if (s.empty()) return;
    unsigned b[6];
    if (std::sscanf(s.c_str(), "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3],
                    &b[4], &b[5]) != 6)
        throw Error("bad MAC address: " + s);
    for (int i = 0; i < 6; i++) {
        if (b[i] > 0xFF) throw Error("bad MAC address: " + s);
        out[i] = static_cast<uint8_t>(b[i]);
    }
}

gtp2_fteid_t fteid_to_c(const Fteid& f)
{
    gtp2_fteid_t c;
    std::memset(&c, 0, sizeof c);
    c.if_type = f.if_type;
    c.teid    = f.teid;
    if (!f.addr4.empty()) {
        c.v4 = true;
        addr4_parse(f.addr4, c.addr4);
    }
    if (!f.addr6.empty()) {
        c.v6 = true;
        addr6_parse(f.addr6, c.addr6);
    }
    if (!c.v4 && !c.v6) throw Error("F-TEID needs at least one of addr4/addr6");
    return c;
}

Fteid fteid_from_c(const gtp2_fteid_t& c)
{
    Fteid f;
    f.if_type = c.if_type;
    f.teid    = c.teid;
    if (c.v4) f.addr4 = addr4_format(c.addr4);
    if (c.v6) f.addr6 = addr6_format(c.addr6);
    return f;
}

gtp2_paa_t paa_to_c(const Paa& p)
{
    gtp2_paa_t c;
    std::memset(&c, 0, sizeof c);
    c.pdn_type   = p.pdn_type;
    c.prefix_len = p.prefix_len;
    if (!p.addr4.empty()) addr4_parse(p.addr4, c.addr4);
    if (!p.addr6.empty()) addr6_parse(p.addr6, c.addr6);
    return c;
}

Paa paa_from_c(const gtp2_paa_t& c)
{
    Paa p;
    p.pdn_type   = c.pdn_type;
    p.prefix_len = c.prefix_len;
    if (c.pdn_type == GTP2_PDN_IPV4 || c.pdn_type == GTP2_PDN_IPV4V6)
        p.addr4 = addr4_format(c.addr4);
    if (c.pdn_type == GTP2_PDN_IPV6 || c.pdn_type == GTP2_PDN_IPV4V6)
        p.addr6 = addr6_format(c.addr6);
    return p;
}

gtp2_bearer_qos_t qos_to_c(const BearerQos& q)
{
    gtp2_bearer_qos_t c;
    std::memset(&c, 0, sizeof c);
    c.pci    = q.pci;
    c.pl     = q.pl;
    c.pvi    = q.pvi;
    c.qci    = q.qci;
    c.mbr_ul = q.mbr_ul;
    c.mbr_dl = q.mbr_dl;
    c.gbr_ul = q.gbr_ul;
    c.gbr_dl = q.gbr_dl;
    return c;
}

BearerQos qos_from_c(const gtp2_bearer_qos_t& c)
{
    BearerQos q;
    q.pci    = c.pci;
    q.pl     = c.pl;
    q.pvi    = c.pvi;
    q.qci    = c.qci;
    q.mbr_ul = c.mbr_ul;
    q.mbr_dl = c.mbr_dl;
    q.gbr_ul = c.gbr_ul;
    q.gbr_dl = c.gbr_dl;
    return q;
}

gtp2_view_t view_of(const Bytes& b)
{
    gtp2_view_t v;
    v.data = b.empty() ? nullptr : b.data();
    v.len  = static_cast<uint16_t>(b.size());
    return v;
}

Bytes bytes_of(const gtp2_view_t& v)
{
    if (!v.data) return {};
    return Bytes(v.data, v.data + v.len);
}

void throw_gtp2(int code, const char* doing)
{
    const char* what;
    switch (code) {
    case GTP2_E_SHORT:    what = "input truncated"; break;
    case GTP2_E_VERSION:  what = "not a GTPv2 message"; break;
    case GTP2_E_LENGTH:   what = "header length inconsistent"; break;
    case GTP2_E_OVERFLOW: what = "write buffer too small"; break;
    case GTP2_E_INVAL:    what = "invalid argument"; break;
    case GTP2_E_MISSING:  what = "mandatory IE absent"; break;
    default:              what = "error"; break;
    }
    throw Error(std::string(doing) + ": " + what, code);
}

} /* namespace intl */
} /* namespace gtp */
