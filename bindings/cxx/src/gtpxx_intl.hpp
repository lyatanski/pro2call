#ifndef GTPXX_INTL_HPP
#define GTPXX_INTL_HPP

/* Shared internals of the gtpxx facade — string/wire conversions used
 * by both the message codecs and the session layer. Not installed. */

#include "gtpxx.hpp"

namespace gtp
{
namespace intl
{

/* Literal address string -> 4- or 16-byte buffer. Throws Error. */
void        addr4_parse(const std::string& s, uint8_t out[4]);
void        addr6_parse(const std::string& s, uint8_t out[16]);
std::string addr4_format(const uint8_t a[4]);
std::string addr6_format(const uint8_t a[16]);

/* "aa:bb:cc:dd:ee:ff" -> 6 bytes; empty string leaves out untouched. */
void mac_parse(const std::string& s, uint8_t out[6]);

gtp2_fteid_t fteid_to_c(const Fteid& f);
Fteid        fteid_from_c(const gtp2_fteid_t& c);

gtp2_paa_t paa_to_c(const Paa& p);
Paa        paa_from_c(const gtp2_paa_t& c);

gtp2_bearer_qos_t qos_to_c(const BearerQos& q);
BearerQos         qos_from_c(const gtp2_bearer_qos_t& c);

/* View over caller-owned bytes; {NULL, 0} when empty. */
gtp2_view_t view_of(const Bytes& b);
Bytes       bytes_of(const gtp2_view_t& v);

[[noreturn]] void throw_gtp2(int code, const char* doing);

} /* namespace intl */
} /* namespace gtp */

#endif /* GTPXX_INTL_HPP */
