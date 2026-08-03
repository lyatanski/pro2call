#ifndef SMSXX_HPP
#define SMSXX_HPP

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include "sms.h"
#include "sms_rp.h"

/* smsxx — C++ facade over the C SMS codec (sms/inc/sms.h, sms_rp.h),
 * written to be wrapped by SWIG (bindings/swig/sms.i) and driven from a
 * scripting language. Same rules as the other facades:
 *
 *   - value types: Tpdu/Rpdu/Address own copies of everything, so
 *     nothing a script holds borrows from the wire buffer (the C
 *     layer's zero-copy views are materialized exactly once, here);
 *   - enums, not strings: message types, alphabets, causes and
 *     type-of-number keep the C library's numeric ids, so a script
 *     writes sms.T_SUBMIT / sms.ALPHA_UCS2 / sms.RP_CAUSE_CONGESTION;
 *   - errors are exceptions (sms::Error), never return codes.
 *
 * Three things an SMS consumer gets wrong exactly once are resolved
 * here rather than at every call site:
 *
 *   - the tagged union of six TPDU types is flattened into one Tpdu
 *     with a `type` tag, because a script dispatching on the type does
 *     not want to know which arm of a union to reach into;
 *   - Rpdu::tpdu() parses the contained TPDU with the direction the
 *     RPDU implies, and adds SMS_DIR_NEGATIVE when the RPDU is an
 *     RP-ERROR — the one piece of context the TPDU itself cannot carry;
 *   - Tpdu::text() applies TP-DCS, TP-UDHI and TP-UDL together, which
 *     is the only way to get the septet alignment and the length units
 *     right at once.
 */

namespace sms
{

/* Every failure surfaces as one of these; code() keeps the SMS_E_*
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

/* ---- enums, mirrored from the C headers ---- */

/* Transfer direction. NEGATIVE is a modifier, OR-ed in, and matters for
 * one thing only: a report TPDU carried in an RP-ERROR has a TP-FCS
 * octet the RP-ACK variant does not. Rpdu::tpdu() sets it for you. */
enum Direction {
    DIR_MS_TO_SC = SMS_DIR_MS_TO_SC,
    DIR_SC_TO_MS = SMS_DIR_SC_TO_MS,
    DIR_NEGATIVE = SMS_DIR_NEGATIVE
};

enum Type {
    T_DELIVER        = SMS_T_DELIVER,
    T_DELIVER_REPORT = SMS_T_DELIVER_REPORT,
    T_SUBMIT         = SMS_T_SUBMIT,
    T_SUBMIT_REPORT  = SMS_T_SUBMIT_REPORT,
    T_STATUS_REPORT  = SMS_T_STATUS_REPORT,
    T_COMMAND        = SMS_T_COMMAND
};

enum Alphabet {
    ALPHA_AUTO = SMS_ALPHA_AUTO, /* GSM 7-bit if it fits, else UCS2 */
    ALPHA_GSM7 = SMS_ALPHA_GSM7,
    ALPHA_8BIT = SMS_ALPHA_8BIT,
    ALPHA_UCS2 = SMS_ALPHA_UCS2
};

enum Ton {
    TON_UNKNOWN       = SMS_TON_UNKNOWN,
    TON_INTERNATIONAL = SMS_TON_INTERNATIONAL,
    TON_NATIONAL      = SMS_TON_NATIONAL,
    TON_NETWORK       = SMS_TON_NETWORK,
    TON_SUBSCRIBER    = SMS_TON_SUBSCRIBER,
    TON_ALPHANUM      = SMS_TON_ALPHANUM,
    TON_ABBREVIATED   = SMS_TON_ABBREVIATED
};

enum Npi {
    NPI_UNKNOWN  = SMS_NPI_UNKNOWN,
    NPI_ISDN     = SMS_NPI_ISDN,
    NPI_DATA     = SMS_NPI_DATA,
    NPI_NATIONAL = SMS_NPI_NATIONAL,
    NPI_PRIVATE  = SMS_NPI_PRIVATE
};

enum Vpf {
    VPF_NONE     = SMS_VPF_NONE,
    VPF_ENHANCED = SMS_VPF_ENHANCED,
    VPF_RELATIVE = SMS_VPF_RELATIVE,
    VPF_ABSOLUTE = SMS_VPF_ABSOLUTE
};

enum UdhIei {
    UDH_CONCAT8     = SMS_UDH_CONCAT8,
    UDH_SPECIAL_SMS = SMS_UDH_SPECIAL_SMS,
    UDH_PORT8       = SMS_UDH_PORT8,
    UDH_PORT16      = SMS_UDH_PORT16,
    UDH_SMSC_CTRL   = SMS_UDH_SMSC_CTRL,
    UDH_SOURCE_IND  = SMS_UDH_SOURCE_IND,
    UDH_CONCAT16    = SMS_UDH_CONCAT16,
    UDH_TEXT_FORMAT = SMS_UDH_TEXT_FORMAT,
    UDH_NL_SS       = SMS_UDH_NL_SS,
    UDH_NL_LS       = SMS_UDH_NL_LS
};

enum RpType {
    RP_T_DATA  = SMS_RP_T_DATA,
    RP_T_ACK   = SMS_RP_T_ACK,
    RP_T_ERROR = SMS_RP_T_ERROR,
    RP_T_SMMA  = SMS_RP_T_SMMA
};

/* TS 24.011 §8.2.5.4. Anything unlisted must be treated as TEMPORARY
 * FAILURE, which is what rp_cause_fold() does. */
enum RpCause {
    RP_CAUSE_UNASSIGNED_NUMBER    = SMS_RP_CAUSE_UNASSIGNED_NUMBER,
    RP_CAUSE_OPERATOR_BARRING     = SMS_RP_CAUSE_OPERATOR_BARRING,
    RP_CAUSE_CALL_BARRED          = SMS_RP_CAUSE_CALL_BARRED,
    RP_CAUSE_TRANSFER_REJECTED    = SMS_RP_CAUSE_TRANSFER_REJECTED,
    RP_CAUSE_DEST_OUT_OF_ORDER    = SMS_RP_CAUSE_DEST_OUT_OF_ORDER,
    RP_CAUSE_UNIDENTIFIED_SUB     = SMS_RP_CAUSE_UNIDENTIFIED_SUB,
    RP_CAUSE_FACILITY_REJECTED    = SMS_RP_CAUSE_FACILITY_REJECTED,
    RP_CAUSE_UNKNOWN_SUB          = SMS_RP_CAUSE_UNKNOWN_SUB,
    RP_CAUSE_NETWORK_OUT_OF_ORDER = SMS_RP_CAUSE_NETWORK_OUT_OF_ORDER,
    RP_CAUSE_TEMPORARY_FAILURE    = SMS_RP_CAUSE_TEMPORARY_FAILURE,
    RP_CAUSE_CONGESTION           = SMS_RP_CAUSE_CONGESTION,
    RP_CAUSE_RESOURCES_UNAVAIL    = SMS_RP_CAUSE_RESOURCES_UNAVAIL,
    RP_CAUSE_FACILITY_NOT_SUBSCR  = SMS_RP_CAUSE_FACILITY_NOT_SUBSCR,
    RP_CAUSE_FACILITY_NOT_IMPL    = SMS_RP_CAUSE_FACILITY_NOT_IMPL,
    RP_CAUSE_INVALID_REFERENCE    = SMS_RP_CAUSE_INVALID_REFERENCE,
    RP_CAUSE_SEMANTIC_ERROR       = SMS_RP_CAUSE_SEMANTIC_ERROR,
    RP_CAUSE_INVALID_MANDATORY    = SMS_RP_CAUSE_INVALID_MANDATORY,
    RP_CAUSE_MSG_TYPE_UNKNOWN     = SMS_RP_CAUSE_MSG_TYPE_UNKNOWN,
    RP_CAUSE_MSG_INCOMPATIBLE     = SMS_RP_CAUSE_MSG_INCOMPATIBLE,
    RP_CAUSE_IE_UNKNOWN           = SMS_RP_CAUSE_IE_UNKNOWN,
    RP_CAUSE_PROTOCOL_ERROR       = SMS_RP_CAUSE_PROTOCOL_ERROR,
    RP_CAUSE_INTERWORKING         = SMS_RP_CAUSE_INTERWORKING
};

/* Limits, mirrored so a script can size its own buffers and assert. */
enum Limits {
    UD_MAX          = SMS_UD_MAX,
    CD_MAX          = SMS_CD_MAX,
    ADDR_MAX_DIGITS = SMS_ADDR_MAX_DIGITS,
    TPDU_MAX        = SMS_TPDU_MAX,
    RP_MAX          = SMS_RP_MAX
};

/* The MIME type SMS-over-IMS puts an RPDU in (TS 24.341 §5.3.2). Here
 * so no script has to spell it, and none of them disagree. */
extern const char* const CONTENT_TYPE; /* "application/vnd.3gpp.sms" */

/* The feature tag a UE puts on its REGISTER Contact to say it does SMS
 * over IP (TS 24.341 §5.3.2.2). */
extern const char* const FEATURE_TAG; /* "+g.3gpp.smsip" */

/* ---- value types ---- */

/* TP-OA / TP-DA / TP-RA. digits carries what the wire carries: no '+'
 * for an international number, because inventing one makes round-trips
 * lossy. display() adds it. For TON_ALPHANUM the field is not digits at
 * all but GSM 7-bit text, decoded to UTF-8. */
struct Address {
    int         ton = TON_UNKNOWN;
    int         npi = NPI_ISDN;
    std::string digits;

    std::string display() const; /* "+<digits>" when international */
    bool        empty() const
    {
        return digits.empty();
    }
};

/* TP-SCTS / TP-DT / an absolute TP-VP. tz is in quarter-hours east of
 * GMT and really is signed (TS 23.040 §9.2.3.11). */
struct Timestamp {
    int year = 0;
    int mon  = 0;
    int day  = 0;
    int hour = 0;
    int min  = 0;
    int sec  = 0;
    int tz   = 0;

    int64_t     unix_time() const; /* -1 when the fields are nonsense */
    std::string iso8601() const;
    bool        valid() const
    {
        return year != 0;
    }
};

/* A decoded TP-DCS (TS 23.038 §4). The octet is a coding *group* whose
 * top nibble decides what the bottom one means, so nothing useful can
 * be read out of it without this. */
struct Dcs {
    int  octet       = 0;
    int  alphabet    = ALPHA_GSM7;
    bool compressed  = false;
    bool has_class   = false;
    int  cls         = 0;
    bool auto_delete = false;
    bool mwi         = false;
    bool mwi_active  = false;
    int  mwi_type    = 0;
    bool mwi_discard = false;
};

/* One TP-UD header element (TS 23.040 §9.2.3.24). data is raw octets. */
struct UdhIe {
    int         iei = 0;
    std::string data;
};

/* The concatenation element of a multi-part message. */
struct Concat {
    int  ref   = 0;
    int  total = 0;
    int  seq   = 0; /* 1-based */
    bool ref16 = false;
};

/* One decoded TPDU, with the six types flattened onto one struct and
 * `type` as the tag. Which fields carry meaning depends on `type`; the
 * ones that do not are left at their defaults rather than holding
 * whatever a union arm happened to overlap.
 *
 *   T_DELIVER        addr=TP-OA  scts  pid dcs ud   mms lp rp udhi sri
 *   T_SUBMIT         addr=TP-DA  vp    pid dcs ud   mr rd rp udhi srr
 *   T_STATUS_REPORT  addr=TP-RA  scts dt st  mr  [pid dcs ud] mms lp srq
 *   T_COMMAND        addr=TP-DA  mr pid ct mn command_data   udhi srr
 *   T_*_REPORT       [fcs] [scts] [pid dcs ud]               udhi
 */
class Tpdu
{
  public:
    int type = T_DELIVER;
    int mti  = 0;
    int dir  = DIR_SC_TO_MS;

    /* octet-0 flags; TP-MMS is 1 for "no more messages waiting", which
     * is the wire sense, not the intuitive one. */
    bool mms  = false;
    bool lp   = false;
    bool rp   = false;
    bool udhi = false;
    bool sri  = false;
    bool srr  = false;
    bool srq  = false;
    bool rd   = false;

    int mr  = 0;
    int pid = 0;
    int dcs = 0;
    int st  = 0; /* T_STATUS_REPORT */
    int ct  = 0; /* T_COMMAND       */
    int mn  = 0; /* T_COMMAND       */
    int fcs = 0; /* the RP-ERROR report variant */

    /* The other party: TP-OA for a DELIVER, TP-DA for a SUBMIT or
     * COMMAND, TP-RA for a STATUS-REPORT. */
    Address addr;

    Timestamp scts;
    Timestamp dt; /* T_STATUS_REPORT discharge time */

    int       vpf    = VPF_NONE;
    int       vp_rel = 0; /* raw code; vp_seconds() decodes it */
    Timestamp vp_abs;

    /* Raw TP-UD, header included; text() decodes it. udl keeps the wire
     * units (septets for a 7-bit DCS, octets otherwise). */
    std::string user_data;
    int         udl           = 0;
    bool        has_user_data = false;

    std::string command_data; /* T_COMMAND TP-CD */

    /* Which optional fields a report or status report actually carried
     * (TP-PI, TS 23.040 §9.2.3.27). */
    bool has_pid  = false;
    bool has_dcs  = false;
    bool has_scts = false;
    bool has_fcs  = false;

    /* ---- derived ---- */

    /* TP-UD as UTF-8, with TP-DCS, TP-UDHI and TP-UDL applied together.
     * Throws Error when the DCS is compressed or reserved. For an 8-bit
     * DCS the bytes come back verbatim — 8-bit data is not text and has
     * no charset. */
    std::string text() const;

    int  alphabet() const; /* Alphabet, from the DCS */
    Dcs  coding() const;   /* the whole decoded DCS  */
    bool binary() const
    {
        return alphabet() == ALPHA_8BIT;
    }

    /* TP-VP as seconds; 0 when there is none or it is absolute. */
    unsigned vp_seconds() const;

    /* User data header. count()/at(i) rather than a vector — see
     * bindings/swig/sms.i on the shared type registry. */
    bool  has_udh() const;
    int   udh_count() const;
    UdhIe udh_at(int i) const; /* throws on range */

    bool   has_concat() const;
    Concat concat() const; /* throws when absent */

    /* TP-ST bands (TS 23.040 §9.2.3.15) — was it delivered, is the SC
     * still trying, has it given up. */
    bool delivered() const
    {
        return sms_st_completed((uint8_t)st);
    }
    bool pending() const
    {
        return sms_st_temporary((uint8_t)st);
    }
    bool failed() const
    {
        return sms_st_permanent((uint8_t)st);
    }

    std::string type_name() const;
    std::string status_name() const; /* TP-ST  */
    std::string cause_name() const;  /* TP-FCS */

    /* Back to the wire. */
    std::string encode() const;
};

/* A decoded RPDU (TS 24.011 §7.3). */
class Rpdu
{
  public:
    int  type    = RP_T_DATA;
    int  mti     = 0;
    bool from_ms = false;
    int  mr      = 0;

    Address oa; /* RP-DATA only */
    Address da;

    int  cause          = 0; /* RP-ERROR only */
    bool has_cause_diag = false;
    int  cause_diag     = 0;

    /* RP-User-Data: the TPDU, raw. Mandatory in RP-DATA, optional in
     * RP-ACK and RP-ERROR, absent from RP-SMMA. */
    std::string user_data;
    bool        has_user_data = false;

    bool has_tpdu() const
    {
        return has_user_data && !user_data.empty();
    }

    /* Parse the contained TPDU. The direction comes from this RPDU, and
     * SMS_DIR_NEGATIVE is added when the RPDU is an RP-ERROR — the one
     * piece of context a report TPDU cannot carry itself. Throws when
     * there is nothing to parse. */
    Tpdu tpdu() const;

    std::string type_name() const;
    std::string cause_name() const;

    std::string encode() const;
};

/* ---- parse ---- */

/* dir is a Direction; an RPDU whose RP-MTI says it travels the other
 * way is an error, not a silent reinterpretation. */
Rpdu parse_rpdu(const std::string& wire, int dir);

/* dir may be OR-ed with DIR_NEGATIVE for a report carried in an
 * RP-ERROR. Prefer Rpdu::tpdu(), which knows. */
Tpdu parse_tpdu(const std::string& wire, int dir);

/* ---- build: the four things an endpoint sends ---- */

/* What a UE submits. Only `to` and `text` are usually set, so in Lua
 * this reads sms.submit{ to = "+44...", text = "hi", srr = true }. */
struct Submission {
    std::string to;   /* required: TP-DA                          */
    std::string text; /* UTF-8, or raw octets when binary         */
    std::string sc;   /* service centre for RP-DA; "" = absent    */
    int         alphabet = ALPHA_AUTO;
    bool        srr      = false; /* ask for a status report       */
    bool        rd       = false; /* reject duplicates             */
    bool        rp       = false; /* reply path                    */
    int         mr       = 0;     /* TP-MR, and the RP-MR          */
    int         pid      = 0;
    int         cls      = -1; /* message class; -1 leaves it unset */
    int         validity = 0;  /* seconds; 0 = no TP-VP            */
    std::string udh;           /* raw user data header; "" = none  */
};

/* The complete RPDU — the body of the SIP MESSAGE. */
std::string submit(const Submission& s);
/* Just the TPDU, for a caller doing its own RP framing. */
std::string submit_tpdu(const Submission& s);

/* What a service centre (or an IP-SM-GW in loopback) delivers. */
struct Delivery {
    std::string from; /* required: TP-OA                          */
    std::string text;
    std::string sc; /* service centre for RP-OA; "" = absent    */
    int         alphabet = ALPHA_AUTO;
    bool        sri      = false; /* a status report will follow   */
    bool        more     = false; /* more messages waiting at SC   */
    bool        rp       = false;
    int         mr       = 0;
    int         pid      = 0;
    int         cls      = -1;
    int64_t     scts     = 0; /* unix seconds; 0 = now            */
    int         tz       = 0; /* quarter-hours east of GMT        */
    std::string udh;
};

std::string deliver(const Delivery& d);
std::string deliver_tpdu(const Delivery& d);

/* RP-ACK / RP-ERROR / RP-SMMA. tpdu may be empty. */
std::string ack(int dir, int mr, const std::string& tpdu = "");
std::string error(int dir, int mr, int cause, const std::string& tpdu = "");
std::string smma(int mr);

/* RP-DATA around a TPDU a caller built or forwarded verbatim. */
std::string rp_data(int dir, int mr, const std::string& sc,
                    const std::string& tpdu);

/* ---- store and forward ----
 *
 * What a service centre does to a submitted message (TS 23.040 §10):
 * turn the SMS-SUBMIT into an SMS-DELIVER by replacing the address with
 * the originator's and stamping it, while keeping TP-PID, TP-DCS,
 * TP-UDHI and TP-UD byte for byte.
 *
 * The copy matters. Re-encoding the text would destroy 8-bit payloads,
 * a user data header, a concatenation element, and any national-language
 * shift — so a test asserting that what arrived equals what was sent
 * would be testing the codec against itself rather than the network.
 *
 * scts 0 means now. Returns the DELIVER TPDU; wrap it with rp_data(). */
std::string deliver_from_submit(const std::string& tpdu, const std::string& oa,
                                int64_t scts = 0, int tz = 0,
                                bool more = false);

/* The SMS-STATUS-REPORT an SC returns when TP-SRR was set. st is a
 * TP-ST value (0 = delivered to the SME). */
std::string status_report_tpdu(const std::string& ra, int mr, int st,
                               int64_t scts = 0, int64_t dt = 0, int tz = 0);

/* ---- concatenation ----
 *
 * A Submission whose text needs more than one message. count()/at(i)
 * rather than a std::vector, for the reason sms.i documents. */
class Parts
{
  public:
    int count() const
    {
        return (int)v_.size();
    }
    std::string at(int i) const; /* RPDU bytes; throws on range */
    std::string tpdu_at(int i) const;

    std::vector<std::string> v_;  /* hidden from scripts */
    std::vector<std::string> tv_; /* hidden from scripts */
};

/* Split and frame in one step. ref identifies the group; ref16 selects
 * the 16-bit reference element. A text that fits one message comes back
 * as a single part with no concatenation header at all. */
Parts submit_parts(const Submission& s, int ref, bool ref16 = false);
Parts deliver_parts(const Delivery& d, int ref, bool ref16 = false);

/* ---- helpers a script actually reaches for ---- */

/* Septets the text needs in the GSM 7-bit alphabet (extension
 * characters count two); throws when a character has no mapping. Use it
 * to decide whether a body will fit before building it. */
int gsm7_septets(const std::string& text);

/* Can the default alphabet hold this text at all? */
bool is_gsm7(const std::string& text);

/* The DCS octet for a plain message; cls < 0 leaves the class unset. */
int dcs_make(int alphabet, int cls = -1);
Dcs dcs_decode(int octet);

/* Relative TP-VP code <-> seconds (TS 23.040 §9.2.3.12.1: four ranges
 * with different steps, not a linear scale). */
unsigned vp_seconds(int rel_code);
int      vp_code(unsigned seconds);

/* Name tables, for logging. */
std::string type_name(int type);
std::string rp_type_name(int type);
std::string rp_cause_name(int cause);
std::string status_name(int st);   /* TP-ST  */
std::string failure_name(int fcs); /* TP-FCS */
std::string pid_name(int pid);     /* TP-PID */
std::string ton_name(int ton);
int         rp_cause_fold(int cause); /* §8.2.5.4 */

} // namespace sms

#endif /* SMSXX_HPP */
