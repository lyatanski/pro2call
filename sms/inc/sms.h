#ifndef SMS_H
#define SMS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SMS transfer-layer codec — 3GPP TS 23.040 (TPDUs) with the data
 * coding schemes and alphabets of TS 23.038. The relay layer that wraps
 * these on the way to an SC lives in sms_rp.h (TS 24.011).
 *
 * SMS is bit-packed, not tag-length-value, so nothing here uses tlv.h:
 * the first octet of every TPDU is a bag of one- and two-bit flags, and
 * which fields follow depends on them (TP-VPF picks a 0-, 1- or
 * 7-octet validity period; TP-PI picks which of TP-PID/TP-DCS/TP-UDL a
 * report carries; TP-UDHI decides whether TP-UD starts with a header).
 *
 * Decode is zero-copy for the one variable-length field that matters:
 * TP-UD comes out as a pointer+length view into the caller's buffer, so
 * the buffer must stay valid while the TPDU is in use. The small fixed
 * fields — addresses (≤ 12 octets) and timestamps — are copied into the
 * struct, because slicing them would buy nothing and cost every caller
 * a semi-octet decode.
 *
 * Encode writes into a caller-supplied buffer with no allocation, and
 * returns the byte count or a negative sms_err_t.
 *
 * Direction is an input, never a guess: the same TP-MTI value names a
 * different TPDU depending on whether the message travels MS->SC or
 * SC->MS (TS 23.040 §9.2.3.1), so sms_tpdu_decode() takes it and
 * refuses to infer it.
 *
 * Wire layout reference (TS 23.040 §9.2.2.x), octet 0 bit positions:
 *   SUBMIT  : RP UDHI SRR VPF(2) RD  MTI(2)=01
 *   DELIVER : RP UDHI SRI -      LP  MMS MTI(2)=00
 *   STATUS  : -  UDHI SRQ -      LP  MMS MTI(2)=10
 *   COMMAND : -  UDHI SRR -      -   -   MTI(2)=10
 */

/* ---- limits ---- */

/* TP-UD is at most 140 octets (TS 23.040 §9.2.3.24); TP-CD at most 156
 * (§9.2.3.21). An address is at most 20 digits, which is 12 octets on
 * the wire (§9.1.2.5). */
#define SMS_UD_MAX          140
#define SMS_CD_MAX          156
#define SMS_ADDR_MAX_DIGITS 20
#define SMS_ADDR_MAX_OCTETS 12

/* An alphanumeric address (TON 101) packs GSM 7-bit characters into
 * those same 10 value octets — 11 septets, each up to 3 UTF-8 bytes.
 * One buffer serves both forms. */
#define SMS_ADDR_MAX_TEXT 35

/* A TPDU never exceeds header + address + TP-UD; 176 covers every type
 * with room to spare, so callers can size a stack buffer once. */
#define SMS_TPDU_MAX 176

typedef enum {
    SMS_OK         = 0,
    SMS_E_SHORT    = -1, /* buffer ends inside a mandatory field    */
    SMS_E_LENGTH   = -2, /* a length field disagrees with the data  */
    SMS_E_OVERFLOW = -3, /* write buffer too small                  */
    SMS_E_INVAL    = -4, /* invalid argument                        */
    SMS_E_ALPHABET = -5, /* text has no encoding in this alphabet   */
    SMS_E_MTI      = -6, /* reserved TP-MTI for this direction      */
    SMS_E_MISSING  = -7  /* expected element absent                 */
} sms_err_t;

/* Transfer direction. The TP-MTI is only half of a TPDU's identity
 * (TS 23.040 §9.2.3.1): MTI 00 is SMS-DELIVER from the SC and
 * SMS-DELIVER-REPORT towards it.
 *
 * SMS_DIR_NEGATIVE is a modifier, OR-ed into the direction, and it
 * matters for exactly one thing: a report TPDU carried in an RP-ERROR
 * has a TP-FCS octet that the RP-ACK variant does not (§9.2.2.1a,
 * §9.2.2.2a). Nothing in the TPDU says which it is — the RP layer
 * knows — and guessing shifts every following field by one octet. */
typedef enum {
    SMS_DIR_MS_TO_SC = 0, /* SUBMIT, COMMAND, DELIVER-REPORT       */
    SMS_DIR_SC_TO_MS = 1, /* DELIVER, STATUS-REPORT, SUBMIT-REPORT */
    SMS_DIR_NEGATIVE = 2  /* OR in: the report rides an RP-ERROR   */
} sms_dir_t;

/* The six TPDU types, resolved from (TP-MTI, direction) at parse so
 * downstream dispatch is one integer compare. */
typedef enum {
    SMS_T_DELIVER        = 0, /* §9.2.2.1  SC -> MS */
    SMS_T_DELIVER_REPORT = 1, /* §9.2.2.1a MS -> SC */
    SMS_T_SUBMIT         = 2, /* §9.2.2.2  MS -> SC */
    SMS_T_SUBMIT_REPORT  = 3, /* §9.2.2.2a SC -> MS */
    SMS_T_STATUS_REPORT  = 4, /* §9.2.2.3  SC -> MS */
    SMS_T_COMMAND        = 5, /* §9.2.2.4  MS -> SC */
    SMS_T_MAX            = 6
} sms_type_t;

/* Type-of-Number, TS 23.040 §9.1.2.5 (the value of bits 6-4). */
typedef enum {
    SMS_TON_UNKNOWN       = 0,
    SMS_TON_INTERNATIONAL = 1, /* digits carry no leading '+'      */
    SMS_TON_NATIONAL      = 2,
    SMS_TON_NETWORK       = 3,
    SMS_TON_SUBSCRIBER    = 4,
    SMS_TON_ALPHANUM      = 5, /* digits[] is GSM 7-bit text       */
    SMS_TON_ABBREVIATED   = 6,
    SMS_TON_RESERVED      = 7
} sms_ton_t;

/* Numbering-Plan-Identification, TS 23.040 §9.1.2.5 (bits 3-0). */
typedef enum {
    SMS_NPI_UNKNOWN  = 0,
    SMS_NPI_ISDN     = 1, /* E.164 — the only one in practice */
    SMS_NPI_DATA     = 3, /* X.121                            */
    SMS_NPI_TELEX    = 4,
    SMS_NPI_SC_SPEC1 = 5,
    SMS_NPI_SC_SPEC2 = 6,
    SMS_NPI_NATIONAL = 8,
    SMS_NPI_PRIVATE  = 9,
    SMS_NPI_ERMES    = 10,
    SMS_NPI_RESERVED = 15
} sms_npi_t;

/* An address field — TP-OA / TP-DA / TP-RA, TS 23.040 §9.1.2.5.
 *
 * digits[] is NUL-terminated and holds what the semi-octets meant: the
 * decimal digits plus the four escapes the BCD table defines ('*',
 * '#', 'a', 'b', 'c'). No '+' is prepended for an international TON —
 * the wire does not carry one and inventing it makes round-trips lossy;
 * sms_addr_e164() is there when a caller wants the display form.
 *
 * For SMS_TON_ALPHANUM the field is not digits at all: it is GSM 7-bit
 * packed text, and digits[] holds it decoded to UTF-8. */
typedef struct {
    uint8_t ton; /* sms_ton_t */
    uint8_t npi; /* sms_npi_t */
    char    digits[SMS_ADDR_MAX_TEXT + 1];
} sms_addr_t;

/* TP-SCTS / TP-DT / absolute TP-VP — TS 23.040 §9.2.3.11.
 *
 * Seven semi-octet pairs. tz_qh is the offset from GMT in quarters of
 * an hour and really is signed: the sign lives in bit 3 of the seventh
 * octet, which is the top bit of the *tens* digit once the nibbles are
 * swapped back, so a naive BCD decode reads -8 quarters as +88. */
typedef struct {
    int16_t year;  /* full year; the wire carries two digits (see below) */
    uint8_t mon;   /* 1..12                                              */
    uint8_t day;   /* 1..31                                              */
    uint8_t hour;  /* 0..23                                              */
    uint8_t min;   /* 0..59                                              */
    uint8_t sec;   /* 0..59                                              */
    int8_t  tz_qh; /* quarter-hours east of GMT, -48..+48               */
} sms_ts_t;

/* The wire year is two digits. 00..69 is read as 2000..2069 and 70..99
 * as 1970..1999 — the POSIX-style split, which is what every handset
 * does and what keeps encode(decode(x)) == x for any year a live
 * network will produce. */
#define SMS_YEAR_PIVOT 70

/* TP-VPF — TS 23.040 §9.2.3.3, the two bits that decide how wide the
 * validity period is. */
typedef enum {
    SMS_VPF_NONE     = 0, /* field absent            */
    SMS_VPF_ENHANCED = 1, /* 7 octets, §9.2.3.12.3   */
    SMS_VPF_RELATIVE = 2, /* 1 octet,  §9.2.3.12.1   */
    SMS_VPF_ABSOLUTE = 3  /* 7 octets, §9.2.3.12.2   */
} sms_vpf_t;

/* TP-VP. The enhanced form keeps its seven octets verbatim: its own
 * sub-format byte selects between four encodings and one reserved
 * range, and re-deriving it on the way out would make a round-trip
 * lossy for anything this codec does not model. */
typedef struct {
    uint8_t  fmt;    /* sms_vpf_t                                */
    uint8_t  rel;    /* RELATIVE: the raw code, see sms_vp_secs() */
    sms_ts_t abs;    /* ABSOLUTE                                  */
    uint8_t  enh[7]; /* ENHANCED, as received                     */
} sms_vp_t;

/* TP-UD together with its length field.
 *
 * udl is the wire value and keeps the wire's units: septets when the
 * DCS says GSM 7-bit, octets otherwise (TS 23.040 §9.2.3.16). In both
 * cases it counts the user data header. len is always octets — how
 * much of the buffer TP-UD actually occupies — because that is what a
 * memcpy needs and deriving it from udl requires the DCS. */
typedef struct {
    uint8_t        udl;
    uint8_t        len; /* octets addressable at p */
    const uint8_t* p;   /* NULL when the TPDU has no user data */
} sms_ud_t;

/* §9.2.2.1 — what an SC delivers to a handset. */
typedef struct {
    bool       mms;  /* TP-MMS: 1 = no more messages waiting at the SC */
    bool       lp;   /* TP-LP:  loop prevention (Rel-8)                */
    bool       rp;   /* TP-RP:  reply path                             */
    bool       udhi; /* TP-UDHI                                        */
    bool       sri;  /* TP-SRI: SC will return a status report         */
    sms_addr_t oa;   /* TP-OA                                          */
    uint8_t    pid;  /* TP-PID, §9.2.3.9                               */
    uint8_t    dcs;  /* TP-DCS, TS 23.038 §4                           */
    sms_ts_t   scts; /* TP-SCTS                                        */
    sms_ud_t   ud;
} sms_deliver_t;

/* §9.2.2.2 — what a handset submits. */
typedef struct {
    bool       rd;   /* TP-RD:  reject duplicates                      */
    bool       rp;   /* TP-RP                                          */
    bool       udhi; /* TP-UDHI                                        */
    bool       srr;  /* TP-SRR: status report requested                */
    uint8_t    mr;   /* TP-MR:  message reference                      */
    sms_addr_t da;   /* TP-DA                                          */
    uint8_t    pid;
    uint8_t    dcs;
    sms_vp_t   vp; /* TP-VP; fmt == SMS_VPF_NONE when absent           */
    sms_ud_t   ud;
} sms_submit_t;

/* §9.2.2.3 — the SC reporting what became of a submitted message. */
typedef struct {
    bool       mms;
    bool       lp;
    bool       udhi;
    bool       srq;  /* TP-SRQ: 0 = result of a SUBMIT, 1 = of a COMMAND */
    uint8_t    mr;   /* the TP-MR of the message being reported on       */
    sms_addr_t ra;   /* TP-RA                                            */
    sms_ts_t   scts; /* of the original submission                       */
    sms_ts_t   dt;   /* TP-DT: discharge time                            */
    uint8_t    st;   /* TP-ST, §9.2.3.15                                 */
    /* The tail is optional and driven by TP-PI (§9.2.3.27). */
    bool     has_pi;
    uint8_t  pi;
    bool     has_pid, has_dcs, has_ud;
    uint8_t  pid;
    uint8_t  dcs;
    sms_ud_t ud;
} sms_status_report_t;

/* §9.2.2.4 — a handset asking the SC to act on an earlier message. */
typedef struct {
    bool           udhi;
    bool           srr;
    uint8_t        mr;
    uint8_t        pid;
    uint8_t        ct;  /* TP-CT, §9.2.3.19        */
    uint8_t        mn;  /* TP-MN: message number   */
    sms_addr_t     da;  /* TP-DA                   */
    uint8_t        cdl; /* TP-CDL, octets          */
    const uint8_t* cd;  /* TP-CD, zero-copy        */
} sms_command_t;

/* §9.2.2.1a / §9.2.2.2a — the two report TPDUs. They differ by one
 * field, so one struct carries both: has_scts marks the SUBMIT-REPORT
 * (which timestamps the submission) and has_fcs the RP-ERROR variant
 * (which names the failure). */
typedef struct {
    bool     udhi;
    bool     has_fcs; /* set for the RP-ERROR variant */
    uint8_t  fcs;     /* TP-FCS, §9.2.3.22            */
    uint8_t  pi;      /* TP-PI,  §9.2.3.27            */
    bool     has_scts;
    sms_ts_t scts; /* SUBMIT-REPORT only */
    bool     has_pid, has_dcs, has_ud;
    uint8_t  pid;
    uint8_t  dcs;
    sms_ud_t ud;
} sms_report_t;

/* One decoded TPDU. `type` names it; `mti` and `dir` keep the wire
 * inputs that produced the name. */
typedef struct {
    uint8_t type; /* sms_type_t */
    uint8_t mti;  /* 0..2, as on the wire  */
    uint8_t dir;  /* sms_dir_t, without the NEGATIVE modifier */
    union {
        sms_deliver_t       deliver;
        sms_submit_t        submit;
        sms_status_report_t status_report;
        sms_command_t       command;
        sms_report_t        report; /* DELIVER-REPORT and SUBMIT-REPORT */
    } u;
} sms_tpdu_t;

/* ---- TPDU codec ---- */

/* Decode one TPDU. dir is an sms_dir_t, optionally OR-ed with
 * SMS_DIR_NEGATIVE for a report carried in an RP-ERROR. Returns the
 * number of octets consumed (which equals n for a well-formed TPDU) or
 * a negative sms_err_t. The buffer must stay valid while *out is in
 * use: TP-UD and TP-CD are views into it. */
API_EXPORT int sms_tpdu_decode(const uint8_t* b, size_t n, int dir,
                               sms_tpdu_t* out);

/* Encode a TPDU into b[0..cap). Returns the byte count or a negative
 * sms_err_t. The TP-UD/TP-CD views in *t are copied out as they are —
 * this does no alphabet conversion, so t->u.*.ud.udl must already be
 * in the units its DCS implies (sms_ud_from_utf8() sets both). */
API_EXPORT int sms_tpdu_encode(uint8_t* b, size_t cap, const sms_tpdu_t* t);

/* Zero a TPDU and set its type, so a caller can fill in only what it
 * cares about. Sets mti/dir consistently with type. */
API_EXPORT void sms_tpdu_init(sms_tpdu_t* t, sms_type_t type);

/* ---- addresses ---- */

/* Decode an address field starting at b[0] (the Address-Length octet).
 * Returns the octets consumed, or a negative sms_err_t. */
API_EXPORT int sms_addr_decode(const uint8_t* b, size_t n, sms_addr_t* out);

/* Encode one. Returns the octets written or a negative sms_err_t. */
API_EXPORT int sms_addr_encode(uint8_t* b, size_t cap, const sms_addr_t* a);

/* Fill *a from a number string. A leading '+' selects
 * SMS_TON_INTERNATIONAL and is stripped; anything else keeps the ton
 * passed in. npi is SMS_NPI_ISDN. */
API_EXPORT int sms_addr_set(sms_addr_t* a, const char* num, int ton);

/* Fill *a with alphanumeric text (UTF-8, GSM 7-bit representable). */
API_EXPORT int sms_addr_set_text(sms_addr_t* a, const char* text);

/* Display form: "+<digits>" for an international TON, digits or text
 * otherwise. Writes at most cap bytes including the NUL and returns the
 * length written, or SMS_E_OVERFLOW. */
API_EXPORT int sms_addr_e164(const sms_addr_t* a, char* out, size_t cap);

/* ---- timestamps ---- */

API_EXPORT int sms_ts_decode(const uint8_t* b, size_t n, sms_ts_t* out);
API_EXPORT int sms_ts_encode(uint8_t* b, size_t cap, const sms_ts_t* t);

/* Seconds since the Unix epoch for a timestamp, tz_qh applied. Returns
 * (int64_t)-1 only for a timestamp whose fields are out of range. */
API_EXPORT int64_t sms_ts_unix(const sms_ts_t* t);

/* Fill *out from a Unix time, expressed at the given offset from GMT. */
API_EXPORT void sms_ts_from_unix(sms_ts_t* out, int64_t secs, int tz_qh);

/* ISO-8601 rendering ("2026-08-03T07:14:05+02:00"); returns the length
 * written or SMS_E_OVERFLOW. Wants 26 bytes. */
API_EXPORT int sms_ts_iso8601(const sms_ts_t* t, char* out, size_t cap);

/* ---- validity period ---- */

/* Relative TP-VP as seconds (TS 23.040 §9.2.3.12.1): the code is four
 * ranges with different steps, not a linear scale. */
API_EXPORT uint32_t sms_vp_secs(uint8_t rel);

/* Nearest relative code at or above `secs`, clamped to the 63-week
 * maximum. */
API_EXPORT uint8_t sms_vp_rel_from_secs(uint32_t secs);

/* ---- name tables (logging and dispatch) ---- */

API_EXPORT const char* sms_type_name(sms_type_t t);
API_EXPORT const char* sms_ton_name(sms_ton_t t);
API_EXPORT const char* sms_npi_name(sms_npi_t n);
API_EXPORT const char* sms_err_name(int err);

/* TP-ST (§9.2.3.15), TP-FCS (§9.2.3.22), TP-PID (§9.2.3.9) and TP-CT
 * (§9.2.3.19) renderings. Both registries are mostly ranges, so these
 * name the defined points and describe the range otherwise; never
 * NULL. */
API_EXPORT const char* sms_st_name(uint8_t st);
API_EXPORT const char* sms_fcs_name(uint8_t fcs);
API_EXPORT const char* sms_pid_name(uint8_t pid);
API_EXPORT const char* sms_ct_name(uint8_t ct);

/* TP-ST is banded: bits 6-5 say whether the SC is done trying. */
API_EXPORT bool sms_st_completed(uint8_t st); /* 000xxxx: delivered   */
API_EXPORT bool sms_st_permanent(uint8_t st); /* 010xxxx/011xxxx: gave up */
API_EXPORT bool sms_st_temporary(uint8_t st); /* 001xxxx: still trying */

/* ==================================================================
 * Data coding scheme and user data — TS 23.038
 * ================================================================== */

/* The alphabet a DCS selects. SMS_ALPHA_AUTO is not a wire value: it
 * asks the encoder to pick GSM 7-bit when every character has a
 * mapping and UCS2 when one does not, which is what a handset does. */
typedef enum {
    SMS_ALPHA_AUTO     = -1,
    SMS_ALPHA_GSM7     = 0,
    SMS_ALPHA_8BIT     = 1,
    SMS_ALPHA_UCS2     = 2,
    SMS_ALPHA_RESERVED = 3
} sms_alpha_t;

/* A decoded TP-DCS — TS 23.038 §4. The octet is a coding *group* in
 * the top nibble and the group decides what the bottom nibble means,
 * so nothing useful can be read out of it without this table. */
typedef struct {
    uint8_t alphabet;   /* sms_alpha_t                              */
    bool    compressed; /* §4 compression bit; this codec decodes   */
                        /* nothing compressed and says so           */
    bool    has_class;
    uint8_t cls;         /* 0..3 when has_class                     */
    bool    auto_delete; /* groups 0100..0111                       */
    bool    mwi;         /* message-waiting-indication group        */
    bool    mwi_active;  /* indication sense                        */
    uint8_t mwi_type;    /* 0 voicemail, 1 fax, 2 e-mail, 3 other   */
    bool    mwi_discard; /* group 1100: show it, do not store it    */
} sms_dcs_t;

API_EXPORT void sms_dcs_decode(uint8_t dcs, sms_dcs_t* out);

/* The DCS octet for a plain message in `alphabet`; cls < 0 leaves the
 * class unset (group 0000), otherwise the class bit is set. */
API_EXPORT uint8_t sms_dcs_make(int alphabet, int cls);

/* Shortcut used all over the codec: which alphabet, ignoring the rest.
 * A compressed or reserved DCS yields SMS_ALPHA_RESERVED. */
API_EXPORT int sms_dcs_alphabet(uint8_t dcs);

/* ---- GSM 7-bit default alphabet (TS 23.038 §6.2.1) ---- */

/* Septet value <-> Unicode. sms_gsm7_to_ucs() returns the code point,
 * or -1 for the escape (0x1B) which is not a character on its own.
 * sms_gsm7_from_ucs() returns the septet, or 0x1B00|<septet> when the
 * character needs the extension table (§6.2.1.1), or -1 when the
 * default alphabet cannot represent it. */
API_EXPORT int32_t sms_gsm7_to_ucs(uint8_t septet);
API_EXPORT int32_t sms_gsm7_from_ucs(uint32_t ucs);

/* UTF-8 <-> septet values (still one septet per array entry; packing
 * is separate). from_utf8 expands extension characters into the two
 * septets 0x1B,<x> and returns the septet count, or SMS_E_ALPHABET at
 * the first character with no mapping. */
API_EXPORT int sms_gsm7_from_utf8(const char* s, size_t n, uint8_t* septets,
                                  size_t cap);
API_EXPORT int sms_gsm7_to_utf8(const uint8_t* septets, size_t n, char* out,
                                size_t cap);

/* Septets a UTF-8 string needs in the default alphabet (extension
 * characters count 2), or SMS_E_ALPHABET when one has no mapping. */
API_EXPORT int sms_gsm7_septets(const char* s, size_t n);

/* ---- 7-bit packing ----
 *
 * Septets are packed least-significant-bit first, so septet k occupies
 * bits [7k, 7k+7) of the octet run. septet_off skips that many septet
 * positions before the first character: with TP-UDHI set, the text
 * starts at the septet boundary *after* the header, and the 0..6 bits
 * between the two are fill (TS 23.040 §9.2.3.24). Getting this wrong
 * is the classic "last character of a concatenated SMS is garbage". */

/* Septet position the text starts at, given a header of udh_len octets
 * (the UDHL octet included). */
API_EXPORT size_t sms_gsm7_septet_off(size_t udh_len);

/* Pack n septets into out[] starting at septet position septet_off.
 * The bits below that are left exactly as the caller wrote them (the
 * header and its fill bits), so out[] must already hold the header.
 * Returns the total octet length of the packed run — header, fill and
 * text — or a negative sms_err_t. */
API_EXPORT int sms_gsm7_pack(const uint8_t* septets, size_t n,
                             size_t septet_off, uint8_t* out, size_t cap);

/* Unpack `count` septets starting at septet position septet_off of the
 * n-octet run at in[]. count is required rather than derived: the last
 * octet of a packed run holds up to seven spare bits, and reading them
 * as an eighth septet is where the phantom trailing '@' comes from —
 * only TP-UDL says how many septets are real. */
API_EXPORT int sms_gsm7_unpack(const uint8_t* in, size_t n, size_t septet_off,
                               size_t count, uint8_t* out, size_t cap);

/* ---- TP-UD <-> UTF-8 ---- */

/* Decode TP-UD to UTF-8. ud/ud_len is the whole field including any
 * header; udhi and udl come from the TPDU. The header is skipped (and
 * for 7-bit data its septet alignment applied). NUL-terminates when
 * cap allows. Returns the byte count written, or a negative
 * sms_err_t. */
API_EXPORT int sms_ud_to_utf8(uint8_t dcs, bool udhi, const uint8_t* ud,
                              size_t ud_len, uint8_t udl, char* out,
                              size_t cap);

/* Build TP-UD from UTF-8. udh (may be NULL) is copied in front and the
 * 7-bit alignment applied. Writes the chosen DCS and the TP-UDL — in
 * the units that DCS implies — through the out params. Returns the
 * TP-UD octet length, or a negative sms_err_t (SMS_E_LENGTH when the
 * result would exceed SMS_UD_MAX; split it with sms_concat_split()). */
API_EXPORT int sms_ud_from_utf8(const char* s, size_t n, int alphabet,
                                const uint8_t* udh, size_t udh_len,
                                uint8_t* out, size_t cap, uint8_t* udl_out,
                                uint8_t* dcs_out);

/* ---- user data header (TS 23.040 §9.2.3.24) ---- */

/* The IEIs this module names; any other is passed through untouched. */
typedef enum {
    SMS_UDH_CONCAT8     = 0x00, /* §9.2.3.24.1  ref, total, seq     */
    SMS_UDH_SPECIAL_SMS = 0x01, /* §9.2.3.24.2                      */
    SMS_UDH_PORT8       = 0x04, /* §9.2.3.24.3                      */
    SMS_UDH_PORT16      = 0x05, /* §9.2.3.24.4                      */
    SMS_UDH_SMSC_CTRL   = 0x06, /* §9.2.3.24.5                      */
    SMS_UDH_SOURCE_IND  = 0x07, /* §9.2.3.24.6                      */
    SMS_UDH_CONCAT16    = 0x08, /* §9.2.3.24.8  ref16, total, seq   */
    SMS_UDH_TEXT_FORMAT = 0x0A, /* EMS                              */
    SMS_UDH_NL_SS       = 0x24, /* §9.2.3.24.15 single shift        */
    SMS_UDH_NL_LS       = 0x25  /* §9.2.3.24.16 locking shift       */
} sms_udh_iei_t;

typedef struct {
    uint8_t        iei;
    uint8_t        len;
    const uint8_t* data; /* len octets, into the caller's buffer */
} sms_udh_ie_t;

typedef struct {
    const uint8_t* p;
    size_t         end; /* one past the last header octet */
    size_t         off;
} sms_udh_iter_t;

/* Start iterating the header at the front of a TP-UD field. Returns
 * false when there is no well-formed header (which includes ud_len
 * smaller than the UDHL octet claims). */
API_EXPORT bool sms_udh_begin(sms_udh_iter_t* it, const uint8_t* ud,
                              size_t ud_len);
API_EXPORT bool sms_udh_next(sms_udh_iter_t* it, sms_udh_ie_t* out);

/* Header extent in octets — the UDHL octet plus what it counts — or 0
 * when there is none. */
API_EXPORT size_t sms_udh_len(const uint8_t* ud, size_t ud_len);

/* ---- concatenation ---- */

typedef struct {
    uint16_t ref;
    uint8_t  total; /* parts in the message  */
    uint8_t  seq;   /* 1-based part number   */
    bool     ref16; /* the 16-bit IEI was used */
} sms_concat_t;

/* Read the concatenation IE (either width) out of a TP-UD header. */
API_EXPORT bool sms_concat_get(const uint8_t* ud, size_t ud_len,
                               sms_concat_t* out);

/* Build a concatenation header into out[]; returns its octet length
 * (6 for the 8-bit reference form, 7 for the 16-bit one). */
API_EXPORT int sms_concat_udh(uint8_t* out, size_t cap, const sms_concat_t* c);

/* One part of a split message: a complete TP-UD, header included. */
typedef struct {
    uint8_t ud[SMS_UD_MAX];
    uint8_t ud_len; /* octets */
    uint8_t udl;    /* wire units */
    uint8_t dcs;
    uint8_t seq, total;
} sms_part_t;

/* Split UTF-8 text into concatenated parts under one alphabet. Writes
 * at most `max` parts and returns how many it produced, or a negative
 * sms_err_t (SMS_E_LENGTH when the text needs more than `max`). A text
 * that fits one message produces one part with no header at all, which
 * is what a receiver expects — a single-part message wrapped in a
 * concatenation IE is legal but wasteful and confuses some handsets. */
API_EXPORT int sms_concat_split(const char* s, size_t n, int alphabet,
                                uint16_t ref, bool ref16, sms_part_t* parts,
                                int max);

#ifdef __cplusplus
}
#endif

#endif /* SMS_H */
