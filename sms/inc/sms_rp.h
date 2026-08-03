#ifndef SMS_RP_H
#define SMS_RP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* sms_dir_t, sms_err_t, sms_ton_t and the address bounds are shared
 * with the transfer layer. */
#include "sms.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SMS relay layer — 3GPP TS 24.011 §7.3 (RPDU formats) and §8.2 (their
 * contents). This is the envelope a TPDU travels in between the MS and
 * the SC; over IMS it is the whole body of a SIP MESSAGE with
 * Content-Type application/vnd.3gpp.sms (TS 24.341 §5.3.2).
 *
 * Over the radio interface the RP layer sits under a CP (connection
 * management) layer with its own timers. Over IMS there is no CP layer
 * at all: SIP is the reliable transport, so this module implements RP
 * and stops there.
 *
 * Same conventions as sms.h — direction is an input rather than a
 * guess (the RP-MTI encodes it, so a decode with the wrong direction
 * is caught rather than silently reinterpreted), decode leaves the
 * user data as a view into the caller's buffer, encode writes into a
 * caller-supplied buffer.
 *
 * Wire layout (§7.3):
 *   octet 0 : bits 2-0 RP-MTI, bits 7-3 spare
 *   octet 1 : RP-Message Reference
 *   RP-DATA : RP-OA (LV), RP-DA (LV), RP-User-Data (LV)
 *   RP-ACK  : [RP-User-Data (TLV, IEI 0x41)]
 *   RP-ERROR: RP-Cause (LV), [RP-User-Data (TLV, IEI 0x41)]
 *   RP-SMMA : nothing further
 */

/* An RPDU is two octets of header plus at most two 12-octet addresses
 * and a 164-octet user-data element. */
#define SMS_RP_MAX      256
#define SMS_RP_ADDR_MAX 12

typedef enum {
    SMS_RP_DATA_MS_TO_N  = 0, /* §7.3.1.1 */
    SMS_RP_DATA_N_TO_MS  = 1, /* §7.3.1.2 */
    SMS_RP_ACK_MS_TO_N   = 2, /* §7.3.3   */
    SMS_RP_ACK_N_TO_MS   = 3,
    SMS_RP_ERROR_MS_TO_N = 4, /* §7.3.4   */
    SMS_RP_ERROR_N_TO_MS = 5,
    SMS_RP_SMMA_MS_TO_N  = 6 /* §7.3.2   */
} sms_rp_mti_t;

/* What the RPDU is, with the direction factored out — dispatch on this
 * and read `mti` when the direction matters. */
typedef enum {
    SMS_RP_T_DATA  = 0,
    SMS_RP_T_ACK   = 1,
    SMS_RP_T_ERROR = 2,
    SMS_RP_T_SMMA  = 3,
    SMS_RP_T_MAX   = 4
} sms_rp_type_t;

/* Information element identifiers that appear as TLVs (§8.2.5). */
#define SMS_RP_IEI_USER_DATA 0x41

/* RP-Cause values — TS 24.011 §8.2.5.4. Anything not listed must be
 * treated as TEMPORARY_FAILURE, which is what sms_rp_cause_fold()
 * does. */
typedef enum {
    SMS_RP_CAUSE_UNASSIGNED_NUMBER    = 1,
    SMS_RP_CAUSE_OPERATOR_BARRING     = 8,
    SMS_RP_CAUSE_CALL_BARRED          = 10,
    SMS_RP_CAUSE_RESERVED             = 11,
    SMS_RP_CAUSE_TRANSFER_REJECTED    = 21,
    SMS_RP_CAUSE_DEST_OUT_OF_ORDER    = 27,
    SMS_RP_CAUSE_UNIDENTIFIED_SUB     = 28,
    SMS_RP_CAUSE_FACILITY_REJECTED    = 29,
    SMS_RP_CAUSE_UNKNOWN_SUB          = 30,
    SMS_RP_CAUSE_NETWORK_OUT_OF_ORDER = 38,
    SMS_RP_CAUSE_TEMPORARY_FAILURE    = 41,
    SMS_RP_CAUSE_CONGESTION           = 42,
    SMS_RP_CAUSE_RESOURCES_UNAVAIL    = 47,
    SMS_RP_CAUSE_FACILITY_NOT_SUBSCR  = 50,
    SMS_RP_CAUSE_FACILITY_NOT_IMPL    = 69,
    SMS_RP_CAUSE_INVALID_REFERENCE    = 81,
    SMS_RP_CAUSE_SEMANTIC_ERROR       = 95,
    SMS_RP_CAUSE_INVALID_MANDATORY    = 96,
    SMS_RP_CAUSE_MSG_TYPE_UNKNOWN     = 97,
    SMS_RP_CAUSE_MSG_INCOMPATIBLE     = 98,
    SMS_RP_CAUSE_IE_UNKNOWN           = 99,
    SMS_RP_CAUSE_PROTOCOL_ERROR       = 111,
    SMS_RP_CAUSE_INTERWORKING         = 127
} sms_rp_cause_t;

/* An RP address — TS 24.011 §8.2.5.1/§8.2.5.2, which carry a
 * TS 24.008 §10.5.4.7 called-party BCD number.
 *
 * Close to but not the same as a TPDU address (TS 23.040 §9.1.2.5):
 * there is no digit-count octet, so an odd number of digits is marked
 * only by the 0xF filler in the last high nibble, and the length octet
 * counts the type-of-number octet as well as the digits.
 *
 * `present` distinguishes an absent address (length 0, which RP-DATA
 * uses for the direction that has no meaningful party) from one whose
 * digits happen to be empty. */
typedef struct {
    bool    present;
    uint8_t ton; /* sms_ton_t */
    uint8_t npi; /* sms_npi_t */
    char    digits[SMS_ADDR_MAX_DIGITS + 1];
} sms_rp_addr_t;

typedef struct {
    uint8_t mti;  /* sms_rp_mti_t, as on the wire  */
    uint8_t type; /* sms_rp_type_t                 */
    bool    from_ms;
    uint8_t mr; /* RP-Message Reference          */

    /* RP-DATA only. */
    sms_rp_addr_t oa;
    sms_rp_addr_t da;

    /* RP-ERROR only. cause_diag is the optional diagnostic octet. */
    uint8_t cause;
    bool    has_cause_diag;
    uint8_t cause_diag;

    /* RP-User-Data: the TPDU. Mandatory in RP-DATA, optional in RP-ACK
     * and RP-ERROR, absent from RP-SMMA. A view into the caller's
     * buffer. */
    bool           has_ud;
    const uint8_t* ud;
    uint8_t        ud_len;
} sms_rp_pdu_t;

/* ---- codec ---- */

/* Decode one RPDU. dir is an sms_dir_t (SMS_DIR_MS_TO_SC when the
 * message travels towards the network). An RP-MTI that belongs to the
 * other direction is SMS_E_MTI, not a silent reinterpretation.
 * Returns the octets consumed or a negative sms_err_t. */
API_EXPORT int sms_rp_decode(const uint8_t* b, size_t n, int dir,
                             sms_rp_pdu_t* out);

API_EXPORT int sms_rp_encode(uint8_t* b, size_t cap, const sms_rp_pdu_t* p);

/* Zero an RPDU and set its type and direction. */
API_EXPORT void sms_rp_init(sms_rp_pdu_t* p, sms_rp_type_t type, int dir);

/* ---- addresses ---- */

API_EXPORT int sms_rp_addr_decode(const uint8_t* b, size_t n,
                                  sms_rp_addr_t* out);
API_EXPORT int sms_rp_addr_encode(uint8_t* b, size_t cap,
                                  const sms_rp_addr_t* a);
API_EXPORT int sms_rp_addr_set(sms_rp_addr_t* a, const char* num, int ton);

/* ---- shorthands for the four messages a UE or an IP-SM-GW builds ----
 *
 * Each writes a complete RPDU into b[0..cap) and returns its length or
 * a negative sms_err_t. sc may be NULL/"" for an absent address. */

/* RP-DATA carrying a TPDU. Towards the network the originator address
 * is absent and the destination is the service centre; towards the MS
 * it is the other way round (§7.3.1). */
API_EXPORT int sms_rp_data(uint8_t* b, size_t cap, int dir, uint8_t mr,
                           const char* sc, const uint8_t* tpdu,
                           size_t tpdu_len);

/* RP-ACK, optionally carrying a report TPDU. */
API_EXPORT int sms_rp_ack(uint8_t* b, size_t cap, int dir, uint8_t mr,
                          const uint8_t* tpdu, size_t tpdu_len);

/* RP-ERROR with an RP-Cause, optionally carrying a report TPDU. */
API_EXPORT int sms_rp_error(uint8_t* b, size_t cap, int dir, uint8_t mr,
                            uint8_t cause, const uint8_t* tpdu,
                            size_t tpdu_len);

/* RP-SMMA — "memory available again", MS to network only. */
API_EXPORT int sms_rp_smma(uint8_t* b, size_t cap, uint8_t mr);

/* ---- names ---- */

API_EXPORT const char* sms_rp_type_name(sms_rp_type_t t);
API_EXPORT const char* sms_rp_mti_name(sms_rp_mti_t mti);
API_EXPORT const char* sms_rp_cause_name(uint8_t cause);

/* §8.2.5.4: every unlisted cause means "Temporary failure". */
API_EXPORT uint8_t sms_rp_cause_fold(uint8_t cause);

#ifdef __cplusplus
}
#endif

#endif /* SMS_RP_H */
