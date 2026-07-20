#ifndef GTP2_IE_H
#define GTP2_IE_H

#include "gtp2.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Sub-IE codecs: typed views of individual GTPv2-C IE values,
 * TS 29.274 §8. Shared by the hand-written and the generated message
 * layers; the wire layouts here are octet diagrams in the spec and are
 * maintained by hand, while the message grammars that reference them
 * are generated (tools/gtpgen).
 *
 * Decode reads an IE value into a host-order struct; put appends a
 * complete IE to the write buffer and follows gtp2_wbuf_t
 * sticky-overflow rules. */

/* F-TEID interface types — TS 29.274 §8.22 (LTE subset). */
typedef enum {
    GTP2_IF_S1U_ENODEB = 0,
    GTP2_IF_S1U_SGW    = 1,
    GTP2_IF_S12_RNC    = 2,
    GTP2_IF_S12_SGW    = 3,
    GTP2_IF_S5S8U_SGW  = 4,
    GTP2_IF_S5S8U_PGW  = 5,
    GTP2_IF_S5S8C_SGW  = 6,
    GTP2_IF_S5S8C_PGW  = 7,
    GTP2_IF_S11_MME    = 10,
    GTP2_IF_S11S4_SGW  = 11
} gtp2_if_type_t;

/* Cause values — TS 29.274 §8.4, Table 8.4-1 (subset). */
typedef enum {
    GTP2_CAUSE_REQUEST_ACCEPTED           = 16,
    GTP2_CAUSE_REQUEST_ACCEPTED_PARTIALLY = 17,
    GTP2_CAUSE_NEW_PDN_TYPE_PREFERENCE    = 18,
    GTP2_CAUSE_CONTEXT_NOT_FOUND          = 64,
    GTP2_CAUSE_MANDATORY_IE_MISSING       = 70,
    GTP2_CAUSE_REQUEST_REJECTED           = 94
} gtp2_cause_t;

/* RAT types — TS 29.274 §8.17. */
typedef enum {
    GTP2_RAT_UTRAN  = 1,
    GTP2_RAT_GERAN  = 2,
    GTP2_RAT_WLAN   = 3,
    GTP2_RAT_GAN    = 4,
    GTP2_RAT_HSPA   = 5,
    GTP2_RAT_EUTRAN = 6
} gtp2_rat_t;

/* PDN types — TS 29.274 §8.34. */
typedef enum {
    GTP2_PDN_IPV4   = 1,
    GTP2_PDN_IPV6   = 2,
    GTP2_PDN_IPV4V6 = 3
} gtp2_pdn_t;

/* Borrowed byte range; data == NULL means the field is absent. */
typedef struct {
    const uint8_t* data;
    uint16_t       len;
} gtp2_view_t;

/* F-TEID — §8.22. At least one of v4/v6 must be set. */
typedef struct {
    bool     v4;
    bool     v6;
    uint8_t  if_type; /* gtp2_if_type_t */
    uint32_t teid;
    uint8_t  addr4[4];  /* network order, valid when v4 */
    uint8_t  addr6[16]; /* valid when v6 */
} gtp2_fteid_t;

/* Bearer QoS — §8.15. Bitrates in kbps (40-bit on the wire). */
typedef struct {
    uint8_t  pci; /* pre-emption capability, 1 bit */
    uint8_t  pl;  /* priority level, 4 bits */
    uint8_t  pvi; /* pre-emption vulnerability, 1 bit */
    uint8_t  qci;
    uint64_t mbr_ul;
    uint64_t mbr_dl;
    uint64_t gbr_ul;
    uint64_t gbr_dl;
} gtp2_bearer_qos_t;

/* PDN Address Allocation — §8.14. */
typedef struct {
    uint8_t pdn_type;   /* gtp2_pdn_t */
    uint8_t prefix_len; /* IPv6 only */
    uint8_t addr4[4];
    uint8_t addr6[16];
} gtp2_paa_t;

/* Aggregate Maximum Bit Rate — §8.7. */
typedef struct {
    uint32_t ul_kbps;
    uint32_t dl_kbps;
} gtp2_ambr_t;

/* Decode returns 0 or a negative gtp2_err_t. */

API_EXPORT int gtp2_fteid_decode(const gtp2_ie_view_t* ie, gtp2_fteid_t* out);
API_EXPORT int gtp2_fteid_put(gtp2_wbuf_t* w, uint8_t instance,
                              const gtp2_fteid_t* f);

API_EXPORT int gtp2_bearer_qos_decode(const gtp2_ie_view_t* ie,
                                      gtp2_bearer_qos_t*    out);
API_EXPORT int gtp2_bearer_qos_put(gtp2_wbuf_t* w, uint8_t instance,
                                   const gtp2_bearer_qos_t* q);

API_EXPORT int gtp2_paa_decode(const gtp2_ie_view_t* ie, gtp2_paa_t* out);
API_EXPORT int gtp2_paa_put(gtp2_wbuf_t* w, uint8_t instance,
                            const gtp2_paa_t* p);

API_EXPORT int gtp2_ambr_decode(const gtp2_ie_view_t* ie, gtp2_ambr_t* out);
API_EXPORT int gtp2_ambr_put(gtp2_wbuf_t* w, uint8_t instance,
                             const gtp2_ambr_t* a);

#ifdef __cplusplus
}
#endif

#endif /* GTP2_IE_H */
