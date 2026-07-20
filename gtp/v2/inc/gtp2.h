#ifndef GTP2_H
#define GTP2_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "tlv.h"

#ifdef __cplusplus
extern "C" {
#endif

/* GTPv2-C codec — 3GPP TS 29.274.
 *
 * The IE layer binds the generic zero-copy TLV codec (task/inc/tlv.h)
 * to the GTPv2-C wire profile; the message header codec is local.
 *
 * Decode is zero-copy: the iterator yields (type, instance, length, value)
 * views over the caller's buffer. Grouped IEs are walked by nesting a
 * second iterator over the parent IE's value range.
 *
 * Encode writes directly into a caller-supplied buffer; no allocation.
 * Grouped IEs use begin/end pairs that backfill the length field.
 *
 * Wire layout reference:
 *   header (8 or 12 B): flags | type | length(2) | [TEID(4)] | seq(3) |
 * spare/MP IE     (4+N B)    : type | length(2) | spare/instance |
 * value(length)
 */

enum {
    GTP2_VERSION       = 2,
    GTP2_HDR_FIXED_LEN = 8, /* no TEID */
    GTP2_HDR_WITH_TEID = 12,
    GTP2_IE_HDR_LEN    = 4
};

/* Message types — TS 29.274 §6.1, Table 6.1-1. */
typedef enum {
    GTP2_MT_ECHO_REQUEST          = 1,
    GTP2_MT_ECHO_RESPONSE         = 2,
    GTP2_MT_VERSION_NOT_SUPPORTED = 3,

    GTP2_MT_CREATE_SESSION_REQUEST        = 32,
    GTP2_MT_CREATE_SESSION_RESPONSE       = 33,
    GTP2_MT_MODIFY_BEARER_REQUEST         = 34,
    GTP2_MT_MODIFY_BEARER_RESPONSE        = 35,
    GTP2_MT_DELETE_SESSION_REQUEST        = 36,
    GTP2_MT_DELETE_SESSION_RESPONSE       = 37,
    GTP2_MT_CHANGE_NOTIFICATION_REQUEST   = 38,
    GTP2_MT_CHANGE_NOTIFICATION_RESPONSE  = 39,
    GTP2_MT_REMOTE_UE_REPORT_NOTIFICATION = 40,
    GTP2_MT_REMOTE_UE_REPORT_ACK          = 41,

    GTP2_MT_MODIFY_BEARER_COMMAND      = 64,
    GTP2_MT_MODIFY_BEARER_FAILURE      = 65,
    GTP2_MT_DELETE_BEARER_COMMAND      = 66,
    GTP2_MT_DELETE_BEARER_FAILURE      = 67,
    GTP2_MT_BEARER_RESOURCE_COMMAND    = 68,
    GTP2_MT_BEARER_RESOURCE_FAILURE    = 69,
    GTP2_MT_DL_DATA_NOTIF_FAILURE      = 70,
    GTP2_MT_TRACE_SESSION_ACTIVATION   = 71,
    GTP2_MT_TRACE_SESSION_DEACTIVATION = 72,
    GTP2_MT_STOP_PAGING_INDICATION     = 73,

    GTP2_MT_CREATE_BEARER_REQUEST        = 95,
    GTP2_MT_CREATE_BEARER_RESPONSE       = 96,
    GTP2_MT_UPDATE_BEARER_REQUEST        = 97,
    GTP2_MT_UPDATE_BEARER_RESPONSE       = 98,
    GTP2_MT_DELETE_BEARER_REQUEST        = 99,
    GTP2_MT_DELETE_BEARER_RESPONSE       = 100,
    GTP2_MT_DELETE_PDN_CONN_SET_REQUEST  = 101,
    GTP2_MT_DELETE_PDN_CONN_SET_RESPONSE = 102,
    GTP2_MT_PGW_DL_TRIG_NOTIF            = 103,
    GTP2_MT_PGW_DL_TRIG_ACK              = 104,

    GTP2_MT_IDENTIFICATION_REQUEST          = 128,
    GTP2_MT_IDENTIFICATION_RESPONSE         = 129,
    GTP2_MT_CONTEXT_REQUEST                 = 130,
    GTP2_MT_CONTEXT_RESPONSE                = 131,
    GTP2_MT_CONTEXT_ACK                     = 132,
    GTP2_MT_FORWARD_RELOC_REQUEST           = 133,
    GTP2_MT_FORWARD_RELOC_RESPONSE          = 134,
    GTP2_MT_FORWARD_RELOC_COMPLETE_NOTIF    = 135,
    GTP2_MT_FORWARD_RELOC_COMPLETE_ACK      = 136,
    GTP2_MT_FORWARD_ACCESS_CTX_NOTIF        = 137,
    GTP2_MT_FORWARD_ACCESS_CTX_ACK          = 138,
    GTP2_MT_RELOC_CANCEL_REQUEST            = 139,
    GTP2_MT_RELOC_CANCEL_RESPONSE           = 140,
    GTP2_MT_CONFIG_TRANSFER_TUNNEL          = 141,
    GTP2_MT_DETACH_NOTIFICATION             = 149,
    GTP2_MT_DETACH_ACK                      = 150,
    GTP2_MT_CS_PAGING_INDICATION            = 151,
    GTP2_MT_RAN_INFO_RELAY                  = 152,
    GTP2_MT_ALERT_MME_NOTIF                 = 153,
    GTP2_MT_ALERT_MME_ACK                   = 154,
    GTP2_MT_UE_ACTIVITY_NOTIF               = 155,
    GTP2_MT_UE_ACTIVITY_ACK                 = 156,
    GTP2_MT_ISR_STATUS                      = 157,
    GTP2_MT_UE_REGISTRATION_QUERY_REQUEST   = 158,
    GTP2_MT_UE_REGISTRATION_QUERY_RESPONSE  = 159,
    GTP2_MT_CREATE_FWD_TUNNEL_REQUEST       = 160,
    GTP2_MT_CREATE_FWD_TUNNEL_RESPONSE      = 161,
    GTP2_MT_SUSPEND_NOTIFICATION            = 162,
    GTP2_MT_SUSPEND_ACK                     = 163,
    GTP2_MT_RESUME_NOTIFICATION             = 164,
    GTP2_MT_RESUME_ACK                      = 165,
    GTP2_MT_CREATE_INDIRECT_FWD_REQUEST     = 166,
    GTP2_MT_CREATE_INDIRECT_FWD_RESPONSE    = 167,
    GTP2_MT_DELETE_INDIRECT_FWD_REQUEST     = 168,
    GTP2_MT_DELETE_INDIRECT_FWD_RESPONSE    = 169,
    GTP2_MT_RELEASE_ACCESS_BEARERS_REQUEST  = 170,
    GTP2_MT_RELEASE_ACCESS_BEARERS_RESPONSE = 171,
    GTP2_MT_DL_DATA_NOTIFICATION            = 176,
    GTP2_MT_DL_DATA_NOTIFICATION_ACK        = 177,
    GTP2_MT_PGW_RESTART_NOTIFICATION        = 179,
    GTP2_MT_PGW_RESTART_NOTIFICATION_ACK    = 180,
    GTP2_MT_UPDATE_PDN_CONN_SET_REQUEST     = 200,
    GTP2_MT_UPDATE_PDN_CONN_SET_RESPONSE    = 201,
    GTP2_MT_MODIFY_ACCESS_BEARERS_REQUEST   = 211,
    GTP2_MT_MODIFY_ACCESS_BEARERS_RESPONSE  = 212,
    GTP2_MT_MBMS_SESSION_START_REQUEST      = 231,
    GTP2_MT_MBMS_SESSION_START_RESPONSE     = 232,
    GTP2_MT_MBMS_SESSION_UPDATE_REQUEST     = 233,
    GTP2_MT_MBMS_SESSION_UPDATE_RESPONSE    = 234,
    GTP2_MT_MBMS_SESSION_STOP_REQUEST       = 235,
    GTP2_MT_MBMS_SESSION_STOP_RESPONSE      = 236
} gtp2_mt_t;

/* IE types — TS 29.274 §8.1, Table 8.1-1. */
typedef enum {
    GTP2_IE_IMSI                               = 1,
    GTP2_IE_CAUSE                              = 2,
    GTP2_IE_RECOVERY                           = 3,
    GTP2_IE_STN_SR                             = 51,
    GTP2_IE_APN                                = 71,
    GTP2_IE_AMBR                               = 72,
    GTP2_IE_EBI                                = 73,
    GTP2_IE_IP_ADDRESS                         = 74,
    GTP2_IE_MEI                                = 75,
    GTP2_IE_MSISDN                             = 76,
    GTP2_IE_INDICATION                         = 77,
    GTP2_IE_PCO                                = 78,
    GTP2_IE_PAA                                = 79,
    GTP2_IE_BEARER_QOS                         = 80,
    GTP2_IE_FLOW_QOS                           = 81,
    GTP2_IE_RAT_TYPE                           = 82,
    GTP2_IE_SERVING_NETWORK                    = 83,
    GTP2_IE_BEARER_TFT                         = 84,
    GTP2_IE_TAD                                = 85,
    GTP2_IE_ULI                                = 86,
    GTP2_IE_FTEID                              = 87,
    GTP2_IE_TMSI                               = 88,
    GTP2_IE_GLOBAL_CN_ID                       = 89,
    GTP2_IE_S103PDF                            = 90,
    GTP2_IE_S1UDF                              = 91,
    GTP2_IE_DELAY_VALUE                        = 92,
    GTP2_IE_BEARER_CONTEXT                     = 93, /* grouped */
    GTP2_IE_CHARGING_ID                        = 94,
    GTP2_IE_CHARGING_CHARACTERISTICS           = 95,
    GTP2_IE_TRACE_INFORMATION                  = 96,
    GTP2_IE_BEARER_FLAGS                       = 97,
    GTP2_IE_PDN_TYPE                           = 99,
    GTP2_IE_PTI                                = 100,
    GTP2_IE_MM_CONTEXT_GSM_KEY_TRIPLETS        = 103,
    GTP2_IE_MM_CONTEXT_UMTS_CIPHER_QUINTUPLETS = 104,
    GTP2_IE_MM_CONTEXT_GSM_CIPHER_QUINTUPLETS  = 105,
    GTP2_IE_MM_CONTEXT_UMTS_QUINTUPLETS        = 106,
    GTP2_IE_MM_CONTEXT_EPS_SECURITY            = 107,
    GTP2_IE_MM_CONTEXT_UMTS_QUAD_QUINTUPLETS   = 108,
    GTP2_IE_PDN_CONNECTION                     = 109, /* grouped */
    GTP2_IE_PDU_NUMBERS                        = 110,
    GTP2_IE_P_TMSI                             = 111,
    GTP2_IE_P_TMSI_SIGNATURE                   = 112,
    GTP2_IE_HOP_COUNTER                        = 113,
    GTP2_IE_UE_TIME_ZONE                       = 114,
    GTP2_IE_TRACE_REFERENCE                    = 115,
    GTP2_IE_COMPLETE_REQUEST_MESSAGE           = 116,
    GTP2_IE_GUTI                               = 117,
    GTP2_IE_F_CONTAINER                        = 118,
    GTP2_IE_F_CAUSE                            = 119,
    GTP2_IE_PLMN_ID                            = 120,
    GTP2_IE_TARGET_IDENTIFICATION              = 121,
    GTP2_IE_PACKET_FLOW_ID                     = 123,
    GTP2_IE_RAB_CONTEXT                        = 124,
    GTP2_IE_SRC_RNC_PDCP_CTX_INFO              = 125,
    GTP2_IE_PORT_NUMBER                        = 126,
    GTP2_IE_APN_RESTRICTION                    = 127,
    GTP2_IE_SELECTION_MODE                     = 128,
    GTP2_IE_SOURCE_IDENTIFICATION              = 129,
    GTP2_IE_CHANGE_REPORTING_ACTION            = 131,
    GTP2_IE_FQ_CSID                            = 132,
    GTP2_IE_CHANNEL_NEEDED                     = 133,
    GTP2_IE_EMLPP_PRIORITY                     = 134,
    GTP2_IE_NODE_TYPE                          = 135,
    GTP2_IE_FQDN                               = 136,
    GTP2_IE_TI                                 = 137,
    GTP2_IE_MBMS_SESSION_DURATION              = 138,
    GTP2_IE_MBMS_SERVICE_AREA                  = 139,
    GTP2_IE_MBMS_SESSION_IDENTIFIER            = 140,
    GTP2_IE_MBMS_FLOW_IDENTIFIER               = 141,
    GTP2_IE_MBMS_IP_MULTICAST_DIST             = 142,
    GTP2_IE_MBMS_DIST_ACK                      = 143,
    GTP2_IE_RFSP_INDEX                         = 144,
    GTP2_IE_UCI                                = 145,
    GTP2_IE_CSG_INFO_REPORTING_ACTION          = 146,
    GTP2_IE_CSG_ID                             = 147,
    GTP2_IE_CMI                                = 148,
    GTP2_IE_SERVICE_INDICATOR                  = 149,
    GTP2_IE_DETACH_TYPE                        = 150,
    GTP2_IE_LDN                                = 151,
    GTP2_IE_NODE_FEATURES                      = 152,
    GTP2_IE_MBMS_TIME_TO_DATA                  = 153,
    GTP2_IE_THROTTLING                         = 154,
    GTP2_IE_ARP                                = 155,
    GTP2_IE_EPC_TIMER                          = 156,
    GTP2_IE_SIGNALLING_PRIORITY_INDICATION     = 157,
    GTP2_IE_TMGI                               = 158,
    GTP2_IE_ADD_MM_CONTEXT_SRVCC               = 159,
    GTP2_IE_ADD_FLAGS_SRVCC                    = 160,
    GTP2_IE_MDT_CONFIGURATION                  = 162,
    GTP2_IE_APCO                               = 163,
    GTP2_IE_ABS_TIME_MBMS_DATA_TRANSFER        = 164,
    GTP2_IE_HENB_INFO_REPORTING                = 165,
    GTP2_IE_IP4CP                              = 166,
    GTP2_IE_CHANGE_TO_REPORT_FLAGS             = 167,
    GTP2_IE_ACTION_INDICATION                  = 168,
    GTP2_IE_TWAN_IDENTIFIER                    = 169,
    GTP2_IE_ULI_TIMESTAMP                      = 170,
    GTP2_IE_MBMS_FLAGS                         = 171,
    GTP2_IE_RAN_NAS_CAUSE                      = 172,
    GTP2_IE_CN_OPERATOR_SELECTION_ENTITY       = 173,
    GTP2_IE_TWAN_MODE_INDICATION               = 174,
    GTP2_IE_NODE_NUMBER                        = 175,
    GTP2_IE_NODE_IDENTIFIER                    = 176,
    GTP2_IE_PRA_ACTION                         = 177,
    GTP2_IE_PRA_INFORMATION                    = 178,
    GTP2_IE_TWAN_ID_TIMESTAMP                  = 179,
    GTP2_IE_OVERLOAD_CONTROL_INFORMATION       = 180, /* grouped */
    GTP2_IE_LOAD_CONTROL_INFORMATION           = 181, /* grouped */
    GTP2_IE_METRIC                             = 182,
    GTP2_IE_SEQUENCE_NUMBER                    = 183,
    GTP2_IE_APN_AND_RELATIVE_CAPACITY          = 184,
    GTP2_IE_WLAN_OFFLOADABILITY_INDICATION     = 185,
    GTP2_IE_PAGING_AND_SERVICE_INFO            = 186,
    GTP2_IE_INTEGER_NUMBER                     = 187,
    GTP2_IE_MILLISECOND_TIME_STAMP             = 188,
    GTP2_IE_MONITORING_EVENT_INFO              = 189,
    GTP2_IE_ECGI_LIST                          = 190,
    GTP2_IE_REMOTE_UE_CONTEXT                  = 191, /* grouped */
    GTP2_IE_REMOTE_USER_ID                     = 192,
    GTP2_IE_REMOTE_UE_IP_INFO                  = 193,
    GTP2_IE_CIOT_OPT_SUPPORT_INDICATION        = 194,
    GTP2_IE_SCEF_PDN_CONNECTION                = 195,
    GTP2_IE_HEADER_COMPRESSION_CONFIG          = 196,
    GTP2_IE_EPCO                               = 197,
    GTP2_IE_SERVING_PLMN_RATE_CONTROL          = 198,
    GTP2_IE_COUNTER                            = 199,
    GTP2_IE_MAPPED_UE_USAGE_TYPE               = 200,
    GTP2_IE_SECONDARY_RAT_USAGE_DATA           = 201,
    GTP2_IE_UP_FUNC_SELECTION_INDICATION       = 202,
    GTP2_IE_MAXIMUM_PACKET_LOSS_RATE           = 203,
    GTP2_IE_APN_RATE_CONTROL_STATUS            = 204,
    GTP2_IE_EXTENDED_TRACE_INFO                = 205,
    GTP2_IE_MONITORING_EVENT_EXT_INFO          = 206,
    GTP2_IE_ADDITIONAL_RRM_POLICY_INDEX        = 207,
    GTP2_IE_PRIVATE_EXTENSION                  = 255
} gtp2_ie_t;

typedef enum {
    GTP2_OK         = 0,
    GTP2_E_SHORT    = -1, /* input buffer truncated */
    GTP2_E_VERSION  = -2, /* not GTPv2 */
    GTP2_E_LENGTH   = -3, /* header length field inconsistent with buffer */
    GTP2_E_OVERFLOW = -4, /* write buffer too small */
    GTP2_E_INVAL    = -5, /* invalid argument */
    GTP2_E_MISSING  = -6  /* mandatory IE absent */
} gtp2_err_t;

/* Decoded header in host byte order. */
typedef struct {
    uint8_t  version; /* must be 2 */
    bool     piggyback;
    bool     has_teid;
    bool     has_mp;
    uint8_t  message_type;
    uint16_t length;   /* bytes following octet 4 (incl. TEID + seq + spare) */
    uint32_t teid;     /* 0 when !has_teid */
    uint32_t sequence; /* 24-bit */
    uint8_t  priority; /* 0 when !has_mp */
} gtp2_hdr_t;

/* IE view — points into the caller's input buffer. No ownership, no copy. */
typedef struct {
    uint8_t        type;
    uint8_t        instance; /* 0..15 */
    uint16_t       len;      /* value length */
    const uint8_t* value;
} gtp2_ie_view_t;

/* Iterator and write buffer are the generic TLV codec's types, bound to
 * the GTPv2-C IE wire profile by the functions below. Write-buffer
 * overflow is sticky: once set, all subsequent ops fail. */
typedef tlv_iter_t gtp2_ie_iter_t;
typedef tlv_wbuf_t gtp2_wbuf_t;

/* ---- Header ---- */

/* Decode header. Returns header byte count (8 or 12) on success,
 * or a negative gtp2_err_t. The caller's buffer must remain valid
 * while gtp2_ie_view_t values referencing it are in use. */
API_EXPORT int gtp2_hdr_decode(const uint8_t* buf, size_t len, gtp2_hdr_t* out);

/* Encode header. Returns header byte count on success, negative on error.
 * The Length field is taken from hdr->length; use gtp2_hdr_finalize() if
 * you would rather backfill it after writing IEs. */
API_EXPORT int gtp2_hdr_encode(uint8_t* buf, size_t cap, const gtp2_hdr_t* hdr);

/* ---- IE walk (zero-copy decode) ---- */

API_EXPORT void gtp2_ie_iter_init(gtp2_ie_iter_t* it, const uint8_t* payload,
                                  size_t len);

/* Returns true with *out filled; false at end-of-stream or on truncation. */
API_EXPORT bool gtp2_ie_iter_next(gtp2_ie_iter_t* it, gtp2_ie_view_t* out);

/* Convenience: initialize an iterator over a grouped IE's children. */
API_EXPORT void gtp2_ie_iter_grouped(gtp2_ie_iter_t* it,
                                     const gtp2_ie_view_t* grouped);

/* ---- IE write (encode into caller's buffer) ---- */

API_EXPORT void gtp2_wbuf_init(gtp2_wbuf_t* w, uint8_t* buf, size_t cap);

/* Returns 0 on success, negative gtp2_err_t on error. */
API_EXPORT int gtp2_ie_put(gtp2_wbuf_t* w, uint8_t type, uint8_t instance,
                           const void* val, uint16_t vlen);

/* Inline integer shortcuts (host -> network byte order). */
API_EXPORT int gtp2_ie_put_u8(gtp2_wbuf_t* w, uint8_t type, uint8_t instance,
                              uint8_t v);
API_EXPORT int gtp2_ie_put_u16(gtp2_wbuf_t* w, uint8_t type, uint8_t instance,
                               uint16_t v);
API_EXPORT int gtp2_ie_put_u32(gtp2_wbuf_t* w, uint8_t type, uint8_t instance,
                               uint32_t v);

/* Grouped IE: write begin, then any child IEs, then end. The end call
 * backfills the parent's length. Begin returns a handle (offset) or a
 * negative error; pass it back to end. */
API_EXPORT int gtp2_ie_begin(gtp2_wbuf_t* w, uint8_t type, uint8_t instance);
API_EXPORT int gtp2_ie_end(gtp2_wbuf_t* w, int handle);

/* Backfill the Length field of a header written at hdr_off. Call once
 * all IEs are written. */
API_EXPORT int gtp2_hdr_finalize(gtp2_wbuf_t* w, size_t hdr_off);

#ifdef __cplusplus
}
#endif

#endif /* GTP2_H */
