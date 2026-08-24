#include <string.h>

#include "sms_intl.h"
#include "sms_rp.h"

/* SMS relay layer — TS 24.011 §7.3 and §8.2.
 *
 * The RP layer is small enough that the whole codec fits here: two
 * header octets, up to two addresses, a cause and a user-data element.
 * What makes it fiddly is that the same field appears as an LV in one
 * message and a TLV in another — RP-User-Data is length-prefixed in
 * RP-DATA (§7.3.1, mandatory) but carries an IEI in RP-ACK and
 * RP-ERROR (§7.3.3/§7.3.4, optional). */

/* (type, from_ms) -> RP-MTI. */
static int mti_of(sms_rp_type_t type, bool from_ms)
{
    switch (type) {
    case SMS_RP_T_DATA:
        return from_ms ? SMS_RP_DATA_MS_TO_N : SMS_RP_DATA_N_TO_MS;
    case SMS_RP_T_ACK: return from_ms ? SMS_RP_ACK_MS_TO_N : SMS_RP_ACK_N_TO_MS;
    case SMS_RP_T_ERROR:
        return from_ms ? SMS_RP_ERROR_MS_TO_N : SMS_RP_ERROR_N_TO_MS;
    case SMS_RP_T_SMMA:
        /* There is no network-to-MS SMMA: memory-available is something
         * only the MS can report (§7.3.2). */
        return from_ms ? SMS_RP_SMMA_MS_TO_N : SMS_E_MTI;
    default: return SMS_E_INVAL;
    }
}

/* ---- addresses (§8.2.5.1/§8.2.5.2 over TS 24.008 §10.5.4.7) ---- */

int sms_rp_addr_decode(const uint8_t* b, size_t n, sms_rp_addr_t* out)
{
    if (b == NULL || out == NULL) return SMS_E_INVAL;
    if (n < 1) return SMS_E_SHORT;

    memset(out, 0, sizeof *out);
    size_t len = b[0];      /* octets after this one */
    if (len == 0) return 1; /* legitimately absent; present stays false */
    /* An impossible length is malformed whether or not the buffer
     * happens to be long enough, so it is checked first — the address
     * usually sits inside a larger PDU with bytes to spare. */
    if (len > SMS_RP_ADDR_MAX - 1) return SMS_E_LENGTH;
    if (n < 1 + len) return SMS_E_SHORT;

    out->present = true;
    out->ton     = (uint8_t)((b[1] >> 4) & 0x07);
    out->npi     = (uint8_t)(b[1] & 0x0F);

    /* No digit count here, unlike a TPDU address: the number ends at
     * the 0xF filler in the last high nibble, or at the last octet. */
    size_t k = 0;
    for (size_t i = 2; i <= len; i++) {
        char lo = sms_bcd_char(b[i] & 0x0F);
        char hi = sms_bcd_char((uint8_t)(b[i] >> 4));
        if (lo == '\0') break; /* filler in the low nibble ends it */
        if (k >= SMS_ADDR_MAX_DIGITS) return SMS_E_LENGTH;
        out->digits[k++] = lo;
        if (hi == '\0') break;
        if (k >= SMS_ADDR_MAX_DIGITS) return SMS_E_LENGTH;
        out->digits[k++] = hi;
    }
    out->digits[k] = '\0';
    return (int)(1 + len);
}

int sms_rp_addr_encode(uint8_t* b, size_t cap, const sms_rp_addr_t* a)
{
    if (b == NULL || a == NULL) return SMS_E_INVAL;
    if (!a->present) {
        if (cap < 1) return SMS_E_OVERFLOW;
        b[0] = 0;
        return 1;
    }
    if (a->ton > 7 || a->npi > 15) return SMS_E_INVAL;
    size_t ndig = strlen(a->digits);
    if (ndig > SMS_ADDR_MAX_DIGITS) return SMS_E_LENGTH;
    size_t vlen = (ndig + 1) / 2;
    if (cap < 2 + vlen) return SMS_E_OVERFLOW;

    b[0] = (uint8_t)(1 + vlen); /* the type octet counts towards it */
    /* Bit 7 of the type octet is the extension bit; 1 means "no more
     * type octets", which is always the case here. */
    b[1] = (uint8_t)(0x80 | (a->ton << 4) | a->npi);
    for (size_t i = 0; i < vlen; i++) {
        uint8_t lo = sms_bcd_nibble(a->digits[i * 2]);
        if (lo == 0xFF) return SMS_E_INVAL;
        uint8_t hi = 0x0F;
        if (i * 2 + 1 < ndig) {
            hi = sms_bcd_nibble(a->digits[i * 2 + 1]);
            if (hi == 0xFF) return SMS_E_INVAL;
        }
        b[2 + i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)(2 + vlen);
}

int sms_rp_addr_set(sms_rp_addr_t* a, const char* num, int ton)
{
    if (a == NULL) return SMS_E_INVAL;
    memset(a, 0, sizeof *a);
    if (num == NULL || *num == '\0') return SMS_OK; /* absent */
    if (*num == '+') {
        ton = SMS_TON_INTERNATIONAL;
        num++;
    }
    a->present = true;
    a->ton     = (uint8_t)ton;
    a->npi     = SMS_NPI_ISDN;
    size_t k   = 0;
    for (; num[k]; k++) {
        if (k >= SMS_ADDR_MAX_DIGITS) return SMS_E_LENGTH;
        if (sms_bcd_nibble(num[k]) == 0xFF) return SMS_E_INVAL;
        a->digits[k] = num[k];
    }
    a->digits[k] = '\0';
    return SMS_OK;
}

/* ---- codec ---- */

void sms_rp_init(sms_rp_pdu_t* p, sms_rp_type_t type, int dir)
{
    if (p == NULL) return;
    memset(p, 0, sizeof *p);
    bool from_ms = (dir & 1) == SMS_DIR_MS_TO_SC;
    int  mti     = mti_of(type, from_ms);
    p->type      = (uint8_t)type;
    p->from_ms   = from_ms;
    p->mti       = mti < 0 ? 0 : (uint8_t)mti;
}

int sms_rp_decode(const uint8_t* b, size_t n, int dir, sms_rp_pdu_t* out)
{
    if (b == NULL || out == NULL) return SMS_E_INVAL;
    if (n < 2) return SMS_E_SHORT;

    memset(out, 0, sizeof *out);
    uint8_t mti = (uint8_t)(b[0] & 0x07);
    out->mti    = mti;
    out->mr     = b[1];
    size_t off  = 2;

    bool from_ms;
    switch (mti) {
    case SMS_RP_DATA_MS_TO_N:
        out->type = SMS_RP_T_DATA;
        from_ms   = true;
        break;
    case SMS_RP_DATA_N_TO_MS:
        out->type = SMS_RP_T_DATA;
        from_ms   = false;
        break;
    case SMS_RP_ACK_MS_TO_N:
        out->type = SMS_RP_T_ACK;
        from_ms   = true;
        break;
    case SMS_RP_ACK_N_TO_MS:
        out->type = SMS_RP_T_ACK;
        from_ms   = false;
        break;
    case SMS_RP_ERROR_MS_TO_N:
        out->type = SMS_RP_T_ERROR;
        from_ms   = true;
        break;
    case SMS_RP_ERROR_N_TO_MS:
        out->type = SMS_RP_T_ERROR;
        from_ms   = false;
        break;
    case SMS_RP_SMMA_MS_TO_N:
        out->type = SMS_RP_T_SMMA;
        from_ms   = true;
        break;
    default: return SMS_E_MTI; /* 111 is not assigned */
    }
    out->from_ms = from_ms;

    /* The MTI already says which way the message travels, so a caller
     * that got the direction wrong is told rather than handed a PDU
     * that will be misread one layer up. */
    if (from_ms != ((dir & 1) == SMS_DIR_MS_TO_SC)) return SMS_E_MTI;

    int rc;
    switch (out->type) {
    case SMS_RP_T_DATA: {
        rc = sms_rp_addr_decode(b + off, n - off, &out->oa);
        if (rc < 0) return rc;
        off += (size_t)rc;
        rc = sms_rp_addr_decode(b + off, n - off, &out->da);
        if (rc < 0) return rc;
        off += (size_t)rc;
        /* RP-User-Data is an LV here and mandatory. */
        if (off >= n) return SMS_E_SHORT;
        size_t ulen = b[off++];
        if (n - off < ulen) return SMS_E_SHORT;
        out->has_ud = true;
        out->ud     = ulen ? b + off : NULL;
        out->ud_len = (uint8_t)ulen;
        off += ulen;
        break;
    }
    case SMS_RP_T_ERROR: {
        /* RP-Cause is an LV: one length octet, then the cause and an
         * optional diagnostic (§8.2.5.4). */
        if (off >= n) return SMS_E_SHORT;
        size_t clen = b[off++];
        if (clen < 1) return SMS_E_LENGTH;
        if (n - off < clen) return SMS_E_SHORT;
        out->cause = (uint8_t)(b[off] & 0x7F);
        if (clen >= 2) {
            out->has_cause_diag = true;
            out->cause_diag     = b[off + 1];
        }
        off += clen;
        goto optional_ud; /* the TLV user data, if any */
    }
    case SMS_RP_T_ACK:  goto optional_ud;
    case SMS_RP_T_SMMA: break;
    default:            return SMS_E_MTI;
    }
    return (int)off;

optional_ud:
    /* RP-User-Data as a TLV (IEI 0x41). Absent is normal: an RP-ACK
     * with no TPDU is what most handsets send. */
    if (off < n) {
        if (b[off] != SMS_RP_IEI_USER_DATA) return SMS_E_LENGTH;
        off++;
        if (off >= n) return SMS_E_SHORT;
        size_t ulen = b[off++];
        if (n - off < ulen) return SMS_E_SHORT;
        out->has_ud = true;
        out->ud     = ulen ? b + off : NULL;
        out->ud_len = (uint8_t)ulen;
        off += ulen;
    }
    return (int)off;
}

int sms_rp_encode(uint8_t* b, size_t cap, const sms_rp_pdu_t* p)
{
    if (b == NULL || p == NULL) return SMS_E_INVAL;
    if (p->type >= SMS_RP_T_MAX) return SMS_E_INVAL;
    if (p->has_ud && p->ud_len && p->ud == NULL) return SMS_E_INVAL;

    int mti = mti_of((sms_rp_type_t)p->type, p->from_ms);
    if (mti < 0) return mti;
    if (cap < 2) return SMS_E_OVERFLOW;

    b[0]       = (uint8_t)mti;
    b[1]       = p->mr;
    size_t off = 2;
    int    rc;

    switch (p->type) {
    case SMS_RP_T_DATA:
        rc = sms_rp_addr_encode(b + off, cap - off, &p->oa);
        if (rc < 0) return rc;
        off += (size_t)rc;
        rc = sms_rp_addr_encode(b + off, cap - off, &p->da);
        if (rc < 0) return rc;
        off += (size_t)rc;
        /* Mandatory LV, even when empty. */
        if (cap - off < 1u + p->ud_len) return SMS_E_OVERFLOW;
        b[off++] = p->ud_len;
        if (p->ud_len) {
            memcpy(b + off, p->ud, p->ud_len);
            off += p->ud_len;
        }
        break;

    case SMS_RP_T_ERROR: {
        uint8_t clen = p->has_cause_diag ? 2 : 1;
        if (cap - off < 1u + clen) return SMS_E_OVERFLOW;
        b[off++] = clen;
        b[off++] = (uint8_t)(p->cause & 0x7F);
        if (p->has_cause_diag) b[off++] = p->cause_diag;
        goto optional_ud;
    }
    case SMS_RP_T_ACK:  goto optional_ud;
    case SMS_RP_T_SMMA: break;
    default:            return SMS_E_INVAL;
    }
    return (int)off;

optional_ud:
    if (p->has_ud) {
        if (cap - off < 2u + p->ud_len) return SMS_E_OVERFLOW;
        b[off++] = SMS_RP_IEI_USER_DATA;
        b[off++] = p->ud_len;
        if (p->ud_len) {
            memcpy(b + off, p->ud, p->ud_len);
            off += p->ud_len;
        }
    }
    return (int)off;
}

/* ---- shorthands ---- */

int sms_rp_data(uint8_t* b, size_t cap, int dir, uint8_t mr, const char* sc,
                const uint8_t* tpdu, size_t tpdu_len)
{
    sms_rp_pdu_t p;
    int          rc;
    if (tpdu_len > 255) return SMS_E_LENGTH;
    sms_rp_init(&p, SMS_RP_T_DATA, dir);
    p.mr = mr;
    /* §7.3.1: towards the network the originator is implicit (the MS
     * itself) and the destination is the service centre; towards the MS
     * the originator is the SC and the destination is implicit. */
    if (p.from_ms) rc = sms_rp_addr_set(&p.da, sc, SMS_TON_INTERNATIONAL);
    else rc = sms_rp_addr_set(&p.oa, sc, SMS_TON_INTERNATIONAL);
    if (rc < 0) return rc;
    p.has_ud = true;
    p.ud     = tpdu;
    p.ud_len = (uint8_t)tpdu_len;
    return sms_rp_encode(b, cap, &p);
}

int sms_rp_ack(uint8_t* b, size_t cap, int dir, uint8_t mr, const uint8_t* tpdu,
               size_t tpdu_len)
{
    sms_rp_pdu_t p;
    if (tpdu_len > 255) return SMS_E_LENGTH;
    sms_rp_init(&p, SMS_RP_T_ACK, dir);
    p.mr = mr;
    if (tpdu != NULL && tpdu_len > 0) {
        p.has_ud = true;
        p.ud     = tpdu;
        p.ud_len = (uint8_t)tpdu_len;
    }
    return sms_rp_encode(b, cap, &p);
}

int sms_rp_error(uint8_t* b, size_t cap, int dir, uint8_t mr, uint8_t cause,
                 const uint8_t* tpdu, size_t tpdu_len)
{
    sms_rp_pdu_t p;
    if (tpdu_len > 255) return SMS_E_LENGTH;
    sms_rp_init(&p, SMS_RP_T_ERROR, dir);
    p.mr    = mr;
    p.cause = cause;
    if (tpdu != NULL && tpdu_len > 0) {
        p.has_ud = true;
        p.ud     = tpdu;
        p.ud_len = (uint8_t)tpdu_len;
    }
    return sms_rp_encode(b, cap, &p);
}

int sms_rp_smma(uint8_t* b, size_t cap, uint8_t mr)
{
    sms_rp_pdu_t p;
    sms_rp_init(&p, SMS_RP_T_SMMA, SMS_DIR_MS_TO_SC);
    p.mr = mr;
    return sms_rp_encode(b, cap, &p);
}

/* ---- names ---- */

const char* sms_rp_type_name(sms_rp_type_t t)
{
    static const char* n[SMS_RP_T_MAX] = { "RP-DATA", "RP-ACK", "RP-ERROR",
                                           "RP-SMMA" };
    /* Cast: the enum parameter makes the compare signed, and a script can
     * reach this through the Lua module with any integer. */
    return (unsigned)t < SMS_RP_T_MAX ? n[t] : "";
}

const char* sms_rp_mti_name(sms_rp_mti_t mti)
{
    switch (mti) {
    case SMS_RP_DATA_MS_TO_N:  return "RP-DATA (ms->n)";
    case SMS_RP_DATA_N_TO_MS:  return "RP-DATA (n->ms)";
    case SMS_RP_ACK_MS_TO_N:   return "RP-ACK (ms->n)";
    case SMS_RP_ACK_N_TO_MS:   return "RP-ACK (n->ms)";
    case SMS_RP_ERROR_MS_TO_N: return "RP-ERROR (ms->n)";
    case SMS_RP_ERROR_N_TO_MS: return "RP-ERROR (n->ms)";
    case SMS_RP_SMMA_MS_TO_N:  return "RP-SMMA (ms->n)";
    default:                   return "";
    }
}

const char* sms_rp_cause_name(uint8_t cause)
{
    switch (cause) {
    case SMS_RP_CAUSE_UNASSIGNED_NUMBER: return "unassigned number";
    case SMS_RP_CAUSE_OPERATOR_BARRING:  return "operator determined barring";
    case SMS_RP_CAUSE_CALL_BARRED:       return "call barred";
    case SMS_RP_CAUSE_RESERVED:          return "reserved";
    case SMS_RP_CAUSE_TRANSFER_REJECTED:
        return "short message transfer rejected";
    case SMS_RP_CAUSE_DEST_OUT_OF_ORDER:    return "destination out of order";
    case SMS_RP_CAUSE_UNIDENTIFIED_SUB:     return "unidentified subscriber";
    case SMS_RP_CAUSE_FACILITY_REJECTED:    return "facility rejected";
    case SMS_RP_CAUSE_UNKNOWN_SUB:          return "unknown subscriber";
    case SMS_RP_CAUSE_NETWORK_OUT_OF_ORDER: return "network out of order";
    case SMS_RP_CAUSE_TEMPORARY_FAILURE:    return "temporary failure";
    case SMS_RP_CAUSE_CONGESTION:           return "congestion";
    case SMS_RP_CAUSE_RESOURCES_UNAVAIL:
        return "resources unavailable, unspecified";
    case SMS_RP_CAUSE_FACILITY_NOT_SUBSCR:
        return "requested facility not subscribed";
    case SMS_RP_CAUSE_FACILITY_NOT_IMPL:
        return "requested facility not implemented";
    case SMS_RP_CAUSE_INVALID_REFERENCE:
        return "invalid short message transfer reference value";
    case SMS_RP_CAUSE_SEMANTIC_ERROR:    return "semantically incorrect message";
    case SMS_RP_CAUSE_INVALID_MANDATORY: return "invalid mandatory information";
    case SMS_RP_CAUSE_MSG_TYPE_UNKNOWN:
        return "message type non existent or not implemented";
    case SMS_RP_CAUSE_MSG_INCOMPATIBLE:
        return "message not compatible with short message protocol state";
    case SMS_RP_CAUSE_IE_UNKNOWN:
        return "information element non existent or not implemented";
    case SMS_RP_CAUSE_PROTOCOL_ERROR: return "protocol error, unspecified";
    case SMS_RP_CAUSE_INTERWORKING:   return "interworking, unspecified";
    default:                          return "unassigned (treat as temporary failure)";
    }
}

uint8_t sms_rp_cause_fold(uint8_t cause)
{
    switch (cause) {
    case SMS_RP_CAUSE_UNASSIGNED_NUMBER:
    case SMS_RP_CAUSE_OPERATOR_BARRING:
    case SMS_RP_CAUSE_CALL_BARRED:
    case SMS_RP_CAUSE_RESERVED:
    case SMS_RP_CAUSE_TRANSFER_REJECTED:
    case SMS_RP_CAUSE_DEST_OUT_OF_ORDER:
    case SMS_RP_CAUSE_UNIDENTIFIED_SUB:
    case SMS_RP_CAUSE_FACILITY_REJECTED:
    case SMS_RP_CAUSE_UNKNOWN_SUB:
    case SMS_RP_CAUSE_NETWORK_OUT_OF_ORDER:
    case SMS_RP_CAUSE_TEMPORARY_FAILURE:
    case SMS_RP_CAUSE_CONGESTION:
    case SMS_RP_CAUSE_RESOURCES_UNAVAIL:
    case SMS_RP_CAUSE_FACILITY_NOT_SUBSCR:
    case SMS_RP_CAUSE_FACILITY_NOT_IMPL:
    case SMS_RP_CAUSE_INVALID_REFERENCE:
    case SMS_RP_CAUSE_SEMANTIC_ERROR:
    case SMS_RP_CAUSE_INVALID_MANDATORY:
    case SMS_RP_CAUSE_MSG_TYPE_UNKNOWN:
    case SMS_RP_CAUSE_MSG_INCOMPATIBLE:
    case SMS_RP_CAUSE_IE_UNKNOWN:
    case SMS_RP_CAUSE_PROTOCOL_ERROR:
    case SMS_RP_CAUSE_INTERWORKING:         return cause;
    default:                                return SMS_RP_CAUSE_TEMPORARY_FAILURE;
    }
}
