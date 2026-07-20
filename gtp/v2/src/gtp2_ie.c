#include "gtp2_ie.h"
#include "endian.h"

#include <string.h>

int gtp2_fteid_decode(const gtp2_ie_view_t* ie, gtp2_fteid_t* out)
{
    if (TASK_UNLIKELY(!ie || !out)) return GTP2_E_INVAL;
    if (TASK_UNLIKELY(ie->len < 5)) return GTP2_E_SHORT;

    const uint8_t* v = ie->value;
    out->v4          = (v[0] & 0x80) != 0;
    out->v6          = (v[0] & 0x40) != 0;
    out->if_type     = (uint8_t)(v[0] & 0x3F);
    out->teid        = be32_load(v + 1);

    memset(out->addr4, 0, sizeof out->addr4);
    memset(out->addr6, 0, sizeof out->addr6);

    uint16_t n = 5;
    if (out->v4) {
        if (TASK_UNLIKELY(ie->len < n + 4)) return GTP2_E_SHORT;
        memcpy(out->addr4, v + n, 4);
        n += 4;
    }
    if (out->v6) {
        if (TASK_UNLIKELY(ie->len < n + 16)) return GTP2_E_SHORT;
        memcpy(out->addr6, v + n, 16);
    }
    return GTP2_OK;
}

int gtp2_fteid_put(gtp2_wbuf_t* w, uint8_t instance, const gtp2_fteid_t* f)
{
    if (TASK_UNLIKELY(!w || !f)) return GTP2_E_INVAL;
    if (TASK_UNLIKELY(!f->v4 && !f->v6)) return GTP2_E_INVAL;

    uint8_t v[25];
    v[0] = (uint8_t)((f->v4 ? 0x80 : 0) | (f->v6 ? 0x40 : 0) |
                     (f->if_type & 0x3F));
    be32_store(v + 1, f->teid);

    uint16_t n = 5;
    if (f->v4) {
        memcpy(v + n, f->addr4, 4);
        n += 4;
    }
    if (f->v6) {
        memcpy(v + n, f->addr6, 16);
        n += 16;
    }
    return gtp2_ie_put(w, GTP2_IE_FTEID, instance, v, n);
}

int gtp2_bearer_qos_decode(const gtp2_ie_view_t* ie, gtp2_bearer_qos_t* out)
{
    if (TASK_UNLIKELY(!ie || !out)) return GTP2_E_INVAL;
    if (TASK_UNLIKELY(ie->len < 22)) return GTP2_E_SHORT;

    const uint8_t* v = ie->value;
    out->pci         = (uint8_t)((v[0] >> 6) & 0x01);
    out->pl          = (uint8_t)((v[0] >> 2) & 0x0F);
    out->pvi         = (uint8_t)(v[0] & 0x01);
    out->qci         = v[1];
    out->mbr_ul      = be40_load(v + 2);
    out->mbr_dl      = be40_load(v + 7);
    out->gbr_ul      = be40_load(v + 12);
    out->gbr_dl      = be40_load(v + 17);
    return GTP2_OK;
}

int gtp2_bearer_qos_put(gtp2_wbuf_t* w, uint8_t instance,
                        const gtp2_bearer_qos_t* q)
{
    if (TASK_UNLIKELY(!w || !q)) return GTP2_E_INVAL;

    uint8_t v[22];
    v[0] = (uint8_t)(((q->pci & 0x01) << 6) | ((q->pl & 0x0F) << 2) |
                     (q->pvi & 0x01));
    v[1] = q->qci;
    be40_store(v + 2, q->mbr_ul);
    be40_store(v + 7, q->mbr_dl);
    be40_store(v + 12, q->gbr_ul);
    be40_store(v + 17, q->gbr_dl);
    return gtp2_ie_put(w, GTP2_IE_BEARER_QOS, instance, v, sizeof v);
}

int gtp2_paa_decode(const gtp2_ie_view_t* ie, gtp2_paa_t* out)
{
    if (TASK_UNLIKELY(!ie || !out)) return GTP2_E_INVAL;
    if (TASK_UNLIKELY(ie->len < 1)) return GTP2_E_SHORT;

    const uint8_t* v = ie->value;
    memset(out, 0, sizeof *out);
    out->pdn_type = (uint8_t)(v[0] & 0x07);

    switch (out->pdn_type) {
    case GTP2_PDN_IPV4:
        if (TASK_UNLIKELY(ie->len < 5)) return GTP2_E_SHORT;
        memcpy(out->addr4, v + 1, 4);
        return GTP2_OK;
    case GTP2_PDN_IPV6:
        if (TASK_UNLIKELY(ie->len < 18)) return GTP2_E_SHORT;
        out->prefix_len = v[1];
        memcpy(out->addr6, v + 2, 16);
        return GTP2_OK;
    case GTP2_PDN_IPV4V6:
        if (TASK_UNLIKELY(ie->len < 22)) return GTP2_E_SHORT;
        out->prefix_len = v[1];
        memcpy(out->addr6, v + 2, 16);
        memcpy(out->addr4, v + 18, 4);
        return GTP2_OK;
    default: return GTP2_E_INVAL;
    }
}

int gtp2_paa_put(gtp2_wbuf_t* w, uint8_t instance, const gtp2_paa_t* p)
{
    if (TASK_UNLIKELY(!w || !p)) return GTP2_E_INVAL;

    uint8_t  v[22];
    uint16_t n;
    v[0] = (uint8_t)(p->pdn_type & 0x07);

    switch (p->pdn_type) {
    case GTP2_PDN_IPV4:
        memcpy(v + 1, p->addr4, 4);
        n = 5;
        break;
    case GTP2_PDN_IPV6:
        v[1] = p->prefix_len;
        memcpy(v + 2, p->addr6, 16);
        n = 18;
        break;
    case GTP2_PDN_IPV4V6:
        v[1] = p->prefix_len;
        memcpy(v + 2, p->addr6, 16);
        memcpy(v + 18, p->addr4, 4);
        n = 22;
        break;
    default: return GTP2_E_INVAL;
    }
    return gtp2_ie_put(w, GTP2_IE_PAA, instance, v, n);
}

int gtp2_ambr_decode(const gtp2_ie_view_t* ie, gtp2_ambr_t* out)
{
    if (TASK_UNLIKELY(!ie || !out)) return GTP2_E_INVAL;
    if (TASK_UNLIKELY(ie->len < 8)) return GTP2_E_SHORT;
    out->ul_kbps = be32_load(ie->value);
    out->dl_kbps = be32_load(ie->value + 4);
    return GTP2_OK;
}

int gtp2_ambr_put(gtp2_wbuf_t* w, uint8_t instance, const gtp2_ambr_t* a)
{
    if (TASK_UNLIKELY(!w || !a)) return GTP2_E_INVAL;
    uint8_t v[8];
    be32_store(v, a->ul_kbps);
    be32_store(v + 4, a->dl_kbps);
    return gtp2_ie_put(w, GTP2_IE_AMBR, instance, v, sizeof v);
}
