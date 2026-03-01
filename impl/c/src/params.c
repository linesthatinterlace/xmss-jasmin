/**
 * params.c - XMSS parameter set derivation
 *
 * RFC 8391 §5.3: all 12 XMSS parameter sets.
 * Formulae from RFC 8391 §3.1 and §5.3.
 */
#include <string.h>
#include <stddef.h>

#include "../include/xmss/params.h"
#include "../include/xmss/xmss.h"

/* ceil(a/b) for positive integers */
static uint32_t ceil_div(uint32_t a, uint32_t b)
{
    return (a + b - 1) / b;
}

/* floor(log2(x)) for x > 0 */
static uint32_t floor_log2(uint32_t x)
{
    uint32_t r = 0;
    while (x > 1) { x >>= 1; r++; }
    return r;
}

/*
 * Derive all computed fields given the primitive parameters.
 * Caller must set: oid, func, n, w, h, d before calling.
 * Returns 0 on success.
 */
static int derive_params(xmss_params *p)
{
    /* log2(w) */
    if (p->w == 4)        { p->log2_w = 2; }
    else if (p->w == 16)  { p->log2_w = 4; }
    else { return -1; }

    /* RFC 8391 §3.1.1 */
    p->len1 = ceil_div(8 * p->n, p->log2_w);
    p->len2 = floor_log2(p->len1 * (p->w - 1)) / p->log2_w + 1;
    p->len  = p->len1 + p->len2;

    if (p->len > XMSS_MAX_WOTS_LEN) { return -1; }

    /* per-tree height */
    p->tree_height = p->h / p->d;

    if (p->tree_height > XMSS_MAX_H) { return -1; }

    /* pad_len: n bytes for all standard parameter sets */
    p->pad_len = p->n;

    /* idx_bytes: 4 for XMSS (d=1), ceil(h/8) for XMSS-MT */
    if (p->d == 1) {
        p->idx_bytes = 4;
    } else {
        p->idx_bytes = ceil_div(p->h, 8);
    }

    /* idx_max = 2^h - 1 */
    p->idx_max = ((uint64_t)1 << p->h) - 1;

    /*
     * Signature size:
     * XMSS:    idx_bytes + n + len*n + h*n
     * XMSS-MT: idx_bytes + n + d * (len + tree_height) * n
     *        = idx_bytes + n + d*len*n + d*tree_height*n
     *        = idx_bytes + n + d*len*n + h*n
     */
    p->sig_bytes = p->idx_bytes + p->n + p->d * p->len * p->n + p->h * p->n;

    /*
     * pk_bytes = 4 (OID) + n (root) + n (SEED)
     * Same for XMSS and XMSS-MT.
     */
    p->pk_bytes = 4 + 2 * p->n;

    /*
     * sk_bytes = 4 (OID) + idx_bytes + n (SK_SEED) + n (SK_PRF)
     *          + n (root) + n (SEED)
     * Same structure for XMSS and XMSS-MT.
     */
    p->sk_bytes = 4 + p->idx_bytes + 4 * p->n;

    return 0;
}

/*
 * Static OID tables.  XMSS and XMSS-MT have separate OID namespaces per RFC 8391.
 * Fields: oid, name, func, n, w, h, d.  Remaining fields derived by derive_params().
 */
typedef struct {
    uint32_t oid;
    const char *name;
    uint8_t  func;
    uint32_t n;
    uint32_t w;
    uint32_t h;
    uint32_t d;
} oid_entry_t;

/* RFC 8391 Appendix A — 12 XMSS parameter sets (d=1) */
static const oid_entry_t xmss_oid_table[] = {
    /* SHA-2 based */
    { OID_XMSS_SHA2_10_256,  "XMSS-SHA2_10_256",  XMSS_FUNC_SHA2,    32, 16, 10, 1 },
    { OID_XMSS_SHA2_16_256,  "XMSS-SHA2_16_256",  XMSS_FUNC_SHA2,    32, 16, 16, 1 },
    { OID_XMSS_SHA2_20_256,  "XMSS-SHA2_20_256",  XMSS_FUNC_SHA2,    32, 16, 20, 1 },
    { OID_XMSS_SHA2_10_512,  "XMSS-SHA2_10_512",  XMSS_FUNC_SHA2,    64, 16, 10, 1 },
    { OID_XMSS_SHA2_16_512,  "XMSS-SHA2_16_512",  XMSS_FUNC_SHA2,    64, 16, 16, 1 },
    { OID_XMSS_SHA2_20_512,  "XMSS-SHA2_20_512",  XMSS_FUNC_SHA2,    64, 16, 20, 1 },
    /* SHAKE based */
    { OID_XMSS_SHAKE_10_256, "XMSS-SHAKE_10_256", XMSS_FUNC_SHAKE128, 32, 16, 10, 1 },
    { OID_XMSS_SHAKE_16_256, "XMSS-SHAKE_16_256", XMSS_FUNC_SHAKE128, 32, 16, 16, 1 },
    { OID_XMSS_SHAKE_20_256, "XMSS-SHAKE_20_256", XMSS_FUNC_SHAKE128, 32, 16, 20, 1 },
    { OID_XMSS_SHAKE_10_512, "XMSS-SHAKE_10_512", XMSS_FUNC_SHAKE256, 64, 16, 10, 1 },
    { OID_XMSS_SHAKE_16_512, "XMSS-SHAKE_16_512", XMSS_FUNC_SHAKE256, 64, 16, 16, 1 },
    { OID_XMSS_SHAKE_20_512, "XMSS-SHAKE_20_512", XMSS_FUNC_SHAKE256, 64, 16, 20, 1 },
};

#define XMSS_OID_TABLE_SIZE ((uint32_t)(sizeof(xmss_oid_table) / sizeof(xmss_oid_table[0])))

/* RFC 8391 Appendix B — 32 XMSS-MT parameter sets (d>1) */
static const oid_entry_t xmss_mt_oid_table[] = {
    /* SHA-2 based, n=32 */
    { OID_XMSS_MT_SHA2_20_2_256,  "XMSSMT-SHA2_20/2_256",  XMSS_FUNC_SHA2,     32, 16, 20,  2 },
    { OID_XMSS_MT_SHA2_20_4_256,  "XMSSMT-SHA2_20/4_256",  XMSS_FUNC_SHA2,     32, 16, 20,  4 },
    { OID_XMSS_MT_SHA2_40_2_256,  "XMSSMT-SHA2_40/2_256",  XMSS_FUNC_SHA2,     32, 16, 40,  2 },
    { OID_XMSS_MT_SHA2_40_4_256,  "XMSSMT-SHA2_40/4_256",  XMSS_FUNC_SHA2,     32, 16, 40,  4 },
    { OID_XMSS_MT_SHA2_40_8_256,  "XMSSMT-SHA2_40/8_256",  XMSS_FUNC_SHA2,     32, 16, 40,  8 },
    { OID_XMSS_MT_SHA2_60_3_256,  "XMSSMT-SHA2_60/3_256",  XMSS_FUNC_SHA2,     32, 16, 60,  3 },
    { OID_XMSS_MT_SHA2_60_6_256,  "XMSSMT-SHA2_60/6_256",  XMSS_FUNC_SHA2,     32, 16, 60,  6 },
    { OID_XMSS_MT_SHA2_60_12_256, "XMSSMT-SHA2_60/12_256", XMSS_FUNC_SHA2,     32, 16, 60, 12 },
    /* SHA-2 based, n=64 */
    { OID_XMSS_MT_SHA2_20_2_512,  "XMSSMT-SHA2_20/2_512",  XMSS_FUNC_SHA2,     64, 16, 20,  2 },
    { OID_XMSS_MT_SHA2_20_4_512,  "XMSSMT-SHA2_20/4_512",  XMSS_FUNC_SHA2,     64, 16, 20,  4 },
    { OID_XMSS_MT_SHA2_40_2_512,  "XMSSMT-SHA2_40/2_512",  XMSS_FUNC_SHA2,     64, 16, 40,  2 },
    { OID_XMSS_MT_SHA2_40_4_512,  "XMSSMT-SHA2_40/4_512",  XMSS_FUNC_SHA2,     64, 16, 40,  4 },
    { OID_XMSS_MT_SHA2_40_8_512,  "XMSSMT-SHA2_40/8_512",  XMSS_FUNC_SHA2,     64, 16, 40,  8 },
    { OID_XMSS_MT_SHA2_60_3_512,  "XMSSMT-SHA2_60/3_512",  XMSS_FUNC_SHA2,     64, 16, 60,  3 },
    { OID_XMSS_MT_SHA2_60_6_512,  "XMSSMT-SHA2_60/6_512",  XMSS_FUNC_SHA2,     64, 16, 60,  6 },
    { OID_XMSS_MT_SHA2_60_12_512, "XMSSMT-SHA2_60/12_512", XMSS_FUNC_SHA2,     64, 16, 60, 12 },
    /* SHAKE based, n=32 */
    { OID_XMSS_MT_SHAKE_20_2_256,  "XMSSMT-SHAKE_20/2_256",  XMSS_FUNC_SHAKE128, 32, 16, 20,  2 },
    { OID_XMSS_MT_SHAKE_20_4_256,  "XMSSMT-SHAKE_20/4_256",  XMSS_FUNC_SHAKE128, 32, 16, 20,  4 },
    { OID_XMSS_MT_SHAKE_40_2_256,  "XMSSMT-SHAKE_40/2_256",  XMSS_FUNC_SHAKE128, 32, 16, 40,  2 },
    { OID_XMSS_MT_SHAKE_40_4_256,  "XMSSMT-SHAKE_40/4_256",  XMSS_FUNC_SHAKE128, 32, 16, 40,  4 },
    { OID_XMSS_MT_SHAKE_40_8_256,  "XMSSMT-SHAKE_40/8_256",  XMSS_FUNC_SHAKE128, 32, 16, 40,  8 },
    { OID_XMSS_MT_SHAKE_60_3_256,  "XMSSMT-SHAKE_60/3_256",  XMSS_FUNC_SHAKE128, 32, 16, 60,  3 },
    { OID_XMSS_MT_SHAKE_60_6_256,  "XMSSMT-SHAKE_60/6_256",  XMSS_FUNC_SHAKE128, 32, 16, 60,  6 },
    { OID_XMSS_MT_SHAKE_60_12_256, "XMSSMT-SHAKE_60/12_256", XMSS_FUNC_SHAKE128, 32, 16, 60, 12 },
    /* SHAKE based, n=64 */
    { OID_XMSS_MT_SHAKE_20_2_512,  "XMSSMT-SHAKE_20/2_512",  XMSS_FUNC_SHAKE256, 64, 16, 20,  2 },
    { OID_XMSS_MT_SHAKE_20_4_512,  "XMSSMT-SHAKE_20/4_512",  XMSS_FUNC_SHAKE256, 64, 16, 20,  4 },
    { OID_XMSS_MT_SHAKE_40_2_512,  "XMSSMT-SHAKE_40/2_512",  XMSS_FUNC_SHAKE256, 64, 16, 40,  2 },
    { OID_XMSS_MT_SHAKE_40_4_512,  "XMSSMT-SHAKE_40/4_512",  XMSS_FUNC_SHAKE256, 64, 16, 40,  4 },
    { OID_XMSS_MT_SHAKE_40_8_512,  "XMSSMT-SHAKE_40/8_512",  XMSS_FUNC_SHAKE256, 64, 16, 40,  8 },
    { OID_XMSS_MT_SHAKE_60_3_512,  "XMSSMT-SHAKE_60/3_512",  XMSS_FUNC_SHAKE256, 64, 16, 60,  3 },
    { OID_XMSS_MT_SHAKE_60_6_512,  "XMSSMT-SHAKE_60/6_512",  XMSS_FUNC_SHAKE256, 64, 16, 60,  6 },
    { OID_XMSS_MT_SHAKE_60_12_512, "XMSSMT-SHAKE_60/12_512", XMSS_FUNC_SHAKE256, 64, 16, 60, 12 },
};

#define XMSS_MT_OID_TABLE_SIZE ((uint32_t)(sizeof(xmss_mt_oid_table) / sizeof(xmss_mt_oid_table[0])))

/* Populate params from a table entry */
static int fill_from_entry(xmss_params *p, const oid_entry_t *e)
{
    p->oid  = e->oid;
    p->func = e->func;
    p->n    = e->n;
    p->w    = e->w;
    p->h    = e->h;
    p->d    = e->d;
    return derive_params(p);
}

int xmss_params_from_oid(xmss_params *p, uint32_t oid)
{
    uint32_t i;
    for (i = 0; i < XMSS_OID_TABLE_SIZE; i++) {
        if (xmss_oid_table[i].oid == oid) {
            return fill_from_entry(p, &xmss_oid_table[i]);
        }
    }
    return XMSS_ERR_PARAMS;
}

int xmss_params_from_name(xmss_params *p, const char *name)
{
    uint32_t i;
    for (i = 0; i < XMSS_OID_TABLE_SIZE; i++) {
        if (strcmp(xmss_oid_table[i].name, name) == 0) {
            return fill_from_entry(p, &xmss_oid_table[i]);
        }
    }
    return XMSS_ERR_PARAMS;
}

int xmss_mt_params_from_oid(xmss_params *p, uint32_t oid)
{
    uint32_t i;
    for (i = 0; i < XMSS_MT_OID_TABLE_SIZE; i++) {
        if (xmss_mt_oid_table[i].oid == oid) {
            return fill_from_entry(p, &xmss_mt_oid_table[i]);
        }
    }
    return XMSS_ERR_PARAMS;
}

int xmss_mt_params_from_name(xmss_params *p, const char *name)
{
    uint32_t i;
    for (i = 0; i < XMSS_MT_OID_TABLE_SIZE; i++) {
        if (strcmp(xmss_mt_oid_table[i].name, name) == 0) {
            return fill_from_entry(p, &xmss_mt_oid_table[i]);
        }
    }
    return XMSS_ERR_PARAMS;
}
