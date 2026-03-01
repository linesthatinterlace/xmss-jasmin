/**
 * params.h - XMSS parameter sets and OID table
 *
 * RFC 8391 §5.3 and Appendix B (all 12 XMSS parameter sets).
 */
#ifndef XMSS_PARAMS_H
#define XMSS_PARAMS_H

#include <stdint.h>

/* Maximums for static buffer sizing (Jasmin Rule J1: no VLAs) */
#define XMSS_MAX_N        64U
#define XMSS_MAX_H        20U   /* max per-tree height (BDS arrays sized by this) */
#define XMSS_MAX_FULL_H   60U   /* max total tree height across all layers */
#define XMSS_MAX_D        12U   /* max number of layers (XMSSMT-*_60/12_*) */
/* WOTS+ len for n=64, w=16 (RFC 8391 standard sets):
 *   len1 = ceil(8*64/log2(16)) = ceil(512/4) = 128
 *   len2 = floor(log2(128*15)/4) + 1 = floor(10.9/4) + 1 = 3
 *   len  = 131
 */
#define XMSS_MAX_WOTS_LEN 131U
#define XMSS_MAX_BDS_K    4U   /* max BDS retain parameter (must be even, ≤ XMSS_MAX_H) */

/* Hash function identifiers */
#define XMSS_FUNC_SHA2    0
#define XMSS_FUNC_SHAKE128 1
#define XMSS_FUNC_SHAKE256 2

/**
 * xmss_params - all derived parameters for one XMSS/XMSS-MT instance.
 *
 * Fields are derived from (n, w, h, d, func) by xmss_params_from_oid()
 * or xmss_mt_params_from_oid().
 * Never modify fields directly; treat as read-only after initialisation.
 *
 * For XMSS (d=1): tree_height == h.
 * For XMSS-MT (d>1): tree_height = h/d (per-tree height).
 */
typedef struct {
    uint32_t oid;
    uint8_t  func;        /* XMSS_FUNC_* */
    uint32_t n;           /* hash output / private key element size in bytes */
    uint32_t w;           /* Winternitz parameter (4 or 16) */
    uint32_t log2_w;      /* log2(w): 2 for w=4, 4 for w=16 */
    uint32_t len1;        /* ceil(8*n / log2(w)) */
    uint32_t len2;        /* floor(log2(len1*(w-1)) / log2(w)) + 1 */
    uint32_t len;         /* len1 + len2 */
    uint32_t h;           /* full tree height (h for XMSS, h_total for XMSS-MT) */
    uint32_t tree_height; /* per-tree height: h for XMSS (d=1), h/d for XMSS-MT */
    uint32_t d;           /* number of layers (1 for XMSS, >1 for XMSS-MT) */
    uint32_t pad_len;     /* PRF padding length (n for standard; 4 for n=24) */
    uint32_t idx_bytes;   /* bytes to encode leaf index: 4 for XMSS, ceil(h/8) for MT */
    uint64_t idx_max;     /* 2^h - 1 - maximum leaf index */
    uint32_t sig_bytes;   /* total signature bytes */
    uint32_t pk_bytes;    /* total public key bytes */
    uint32_t sk_bytes;    /* total secret key bytes */
} xmss_params;

/**
 * xmss_params_from_oid() - populate params from a numeric OID.
 *
 * Returns 0 on success, -1 if OID is not recognised.
 * All 12 RFC 8391 XMSS OIDs are supported.
 */
int xmss_params_from_oid(xmss_params *p, uint32_t oid);

/**
 * xmss_params_from_name() - populate params from a name string.
 *
 * Name format: "XMSS-SHA2_10_256", "XMSS-SHAKE_10_256", etc.
 * Returns 0 on success, -1 if name is not recognised.
 */
int xmss_params_from_name(xmss_params *p, const char *name);

/**
 * xmss_mt_params_from_oid() - populate params from an XMSS-MT OID.
 *
 * Accepts RFC 8391 XMSS-MT OIDs (0x00000001-0x00000020).
 * XMSS and XMSS-MT have separate OID namespaces per RFC 8391.
 * Returns 0 on success, -1 if OID is not recognised.
 */
int xmss_mt_params_from_oid(xmss_params *p, uint32_t oid);

/**
 * xmss_mt_params_from_name() - populate params from an XMSS-MT name string.
 *
 * Name format: "XMSSMT-SHA2_20/2_256", "XMSSMT-SHAKE_40/4_512", etc.
 * Returns 0 on success, -1 if name is not recognised.
 */
int xmss_mt_params_from_name(xmss_params *p, const char *name);

/* RFC 8391 Appendix A — XMSS OID values */
#define OID_XMSS_SHA2_10_256   0x00000001U
#define OID_XMSS_SHA2_16_256   0x00000002U
#define OID_XMSS_SHA2_20_256   0x00000003U
#define OID_XMSS_SHA2_10_512   0x00000004U
#define OID_XMSS_SHA2_16_512   0x00000005U
#define OID_XMSS_SHA2_20_512   0x00000006U
#define OID_XMSS_SHAKE_10_256  0x00000007U
#define OID_XMSS_SHAKE_16_256  0x00000008U
#define OID_XMSS_SHAKE_20_256  0x00000009U
#define OID_XMSS_SHAKE_10_512  0x0000000AU
#define OID_XMSS_SHAKE_16_512  0x0000000BU
#define OID_XMSS_SHAKE_20_512  0x0000000CU

/*
 * RFC 8391 Appendix B — XMSS-MT OID values.
 *
 * XMSS and XMSS-MT have separate IANA registries per RFC 8391.
 * The OID values below are the raw RFC values (0x00000001-0x00000020).
 * Use xmss_mt_params_from_oid() (not xmss_params_from_oid()) to look up.
 */

/* SHA-2 based, n=32 */
#define OID_XMSS_MT_SHA2_20_2_256    0x00000001U
#define OID_XMSS_MT_SHA2_20_4_256    0x00000002U
#define OID_XMSS_MT_SHA2_40_2_256    0x00000003U
#define OID_XMSS_MT_SHA2_40_4_256    0x00000004U
#define OID_XMSS_MT_SHA2_40_8_256    0x00000005U
#define OID_XMSS_MT_SHA2_60_3_256    0x00000006U
#define OID_XMSS_MT_SHA2_60_6_256    0x00000007U
#define OID_XMSS_MT_SHA2_60_12_256   0x00000008U

/* SHA-2 based, n=64 */
#define OID_XMSS_MT_SHA2_20_2_512    0x00000009U
#define OID_XMSS_MT_SHA2_20_4_512    0x0000000AU
#define OID_XMSS_MT_SHA2_40_2_512    0x0000000BU
#define OID_XMSS_MT_SHA2_40_4_512    0x0000000CU
#define OID_XMSS_MT_SHA2_40_8_512    0x0000000DU
#define OID_XMSS_MT_SHA2_60_3_512    0x0000000EU
#define OID_XMSS_MT_SHA2_60_6_512    0x0000000FU
#define OID_XMSS_MT_SHA2_60_12_512   0x00000010U

/* SHAKE based, n=32 */
#define OID_XMSS_MT_SHAKE_20_2_256   0x00000011U
#define OID_XMSS_MT_SHAKE_20_4_256   0x00000012U
#define OID_XMSS_MT_SHAKE_40_2_256   0x00000013U
#define OID_XMSS_MT_SHAKE_40_4_256   0x00000014U
#define OID_XMSS_MT_SHAKE_40_8_256   0x00000015U
#define OID_XMSS_MT_SHAKE_60_3_256   0x00000016U
#define OID_XMSS_MT_SHAKE_60_6_256   0x00000017U
#define OID_XMSS_MT_SHAKE_60_12_256  0x00000018U

/* SHAKE based, n=64 */
#define OID_XMSS_MT_SHAKE_20_2_512   0x00000019U
#define OID_XMSS_MT_SHAKE_20_4_512   0x0000001AU
#define OID_XMSS_MT_SHAKE_40_2_512   0x0000001BU
#define OID_XMSS_MT_SHAKE_40_4_512   0x0000001CU
#define OID_XMSS_MT_SHAKE_40_8_512   0x0000001DU
#define OID_XMSS_MT_SHAKE_60_3_512   0x0000001EU
#define OID_XMSS_MT_SHAKE_60_6_512   0x0000001FU
#define OID_XMSS_MT_SHAKE_60_12_512  0x00000020U

#endif /* XMSS_PARAMS_H */
