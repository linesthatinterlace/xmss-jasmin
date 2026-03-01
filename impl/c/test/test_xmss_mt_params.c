/**
 * test_xmss_mt_params.c - Tests for XMSS-MT parameter sets
 *
 * Verifies that all 32 XMSS-MT OIDs produce correct derived parameters.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "test_utils.h"
#include "../include/xmss/params.h"
#include "../include/xmss/xmss.h"

typedef struct {
    uint32_t oid;          /* RFC OID (0x00000001-0x00000020) */
    const char *name;
    uint32_t n;
    uint32_t w;
    uint32_t h;            /* full height */
    uint32_t d;
    uint32_t tree_height;  /* h/d */
    uint32_t len;
    uint32_t sig_bytes;
    uint32_t pk_bytes;
    uint32_t sk_bytes;
    uint32_t idx_bytes;
} expected_mt_params_t;

/*
 * Expected values from RFC 8391 §5.4:
 *
 * n=32, w=16: len=67
 *   sig = idx_bytes + n + d*(len + tree_height)*n
 *       = idx_bytes + 32 + d*(67 + h/d)*32
 *       = idx_bytes + 32 + d*67*32 + h*32
 *   pk  = 4 + 2*32 = 68
 *   sk  = 4 + idx_bytes + 4*32 = 4 + idx_bytes + 128
 *
 * n=64, w=16: len=131
 *   sig = idx_bytes + 64 + d*131*64 + h*64
 *   pk  = 4 + 2*64 = 132
 *   sk  = 4 + idx_bytes + 4*64 = 4 + idx_bytes + 256
 */

static const expected_mt_params_t expected[] = {
    /* SHA-2, n=32 */
    /* h=20: idx_bytes=3, sk=135 */
    { OID_XMSS_MT_SHA2_20_2_256, "XMSSMT-SHA2_20/2_256",
      32, 16, 20, 2, 10, 67, 3 + 32 + 2*67*32 + 20*32, 68, 135, 3 },
    { OID_XMSS_MT_SHA2_20_4_256, "XMSSMT-SHA2_20/4_256",
      32, 16, 20, 4, 5, 67, 3 + 32 + 4*67*32 + 20*32, 68, 135, 3 },
    /* h=40: idx_bytes=5, sk=137 */
    { OID_XMSS_MT_SHA2_40_2_256, "XMSSMT-SHA2_40/2_256",
      32, 16, 40, 2, 20, 67, 5 + 32 + 2*67*32 + 40*32, 68, 137, 5 },
    { OID_XMSS_MT_SHA2_40_4_256, "XMSSMT-SHA2_40/4_256",
      32, 16, 40, 4, 10, 67, 5 + 32 + 4*67*32 + 40*32, 68, 137, 5 },
    { OID_XMSS_MT_SHA2_40_8_256, "XMSSMT-SHA2_40/8_256",
      32, 16, 40, 8, 5, 67, 5 + 32 + 8*67*32 + 40*32, 68, 137, 5 },
    /* h=60: idx_bytes=8, sk=140 */
    { OID_XMSS_MT_SHA2_60_3_256, "XMSSMT-SHA2_60/3_256",
      32, 16, 60, 3, 20, 67, 8 + 32 + 3*67*32 + 60*32, 68, 140, 8 },
    { OID_XMSS_MT_SHA2_60_6_256, "XMSSMT-SHA2_60/6_256",
      32, 16, 60, 6, 10, 67, 8 + 32 + 6*67*32 + 60*32, 68, 140, 8 },
    { OID_XMSS_MT_SHA2_60_12_256, "XMSSMT-SHA2_60/12_256",
      32, 16, 60, 12, 5, 67, 8 + 32 + 12*67*32 + 60*32, 68, 140, 8 },

    /* SHA-2, n=64 */
    /* h=20: idx_bytes=3, sk=263 */
    { OID_XMSS_MT_SHA2_20_2_512, "XMSSMT-SHA2_20/2_512",
      64, 16, 20, 2, 10, 131, 3 + 64 + 2*131*64 + 20*64, 132, 263, 3 },
    { OID_XMSS_MT_SHA2_20_4_512, "XMSSMT-SHA2_20/4_512",
      64, 16, 20, 4, 5, 131, 3 + 64 + 4*131*64 + 20*64, 132, 263, 3 },
    /* h=40: idx_bytes=5, sk=265 */
    { OID_XMSS_MT_SHA2_40_2_512, "XMSSMT-SHA2_40/2_512",
      64, 16, 40, 2, 20, 131, 5 + 64 + 2*131*64 + 40*64, 132, 265, 5 },
    { OID_XMSS_MT_SHA2_40_4_512, "XMSSMT-SHA2_40/4_512",
      64, 16, 40, 4, 10, 131, 5 + 64 + 4*131*64 + 40*64, 132, 265, 5 },
    { OID_XMSS_MT_SHA2_40_8_512, "XMSSMT-SHA2_40/8_512",
      64, 16, 40, 8, 5, 131, 5 + 64 + 8*131*64 + 40*64, 132, 265, 5 },
    /* h=60: idx_bytes=8, sk=268 */
    { OID_XMSS_MT_SHA2_60_3_512, "XMSSMT-SHA2_60/3_512",
      64, 16, 60, 3, 20, 131, 8 + 64 + 3*131*64 + 60*64, 132, 268, 8 },
    { OID_XMSS_MT_SHA2_60_6_512, "XMSSMT-SHA2_60/6_512",
      64, 16, 60, 6, 10, 131, 8 + 64 + 6*131*64 + 60*64, 132, 268, 8 },
    { OID_XMSS_MT_SHA2_60_12_512, "XMSSMT-SHA2_60/12_512",
      64, 16, 60, 12, 5, 131, 8 + 64 + 12*131*64 + 60*64, 132, 268, 8 },

    /* SHAKE, n=32 */
    { OID_XMSS_MT_SHAKE_20_2_256, "XMSSMT-SHAKE_20/2_256",
      32, 16, 20, 2, 10, 67, 3 + 32 + 2*67*32 + 20*32, 68, 135, 3 },
    { OID_XMSS_MT_SHAKE_20_4_256, "XMSSMT-SHAKE_20/4_256",
      32, 16, 20, 4, 5, 67, 3 + 32 + 4*67*32 + 20*32, 68, 135, 3 },
    { OID_XMSS_MT_SHAKE_40_2_256, "XMSSMT-SHAKE_40/2_256",
      32, 16, 40, 2, 20, 67, 5 + 32 + 2*67*32 + 40*32, 68, 137, 5 },
    { OID_XMSS_MT_SHAKE_40_4_256, "XMSSMT-SHAKE_40/4_256",
      32, 16, 40, 4, 10, 67, 5 + 32 + 4*67*32 + 40*32, 68, 137, 5 },
    { OID_XMSS_MT_SHAKE_40_8_256, "XMSSMT-SHAKE_40/8_256",
      32, 16, 40, 8, 5, 67, 5 + 32 + 8*67*32 + 40*32, 68, 137, 5 },
    { OID_XMSS_MT_SHAKE_60_3_256, "XMSSMT-SHAKE_60/3_256",
      32, 16, 60, 3, 20, 67, 8 + 32 + 3*67*32 + 60*32, 68, 140, 8 },
    { OID_XMSS_MT_SHAKE_60_6_256, "XMSSMT-SHAKE_60/6_256",
      32, 16, 60, 6, 10, 67, 8 + 32 + 6*67*32 + 60*32, 68, 140, 8 },
    { OID_XMSS_MT_SHAKE_60_12_256, "XMSSMT-SHAKE_60/12_256",
      32, 16, 60, 12, 5, 67, 8 + 32 + 12*67*32 + 60*32, 68, 140, 8 },

    /* SHAKE, n=64 */
    { OID_XMSS_MT_SHAKE_20_2_512, "XMSSMT-SHAKE_20/2_512",
      64, 16, 20, 2, 10, 131, 3 + 64 + 2*131*64 + 20*64, 132, 263, 3 },
    { OID_XMSS_MT_SHAKE_20_4_512, "XMSSMT-SHAKE_20/4_512",
      64, 16, 20, 4, 5, 131, 3 + 64 + 4*131*64 + 20*64, 132, 263, 3 },
    { OID_XMSS_MT_SHAKE_40_2_512, "XMSSMT-SHAKE_40/2_512",
      64, 16, 40, 2, 20, 131, 5 + 64 + 2*131*64 + 40*64, 132, 265, 5 },
    { OID_XMSS_MT_SHAKE_40_4_512, "XMSSMT-SHAKE_40/4_512",
      64, 16, 40, 4, 10, 131, 5 + 64 + 4*131*64 + 40*64, 132, 265, 5 },
    { OID_XMSS_MT_SHAKE_40_8_512, "XMSSMT-SHAKE_40/8_512",
      64, 16, 40, 8, 5, 131, 5 + 64 + 8*131*64 + 40*64, 132, 265, 5 },
    { OID_XMSS_MT_SHAKE_60_3_512, "XMSSMT-SHAKE_60/3_512",
      64, 16, 60, 3, 20, 131, 8 + 64 + 3*131*64 + 60*64, 132, 268, 8 },
    { OID_XMSS_MT_SHAKE_60_6_512, "XMSSMT-SHAKE_60/6_512",
      64, 16, 60, 6, 10, 131, 8 + 64 + 6*131*64 + 60*64, 132, 268, 8 },
    { OID_XMSS_MT_SHAKE_60_12_512, "XMSSMT-SHAKE_60/12_512",
      64, 16, 60, 12, 5, 131, 8 + 64 + 12*131*64 + 60*64, 132, 268, 8 },
};

#define N_ENTRIES ((int)(sizeof(expected)/sizeof(expected[0])))

int main(void)
{
    int i;
    xmss_params p;

    printf("=== test_xmss_mt_params ===\n");

    for (i = 0; i < N_ENTRIES; i++) {
        const expected_mt_params_t *e = &expected[i];
        int ret;
        char buf[128];

        printf("Testing OID 0x%08x (%s):\n", e->oid, e->name);

        /* Test by OID */
        ret = xmss_mt_params_from_oid(&p, e->oid);
        snprintf(buf, sizeof(buf), "xmss_mt_params_from_oid(0x%08x)", e->oid);
        TEST_INT(buf, ret, 0);
        if (ret != 0) { continue; }

        TEST_INT("n",           p.n,           e->n);
        TEST_INT("w",           p.w,           e->w);
        TEST_INT("h",           p.h,           e->h);
        TEST_INT("d",           p.d,           e->d);
        TEST_INT("tree_height", p.tree_height, e->tree_height);
        TEST_INT("len",         p.len,         e->len);
        TEST_INT("sig_bytes",   p.sig_bytes,   e->sig_bytes);
        TEST_INT("pk_bytes",    p.pk_bytes,    e->pk_bytes);
        TEST_INT("sk_bytes",    p.sk_bytes,    e->sk_bytes);
        TEST_INT("idx_bytes",   p.idx_bytes,   e->idx_bytes);

        /* Test by name */
        ret = xmss_mt_params_from_name(&p, e->name);
        snprintf(buf, sizeof(buf), "xmss_mt_params_from_name(%s)", e->name);
        TEST_INT(buf, ret, 0);
    }

    /*
     * Cross-namespace test: OID 0x01 exists in both XMSS and XMSS-MT registries.
     * xmss_params_from_oid(0x01) → XMSS-SHA2_10_256 (d=1, h=10)
     * xmss_mt_params_from_oid(0x01) → XMSSMT-SHA2_20/2_256 (d=2, h=20)
     */
    {
        int ret;

        ret = xmss_params_from_oid(&p, 0x01);
        TEST_INT("xmss_params_from_oid(0x01) succeeds", ret, 0);
        TEST_INT("XMSS OID 0x01 d=1", p.d, 1);
        TEST_INT("XMSS OID 0x01 h=10", p.h, 10);

        ret = xmss_mt_params_from_oid(&p, 0x01);
        TEST_INT("xmss_mt_params_from_oid(0x01) succeeds", ret, 0);
        TEST_INT("XMSS-MT OID 0x01 d=2", p.d, 2);
        TEST_INT("XMSS-MT OID 0x01 h=20", p.h, 20);
    }

    /* Test invalid OID */
    {
        int ret = xmss_mt_params_from_oid(&p, 0xDEADBEEFU);
        TEST_INT("invalid OID rejected by xmss_mt_params_from_oid", ret, XMSS_ERR_PARAMS);
    }

    printf("Tested %d XMSS-MT parameter sets\n", N_ENTRIES);
    return tests_done();
}
