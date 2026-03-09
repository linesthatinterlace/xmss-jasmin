/**
 * test_utils_internal.c - Unit tests for internal utility functions
 *
 * Tests:
 *   1. ct_memcmp: equal/unequal/zero-length/single-byte-differ
 *   2. ull_to_bytes / bytes_to_ull: round-trip, big-endian layout, limits
 *   3. xmss_memzero: buffer actually cleared after call
 *   4. xmss_PRF_idx: determinism and domain separation
 *   5. Key exhaustion: xmss_sign and xmss_mt_sign return XMSS_ERR_EXHAUSTED
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "test_utils.h"
#include "../include/xmss/xmss.h"
#include "../include/xmss/params.h"
#include "../src/utils.h"
#include "../src/hash/hash_iface.h"

/* ------------------------------------------------------------------ */
/* ct_memcmp                                                           */
/* ------------------------------------------------------------------ */
static void test_ct_memcmp(void)
{
    uint8_t a[32], b[32];
    size_t i;

    printf("--- ct_memcmp ---\n");

    /* Equal buffers → 0 */
    memset(a, 0xAB, 32); memset(b, 0xAB, 32);
    TEST("ct_memcmp equal → 0", ct_memcmp(a, b, 32) == 0);

    /* First byte differs → non-zero */
    b[0] ^= 0x01;
    TEST("ct_memcmp first byte differs → non-zero", ct_memcmp(a, b, 32) != 0);
    b[0] ^= 0x01;

    /* Last byte differs → non-zero */
    b[31] ^= 0xFF;
    TEST("ct_memcmp last byte differs → non-zero", ct_memcmp(a, b, 32) != 0);
    b[31] ^= 0xFF;

    /* Single-byte comparison, equal */
    TEST("ct_memcmp 1 byte equal → 0", ct_memcmp(a, b, 1) == 0);

    /* Zero-length comparison → 0 */
    TEST("ct_memcmp zero length → 0", ct_memcmp(a, b, 0) == 0);

    /* All bytes differ → non-zero */
    for (i = 0; i < 32; i++) { b[i] = (uint8_t)~a[i]; }
    TEST("ct_memcmp all bytes differ → non-zero", ct_memcmp(a, b, 32) != 0);
}

/* ------------------------------------------------------------------ */
/* ull_to_bytes / bytes_to_ull                                        */
/* ------------------------------------------------------------------ */
static void test_ull_bytes(void)
{
    uint8_t buf[8];

    printf("--- ull_to_bytes / bytes_to_ull ---\n");

    /* Round-trip: 4-byte encoding */
    ull_to_bytes(buf, 4, 0x01020304ULL);
    TEST_INT("ull_to_bytes 4: byte 0", buf[0], 0x01);
    TEST_INT("ull_to_bytes 4: byte 1", buf[1], 0x02);
    TEST_INT("ull_to_bytes 4: byte 2", buf[2], 0x03);
    TEST_INT("ull_to_bytes 4: byte 3", buf[3], 0x04);
    TEST("bytes_to_ull 4 round-trip",
         bytes_to_ull(buf, 4) == 0x01020304ULL);

    /* Round-trip: 8-byte encoding */
    ull_to_bytes(buf, 8, 0x0102030405060708ULL);
    TEST_INT("ull_to_bytes 8: byte 0", buf[0], 0x01);
    TEST_INT("ull_to_bytes 8: byte 7", buf[7], 0x08);
    TEST("bytes_to_ull 8 round-trip",
         bytes_to_ull(buf, 8) == 0x0102030405060708ULL);

    /* Round-trip: 1-byte encoding */
    ull_to_bytes(buf, 1, 0xFFULL);
    TEST("bytes_to_ull 1 round-trip", bytes_to_ull(buf, 1) == 0xFFULL);

    /* Zero value */
    ull_to_bytes(buf, 4, 0);
    TEST("ull_to_bytes zero",
         buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[3] == 0);
    TEST("bytes_to_ull zero", bytes_to_ull(buf, 4) == 0);

    /* Max 32-bit value */
    ull_to_bytes(buf, 4, 0xFFFFFFFFULL);
    TEST("ull_to_bytes 4 max value",
         buf[0] == 0xFF && buf[1] == 0xFF && buf[2] == 0xFF && buf[3] == 0xFF);

    /* Values that exactly fit their encoding width */
    ull_to_bytes(buf, 1, 0xFFULL);
    TEST_INT("ull_to_bytes 1 max value", buf[0], 0xFF);

    ull_to_bytes(buf, 2, 0xFFFFULL);
    TEST("ull_to_bytes 2 max value", buf[0] == 0xFF && buf[1] == 0xFF);
}

/* ------------------------------------------------------------------ */
/* xmss_memzero                                                        */
/* ------------------------------------------------------------------ */
static void test_memzero(void)
{
    uint8_t buf[64];
    size_t i;
    int all_zero;

    printf("--- xmss_memzero ---\n");

    /* Fill with non-zero data */
    for (i = 0; i < sizeof(buf); i++) { buf[i] = (uint8_t)(i + 1); }

    xmss_memzero(buf, sizeof(buf));

    all_zero = 1;
    for (i = 0; i < sizeof(buf); i++) { if (buf[i] != 0) { all_zero = 0; break; } }
    TEST("xmss_memzero clears 64-byte buffer", all_zero);

    /* Zero-length call must not crash */
    xmss_memzero(buf, 0);
    TEST("xmss_memzero zero-length does not crash", 1);
}

/* ------------------------------------------------------------------ */
/* xmss_PRF_idx determinism and domain separation                     */
/* ------------------------------------------------------------------ */
static void test_prf_idx(void)
{
    xmss_params p;
    uint8_t sk_prf[64];
    uint8_t out1[64], out2[64], out3[64];
    size_t i;

    printf("--- xmss_PRF_idx ---\n");

    xmss_params_from_oid(&p, OID_XMSS_SHA2_10_256); /* n=32, SHA-2 */

    for (i = 0; i < 32; i++) { sk_prf[i] = (uint8_t)(i + 1); }

    /* Determinism: same inputs → same output */
    xmss_PRF_idx(&p, out1, sk_prf, 42);
    xmss_PRF_idx(&p, out2, sk_prf, 42);
    TEST_BYTES("PRF_idx deterministic (SHA2 n=32)", out1, out2, 32);

    /* Different index → different output */
    xmss_PRF_idx(&p, out3, sk_prf, 43);
    TEST("PRF_idx idx=42 != idx=43", memcmp(out1, out3, 32) != 0);

    /* Different key → different output */
    {
        uint8_t sk_prf2[32];
        uint8_t out4[32];
        for (i = 0; i < 32; i++) { sk_prf2[i] = (uint8_t)(i + 2); }
        xmss_PRF_idx(&p, out4, sk_prf2, 42);
        TEST("PRF_idx different key → different output", memcmp(out1, out4, 32) != 0);
    }

    /* SHAKE variant also deterministic */
    xmss_params_from_oid(&p, OID_XMSS_SHAKE_10_256);
    xmss_PRF_idx(&p, out1, sk_prf, 0);
    xmss_PRF_idx(&p, out2, sk_prf, 0);
    TEST_BYTES("PRF_idx deterministic (SHAKE n=32)", out1, out2, 32);
}

/* ------------------------------------------------------------------ */
/* Key exhaustion — XMSS                                              */
/* ------------------------------------------------------------------ */
static void test_exhaustion_xmss(void)
{
    xmss_params p;
    xmss_bds_state *state;
    uint8_t *pk, *sk, *sig;
    uint8_t msg[] = { 0x01, 0x02 };
    int ret;
    uint32_t i;

    printf("--- XMSS key exhaustion ---\n");

    /* Use h=10 so idx_max = 1023 (2^10 - 1).
     * Inject idx = idx_max directly into SK to avoid signing 1023 times. */
    xmss_params_from_oid(&p, OID_XMSS_SHA2_10_256);

    pk    = (uint8_t *)malloc(p.pk_bytes);
    sk    = (uint8_t *)malloc(p.sk_bytes);
    sig   = (uint8_t *)malloc(p.sig_bytes);
    state = (xmss_bds_state *)malloc(sizeof(xmss_bds_state));

    test_rng_reset(0x5566778899AABBCCULL);
    xmss_keygen(&p, pk, sk, state, 0, test_randombytes);

    /* Inject idx = idx_max (last valid index) into SK bytes [4 .. 4+idx_bytes) */
    ull_to_bytes(sk + 4, p.idx_bytes, p.idx_max);

    /* One sign at the last valid index must succeed */
    ret = xmss_sign(&p, sig, msg, sizeof(msg), sk, state, 0);
    TEST_INT("XMSS sign at idx_max succeeds", ret, XMSS_OK);

    /* Now idx = idx_max + 1 in SK — next sign must fail with EXHAUSTED */
    ret = xmss_sign(&p, sig, msg, sizeof(msg), sk, state, 0);
    TEST_INT("XMSS sign after idx_max → EXHAUSTED", ret, XMSS_ERR_EXHAUSTED);

    /* Repeated calls still return EXHAUSTED */
    for (i = 0; i < 3; i++) {
        ret = xmss_sign(&p, sig, msg, sizeof(msg), sk, state, 0);
        TEST_INT("XMSS repeated sign after exhaustion → EXHAUSTED",
                 ret, XMSS_ERR_EXHAUSTED);
    }

    free(pk); free(sk); free(sig); free(state);
}

/* ------------------------------------------------------------------ */
/* Key exhaustion — XMSS-MT                                           */
/* ------------------------------------------------------------------ */
static void test_exhaustion_xmss_mt(void)
{
    xmss_params p;
    xmss_mt_state *state;
    uint8_t *pk, *sk, *sig;
    uint8_t msg[] = { 0x03, 0x04 };
    int ret;

    printf("--- XMSS-MT key exhaustion ---\n");

    /* XMSSMT-SHA2_20/2_256: h=20, idx_max = 2^20 - 1.
     * Inject idx = idx_max to skip signing 2^20 - 1 times. */
    xmss_mt_params_from_oid(&p, OID_XMSS_MT_SHA2_20_2_256);

    pk    = (uint8_t *)malloc(p.pk_bytes);
    sk    = (uint8_t *)malloc(p.sk_bytes);
    sig   = (uint8_t *)malloc(p.sig_bytes);
    state = (xmss_mt_state *)malloc(sizeof(xmss_mt_state));

    test_rng_reset(0xDDEEFF0011223344ULL);
    xmss_mt_keygen(&p, pk, sk, state, 0, test_randombytes);

    /* Inject idx = idx_max into SK */
    ull_to_bytes(sk + 4, p.idx_bytes, p.idx_max);

    /* Sign at idx_max must succeed */
    ret = xmss_mt_sign(&p, sig, msg, sizeof(msg), sk, state, 0);
    TEST_INT("XMSS-MT sign at idx_max succeeds", ret, XMSS_OK);

    /* Next sign must return EXHAUSTED */
    ret = xmss_mt_sign(&p, sig, msg, sizeof(msg), sk, state, 0);
    TEST_INT("XMSS-MT sign after idx_max → EXHAUSTED", ret, XMSS_ERR_EXHAUSTED);

    free(pk); free(sk); free(sig); free(state);
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
int main(void)
{
    printf("=== test_utils_internal ===\n");

    test_ct_memcmp();
    test_ull_bytes();
    test_memzero();
    test_prf_idx();
    test_exhaustion_xmss();
    test_exhaustion_xmss_mt();

    return tests_done();
}
