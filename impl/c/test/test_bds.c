/**
 * test_bds.c - BDS-specific parameter tests
 *
 * Tests BDS-specific behaviour not covered by test_xmss:
 *   1. bds_k parameter validation (odd, >h rejected)
 *   2. Roundtrip with bds_k=2 and bds_k=4
 *   3. Sequential signing with bds_k=2
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "test_utils.h"
#include "../include/xmss/params.h"
#include "../include/xmss/xmss.h"

/* ------------------------------------------------------------------ */
/* bds_k validation                                                   */
/* ------------------------------------------------------------------ */
static void test_bds_k_validation(void)
{
    xmss_test_ctx t;
    int rc;

    xmss_test_ctx_init(&t, OID_XMSS_SHA2_10_256);

    rc = xmss_keygen(&t.p, t.pk, t.sk, t.state, 1, test_randombytes);
    TEST("bds_k=1 (odd) rejected", rc == XMSS_ERR_PARAMS);

    rc = xmss_keygen(&t.p, t.pk, t.sk, t.state, 12, test_randombytes);
    TEST("bds_k=12 (>h) rejected", rc == XMSS_ERR_PARAMS);

    /* Issue #12: bds_k exceeding XMSS_MAX_BDS_K must be rejected even if
     * it passes the other checks (>= 2, < H, (H-K) even). */
    rc = xmss_keygen(&t.p, t.pk, t.sk, t.state, XMSS_MAX_BDS_K + 2, test_randombytes);
    TEST("bds_k=MAX_BDS_K+2 (>MAX_BDS_K) rejected", rc == XMSS_ERR_PARAMS);

    test_rng_reset(1);
    rc = xmss_keygen(&t.p, t.pk, t.sk, t.state, 0, test_randombytes);
    TEST("bds_k=0 accepted", rc == XMSS_OK);

    xmss_test_ctx_free(&t);
}

/* ------------------------------------------------------------------ */
/* Roundtrip with non-zero bds_k                                      */
/* ------------------------------------------------------------------ */
static void test_roundtrip_k(uint32_t oid, const char *name, uint32_t bds_k)
{
    xmss_test_ctx t;
    uint8_t msg[] = { 0xAB, 0xCD };
    char label[128];
    int rc;

    xmss_test_ctx_init(&t, oid);

    test_rng_reset(42);

    rc = xmss_keygen(&t.p, t.pk, t.sk, t.state, bds_k, test_randombytes);
    snprintf(label, sizeof(label), "%s (k=%u): keygen", name, bds_k);
    TEST(label, rc == XMSS_OK);

    rc = xmss_sign(&t.p, t.sig, msg, sizeof(msg), t.sk, t.state, bds_k);
    snprintf(label, sizeof(label), "%s (k=%u): sign", name, bds_k);
    TEST(label, rc == XMSS_OK);

    rc = xmss_verify(&t.p, msg, sizeof(msg), t.sig, t.pk);
    snprintf(label, sizeof(label), "%s (k=%u): verify", name, bds_k);
    TEST(label, rc == XMSS_OK);

    xmss_test_ctx_free(&t);
}

/* ------------------------------------------------------------------ */
/* Sequential signing with non-zero bds_k                             */
/* ------------------------------------------------------------------ */
static void test_sequential_k(uint32_t oid, const char *name, uint32_t bds_k)
{
    xmss_test_ctx t;
    char label[128];
    int i, rc;

    xmss_test_ctx_init(&t, oid);

    test_rng_reset(99);
    rc = xmss_keygen(&t.p, t.pk, t.sk, t.state, bds_k, test_randombytes);
    snprintf(label, sizeof(label), "%s (k=%u): keygen", name, bds_k);
    TEST(label, rc == XMSS_OK);
    if (rc != XMSS_OK) { xmss_test_ctx_free(&t); return; }

    for (i = 0; i < 20; i++) {
        uint8_t msg[4];
        msg[0] = (uint8_t)i;
        msg[1] = (uint8_t)(i + 1);
        msg[2] = (uint8_t)(i * 3);
        msg[3] = (uint8_t)(i ^ 0x55);

        rc = xmss_sign(&t.p, t.sig, msg, sizeof(msg), t.sk, t.state, bds_k);
        if (rc != XMSS_OK) {
            snprintf(label, sizeof(label), "%s (k=%u): seq sign idx=%d", name, bds_k, i);
            TEST(label, 0);
            break;
        }

        rc = xmss_verify(&t.p, msg, sizeof(msg), t.sig, t.pk);
        snprintf(label, sizeof(label), "%s (k=%u): seq verify idx=%d", name, bds_k, i);
        TEST(label, rc == XMSS_OK);
    }

    xmss_test_ctx_free(&t);
}

/* ------------------------------------------------------------------ */
/* Issue #18: sign with mismatched bds_k must be rejected             */
/* ------------------------------------------------------------------ */
static void test_bds_k_sign_mismatch(void)
{
    xmss_test_ctx t;
    uint8_t msg[] = { 0x01, 0x02 };
    int rc;

    xmss_test_ctx_init(&t, OID_XMSS_SHA2_10_256);

    /* Keygen with K=0, sign with K=2 */
    test_rng_reset(10);
    rc = xmss_keygen(&t.p, t.pk, t.sk, t.state, 0, test_randombytes);
    TEST("mismatch: keygen K=0", rc == XMSS_OK);

    rc = xmss_sign(&t.p, t.sig, msg, sizeof(msg), t.sk, t.state, 2);
    TEST("mismatch: sign K=2 after keygen K=0 rejected", rc == XMSS_ERR_PARAMS);

    /* Keygen with K=2, sign with K=4 */
    test_rng_reset(20);
    rc = xmss_keygen(&t.p, t.pk, t.sk, t.state, 2, test_randombytes);
    TEST("mismatch: keygen K=2", rc == XMSS_OK);

    rc = xmss_sign(&t.p, t.sig, msg, sizeof(msg), t.sk, t.state, 4);
    TEST("mismatch: sign K=4 after keygen K=2 rejected", rc == XMSS_ERR_PARAMS);

    /* Keygen with K=2, sign with K=0 */
    test_rng_reset(30);
    rc = xmss_keygen(&t.p, t.pk, t.sk, t.state, 2, test_randombytes);
    TEST("mismatch: keygen K=2 (2)", rc == XMSS_OK);

    rc = xmss_sign(&t.p, t.sig, msg, sizeof(msg), t.sk, t.state, 0);
    TEST("mismatch: sign K=0 after keygen K=2 rejected", rc == XMSS_ERR_PARAMS);

    xmss_test_ctx_free(&t);
}

/* ------------------------------------------------------------------ */
/* Issue #18: MT sign with mismatched bds_k must be rejected          */
/* ------------------------------------------------------------------ */
static void test_bds_k_mt_sign_mismatch(void)
{
    xmss_mt_test_ctx t;
    uint8_t msg[] = { 0x01, 0x02 };
    int rc;

    xmss_mt_test_ctx_init(&t, OID_XMSS_MT_SHA2_20_2_256);

    /* Keygen with K=0, sign with K=2 */
    test_rng_reset(50);
    rc = xmss_mt_keygen(&t.p, t.pk, t.sk, t.state, 0, test_randombytes);
    TEST("MT mismatch: keygen K=0", rc == XMSS_OK);

    rc = xmss_mt_sign(&t.p, t.sig, msg, sizeof(msg), t.sk, t.state, 2);
    TEST("MT mismatch: sign K=2 after keygen K=0 rejected", rc == XMSS_ERR_PARAMS);

    /* Keygen with K=2, sign with K=0 */
    test_rng_reset(60);
    rc = xmss_mt_keygen(&t.p, t.pk, t.sk, t.state, 2, test_randombytes);
    TEST("MT mismatch: keygen K=2", rc == XMSS_OK);

    rc = xmss_mt_sign(&t.p, t.sig, msg, sizeof(msg), t.sk, t.state, 0);
    TEST("MT mismatch: sign K=0 after keygen K=2 rejected", rc == XMSS_ERR_PARAMS);

    xmss_mt_test_ctx_free(&t);
}

/* ------------------------------------------------------------------ */
/* Serialize with invalid bds_k must be rejected                      */
/* ------------------------------------------------------------------ */
static void test_bds_k_serialize_invalid(void)
{
    xmss_test_ctx t;
    int rc;
    uint8_t buf[8192]; /* large enough for any serialized BDS state */

    xmss_test_ctx_init(&t, OID_XMSS_SHA2_10_256);

    /* Keygen with valid K=0 to get a state */
    test_rng_reset(40);
    rc = xmss_keygen(&t.p, t.pk, t.sk, t.state, 0, test_randombytes);
    TEST("serialize: keygen K=0", rc == XMSS_OK);

    /* Serialize with invalid K=6 */
    rc = xmss_bds_serialize(&t.p, buf, t.state, 6);
    TEST("serialize: K=6 rejected", rc == XMSS_ERR_PARAMS);

    /* Deserialize with invalid K=6 */
    rc = xmss_bds_deserialize(&t.p, t.state, buf, 6);
    TEST("deserialize: K=6 rejected", rc == XMSS_ERR_PARAMS);

    xmss_test_ctx_free(&t);
}

int main(void)
{
    printf("=== test_bds (BDS-specific parameters) ===\n");

    printf("--- bds_k validation ---\n");
    test_bds_k_validation();

    printf("--- bds_k sign mismatch ---\n");
    test_bds_k_sign_mismatch();

    printf("--- bds_k MT sign mismatch ---\n");
    test_bds_k_mt_sign_mismatch();

    printf("--- bds_k serialize validation ---\n");
    test_bds_k_serialize_invalid();

    printf("--- roundtrip (k=2) ---\n");
    test_roundtrip_k(OID_XMSS_SHA2_10_256,  "XMSS-SHA2_10_256",  2);
    test_roundtrip_k(OID_XMSS_SHAKE_10_256, "XMSS-SHAKE_10_256", 2);

    printf("--- roundtrip (k=4) ---\n");
    test_roundtrip_k(OID_XMSS_SHA2_10_256,  "XMSS-SHA2_10_256",  4);

    printf("--- sequential (k=2) ---\n");
    test_sequential_k(OID_XMSS_SHA2_10_256, "XMSS-SHA2_10_256", 2);

    printf("--- sequential (k=4) ---\n");
    test_sequential_k(OID_XMSS_SHA2_10_256,  "XMSS-SHA2_10_256",  4);
    test_sequential_k(OID_XMSS_SHAKE_10_256, "XMSS-SHAKE_10_256", 4);

    return tests_done();
}
