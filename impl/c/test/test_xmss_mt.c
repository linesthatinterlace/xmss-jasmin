/**
 * test_xmss_mt.c - Integration tests for XMSS-MT keygen/sign/verify
 *
 * Uses BDS-accelerated hypertree operations.
 *
 * Tests:
 * - keygen -> sign -> verify roundtrip (XMSSMT-SHA2_20/2_256)
 * - Bit-flip and wrong-message rejection
 * - Sequential signing: 5 signatures all verify
 * - Tree boundary crossing: 1024 signatures (crosses layer-0 tree)
 * - Message boundaries: empty and 64-byte messages
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "test_utils.h"
#include "../include/xmss/xmss.h"
#include "../include/xmss/params.h"

/* Smallest practical XMSS-MT: h=20, d=2, tree_height=10 */
#define TEST_OID OID_XMSS_MT_SHA2_20_2_256

static void test_roundtrip(void)
{
    xmss_mt_test_ctx t;
    const char *msg = "Hello, XMSS-MT!";
    size_t msglen = strlen(msg);
    int ret;

    printf("\n--- roundtrip ---\n");

    if (xmss_mt_test_ctx_init(&t, TEST_OID) != 0) {
        printf("  FAIL: init\n");
        return;
    }

    printf("  sig_bytes=%u pk_bytes=%u sk_bytes=%u\n",
           t.p.sig_bytes, t.p.pk_bytes, t.p.sk_bytes);
    printf("  h=%u d=%u tree_height=%u idx_bytes=%u\n",
           t.p.h, t.p.d, t.p.tree_height, t.p.idx_bytes);

    test_rng_reset(0xDEADBEEF42ULL);

    /* Keygen */
    ret = xmss_mt_keygen(&t.p, t.pk, t.sk, t.state, 0, test_randombytes);
    TEST_INT("keygen", ret, XMSS_OK);
    if (ret != XMSS_OK) { goto done; }

    /* Sign */
    ret = xmss_mt_sign(&t.p, t.sig, (const uint8_t *)msg, msglen, t.sk, t.state, 0);
    TEST_INT("sign", ret, XMSS_OK);
    if (ret != XMSS_OK) { goto done; }

    /* Verify valid signature */
    ret = xmss_mt_verify(&t.p, (const uint8_t *)msg, msglen, t.sig, t.pk);
    TEST_INT("verify valid sig", ret, XMSS_OK);

    /* Bit-flip rejection */
    {
        uint8_t *bad_sig = (uint8_t *)malloc(t.p.sig_bytes);
        memcpy(bad_sig, t.sig, t.p.sig_bytes);
        bad_sig[t.p.sig_bytes / 2] ^= 0x01;
        ret = xmss_mt_verify(&t.p, (const uint8_t *)msg, msglen, bad_sig, t.pk);
        TEST_INT("verify bit-flipped sig fails", ret, XMSS_ERR_VERIFY);
        free(bad_sig);
    }

    /* Corrupted PK OID rejection */
    {
        uint8_t *bad_pk = (uint8_t *)malloc(t.p.pk_bytes);
        memcpy(bad_pk, t.pk, t.p.pk_bytes);
        bad_pk[0] ^= 0x01;
        ret = xmss_mt_verify(&t.p, (const uint8_t *)msg, msglen, t.sig, bad_pk);
        TEST_INT("verify corrupted PK OID fails", ret, XMSS_ERR_VERIFY);
        free(bad_pk);
    }

    /* Wrong message rejection */
    {
        const char *bad_msg = "Hello, XMSS-MT?";
        ret = xmss_mt_verify(&t.p, (const uint8_t *)bad_msg, msglen, t.sig, t.pk);
        TEST_INT("verify wrong message fails", ret, XMSS_ERR_VERIFY);
    }

    /* Index should be 1 after one signature */
    {
        uint64_t idx = 0;
        uint32_t i;
        for (i = 0; i < t.p.idx_bytes; i++) {
            idx = (idx << 8) | t.sk[4 + i];
        }
        TEST_INT("idx incremented to 1", (int)idx, 1);
    }

done:
    xmss_mt_test_ctx_free(&t);
}

static void test_sequential(void)
{
    xmss_mt_test_ctx t;
    char label[128];
    int i, rc;
    int nsigs = 5;

    printf("\n--- sequential signing (%d sigs) ---\n", nsigs);

    xmss_mt_test_ctx_init(&t, TEST_OID);

    test_rng_reset(0x1111222233334444ULL);
    rc = xmss_mt_keygen(&t.p, t.pk, t.sk, t.state, 0, test_randombytes);
    snprintf(label, sizeof(label), "sequential keygen");
    TEST_INT(label, rc, XMSS_OK);
    if (rc != XMSS_OK) { xmss_mt_test_ctx_free(&t); return; }

    for (i = 0; i < nsigs; i++) {
        uint8_t msg[4];
        msg[0] = (uint8_t)i;
        msg[1] = (uint8_t)(i + 1);
        msg[2] = (uint8_t)(i * 3);
        msg[3] = (uint8_t)(i ^ 0x55);

        rc = xmss_mt_sign(&t.p, t.sig, msg, sizeof(msg), t.sk, t.state, 0);
        if (rc != XMSS_OK) {
            snprintf(label, sizeof(label), "sign idx=%d", i);
            TEST(label, 0);
            break;
        }

        rc = xmss_mt_verify(&t.p, msg, sizeof(msg), t.sig, t.pk);
        snprintf(label, sizeof(label), "verify idx=%d", i);
        TEST(label, rc == XMSS_OK);
    }

    xmss_mt_test_ctx_free(&t);
}

static void test_tree_boundary(void)
{
    xmss_mt_test_ctx t;
    int i, rc;
    char label[128];
    uint32_t boundary;

    printf("\n--- tree boundary crossing ---\n");

    xmss_mt_test_ctx_init(&t, TEST_OID);

    /* tree_height=10, so layer-0 tree boundary is at idx=1024 */
    boundary = (uint32_t)1 << t.p.tree_height;
    printf("  tree_height=%u, boundary at idx=%u\n", t.p.tree_height, boundary);

    test_rng_reset(0xAAAABBBBCCCCDDDDULL);
    rc = xmss_mt_keygen(&t.p, t.pk, t.sk, t.state, 0, test_randombytes);
    snprintf(label, sizeof(label), "tree_boundary keygen");
    TEST_INT(label, rc, XMSS_OK);
    if (rc != XMSS_OK) { xmss_mt_test_ctx_free(&t); return; }

    /* Sign up to the boundary and a few past it */
    for (i = 0; i < (int)(boundary + 3); i++) {
        uint8_t msg[4];
        msg[0] = (uint8_t)(i >> 0);
        msg[1] = (uint8_t)(i >> 8);
        msg[2] = (uint8_t)(i >> 16);
        msg[3] = (uint8_t)(i >> 24);

        rc = xmss_mt_sign(&t.p, t.sig, msg, sizeof(msg), t.sk, t.state, 0);
        if (rc != XMSS_OK) {
            snprintf(label, sizeof(label), "sign idx=%d FAILED", i);
            TEST(label, 0);
            break;
        }

        /* Verify a few key signatures: first, last-before-boundary,
         * first-after-boundary, and a few more after */
        if (i == 0 || i == (int)(boundary - 1) || i == (int)boundary ||
            i == (int)(boundary + 1) || i == (int)(boundary + 2)) {
            rc = xmss_mt_verify(&t.p, msg, sizeof(msg), t.sig, t.pk);
            snprintf(label, sizeof(label), "verify idx=%d", i);
            TEST(label, rc == XMSS_OK);
        }

        if (i % 200 == 0) {
            printf("  signed %d/%u...\n", i, boundary + 3);
        }
    }

    printf("  signed %u signatures total\n", boundary + 3);

    xmss_mt_test_ctx_free(&t);
}

/* Test a second parameter set: keygen + sign + verify */
static void test_param_set(uint32_t oid, const char *name)
{
    xmss_mt_test_ctx t;
    const char *msg = "param set test";
    size_t msglen = strlen(msg);
    int ret;
    char label[128];

    printf("\n  [%s]\n", name);

    if (xmss_mt_test_ctx_init(&t, oid) != 0) {
        printf("  SKIP: unrecognised OID 0x%08x\n", oid);
        return;
    }

    test_rng_reset(0xCAFEBABEDEADBEEFULL);
    ret = xmss_mt_keygen(&t.p, t.pk, t.sk, t.state, 0, test_randombytes);
    snprintf(label, sizeof(label), "%s keygen", name);
    TEST_INT(label, ret, XMSS_OK);
    if (ret != XMSS_OK) { goto done; }

    ret = xmss_mt_sign(&t.p, t.sig, (const uint8_t *)msg, msglen, t.sk, t.state, 0);
    snprintf(label, sizeof(label), "%s sign", name);
    TEST_INT(label, ret, XMSS_OK);
    if (ret != XMSS_OK) { goto done; }

    ret = xmss_mt_verify(&t.p, (const uint8_t *)msg, msglen, t.sig, t.pk);
    snprintf(label, sizeof(label), "%s verify", name);
    TEST_INT(label, ret, XMSS_OK);

done:
    xmss_mt_test_ctx_free(&t);
}

/* bds_k=2 roundtrip */
static void test_bds_k2(void)
{
    xmss_mt_test_ctx t;
    const char *msg = "bds_k=2 test";
    size_t msglen = strlen(msg);
    int ret;

    printf("\n--- bds_k=2 roundtrip ---\n");

    xmss_mt_test_ctx_init(&t, TEST_OID);

    test_rng_reset(0x8899AABBCCDDEEFFULL);
    ret = xmss_mt_keygen(&t.p, t.pk, t.sk, t.state, 2, test_randombytes);
    TEST_INT("bds_k=2 keygen", ret, XMSS_OK);
    if (ret != XMSS_OK) { goto done; }

    ret = xmss_mt_sign(&t.p, t.sig, (const uint8_t *)msg, msglen, t.sk, t.state, 2);
    TEST_INT("bds_k=2 sign", ret, XMSS_OK);
    if (ret != XMSS_OK) { goto done; }

    ret = xmss_mt_verify(&t.p, (const uint8_t *)msg, msglen, t.sig, t.pk);
    TEST_INT("bds_k=2 verify", ret, XMSS_OK);

done:
    xmss_mt_test_ctx_free(&t);
}

/* bds_k=2 with tree_height=5 (20/4): boundary crossing.
 * Regression test: floor((H-K)/2) = 1 update/sign starves treehash[2],
 * causing wrong auth paths from idx=16 onward. Needs ceil((H-K)/2) = 2. */
static void test_bds_k2_h5_boundary(void)
{
    xmss_mt_test_ctx t;
    uint8_t msg[32];
    char label[128];
    int ret;
    uint32_t boundary;

    printf("\n--- bds_k=2 tree_height=5 boundary crossing ---\n");

    xmss_mt_test_ctx_init(&t, OID_XMSS_MT_SHA2_20_4_256);
    boundary = (uint32_t)1 << t.p.tree_height;
    printf("  tree_height=%u, boundary at idx=%u\n", t.p.tree_height, boundary);

    test_rng_reset(0xBD55A2DEADULL);
    ret = xmss_mt_keygen(&t.p, t.pk, t.sk, t.state, 2, test_randombytes);
    TEST_INT("bds_k=2 h=5 keygen", ret, XMSS_OK);
    if (ret != XMSS_OK) { xmss_mt_test_ctx_free(&t); return; }

    /* Sign and verify every index through the boundary */
    for (uint32_t i = 0; i < boundary + 1; i++) {
        memset(msg, 0, sizeof(msg));
        msg[0] = (uint8_t)(i & 0xFF);
        msg[1] = (uint8_t)(i >> 8);

        ret = xmss_mt_sign(&t.p, t.sig, msg, sizeof(msg), t.sk, t.state, 2);
        if (ret != XMSS_OK) {
            snprintf(label, sizeof(label), "bds_k=2 h=5 sign idx=%u", i);
            TEST_INT(label, ret, XMSS_OK);
            break;
        }

        ret = xmss_mt_verify(&t.p, msg, sizeof(msg), t.sig, t.pk);
        snprintf(label, sizeof(label), "bds_k=2 h=5 verify idx=%u", i);
        TEST_INT(label, ret, XMSS_OK);
        if (ret != XMSS_OK) break;
    }

    xmss_mt_test_ctx_free(&t);
}

/* Message boundary tests: empty message and block-boundary-length message */
static void test_message_boundaries(void)
{
    xmss_mt_test_ctx t;
    uint8_t msg64[64];
    char label[128];
    int ret;
    size_t i;

    printf("\n--- message boundary tests ---\n");

    xmss_mt_test_ctx_init(&t, TEST_OID);

    test_rng_reset(0x0102030405060708ULL);
    ret = xmss_mt_keygen(&t.p, t.pk, t.sk, t.state, 0, test_randombytes);
    snprintf(label, sizeof(label), "XMSS-MT keygen");
    TEST_INT(label, ret, XMSS_OK);
    if (ret != XMSS_OK) { xmss_mt_test_ctx_free(&t); return; }

    /* Empty message */
    ret = xmss_mt_sign(&t.p, t.sig, (const uint8_t *)"", 0, t.sk, t.state, 0);
    snprintf(label, sizeof(label), "XMSS-MT sign empty msg");
    TEST_INT(label, ret, XMSS_OK);
    ret = xmss_mt_verify(&t.p, (const uint8_t *)"", 0, t.sig, t.pk);
    snprintf(label, sizeof(label), "XMSS-MT verify empty msg");
    TEST_INT(label, ret, XMSS_OK);

    /* 64-byte message (SHA-256 block boundary) */
    for (i = 0; i < sizeof(msg64); i++) { msg64[i] = (uint8_t)(i + 1); }
    ret = xmss_mt_sign(&t.p, t.sig, msg64, sizeof(msg64), t.sk, t.state, 0);
    snprintf(label, sizeof(label), "XMSS-MT sign 64-byte msg");
    TEST_INT(label, ret, XMSS_OK);
    ret = xmss_mt_verify(&t.p, msg64, sizeof(msg64), t.sig, t.pk);
    snprintf(label, sizeof(label), "XMSS-MT verify 64-byte msg");
    TEST_INT(label, ret, XMSS_OK);

    xmss_mt_test_ctx_free(&t);
}

/* Cross-key rejection: signature under key A must not verify under key B */
static void test_cross_key(void)
{
    xmss_mt_test_ctx a, b;
    const char *msg = "cross-key xmss-mt";
    size_t msglen = strlen(msg);
    int ret;

    printf("\n--- cross-key rejection ---\n");

    xmss_mt_test_ctx_init(&a, TEST_OID);
    xmss_mt_test_ctx_init(&b, TEST_OID);

    test_rng_reset(0x1122334455667788ULL);
    ret = xmss_mt_keygen(&a.p, a.pk, a.sk, a.state, 0, test_randombytes);
    TEST_INT("cross-key keygen_a", ret, XMSS_OK);
    if (ret != XMSS_OK) { goto done; }

    test_rng_reset(0x8877665544332211ULL);
    ret = xmss_mt_keygen(&b.p, b.pk, b.sk, b.state, 0, test_randombytes);
    TEST_INT("cross-key keygen_b", ret, XMSS_OK);
    if (ret != XMSS_OK) { goto done; }

    ret = xmss_mt_sign(&a.p, a.sig, (const uint8_t *)msg, msglen, a.sk, a.state, 0);
    TEST_INT("cross-key sign", ret, XMSS_OK);
    if (ret != XMSS_OK) { goto done; }

    ret = xmss_mt_verify(&a.p, (const uint8_t *)msg, msglen, a.sig, b.pk);
    TEST_INT("cross-key rejection", ret, XMSS_ERR_VERIFY);

done:
    xmss_mt_test_ctx_free(&a);
    xmss_mt_test_ctx_free(&b);
}

/* Remaining-signatures query for XMSS-MT */
static void test_remaining_sigs(void)
{
    xmss_mt_test_ctx t;
    uint64_t rem;
    uint32_t i;
    int rc;

    printf("\n--- remaining signatures query ---\n");

    xmss_mt_test_ctx_init(&t, TEST_OID);
    test_rng_reset(0xDEADC0DEULL);
    rc = xmss_mt_keygen(&t.p, t.pk, t.sk, t.state, 0, test_randombytes);
    TEST_INT("MT: keygen", rc, XMSS_OK);
    if (rc != XMSS_OK) { xmss_mt_test_ctx_free(&t); return; }

    /* After keygen: remaining == 2^h */
    rem = xmss_mt_remaining_sigs(&t.p, t.sk);
    TEST_INT("MT: remaining after keygen == 2^h",
             (long long)rem, (long long)(t.p.idx_max + 1));

    /* After one signature: remaining == 2^h - 1 */
    rc = xmss_mt_sign(&t.p, t.sig, (const uint8_t *)"x", 1, t.sk, t.state, 0);
    TEST_INT("MT: sign idx=0", rc, XMSS_OK);
    if (rc != XMSS_OK) { xmss_mt_test_ctx_free(&t); return; }
    rem = xmss_mt_remaining_sigs(&t.p, t.sk);
    TEST_INT("MT: remaining after 1 sign == 2^h-1",
             (long long)rem, (long long)(t.p.idx_max));

    /* Set idx to idx_max directly: remaining == 1 */
    for (i = 0; i < t.p.idx_bytes; i++) {
        t.sk[4 + i] = (uint8_t)(t.p.idx_max >> (8 * (t.p.idx_bytes - 1 - i)));
    }
    rem = xmss_mt_remaining_sigs(&t.p, t.sk);
    TEST_INT("MT: remaining at idx_max == 1", (long long)rem, 1LL);

    /* Set idx beyond idx_max: key exhausted, remaining == 0 */
    for (i = 0; i < t.p.idx_bytes; i++) {
        uint64_t exhausted = t.p.idx_max + 1;
        t.sk[4 + i] = (uint8_t)(exhausted >> (8 * (t.p.idx_bytes - 1 - i)));
    }
    rem = xmss_mt_remaining_sigs(&t.p, t.sk);
    TEST_INT("MT: remaining when exhausted == 0", (long long)rem, 0LL);

    xmss_mt_test_ctx_free(&t);
}

int main(void)
{
    printf("=== test_xmss_mt ===\n");

    test_roundtrip();
    test_sequential();
    test_tree_boundary();

    printf("\n--- additional parameter sets ---\n");
    test_param_set(OID_XMSS_MT_SHAKE_20_2_256, "XMSSMT-SHAKE_20/2_256");
    test_param_set(OID_XMSS_MT_SHA2_20_4_256,  "XMSSMT-SHA2_20/4_256");

    test_message_boundaries();
    test_bds_k2();
    test_bds_k2_h5_boundary();
    test_cross_key();
    test_remaining_sigs();

    return tests_done();
}
