/**
 * test_bds_exhaustive.c - Exhaustive BDS (H,K) matrix tests
 *
 * Signs and verifies EVERY index from 0 to 2^H-1 for each feasible (H,K)
 * combination, exercising the full BDS state machine including:
 *   - All treehash completion/consumption cycles
 *   - All retain node usage patterns
 *   - High-tau events (idx = 2^k - 1)
 *   - BDS exhaustion edge cases (treehash reinit when startidx >= 2^H)
 *
 * The treehash completion assertion in bds.c (active in debug builds) provides
 * the invariant check: if any treehash instance is consumed before completion,
 * the process aborts with a clear message.
 *
 * Test matrix:
 *   H=5  via XMSS-MT 20/4 (tree_height=5): K=0 only — 32 sigs
 *         (K=0 is the only valid value for H=5: no even K>0 gives even H-K)
 *   H=10 via XMSS single-tree:              K=0, K=2, K=4  — 1024 sigs each
 *
 * H=5 tests are fast (<1s).  H=10 tests are slow (~2-4 min each).
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "test_utils.h"
#include "../include/xmss/params.h"
#include "../include/xmss/xmss.h"

/* ====================================================================
 * BDS state validation helper
 *
 * Called after each xmss_sign() to check BDS state invariants beyond
 * what the in-code assertion covers.  This runs in all builds (not
 * just debug) and produces test failures rather than aborts.
 * ==================================================================== */
static int bds_validate_state(const xmss_params *p,
                              const xmss_bds_state *state,
                              uint32_t bds_k,
                              uint32_t signed_idx,
                              char *err, size_t errlen)
{
    uint32_t i;
    uint32_t num_th = p->tree_height - bds_k;

    /* 1. Stack offset must be within bounds */
    if (state->stack_offset > p->tree_height + 1) {
        snprintf(err, errlen, "stack_offset=%u exceeds max=%u (idx=%u)",
                 state->stack_offset, p->tree_height + 1, signed_idx);
        return -1;
    }

    /* 2. After signing idx, the next leaf for treehash updates should be
     *    consistent.  Each treehash[i] that is active (completed==0) must
     *    have next_idx within [0, 2^H). */
    for (i = 0; i < num_th; i++) {
        if (!state->treehash[i].completed) {
            if (state->treehash[i].next_idx >= (uint32_t)1 << p->tree_height) {
                snprintf(err, errlen,
                         "treehash[%u].next_idx=%u >= 2^H=%u (idx=%u)",
                         i, state->treehash[i].next_idx,
                         (uint32_t)1 << p->tree_height, signed_idx);
                return -1;
            }
            if (state->treehash[i].h != i) {
                snprintf(err, errlen,
                         "treehash[%u].h=%u != expected %u (idx=%u)",
                         i, state->treehash[i].h, i, signed_idx);
                return -1;
            }
        }
    }

    /* 3. Stack usage per treehash instance must not exceed its target height */
    for (i = 0; i < num_th; i++) {
        if (!state->treehash[i].completed &&
            state->treehash[i].stack_usage > i + 1) {
            snprintf(err, errlen,
                     "treehash[%u].stack_usage=%u exceeds max=%u (idx=%u)",
                     i, state->treehash[i].stack_usage, i + 1, signed_idx);
            return -1;
        }
    }

    (void)signed_idx;
    return 0;
}

/* ====================================================================
 * Full-tree XMSS single-tree test (H=10)
 * ==================================================================== */
static void test_xmss_full_tree(uint32_t oid, const char *name, uint32_t bds_k)
{
    xmss_test_ctx t;
    char label[384];
    int rc;
    uint32_t tree_size, i;
    char err[256];

    xmss_test_ctx_init(&t, oid);
    tree_size = (uint32_t)1 << t.p.tree_height;

    printf("\n--- %s K=%u: signing all %u indices ---\n", name, bds_k, tree_size);

    test_rng_reset(0xBD50ULL + bds_k);
    rc = xmss_keygen(&t.p, t.pk, t.sk, t.state, bds_k, test_randombytes);
    snprintf(label, sizeof(label), "%s K=%u keygen", name, bds_k);
    TEST(label, rc == XMSS_OK);
    if (rc != XMSS_OK) { xmss_test_ctx_free(&t); return; }

    for (i = 0; i < tree_size; i++) {
        uint8_t msg[4];
        msg[0] = (uint8_t)(i >> 0);
        msg[1] = (uint8_t)(i >> 8);
        msg[2] = (uint8_t)(i >> 16);
        msg[3] = (uint8_t)(i >> 24);

        rc = xmss_sign(&t.p, t.sig, msg, sizeof(msg), t.sk, t.state, bds_k);
        if (rc != XMSS_OK) {
            snprintf(label, sizeof(label), "%s K=%u sign idx=%u", name, bds_k, i);
            TEST(label, 0);
            break;
        }

        /* Validate BDS state after every signature */
        if (bds_validate_state(&t.p, t.state, bds_k, i, err, sizeof(err)) != 0) {
            snprintf(label, sizeof(label), "%s K=%u state idx=%u: %s",
                     name, bds_k, i, err);
            TEST(label, 0);
            break;
        }

        /* Verify every signature (the critical check) */
        rc = xmss_verify(&t.p, msg, sizeof(msg), t.sig, t.pk);
        if (rc != XMSS_OK) {
            snprintf(label, sizeof(label), "%s K=%u verify idx=%u", name, bds_k, i);
            TEST(label, 0);
            break;
        }

        if (i % 256 == 0 && i > 0) {
            printf("  %u/%u...\n", i, tree_size);
        }
    }

    snprintf(label, sizeof(label), "%s K=%u: all %u signatures verified", name, bds_k, tree_size);
    TEST(label, i == tree_size);

    /* Test key exhaustion: next sign should fail */
    {
        uint8_t msg_ex[] = { 0xFF };
        rc = xmss_sign(&t.p, t.sig, msg_ex, 1, t.sk, t.state, bds_k);
        snprintf(label, sizeof(label), "%s K=%u: exhaustion after %u sigs", name, bds_k, tree_size);
        TEST(label, rc == XMSS_ERR_EXHAUSTED);
    }

    xmss_test_ctx_free(&t);
}

/* ====================================================================
 * Full-tree XMSS-MT test (uses tree_height from the MT param set)
 *
 * This exercises the per-layer BDS with tree_height=5 (for 20/4).
 * We sign through one full layer-0 tree boundary to exercise both
 * the BDS state machine and the XMSS-MT layer-crossing logic.
 * ==================================================================== */
static void test_xmss_mt_full_tree(uint32_t oid, const char *name, uint32_t bds_k)
{
    xmss_mt_test_ctx t;
    char label[384];
    int rc;
    uint32_t tree_size, i;

    xmss_mt_test_ctx_init(&t, oid);
    tree_size = (uint32_t)1 << t.p.tree_height;

    printf("\n--- %s K=%u tree_height=%u: signing all %u + 1 indices ---\n",
           name, bds_k, t.p.tree_height, tree_size);

    test_rng_reset(0xAE00ULL + bds_k);
    rc = xmss_mt_keygen(&t.p, t.pk, t.sk, t.state, bds_k, test_randombytes);
    snprintf(label, sizeof(label), "%s K=%u keygen", name, bds_k);
    TEST(label, rc == XMSS_OK);
    if (rc != XMSS_OK) { xmss_mt_test_ctx_free(&t); return; }

    /* Sign through one full tree boundary (tree_size + 1 sigs).
     * The +1 crosses the layer-0 boundary and exercises layer-1. */
    for (i = 0; i < tree_size + 1; i++) {
        uint8_t msg[4];
        msg[0] = (uint8_t)(i >> 0);
        msg[1] = (uint8_t)(i >> 8);
        msg[2] = (uint8_t)(i >> 16);
        msg[3] = (uint8_t)(i >> 24);

        rc = xmss_mt_sign(&t.p, t.sig, msg, sizeof(msg), t.sk, t.state, bds_k);
        if (rc != XMSS_OK) {
            snprintf(label, sizeof(label), "%s K=%u sign idx=%u", name, bds_k, i);
            TEST(label, 0);
            break;
        }

        /* Verify every signature */
        rc = xmss_mt_verify(&t.p, msg, sizeof(msg), t.sig, t.pk);
        if (rc != XMSS_OK) {
            snprintf(label, sizeof(label), "%s K=%u verify idx=%u", name, bds_k, i);
            TEST(label, 0);
            break;
        }
    }

    snprintf(label, sizeof(label), "%s K=%u: all %u signatures verified",
             name, bds_k, tree_size + 1);
    TEST(label, i == tree_size + 1);

    xmss_mt_test_ctx_free(&t);
}

int main(void)
{
    printf("=== test_bds_exhaustive: full (H,K) matrix ===\n");

    /* ---- H=5 via XMSS-MT 20/4 (tree_height=5) ---- */
    /* K=0 is the only valid value for H=5: no even K>0 gives even (H-K).
     * K=2 would give H-K=3 (odd), K=4 would give H-K=1 (odd). */

    printf("\n========== H=5 (XMSS-MT 20/4, tree_height=5) ==========\n");
    test_xmss_mt_full_tree(OID_XMSS_MT_SHA2_20_4_256, "XMSSMT-SHA2_20/4_256", 0);

    /* ---- H=10 via XMSS single-tree ---- */
    /* These are slow: 1024 sigs each, ~2-4 min */
    /* H-K = 10 (even), 8 (even), 6 (even) — complementary to H=5 */

    printf("\n========== H=10 (XMSS-SHA2_10_256) ==========\n");
    test_xmss_full_tree(OID_XMSS_SHA2_10_256, "XMSS-SHA2_10_256", 0);
    test_xmss_full_tree(OID_XMSS_SHA2_10_256, "XMSS-SHA2_10_256", 2);
    test_xmss_full_tree(OID_XMSS_SHA2_10_256, "XMSS-SHA2_10_256", 4);

    return tests_done();
}
