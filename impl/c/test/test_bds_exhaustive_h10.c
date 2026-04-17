/**
 * test_bds_exhaustive_h10.c - Exhaustive BDS H=10 test (slow, labelled "deep")
 *
 * Signs and verifies ALL 1024 indices for H=10 via XMSS-SHA2_10_256 for each
 * of K=0, K=2, K=4 — covering all valid even K values (H-K = 10, 8, 6).
 *
 * Exercises:
 *   - All treehash completion/consumption cycles
 *   - All retain node usage patterns
 *   - High-tau events (idx = 2^k - 1)
 *   - BDS exhaustion edge cases (treehash reinit when startidx >= 2^H)
 *   - BDS state invariant validation after every signature
 *
 * The treehash completion assertion in bds.c (active in debug builds) provides
 * the invariant check: if any treehash instance is consumed before completion,
 * the process aborts with a clear message.
 *
 * Runs in ~10 minutes (1024 sigs x 3 K values).  Part of the "deep" tier.
 * See test_bds_exhaustive_h5.c for the fast H=5 core tests.
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

int main(void)
{
    printf("=== test_bds_exhaustive_h10: H=10 (XMSS-SHA2_10_256) ===\n");

    /* H-K = 10 (even), 8 (even), 6 (even) — all valid K values for H=10 */
    printf("\n========== H=10 (XMSS-SHA2_10_256) ==========\n");
    test_xmss_full_tree(OID_XMSS_SHA2_10_256, "XMSS-SHA2_10_256", 0);
    test_xmss_full_tree(OID_XMSS_SHA2_10_256, "XMSS-SHA2_10_256", 2);
    test_xmss_full_tree(OID_XMSS_SHA2_10_256, "XMSS-SHA2_10_256", 4);

    return tests_done();
}
