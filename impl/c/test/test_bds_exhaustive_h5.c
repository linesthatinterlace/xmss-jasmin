/**
 * test_bds_exhaustive_h5.c - Exhaustive BDS H=5 test (fast, labelled "core")
 *
 * Signs and verifies ALL 32 indices for H=5 via XMSS-MT 20/4 (tree_height=5)
 * with K=0 (the only valid value for H=5: no even K>0 gives even H-K).
 *
 * Exercises:
 *   - All treehash completion/consumption cycles
 *   - All retain node usage patterns
 *   - High-tau events (idx = 2^k - 1)
 *   - BDS exhaustion edge cases
 *
 * The treehash completion assertion in bds.c (active in debug builds) provides
 * the invariant check: if any treehash instance is consumed before completion,
 * the process aborts with a clear message.
 *
 * Runs in < 1 s.  Part of the "core" tier.
 * See test_bds_exhaustive_h10.c for the slow H=10 deep tests.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "test_utils.h"
#include "../include/xmss/params.h"
#include "../include/xmss/xmss.h"

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
    printf("=== test_bds_exhaustive_h5: H=5 (XMSS-MT 20/4) ===\n");

    /* K=0 is the only valid value for H=5: no even K>0 gives even (H-K).
     * K=2 would give H-K=3 (odd), K=4 would give H-K=1 (odd). */
    printf("\n========== H=5 (XMSS-MT 20/4, tree_height=5) ==========\n");
    test_xmss_mt_full_tree(OID_XMSS_MT_SHA2_20_4_256, "XMSSMT-SHA2_20/4_256", 0);

    return tests_done();
}
