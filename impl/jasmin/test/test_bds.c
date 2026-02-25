/* test_bds.c — C harness for BDS Jasmin tests
 *
 * Self-consistency tests (no cross-validation against C reference):
 *
 * bds_treehash_init:
 *   1. Smoke: root is non-zero
 *   2. Determinism: same seeds → same root + same state
 *   3. Sensitivity: different sk_seed → different root
 *
 * bds_round + bds_treehash_update (integrated):
 *   4. Round changes auth path
 *   5. Determinism: repeat from same state → same result
 *   6. Sequential: several round+update cycles, auth changes each time
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define N 32
#define LEN 67
#define TREE_HEIGHT 10
#define BDS_K 2

/* BDS state layout — must match bds.jinc offsets */
#define BDS_AUTH_OFF     0
#define BDS_KEEP_OFF     (TREE_HEIGHT * N)
#define BDS_STACK_OFF    ((TREE_HEIGHT + TREE_HEIGHT / 2) * N)
#define BDS_LEVELS_OFF   ((TREE_HEIGHT + TREE_HEIGHT / 2 + TREE_HEIGHT + 1) * N)
#define BDS_STKOFF_OFF   (BDS_LEVELS_OFF + (TREE_HEIGHT + 1))
#define TH_INST_SIZE     (N + 10)
#define BDS_TH_OFF       (BDS_STKOFF_OFF + 4)
#define NUM_TH           (TREE_HEIGHT - BDS_K)
#define BDS_RETAIN_OFF   (BDS_TH_OFF + NUM_TH * TH_INST_SIZE)
#define RETAIN_NODES     ((1 << BDS_K) - BDS_K - 1)
#define BDS_NEXTLEAF_OFF (BDS_RETAIN_OFF + RETAIN_NODES * N)
#define BDS_STATE_BYTES  (BDS_NEXTLEAF_OFF + 4)

/* Jasmin-exported functions */
extern uint64_t test_bds_treehash_init(uint8_t *root, uint8_t *state,
                                        const uint8_t *sk_seed,
                                        const uint8_t *pub_seed,
                                        uint8_t *scratch);

extern uint64_t test_bds_round(uint8_t *state, uint64_t leaf_idx,
                                const uint8_t *sk_seed,
                                const uint8_t *pub_seed,
                                uint8_t *scratch);

extern uint64_t test_bds_treehash_update(uint8_t *state, uint64_t updates,
                                          const uint8_t *sk_seed,
                                          const uint8_t *pub_seed,
                                          uint8_t *scratch);

static void hex_print(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len && i < 16; i++)
        printf("%02x", data[i]);
    if (len > 16) printf("...");
    printf("\n");
}

static void fill_deterministic(uint8_t *buf, size_t len, uint8_t seed_byte) {
    for (size_t i = 0; i < len; i++)
        buf[i] = (uint8_t)((seed_byte * 37 + i * 13 + 7) & 0xFF);
}

static int is_nonzero(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++)
        if (buf[i] != 0) return 1;
    return 0;
}

/* scratch layout: [0..31] ADRS, [32..32+LEN*N+N-1] wots_buf */
#define SCRATCH_SIZE (32 + LEN * N + N)

static int test_treehash_init_suite(void) {
    uint8_t sk_seed[N], sk_seed2[N], pub_seed[N];
    uint8_t root1[N], root2[N];
    uint8_t __attribute__((aligned(16))) state1[BDS_STATE_BYTES];
    uint8_t __attribute__((aligned(16))) state2[BDS_STATE_BYTES];
    uint8_t scratch[SCRATCH_SIZE];
    int pass = 1;

    fill_deterministic(sk_seed, N, 0x10);
    fill_deterministic(sk_seed2, N, 0x11);
    fill_deterministic(pub_seed, N, 0x20);

    /* Test 1: smoke */
    printf("Test 1: bds_treehash_init smoke... ");
    fflush(stdout);
    memset(state1, 0, BDS_STATE_BYTES);
    memset(scratch, 0, SCRATCH_SIZE);
    test_bds_treehash_init(root1, state1, sk_seed, pub_seed, scratch);
    if (is_nonzero(root1, N)) {
        printf("OK\n");
    } else {
        printf("FAIL (all zeros)\n");
        pass = 0;
    }
    hex_print("  root", root1, N);

    /* Test 2: determinism */
    printf("Test 2: bds_treehash_init determinism... ");
    fflush(stdout);
    memset(state2, 0, BDS_STATE_BYTES);
    memset(scratch, 0, SCRATCH_SIZE);
    test_bds_treehash_init(root2, state2, sk_seed, pub_seed, scratch);
    if (memcmp(root1, root2, N) == 0 &&
        memcmp(state1, state2, BDS_STATE_BYTES) == 0) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        if (memcmp(root1, root2, N) != 0) {
            hex_print("  root1", root1, N);
            hex_print("  root2", root2, N);
        }
        if (memcmp(state1, state2, BDS_STATE_BYTES) != 0) {
            printf("  state mismatch\n");
        }
        pass = 0;
    }

    /* Test 3: sensitivity */
    printf("Test 3: bds_treehash_init sk_seed sensitivity... ");
    fflush(stdout);
    memset(state2, 0, BDS_STATE_BYTES);
    memset(scratch, 0, SCRATCH_SIZE);
    test_bds_treehash_init(root2, state2, sk_seed2, pub_seed, scratch);
    if (memcmp(root1, root2, N) != 0) {
        printf("OK\n");
    } else {
        printf("FAIL (same root despite different sk_seed)\n");
        pass = 0;
    }

    return pass;
}

static int test_round_update_suite(void) {
    uint8_t sk_seed[N], pub_seed[N];
    uint8_t root[N];
    uint8_t __attribute__((aligned(16))) state[BDS_STATE_BYTES];
    uint8_t __attribute__((aligned(16))) state_copy[BDS_STATE_BYTES];
    uint8_t auth_before[TREE_HEIGHT * N];
    uint8_t auth_after[TREE_HEIGHT * N];
    uint8_t auth_after2[TREE_HEIGHT * N];
    uint8_t scratch[SCRATCH_SIZE];
    int pass = 1;

    fill_deterministic(sk_seed, N, 0x10);
    fill_deterministic(pub_seed, N, 0x20);

    /* First, init the BDS state */
    memset(state, 0, BDS_STATE_BYTES);
    memset(scratch, 0, SCRATCH_SIZE);
    test_bds_treehash_init(root, state, sk_seed, pub_seed, scratch);

    /* Save auth path before round */
    memcpy(auth_before, state + BDS_AUTH_OFF, TREE_HEIGHT * N);
    /* Save state for determinism test */
    memcpy(state_copy, state, BDS_STATE_BYTES);

    /* Test 4: round changes auth path */
    printf("Test 4: bds_round changes auth... ");
    fflush(stdout);
    memset(scratch, 0, SCRATCH_SIZE);
    test_bds_round(state, 0, sk_seed, pub_seed, scratch);
    memset(scratch, 0, SCRATCH_SIZE);
    test_bds_treehash_update(state, (TREE_HEIGHT - BDS_K) / 2 + 1, sk_seed, pub_seed, scratch);
    memcpy(auth_after, state + BDS_AUTH_OFF, TREE_HEIGHT * N);
    if (memcmp(auth_before, auth_after, TREE_HEIGHT * N) != 0) {
        printf("OK\n");
    } else {
        printf("FAIL (auth unchanged after round)\n");
        pass = 0;
    }

    /* Test 5: determinism — repeat from saved state */
    printf("Test 5: bds_round determinism... ");
    fflush(stdout);
    memcpy(state, state_copy, BDS_STATE_BYTES);
    memset(scratch, 0, SCRATCH_SIZE);
    test_bds_round(state, 0, sk_seed, pub_seed, scratch);
    memset(scratch, 0, SCRATCH_SIZE);
    test_bds_treehash_update(state, (TREE_HEIGHT - BDS_K) / 2 + 1, sk_seed, pub_seed, scratch);
    memcpy(auth_after2, state + BDS_AUTH_OFF, TREE_HEIGHT * N);
    if (memcmp(auth_after, auth_after2, TREE_HEIGHT * N) == 0) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        pass = 0;
    }

    /* Test 6: sequential rounds — auth changes each time */
    printf("Test 6: sequential rounds... ");
    fflush(stdout);
    /* Reset state */
    memset(state, 0, BDS_STATE_BYTES);
    memset(scratch, 0, SCRATCH_SIZE);
    test_bds_treehash_init(root, state, sk_seed, pub_seed, scratch);

    int all_different = 1;
    for (uint32_t idx = 0; idx < 4; idx++) {
        memcpy(auth_before, state + BDS_AUTH_OFF, TREE_HEIGHT * N);
        memset(scratch, 0, SCRATCH_SIZE);
        test_bds_round(state, idx, sk_seed, pub_seed, scratch);
        memset(scratch, 0, SCRATCH_SIZE);
        test_bds_treehash_update(state, (TREE_HEIGHT - BDS_K) / 2 + 1, sk_seed, pub_seed, scratch);
        if (memcmp(auth_before, state + BDS_AUTH_OFF, TREE_HEIGHT * N) == 0) {
            printf("\n  FAIL at idx=%u (auth unchanged)\n", idx);
            all_different = 0;
            break;
        }
    }
    if (all_different) {
        printf("OK (4 rounds)\n");
    } else {
        pass = 0;
    }

    return pass;
}

int main(void) {
    int pass = 1;

    printf("=== BDS Jasmin Test ===\n");
    printf("BDS state size: %d bytes\n\n", BDS_STATE_BYTES);

    printf("--- bds_treehash_init ---\n");
    if (!test_treehash_init_suite()) pass = 0;

    printf("\n--- bds_round + bds_treehash_update ---\n");
    if (!test_round_update_suite()) pass = 0;

    printf("\n%s\n", pass ? "All tests passed." : "SOME TESTS FAILED.");
    return pass ? 0 : 1;
}
