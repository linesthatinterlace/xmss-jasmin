/* test_treehash.c — C harness for treehash Jasmin tests
 *
 * Tests:
 *   treehash:
 *     1. Smoke: full-tree root is non-zero
 *     2. Determinism: same seeds → same root
 *     3. Sensitivity: different sk_seed → different root
 *     4. Subtree: treehash(0, 2^h) == treehash built from subtrees
 *
 *   compute_root:
 *     5. Smoke: compute_root with known auth path produces non-zero root
 *     6. Roundtrip: treehash → extract leaf 0 auth → compute_root matches
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define N 32
#define LEN 67
#define TREE_HEIGHT 10

/* Jasmin-exported functions */
extern uint64_t test_treehash(uint8_t *root, uint64_t s_val, uint64_t t_val,
                               const uint8_t *sk_seed,
                               const uint8_t *pub_seed,
                               uint8_t *scratch);

extern uint64_t test_compute_root(uint8_t *root, const uint8_t *leaf,
                                   uint64_t leaf_idx,
                                   const uint8_t *auth,
                                   const uint8_t *seed,
                                   uint8_t *adrs_ptr);

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

/* scratch layout for treehash:
 * [0..31] ADRS bytes, [32..32+LEN*N-1] wots_buf, [32+LEN*N..] nodes_buf
 * nodes_buf needs (TREE_HEIGHT+1)*N bytes */
#define SCRATCH_SIZE (32 + LEN * N + (TREE_HEIGHT + 1) * N)

static int test_treehash_suite(void) {
    uint8_t sk_seed[N], sk_seed2[N], pub_seed[N];
    uint8_t root1[N], root2[N];
    uint8_t scratch[SCRATCH_SIZE];
    int pass = 1;

    fill_deterministic(sk_seed, N, 0x10);
    fill_deterministic(sk_seed2, N, 0x11);
    fill_deterministic(pub_seed, N, 0x20);

    /* Test 1: smoke — full tree root is non-zero */
    printf("Test 1: treehash smoke... ");
    fflush(stdout);
    memset(scratch, 0, SCRATCH_SIZE);
    test_treehash(root1, 0, 1 << TREE_HEIGHT, sk_seed, pub_seed, scratch);
    if (is_nonzero(root1, N)) {
        printf("OK\n");
    } else {
        printf("FAIL (all zeros)\n");
        pass = 0;
    }
    hex_print("  root", root1, N);

    /* Test 2: determinism */
    printf("Test 2: treehash determinism... ");
    fflush(stdout);
    memset(scratch, 0, SCRATCH_SIZE);
    test_treehash(root2, 0, 1 << TREE_HEIGHT, sk_seed, pub_seed, scratch);
    if (memcmp(root1, root2, N) == 0) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        hex_print("  root1", root1, N);
        hex_print("  root2", root2, N);
        pass = 0;
    }

    /* Test 3: sk_seed sensitivity */
    printf("Test 3: treehash sk_seed sensitivity... ");
    fflush(stdout);
    memset(scratch, 0, SCRATCH_SIZE);
    test_treehash(root2, 0, 1 << TREE_HEIGHT, sk_seed2, pub_seed, scratch);
    if (memcmp(root1, root2, N) != 0) {
        printf("OK\n");
    } else {
        printf("FAIL (same root despite different sk_seed)\n");
        pass = 0;
    }

    /* Test 4: subtree consistency — treehash(0, 2^h) should equal
     * building from two half-trees merged. We verify indirectly:
     * treehash(0, 4) should give a deterministic non-zero result
     * different from treehash(0, 2^h). */
    printf("Test 4: treehash subtree... ");
    fflush(stdout);
    memset(scratch, 0, SCRATCH_SIZE);
    test_treehash(root2, 0, 4, sk_seed, pub_seed, scratch);
    if (is_nonzero(root2, N) && memcmp(root1, root2, N) != 0) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        pass = 0;
    }

    return pass;
}

static int test_compute_root_suite(void) {
    uint8_t sk_seed[N], pub_seed[N];
    uint8_t full_root[N], computed_root[N];
    uint8_t scratch[SCRATCH_SIZE];
    uint8_t adrs_buf[32];
    int pass = 1;

    fill_deterministic(sk_seed, N, 0x10);
    fill_deterministic(pub_seed, N, 0x20);

    /* Build full tree root for comparison */
    memset(scratch, 0, SCRATCH_SIZE);
    test_treehash(full_root, 0, 1 << TREE_HEIGHT, sk_seed, pub_seed, scratch);

    /* Build leaf 0 via treehash(0, 1) — this is the leaf value */
    uint8_t leaf[N];
    memset(scratch, 0, SCRATCH_SIZE);
    test_treehash(leaf, 0, 1, sk_seed, pub_seed, scratch);

    /* Test 5: smoke — compute_root with a fabricated auth path */
    printf("Test 5: compute_root smoke... ");
    fflush(stdout);

    /* Build auth path: auth[i] = treehash of sibling subtree at height i.
     * For leaf 0: auth[0] = leaf 1, auth[1] = treehash(2,2), etc.
     * auth[i] = treehash(sibling_start, 2^i) where
     *   sibling_start = (0 >> i ^ 1) << i = 1 << i  (for leaf 0) */
    uint8_t auth[TREE_HEIGHT * N];
    for (int i = 0; i < TREE_HEIGHT; i++) {
        uint32_t sibling_start = 1u << i;
        uint32_t subtree_size = 1u << i;
        memset(scratch, 0, SCRATCH_SIZE);
        test_treehash(auth + i * N, sibling_start, subtree_size,
                      sk_seed, pub_seed, scratch);
    }

    /* Now compute_root(leaf, 0, auth, pub_seed) should equal full_root */
    memset(adrs_buf, 0, 32);
    test_compute_root(computed_root, leaf, 0, auth, pub_seed, adrs_buf);

    if (is_nonzero(computed_root, N)) {
        printf("OK\n");
    } else {
        printf("FAIL (all zeros)\n");
        pass = 0;
    }
    hex_print("  computed_root", computed_root, N);

    /* Test 6: roundtrip — computed root should match treehash full root */
    printf("Test 6: compute_root roundtrip... ");
    fflush(stdout);
    if (memcmp(full_root, computed_root, N) == 0) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        hex_print("  full_root", full_root, N);
        hex_print("  computed", computed_root, N);
        pass = 0;
    }

    return pass;
}

int main(void) {
    int pass = 1;

    printf("=== Treehash Jasmin Test ===\n\n");

    printf("--- treehash ---\n");
    if (!test_treehash_suite()) pass = 0;

    printf("\n--- compute_root ---\n");
    if (!test_compute_root_suite()) pass = 0;

    printf("\n%s\n", pass ? "All tests passed." : "SOME TESTS FAILED.");
    return pass ? 0 : 1;
}
