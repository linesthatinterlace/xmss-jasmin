/* test_ltree.c — C harness for L-tree Jasmin tests
 *
 * Tests:
 * 1. Smoke test: output is non-zero
 * 2. Determinism: same inputs → same output
 * 3. Sensitivity: different pk → different root
 * 4. Sensitivity: different seed → different root
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define N 32
#define LEN 67

extern uint64_t test_ltree(uint8_t *root, uint8_t *pk, const uint8_t *seed,
                            const uint8_t *adrs_bytes);

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

int main(void) {
    uint8_t seed[N], seed2[N];
    uint8_t adrs_bytes[32];
    uint8_t pk[LEN * N], pk_copy[LEN * N];
    uint8_t root1[N], root2[N];
    int pass = 1;

    fill_deterministic(seed, N, 0x10);
    fill_deterministic(seed2, N, 0x20);
    fill_deterministic(pk, LEN * N, 0x30);

    /* ADRS: type=1 (L-tree), ltree index=3 */
    memset(adrs_bytes, 0, 32);
    adrs_bytes[15] = 0x01; /* type = 1 (word 3, big-endian) */
    adrs_bytes[19] = 0x03; /* ltree index = 3 (word 4, big-endian) */

    printf("=== L-tree Jasmin Test ===\n\n");

    /* Test 1: smoke test */
    printf("Test 1: ltree smoke test... ");
    fflush(stdout);
    memcpy(pk_copy, pk, LEN * N);
    test_ltree(root1, pk_copy, seed, adrs_bytes);

    int nonzero = 0;
    for (int i = 0; i < N; i++)
        if (root1[i] != 0) nonzero = 1;

    if (nonzero) {
        printf("OK (non-zero output)\n");
    } else {
        printf("FAIL (all zeros)\n");
        pass = 0;
    }
    hex_print("  root", root1, N);

    /* Test 2: determinism */
    printf("\nTest 2: determinism... ");
    fflush(stdout);
    memcpy(pk_copy, pk, LEN * N);
    test_ltree(root2, pk_copy, seed, adrs_bytes);

    if (memcmp(root1, root2, N) == 0) {
        printf("OK (same output)\n");
    } else {
        printf("FAIL (different output)\n");
        hex_print("  root1", root1, N);
        hex_print("  root2", root2, N);
        pass = 0;
    }

    /* Test 3: different pk → different root */
    printf("\nTest 3: pk sensitivity... ");
    fflush(stdout);
    memcpy(pk_copy, pk, LEN * N);
    pk_copy[0] ^= 0xFF; /* flip first byte */
    test_ltree(root2, pk_copy, seed, adrs_bytes);

    if (memcmp(root1, root2, N) != 0) {
        printf("OK (different root)\n");
    } else {
        printf("FAIL (same root despite different pk)\n");
        pass = 0;
    }

    /* Test 4: different seed → different root */
    printf("\nTest 4: seed sensitivity... ");
    fflush(stdout);
    memcpy(pk_copy, pk, LEN * N);
    test_ltree(root2, pk_copy, seed2, adrs_bytes);

    if (memcmp(root1, root2, N) != 0) {
        printf("OK (different root)\n");
    } else {
        printf("FAIL (same root despite different seed)\n");
        pass = 0;
    }

    printf("\n%s\n", pass ? "All tests passed." : "SOME TESTS FAILED.");
    return pass ? 0 : 1;
}
