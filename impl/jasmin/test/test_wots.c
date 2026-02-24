/* test_wots.c — C harness for WOTS+ Jasmin tests
 *
 * Tests:
 * 1. wots_gen_pk: generates a public key (smoke test)
 * 2. sign → pk_from_sig roundtrip: sign a message, recover pk, compare
 * 3. Wrong message: pk_from_sig with different message should differ
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define N 32
#define W 16
#define LEN 67

/* Jasmin-exported functions */
extern uint64_t test_wots_gen_pk(uint8_t *pk, const uint8_t *sk_seed,
                                  const uint8_t *pub_seed,
                                  const uint8_t *adrs_bytes);

extern uint64_t test_wots_sign(uint8_t *sig, const uint8_t *msg,
                                const uint8_t *sk_seed,
                                const uint8_t *pub_seed,
                                const uint8_t *adrs_bytes);

extern uint64_t test_wots_pk_from_sig(uint8_t *pk, const uint8_t *sig,
                                       const uint8_t *msg,
                                       const uint8_t *pub_seed,
                                       const uint8_t *adrs_bytes);

static void hex_print(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len && i < 16; i++)
        printf("%02x", data[i]);
    if (len > 16) printf("...");
    printf("\n");
}

/* Deterministic "random" fill for reproducibility */
static void fill_deterministic(uint8_t *buf, size_t len, uint8_t seed_byte) {
    for (size_t i = 0; i < len; i++)
        buf[i] = (uint8_t)((seed_byte * 37 + i * 13 + 7) & 0xFF);
}

int main(void) {
    uint8_t sk_seed[N], pub_seed[N], msg[N], msg2[N];
    uint8_t adrs_bytes[32]; /* ADRS serialized as big-endian u32[8] */
    uint8_t pk1[LEN * N], pk2[LEN * N];
    uint8_t sig[LEN * N];
    int pass = 1;

    /* Initialize test data */
    fill_deterministic(sk_seed, N, 0x01);
    fill_deterministic(pub_seed, N, 0x02);
    fill_deterministic(msg, N, 0x03);
    fill_deterministic(msg2, N, 0x04);
    memset(adrs_bytes, 0, 32);
    /* Set type = 0 (OTS), OTS address = 5 (word 4, big-endian) */
    adrs_bytes[19] = 0x05; /* word 4, byte 3 = OTS index 5 */

    printf("=== WOTS+ Jasmin Test ===\n\n");

    /* Test 1: gen_pk smoke test */
    printf("Test 1: wots_gen_pk... ");
    fflush(stdout);
    test_wots_gen_pk(pk1, sk_seed, pub_seed, adrs_bytes);
    /* Check pk is not all zeros */
    int nonzero = 0;
    for (int i = 0; i < LEN * N; i++)
        if (pk1[i] != 0) nonzero = 1;
    if (nonzero) {
        printf("OK (non-zero output)\n");
    } else {
        printf("FAIL (all zeros)\n");
        pass = 0;
    }
    hex_print("  pk[0..31]", pk1, N);

    /* Test 2: sign → pk_from_sig roundtrip */
    printf("\nTest 2: sign -> pk_from_sig roundtrip... ");
    fflush(stdout);
    test_wots_sign(sig, msg, sk_seed, pub_seed, adrs_bytes);
    test_wots_pk_from_sig(pk2, sig, msg, pub_seed, adrs_bytes);

    if (memcmp(pk1, pk2, LEN * N) == 0) {
        printf("OK (pk matches)\n");
    } else {
        printf("FAIL (pk mismatch)\n");
        hex_print("  gen_pk[0..31]", pk1, N);
        hex_print("  from_sig[0..31]", pk2, N);
        pass = 0;
    }

    /* Test 3: wrong message should produce different pk */
    printf("\nTest 3: wrong message detection... ");
    fflush(stdout);
    test_wots_pk_from_sig(pk2, sig, msg2, pub_seed, adrs_bytes);

    if (memcmp(pk1, pk2, LEN * N) != 0) {
        printf("OK (different pk for different msg)\n");
    } else {
        printf("FAIL (same pk for different msg)\n");
        pass = 0;
    }

    printf("\n%s\n", pass ? "All tests passed." : "SOME TESTS FAILED.");
    return pass ? 0 : 1;
}
