/**
 * test_kat_xmss_sha2_10_256.c — KAT cross-validation for Jasmin XMSS-SHA2_10_256
 *
 * Validates that the Jasmin implementation produces byte-identical output to the
 * xmss-reference implementation (and therefore our C implementation) by:
 *
 *   1. Keygen with deterministic seeds (seed[i] = i for i = 0..95)
 *   2. SHAKE128-fingerprint pk (without 4-byte OID prefix) — validates tree root
 *   3. Advance BDS state to idx=512 by signing 512 dummy messages
 *   4. Sign single-byte message {37} at idx=512
 *   5. SHAKE128-fingerprint sig — validates auth path at idx=512
 *   6. Verify the signature
 *   7. Compare fingerprints against xmss-reference test/vectors.c values
 *
 * Reference fingerprints (same as impl/c/test/test_xmss_kat.c):
 *   PK:  7de72d192121f414d4bb
 *   Sig: 8b6cb278d50a3694ca38
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../include/jade_sign_xmss.h"
#include "shake_local.h"

#define PK_BYTES      JADE_SIGN_XMSS_SHA2_10_256_PUBLICKEYBYTES
#define SK_BYTES      JADE_SIGN_XMSS_SHA2_10_256_SECRETKEYBYTES
#define SIG_BYTES     JADE_SIGN_XMSS_SHA2_10_256_BYTES
#define STATE_BYTES   JADE_SIGN_XMSS_SHA2_10_256_STATEBYTES
#define SEED_BYTES    JADE_SIGN_XMSS_SHA2_10_256_SEEDBYTES
#define SCRATCH_BYTES JADE_SIGN_XMSS_SHA2_10_256_SCRATCHBYTES

#define TREE_HEIGHT   10
#define TARGET_IDX    (1 << (TREE_HEIGHT - 1))  /* 512 */

static const char *EXPECTED_PK_HASH  = "7de72d192121f414d4bb";
static const char *EXPECTED_SIG_HASH = "8b6cb278d50a3694ca38";

static int hex_decode(uint8_t *out, const char *hex, size_t nbytes)
{
    size_t i;
    for (i = 0; i < nbytes; i++) {
        unsigned int v = 0;
        if (sscanf(hex + 2*i, "%02x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

static void hex_print(const char *label, const uint8_t *data, size_t len)
{
    size_t i;
    printf("%s: ", label);
    for (i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

int main(void)
{
    uint8_t seeds[SEED_BYTES];
    uint8_t pk[PK_BYTES];
    uint8_t sk[SK_BYTES];
    uint8_t __attribute__((aligned(16))) state[STATE_BYTES];
    uint8_t scratch[SCRATCH_BYTES];
    uint8_t sig[SIG_BYTES];
    uint8_t msg[1] = {37};
    uint8_t dummy[1] = {0};
    uint8_t fp[10], expected[10];
    uint32_t i;
    uint64_t ret;
    int pass = 1;

    printf("=== test_kat_xmss_sha2_10_256 (cross-validated against xmss-reference) ===\n");
    printf("    Target: sign at idx=%d (after %d dummy signs)\n\n", TARGET_IDX, TARGET_IDX);

    /* Deterministic seeds: seed[i] = i */
    for (i = 0; i < SEED_BYTES; i++)
        seeds[i] = (uint8_t)i;

    /* Keygen */
    printf("Keygen... ");
    fflush(stdout);
    memset(state, 0, STATE_BYTES);
    memset(scratch, 0, SCRATCH_BYTES);
    ret = jade_sign_xmss_sha2_10_256_amd64_ref_keypair(pk, sk, state, seeds, scratch);
    if (ret != 0) {
        printf("FAIL (returned %lu)\n", (unsigned long)ret);
        return 1;
    }
    printf("OK\n");

    /* PK fingerprint: SHAKE128(pk+4, pk_bytes-4) — skip OID */
    shake128_local(fp, 10, pk + 4, PK_BYTES - 4);
    hex_decode(expected, EXPECTED_PK_HASH, 10);
    printf("PK fingerprint... ");
    if (memcmp(fp, expected, 10) != 0) {
        printf("FAIL\n");
        hex_print("  expected", expected, 10);
        hex_print("  got     ", fp, 10);
        pass = 0;
    } else {
        printf("PASS\n");
    }

    /* Advance BDS state to target_idx by signing dummy messages */
    printf("Advancing BDS state to idx=%d... ", TARGET_IDX);
    fflush(stdout);
    for (i = 0; i < TARGET_IDX; i++) {
        memset(scratch, 0, SCRATCH_BYTES);
        ret = jade_sign_xmss_sha2_10_256_amd64_ref(sig, dummy, 1, sk, state, scratch);
        if (ret != 0) {
            printf("FAIL (sign at idx=%u returned %lu)\n", i, (unsigned long)ret);
            return 1;
        }
    }
    printf("OK\n");

    /* Sign KAT message {37} at target_idx */
    printf("Sign msg={37} at idx=%d... ", TARGET_IDX);
    fflush(stdout);
    memset(scratch, 0, SCRATCH_BYTES);
    ret = jade_sign_xmss_sha2_10_256_amd64_ref(sig, msg, 1, sk, state, scratch);
    if (ret != 0) {
        printf("FAIL (returned %lu)\n", (unsigned long)ret);
        return 1;
    }
    printf("OK\n");

    /* Sig fingerprint: SHAKE128(sig, sig_bytes) */
    shake128_local(fp, 10, sig, SIG_BYTES);
    hex_decode(expected, EXPECTED_SIG_HASH, 10);
    printf("Sig fingerprint... ");
    if (memcmp(fp, expected, 10) != 0) {
        printf("FAIL\n");
        hex_print("  expected", expected, 10);
        hex_print("  got     ", fp, 10);
        pass = 0;
    } else {
        printf("PASS\n");
    }

    /* Verify the signature */
    printf("Verify... ");
    fflush(stdout);
    memset(scratch, 0, SCRATCH_BYTES);
    ret = jade_sign_xmss_sha2_10_256_amd64_ref_open(msg, 1, sig, pk, scratch);
    if (ret != 0) {
        printf("FAIL (returned %lu)\n", (unsigned long)ret);
        pass = 0;
    } else {
        printf("PASS\n");
    }

    printf("\n%s\n", pass ? "All KAT checks passed." : "SOME KAT CHECKS FAILED.");
    return pass ? 0 : 1;
}
