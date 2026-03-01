/**
 * test_interop_xmss_sha2_10_256.c — Cross-implementation verification (C ↔ Jasmin)
 *
 * Links against both libxmss.a (C impl) and xmss_sha2_10_256.s (Jasmin).
 * Tests:
 *   1. Keygen with same seeds → PK and SK match byte-for-byte
 *   2. C sign → Jasmin verify
 *   3. Jasmin sign → C verify
 *   4. Wrong-message rejection in both directions
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* C implementation headers */
#include "xmss/xmss.h"
#include "xmss/params.h"

/* Jasmin API header */
#include "../include/jade_sign_xmss.h"

/* ---------- constants ---------- */

#define N           32
#define SEED_BYTES  96   /* 3 * N */
#define BDS_K       2    /* must match Jasmin param int BDS_K */

/* C-side sizes (from params) */
#define C_PK_BYTES  68
#define C_SK_BYTES  136
#define C_SIG_BYTES 2500

/* Jasmin-side sizes */
#define J_PK_BYTES      JADE_SIGN_XMSS_SHA2_10_256_PUBLICKEYBYTES
#define J_SK_BYTES      JADE_SIGN_XMSS_SHA2_10_256_SECRETKEYBYTES
#define J_SIG_BYTES     JADE_SIGN_XMSS_SHA2_10_256_BYTES
#define J_STATE_BYTES   JADE_SIGN_XMSS_SHA2_10_256_STATEBYTES
#define J_SCRATCH_BYTES JADE_SIGN_XMSS_SHA2_10_256_SCRATCHBYTES

/* ---------- replay callback for C keygen ---------- */

static uint8_t replay_buf[SEED_BYTES];

static int replay_randombytes(uint8_t *buf, size_t len)
{
    if (len > SEED_BYTES) return -1;
    memcpy(buf, replay_buf, len);
    return 0;
}

/* ---------- helpers ---------- */

static void hex_print(const char *label, const uint8_t *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len && i < 16; i++)
        printf("%02x", data[i]);
    if (len > 16) printf("...");
    printf("\n");
}

/* ---------- main ---------- */

int main(void)
{
    /* Shared seed: seeds[i] = i */
    uint8_t seeds[SEED_BYTES];
    for (int i = 0; i < SEED_BYTES; i++)
        seeds[i] = (uint8_t)i;
    memcpy(replay_buf, seeds, SEED_BYTES);

    /* C-side buffers */
    xmss_params p;
    xmss_params_from_oid(&p, OID_XMSS_SHA2_10_256);
    uint8_t pk_c[C_PK_BYTES], sk_c[C_SK_BYTES];
    uint8_t sig_c[C_SIG_BYTES];
    xmss_bds_state state_c;

    /* Jasmin-side buffers */
    uint8_t pk_j[J_PK_BYTES], sk_j[J_SK_BYTES];
    uint8_t sig_j[J_SIG_BYTES];
    uint8_t __attribute__((aligned(16))) state_j[J_STATE_BYTES];
    uint8_t scratch[J_SCRATCH_BYTES];

    uint8_t msg[64];
    for (int i = 0; i < 64; i++)
        msg[i] = (uint8_t)(0x42 + i);

    int pass = 1;
    int ret;
    uint64_t jret;

    printf("=== XMSS-SHA2_10_256 Cross-Implementation Interop ===\n\n");

    /* ---- Test 1: keygen match ---- */
    printf("Test 1: keygen PK/SK match... ");
    fflush(stdout);

    /* C keygen */
    memset(&state_c, 0, sizeof(state_c));
    ret = xmss_keygen(&p, pk_c, sk_c, &state_c, BDS_K, replay_randombytes);
    if (ret != XMSS_OK) {
        printf("FAIL (C keygen returned %d)\n", ret);
        return 1;
    }

    /* Jasmin keygen */
    memset(state_j, 0, J_STATE_BYTES);
    memset(scratch, 0, J_SCRATCH_BYTES);
    jret = jade_sign_xmss_sha2_10_256_amd64_ref_keypair(
        pk_j, sk_j, state_j, seeds, scratch);
    if (jret != 0) {
        printf("FAIL (Jasmin keygen returned %lu)\n", (unsigned long)jret);
        return 1;
    }

    if (memcmp(pk_c, pk_j, C_PK_BYTES) != 0) {
        printf("FAIL (PK mismatch)\n");
        hex_print("  C PK ", pk_c, C_PK_BYTES);
        hex_print("  J PK ", pk_j, J_PK_BYTES);
        pass = 0;
    } else if (memcmp(sk_c, sk_j, C_SK_BYTES) != 0) {
        printf("FAIL (SK mismatch)\n");
        hex_print("  C SK ", sk_c, C_SK_BYTES);
        hex_print("  J SK ", sk_j, J_SK_BYTES);
        pass = 0;
    } else {
        printf("OK\n");
    }

    /* ---- Test 2: C sign → Jasmin verify ---- */
    printf("Test 2: C sign -> Jasmin verify... ");
    fflush(stdout);

    /* Re-keygen both sides (signing mutates SK and state) */
    memset(&state_c, 0, sizeof(state_c));
    xmss_keygen(&p, pk_c, sk_c, &state_c, BDS_K, replay_randombytes);

    memset(state_j, 0, J_STATE_BYTES);
    memset(scratch, 0, J_SCRATCH_BYTES);
    jade_sign_xmss_sha2_10_256_amd64_ref_keypair(
        pk_j, sk_j, state_j, seeds, scratch);

    ret = xmss_sign(&p, sig_c, msg, sizeof(msg), sk_c, &state_c, BDS_K);
    if (ret != XMSS_OK) {
        printf("FAIL (C sign returned %d)\n", ret);
        pass = 0;
    } else {
        memset(scratch, 0, J_SCRATCH_BYTES);
        jret = jade_sign_xmss_sha2_10_256_amd64_ref_open(
            msg, sizeof(msg), sig_c, pk_c, scratch);
        if (jret == 0) {
            printf("OK\n");
        } else {
            printf("FAIL (Jasmin verify returned %lu)\n", (unsigned long)jret);
            pass = 0;
        }
    }

    /* ---- Test 3: Jasmin sign → C verify ---- */
    printf("Test 3: Jasmin sign -> C verify... ");
    fflush(stdout);

    memset(scratch, 0, J_SCRATCH_BYTES);
    jret = jade_sign_xmss_sha2_10_256_amd64_ref(
        sig_j, msg, sizeof(msg), sk_j, state_j, scratch);
    if (jret != 0) {
        printf("FAIL (Jasmin sign returned %lu)\n", (unsigned long)jret);
        pass = 0;
    } else {
        ret = xmss_verify(&p, msg, sizeof(msg), sig_j, pk_j);
        if (ret == XMSS_OK) {
            printf("OK\n");
        } else {
            printf("FAIL (C verify returned %d)\n", ret);
            pass = 0;
        }
    }

    /* ---- Test 4: wrong-message rejection (both directions) ---- */
    printf("Test 4a: C sig + wrong msg -> Jasmin rejects... ");
    fflush(stdout);
    {
        uint8_t bad_msg[64];
        memcpy(bad_msg, msg, sizeof(msg));
        bad_msg[0] ^= 0x01;
        memset(scratch, 0, J_SCRATCH_BYTES);
        jret = jade_sign_xmss_sha2_10_256_amd64_ref_open(
            bad_msg, sizeof(bad_msg), sig_c, pk_c, scratch);
        if (jret != 0) {
            printf("OK\n");
        } else {
            printf("FAIL (Jasmin accepted wrong message)\n");
            pass = 0;
        }
    }

    printf("Test 4b: Jasmin sig + wrong msg -> C rejects... ");
    fflush(stdout);
    {
        uint8_t bad_msg[64];
        memcpy(bad_msg, msg, sizeof(msg));
        bad_msg[0] ^= 0x01;
        ret = xmss_verify(&p, bad_msg, sizeof(bad_msg), sig_j, pk_j);
        if (ret != XMSS_OK) {
            printf("OK\n");
        } else {
            printf("FAIL (C accepted wrong message)\n");
            pass = 0;
        }
    }

    printf("\n%s\n", pass ? "All interop tests passed." : "SOME INTEROP TESTS FAILED.");
    return pass ? 0 : 1;
}
