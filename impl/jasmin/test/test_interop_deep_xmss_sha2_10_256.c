/**
 * test_interop_deep_xmss_sha2_10_256.c — Deep cross-implementation interop
 *
 * Signs N messages with both C and Jasmin from the same seed, comparing
 * signatures byte-for-byte after EACH sign.  Any BDS state divergence
 * causes a sig mismatch because the auth path (embedded in the sig)
 * comes directly from BDS state.
 *
 * This catches state divergence that shallow interop tests (1 signature)
 * would miss — e.g. treehash starvation that only manifests at idx >= 16.
 *
 * XMSS-SHA2_10_256 (H=10, BDS_K=2): signs 64 messages.
 * Covers multiple treehash completion/reinit cycles and high-tau events.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* C implementation headers */
#include "xmss/xmss.h"
#include "xmss/params.h"

/* Jasmin API header */
#include "../include/jade_sign_xmss.h"

/* ---------- constants ---------- */

#define N           32
#define SEED_BYTES  96   /* 3 * N */
#define BDS_K       2    /* must match Jasmin param int BDS_K */
#define NUM_SIGS    64   /* deep enough to catch treehash cycle bugs */

/* C-side sizes */
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
    for (size_t i = 0; i < len && i < 20; i++)
        printf("%02x", data[i]);
    if (len > 20) printf("...");
    printf("\n");
}

/* Find first differing byte between two buffers, return offset or -1 */
static int find_first_diff(const uint8_t *a, const uint8_t *b, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (a[i] != b[i]) return (int)i;
    }
    return -1;
}

/* ---------- main ---------- */

int main(void)
{
    /* Deterministic seed: seeds[i] = i */
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

    int pass = 1;
    int ret;
    uint64_t jret;

    printf("=== Deep XMSS-SHA2_10_256 Interop: %d signatures ===\n\n", NUM_SIGS);

    /* ---- Keygen ---- */
    printf("Keygen... ");
    fflush(stdout);

    memset(&state_c, 0, sizeof(state_c));
    ret = xmss_keygen(&p, pk_c, sk_c, &state_c, BDS_K, replay_randombytes);
    if (ret != XMSS_OK) {
        printf("FAIL (C keygen returned %d)\n", ret);
        return 1;
    }

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
        pass = 0;
    } else if (memcmp(sk_c, sk_j, C_SK_BYTES) != 0) {
        printf("FAIL (SK mismatch)\n");
        pass = 0;
    } else {
        printf("OK (PK and SK match)\n");
    }

    /* ---- Deep sequential signing ---- */
    printf("\nSigning %d messages and comparing signatures...\n", NUM_SIGS);

    int sig_mismatches = 0;
    int sk_mismatches = 0;
    int first_sig_mismatch = -1;
    int first_sk_mismatch = -1;

    for (int i = 0; i < NUM_SIGS; i++) {
        uint8_t msg[4];
        msg[0] = (uint8_t)(i >> 0);
        msg[1] = (uint8_t)(i >> 8);
        msg[2] = (uint8_t)(i >> 16);
        msg[3] = (uint8_t)(i >> 24);

        /* C sign */
        ret = xmss_sign(&p, sig_c, msg, sizeof(msg), sk_c, &state_c, BDS_K);
        if (ret != XMSS_OK) {
            printf("  FAIL: C sign idx=%d returned %d\n", i, ret);
            pass = 0;
            break;
        }

        /* Jasmin sign */
        memset(scratch, 0, J_SCRATCH_BYTES);
        jret = jade_sign_xmss_sha2_10_256_amd64_ref(
            sig_j, msg, sizeof(msg), sk_j, state_j, scratch);
        if (jret != 0) {
            printf("  FAIL: Jasmin sign idx=%d returned %lu\n",
                   i, (unsigned long)jret);
            pass = 0;
            break;
        }

        /* Compare signatures byte-for-byte */
        int diff_off = find_first_diff(sig_c, sig_j, C_SIG_BYTES);
        if (diff_off >= 0) {
            sig_mismatches++;
            if (first_sig_mismatch < 0) {
                first_sig_mismatch = i;
                printf("  FAIL: sig mismatch at idx=%d, first diff at byte %d\n",
                       i, diff_off);
                /* Diagnose: which part of the sig differs? */
                int idx_end = (int)p.idx_bytes;
                int r_end = idx_end + (int)p.n;
                int wots_end = r_end + (int)(p.len * p.n);
                /* auth is everything after wots_end */
                if (diff_off < idx_end) {
                    printf("    Diff is in idx field\n");
                } else if (diff_off < r_end) {
                    printf("    Diff is in randomness r\n");
                } else if (diff_off < wots_end) {
                    printf("    Diff is in WOTS+ signature (offset %d into WOTS)\n",
                           diff_off - r_end);
                } else {
                    int auth_off = diff_off - wots_end;
                    int auth_level = auth_off / (int)p.n;
                    printf("    Diff is in auth path at level %d "
                           "(BDS state divergence)\n", auth_level);
                }
                hex_print("    C sig ", sig_c + diff_off, 32);
                hex_print("    J sig ", sig_j + diff_off, 32);
            }
            pass = 0;
        }

        /* Compare SK (index progression) */
        if (memcmp(sk_c, sk_j, C_SK_BYTES) != 0) {
            sk_mismatches++;
            if (first_sk_mismatch < 0) {
                first_sk_mismatch = i;
                printf("  FAIL: SK mismatch after sign idx=%d\n", i);
            }
            pass = 0;
        }

        /* Progress indicator */
        if ((i + 1) % 16 == 0) {
            printf("  %d/%d signatures compared%s\n", i + 1, NUM_SIGS,
                   sig_mismatches > 0 ? " (MISMATCHES FOUND)" : " OK");
        }
    }

    /* ---- Summary ---- */
    printf("\n--- Summary ---\n");
    printf("  Signatures compared: %d\n", NUM_SIGS);
    printf("  Signature mismatches: %d", sig_mismatches);
    if (first_sig_mismatch >= 0)
        printf(" (first at idx=%d)", first_sig_mismatch);
    printf("\n");
    printf("  SK mismatches: %d", sk_mismatches);
    if (first_sk_mismatch >= 0)
        printf(" (first at idx=%d)", first_sk_mismatch);
    printf("\n");

    /* ---- Cross-verify: C sig verified by Jasmin and vice versa ---- */
    /* Re-keygen for a clean final cross-check at a non-trivial index */
    printf("\n--- Cross-verification at final state ---\n");
    {
        uint8_t msg_final[4] = {0xFF, 0xFE, 0xFD, 0xFC};

        /* C's last signature should verify with Jasmin */
        memset(scratch, 0, J_SCRATCH_BYTES);
        jret = jade_sign_xmss_sha2_10_256_amd64_ref_open(
            msg_final, sizeof(msg_final), sig_c, pk_c, scratch);
        printf("  C sig[%d] -> Jasmin verify: %s\n",
               NUM_SIGS - 1, jret == 0 ? "OK" : "FAIL");
        if (jret != 0) pass = 0;

        /* Jasmin's last signature should verify with C */
        ret = xmss_verify(&p, msg_final, sizeof(msg_final), sig_j, pk_j);
        printf("  Jasmin sig[%d] -> C verify: %s\n",
               NUM_SIGS - 1, ret == XMSS_OK ? "OK" : "FAIL");
        if (ret != XMSS_OK) pass = 0;
    }

    printf("\n%s\n", pass ? "All deep interop tests passed." :
                            "DEEP INTEROP TESTS FAILED.");
    return pass ? 0 : 1;
}
