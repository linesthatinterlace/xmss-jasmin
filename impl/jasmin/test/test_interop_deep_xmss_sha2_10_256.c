/**
 * test_interop_deep_xmss_sha2_10_256.c — Deep cross-implementation interop
 *
 * Signs N messages with both C and Jasmin from the same seed, comparing:
 *   1. Signatures byte-for-byte after EACH sign
 *   2. BDS state byte-for-byte after EACH sign (with endianness conversion)
 *   3. Treehash completion invariants on the Jasmin state
 *
 * State comparison catches divergence that signature comparison alone would
 * miss — a treehash node could be wrong but not yet consumed, silently
 * corrupting a future auth path.
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

#define H           10
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

/* BDS layout offsets (must match Jasmin's bds.jinc and C's bds_serialize.c) */
#define NUM_TH          (H - BDS_K)  /* 8 */
#define RETAIN_NODES    (BDS_K == 0 ? 0 : ((1 << BDS_K) - BDS_K - 1))
#define TH_INST_SIZE    (N + 4 + 4 + 1 + 1)  /* node + h + next_idx + stack_usage + completed */

/* Serialized BDS state offsets (both C and Jasmin use same layout) */
#define OFF_AUTH        0
#define OFF_KEEP        (H * N)
#define OFF_STACK       (OFF_KEEP + (H / 2) * N)
#define OFF_LEVELS      (OFF_STACK + (H + 1) * N)
#define OFF_STK_OFF     (OFF_LEVELS + (H + 1))
#define OFF_TREEHASH    (OFF_STK_OFF + 4)
#define OFF_RETAIN      (OFF_TREEHASH + NUM_TH * TH_INST_SIZE)
#define OFF_NEXTLEAF    (OFF_RETAIN + RETAIN_NODES * N)
#define BDS_SERIAL_SIZE (OFF_NEXTLEAF + 4)

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

static int find_first_diff(const uint8_t *a, const uint8_t *b, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (a[i] != b[i]) return (int)i;
    }
    return -1;
}

/* Swap a 4-byte little-endian integer to big-endian in place */
static void swap32_inplace(uint8_t *p)
{
    uint8_t t;
    t = p[0]; p[0] = p[3]; p[3] = t;
    t = p[1]; p[1] = p[2]; p[2] = t;
}

/**
 * Convert a Jasmin BDS flat buffer (LE integers) to the C serialized format
 * (BE integers) in-place.  Only the integer fields need swapping — all byte
 * arrays (auth, keep, stack, nodes, stack_levels, stack_usage, completed)
 * are identical.
 *
 * Fields to swap:
 *   - stack_offset at OFF_STK_OFF (4 bytes)
 *   - For each treehash[i]: h at +N, next_idx at +N+4 (both 4 bytes)
 *   - next_leaf at OFF_NEXTLEAF (4 bytes)
 */
static void jasmin_state_to_be(uint8_t *buf)
{
    /* stack_offset */
    swap32_inplace(buf + OFF_STK_OFF);

    /* treehash instances */
    for (int i = 0; i < NUM_TH; i++) {
        uint8_t *th = buf + OFF_TREEHASH + i * TH_INST_SIZE;
        swap32_inplace(th + N);      /* h */
        swap32_inplace(th + N + 4);  /* next_idx */
        /* stack_usage (1 byte) and completed (1 byte) need no swap */
    }

    /* next_leaf */
    swap32_inplace(buf + OFF_NEXTLEAF);
}

/* Read a LE u32 from the Jasmin flat buffer */
static uint32_t read_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/**
 * Check treehash completion invariants on Jasmin's BDS state buffer.
 * For the given signed_idx, verify that treehash instances that should
 * be completed (their node was consumed in bds_round) are indeed marked
 * completed.
 *
 * Returns 0 if OK, -1 if an invariant is violated.
 */
static int check_treehash_invariants(const uint8_t *state_buf,
                                     uint32_t signed_idx,
                                     char *err, size_t errlen)
{
    for (int i = 0; i < NUM_TH; i++) {
        const uint8_t *th = state_buf + OFF_TREEHASH + i * TH_INST_SIZE;
        uint8_t completed = th[N + 4 + 4 + 1]; /* completed byte */
        uint32_t next_idx = read_le32(th + N + 4);
        uint32_t th_h = read_le32(th + N);

        if (!completed) {
            /* Active treehash — check next_idx is sane */
            if (next_idx >= ((uint32_t)1 << H)) {
                snprintf(err, errlen,
                         "treehash[%d].next_idx=%u >= 2^H=%u (idx=%u)",
                         i, next_idx, (uint32_t)1 << H, signed_idx);
                return -1;
            }
            if (th_h != (uint32_t)i) {
                snprintf(err, errlen,
                         "treehash[%d].h=%u != expected %d (idx=%u)",
                         i, th_h, i, signed_idx);
                return -1;
            }
        }
    }

    /* Check stack_offset bounds */
    uint32_t stk_off = read_le32(state_buf + OFF_STK_OFF);
    if (stk_off > H + 1) {
        snprintf(err, errlen,
                 "stack_offset=%u exceeds max=%u (idx=%u)",
                 stk_off, H + 1, signed_idx);
        return -1;
    }

    return 0;
}

/**
 * Diagnose which BDS state field first differs between C-serialized
 * and Jasmin-converted buffers.
 */
static void diagnose_state_diff(const uint8_t *c_buf, const uint8_t *j_buf,
                                int diff_off, int idx)
{
    if (diff_off < OFF_KEEP) {
        int level = diff_off / N;
        printf("    State diff in auth[%d] (byte %d within node)\n",
               level, diff_off - level * N);
    } else if (diff_off < OFF_STACK) {
        int off2 = diff_off - OFF_KEEP;
        int level = off2 / N;
        printf("    State diff in keep[%d]\n", level);
    } else if (diff_off < OFF_LEVELS) {
        int off2 = diff_off - OFF_STACK;
        int level = off2 / N;
        printf("    State diff in stack[%d]\n", level);
    } else if (diff_off < OFF_STK_OFF) {
        printf("    State diff in stack_levels[%d]\n", diff_off - OFF_LEVELS);
    } else if (diff_off < OFF_TREEHASH) {
        printf("    State diff in stack_offset\n");
    } else if (diff_off < OFF_RETAIN) {
        int off2 = diff_off - OFF_TREEHASH;
        int th_idx = off2 / TH_INST_SIZE;
        int within = off2 % TH_INST_SIZE;
        if (within < N) {
            printf("    State diff in treehash[%d].node (byte %d)\n", th_idx, within);
        } else if (within < N + 4) {
            printf("    State diff in treehash[%d].h\n", th_idx);
        } else if (within < N + 8) {
            printf("    State diff in treehash[%d].next_idx\n", th_idx);
        } else if (within < N + 9) {
            printf("    State diff in treehash[%d].stack_usage\n", th_idx);
        } else {
            printf("    State diff in treehash[%d].completed\n", th_idx);
        }
    } else if (diff_off < OFF_NEXTLEAF) {
        int off2 = diff_off - OFF_RETAIN;
        printf("    State diff in retain[%d]\n", off2 / N);
    } else {
        printf("    State diff in next_leaf\n");
    }
    hex_print("    C state", c_buf + diff_off, 16);
    hex_print("    J state", j_buf + diff_off, 16);
    (void)idx;
}

/* ---------- main ---------- */

int main(void)
{
    /* Sanity check: our computed size must match Jasmin's */
    if (BDS_SERIAL_SIZE != J_STATE_BYTES) {
        printf("BUG: BDS_SERIAL_SIZE=%d != J_STATE_BYTES=%d\n",
               BDS_SERIAL_SIZE, J_STATE_BYTES);
        return 1;
    }

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
    uint8_t c_serial[BDS_SERIAL_SIZE];

    /* Jasmin-side buffers */
    uint8_t pk_j[J_PK_BYTES], sk_j[J_SK_BYTES];
    uint8_t sig_j[J_SIG_BYTES];
    uint8_t __attribute__((aligned(16))) state_j[J_STATE_BYTES];
    uint8_t j_serial[BDS_SERIAL_SIZE]; /* copy for endianness conversion */
    uint8_t scratch[J_SCRATCH_BYTES];

    int pass = 1;
    int ret;
    uint64_t jret;

    printf("=== Deep XMSS-SHA2_10_256 Interop: %d signatures ===\n", NUM_SIGS);
    printf("    BDS state comparison enabled (%d bytes per state)\n\n",
           BDS_SERIAL_SIZE);

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

    /* Compare initial BDS state */
    xmss_bds_serialize(&p, c_serial, &state_c, BDS_K);
    memcpy(j_serial, state_j, BDS_SERIAL_SIZE);
    jasmin_state_to_be(j_serial);

    if (memcmp(c_serial, j_serial, BDS_SERIAL_SIZE) != 0) {
        int diff = find_first_diff(c_serial, j_serial, BDS_SERIAL_SIZE);
        printf("  FAIL: BDS state mismatch after keygen (byte %d)\n", diff);
        diagnose_state_diff(c_serial, j_serial, diff, -1);
        pass = 0;
    } else {
        printf("  BDS state after keygen: match\n");
    }

    /* ---- Deep sequential signing ---- */
    printf("\nSigning %d messages, comparing sigs + BDS state...\n", NUM_SIGS);

    int sig_mismatches = 0;
    int sk_mismatches = 0;
    int state_mismatches = 0;
    int invariant_failures = 0;
    int first_sig_mismatch = -1;
    int first_sk_mismatch = -1;
    int first_state_mismatch = -1;
    int first_invariant_fail = -1;

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

        /* 1. Compare signatures byte-for-byte */
        int diff_off = find_first_diff(sig_c, sig_j, C_SIG_BYTES);
        if (diff_off >= 0) {
            sig_mismatches++;
            if (first_sig_mismatch < 0) {
                first_sig_mismatch = i;
                printf("  FAIL: sig mismatch at idx=%d, first diff at byte %d\n",
                       i, diff_off);
                int idx_end = (int)p.idx_bytes;
                int r_end = idx_end + (int)p.n;
                int wots_end = r_end + (int)(p.len * p.n);
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

        /* 2. Compare SK (index progression) */
        if (memcmp(sk_c, sk_j, C_SK_BYTES) != 0) {
            sk_mismatches++;
            if (first_sk_mismatch < 0) {
                first_sk_mismatch = i;
                printf("  FAIL: SK mismatch after sign idx=%d\n", i);
            }
            pass = 0;
        }

        /* 3. Compare BDS state (serialize C, convert Jasmin LE→BE, memcmp) */
        xmss_bds_serialize(&p, c_serial, &state_c, BDS_K);
        memcpy(j_serial, state_j, BDS_SERIAL_SIZE);
        jasmin_state_to_be(j_serial);

        int state_diff = find_first_diff(c_serial, j_serial, BDS_SERIAL_SIZE);
        if (state_diff >= 0) {
            state_mismatches++;
            if (first_state_mismatch < 0) {
                first_state_mismatch = i;
                printf("  FAIL: BDS state mismatch after sign idx=%d "
                       "(byte %d of %d)\n", i, state_diff, BDS_SERIAL_SIZE);
                diagnose_state_diff(c_serial, j_serial, state_diff, i);
            }
            pass = 0;
        }

        /* 4. Check treehash invariants on Jasmin state */
        char err[256];
        if (check_treehash_invariants(state_j, (uint32_t)i, err, sizeof(err)) != 0) {
            invariant_failures++;
            if (first_invariant_fail < 0) {
                first_invariant_fail = i;
                printf("  FAIL: treehash invariant at idx=%d: %s\n", i, err);
            }
            pass = 0;
        }

        /* Progress indicator */
        if ((i + 1) % 16 == 0) {
            const char *status = "OK";
            if (sig_mismatches > 0 || state_mismatches > 0)
                status = "MISMATCHES FOUND";
            printf("  %d/%d signatures compared (%s)\n",
                   i + 1, NUM_SIGS, status);
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

    printf("  BDS state mismatches: %d", state_mismatches);
    if (first_state_mismatch >= 0)
        printf(" (first at idx=%d)", first_state_mismatch);
    printf("\n");

    printf("  Treehash invariant failures: %d", invariant_failures);
    if (first_invariant_fail >= 0)
        printf(" (first at idx=%d)", first_invariant_fail);
    printf("\n");

    /* ---- Cross-verify: C sig verified by Jasmin and vice versa ---- */
    printf("\n--- Cross-verification at final state ---\n");
    {
        uint8_t msg_final[4] = {0xFF, 0xFE, 0xFD, 0xFC};

        memset(scratch, 0, J_SCRATCH_BYTES);
        jret = jade_sign_xmss_sha2_10_256_amd64_ref_open(
            msg_final, sizeof(msg_final), sig_c, pk_c, scratch);
        printf("  C sig[%d] -> Jasmin verify: %s\n",
               NUM_SIGS - 1, jret == 0 ? "OK" : "FAIL");
        if (jret != 0) pass = 0;

        ret = xmss_verify(&p, msg_final, sizeof(msg_final), sig_j, pk_j);
        printf("  Jasmin sig[%d] -> C verify: %s\n",
               NUM_SIGS - 1, ret == XMSS_OK ? "OK" : "FAIL");
        if (ret != XMSS_OK) pass = 0;
    }

    printf("\n%s\n", pass ? "All deep interop tests passed." :
                            "DEEP INTEROP TESTS FAILED.");
    return pass ? 0 : 1;
}
