/* test_xmssmt.c — C harness for XMSS-MT keygen/sign/verify Jasmin tests
 *
 * Tests:
 *   1. Keygen smoke: root non-zero, OID correct
 *   2. Keygen determinism: same seeds → same PK, SK, state
 *   3. Sign+verify roundtrip
 *   4. Wrong message rejection
 *   5. Wrong signature rejection
 *   6. Sequential signing: 5 messages, verify each
 *   7. Tree boundary crossing: 1024 signatures (full layer-0 tree)
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define N 32
#define LEN 67
#define TREE_HEIGHT 10
#define BDS_K 2
#define D 2
#define FULL_H 20
#define IDX_BYTES 3

/* BDS state size — must match bds.jinc */
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

/* MT state layout */
#define MT_NUM_BDS       (2 * D - 1)
#define MT_BDS_SIZE      (MT_NUM_BDS * BDS_STATE_BYTES)
#define MT_WOTS_SIG_SIZE (LEN * N)
#define MT_STATE_BYTES   (MT_NUM_BDS * BDS_STATE_BYTES + (D - 1) * LEN * N)

/* SK layout: OID(4) | idx(IDX_BYTES) | SK_SEED(N) | SK_PRF(N) | root(N) | SEED(N) */
#define MT_SK_IDX_OFF      4
#define MT_SK_SEED_OFF     (4 + IDX_BYTES)
#define MT_SK_PRF_OFF      (4 + IDX_BYTES + N)
#define MT_SK_ROOT_OFF     (4 + IDX_BYTES + 2 * N)
#define MT_SK_PUB_SEED_OFF (4 + IDX_BYTES + 3 * N)
#define MT_SK_BYTES        (4 + IDX_BYTES + 4 * N)

/* PK layout */
#define MT_PK_ROOT_OFF  4
#define MT_PK_SEED_OFF  (4 + N)
#define MT_PK_BYTES     (4 + 2 * N)

/* Sig layout */
#define MT_SIG_R_OFF     IDX_BYTES
#define MT_SIG_DATA_OFF  (IDX_BYTES + N)
#define MT_REDUCED_SIG   (LEN * N + TREE_HEIGHT * N)
#define MT_SIG_BYTES     (IDX_BYTES + N + D * (LEN * N + TREE_HEIGHT * N))

#define XMSSMT_OID 0x00000001

/* Scratch sizes */
#define KEYGEN_SCRATCH (32 + LEN * N + N)
#define SIGN_SCRATCH   (64 + LEN * N + N)
#define VERIFY_SCRATCH (96 + LEN * N)

/* Jasmin-exported functions */
extern uint64_t test_xmssmt_keygen(uint8_t *pk, uint8_t *sk, uint8_t *mt_state,
                                    const uint8_t *seeds, uint8_t *scratch);

extern uint64_t test_xmssmt_sign(uint8_t *sig, const uint8_t *msg,
                                  uint64_t msglen, uint8_t *sk,
                                  uint8_t *mt_state, uint8_t *scratch);

extern uint64_t test_xmssmt_verify(const uint8_t *msg, uint64_t msglen,
                                    const uint8_t *sig, const uint8_t *pk,
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

static uint32_t read_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint32_t read_be_idx(const uint8_t *p) {
    /* Read IDX_BYTES big-endian */
    uint32_t v = 0;
    for (int i = 0; i < IDX_BYTES; i++)
        v = (v << 8) | p[i];
    return v;
}

static int test_keygen_suite(void) {
    uint8_t seeds[3 * N];
    uint8_t pk1[MT_PK_BYTES], pk2[MT_PK_BYTES];
    uint8_t sk1[MT_SK_BYTES], sk2[MT_SK_BYTES];
    uint8_t __attribute__((aligned(16))) state1[MT_STATE_BYTES];
    uint8_t __attribute__((aligned(16))) state2[MT_STATE_BYTES];
    uint8_t scratch[KEYGEN_SCRATCH];
    int pass = 1;

    fill_deterministic(seeds, N, 0x10);
    fill_deterministic(seeds + N, N, 0x20);
    fill_deterministic(seeds + 2 * N, N, 0x30);

    /* Test 1: keygen smoke */
    printf("Test 1: keygen smoke... ");
    fflush(stdout);
    memset(state1, 0, MT_STATE_BYTES);
    memset(scratch, 0, KEYGEN_SCRATCH);
    test_xmssmt_keygen(pk1, sk1, state1, seeds, scratch);

    if (!is_nonzero(pk1 + MT_PK_ROOT_OFF, N)) {
        printf("FAIL (root all zeros)\n");
        pass = 0;
    } else if (read_be32(pk1) != XMSSMT_OID) {
        printf("FAIL (PK OID: got 0x%08x, want 0x%08x)\n",
               read_be32(pk1), XMSSMT_OID);
        pass = 0;
    } else if (read_be32(sk1) != XMSSMT_OID) {
        printf("FAIL (SK OID: got 0x%08x, want 0x%08x)\n",
               read_be32(sk1), XMSSMT_OID);
        pass = 0;
    } else if (read_be_idx(sk1 + MT_SK_IDX_OFF) != 0) {
        printf("FAIL (SK idx: got %u, want 0)\n", read_be_idx(sk1 + MT_SK_IDX_OFF));
        pass = 0;
    } else {
        printf("OK\n");
    }
    hex_print("  pk root", pk1 + MT_PK_ROOT_OFF, N);

    /* Verify SK fields match seeds */
    if (memcmp(sk1 + MT_SK_SEED_OFF, seeds, N) != 0) {
        printf("  WARN: SK_SEED mismatch\n"); pass = 0;
    }
    if (memcmp(sk1 + MT_SK_PRF_OFF, seeds + N, N) != 0) {
        printf("  WARN: SK_PRF mismatch\n"); pass = 0;
    }
    if (memcmp(sk1 + MT_SK_ROOT_OFF, pk1 + MT_PK_ROOT_OFF, N) != 0) {
        printf("  WARN: SK root != PK root\n"); pass = 0;
    }
    if (memcmp(sk1 + MT_SK_PUB_SEED_OFF, seeds + 2 * N, N) != 0) {
        printf("  WARN: SK PUB_SEED mismatch\n"); pass = 0;
    }
    if (memcmp(pk1 + MT_PK_SEED_OFF, seeds + 2 * N, N) != 0) {
        printf("  WARN: PK SEED mismatch\n"); pass = 0;
    }

    /* Test 2: keygen determinism */
    printf("Test 2: keygen determinism... ");
    fflush(stdout);
    memset(state2, 0, MT_STATE_BYTES);
    memset(scratch, 0, KEYGEN_SCRATCH);
    test_xmssmt_keygen(pk2, sk2, state2, seeds, scratch);

    if (memcmp(pk1, pk2, MT_PK_BYTES) == 0 &&
        memcmp(sk1, sk2, MT_SK_BYTES) == 0 &&
        memcmp(state1, state2, MT_STATE_BYTES) == 0) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        if (memcmp(pk1, pk2, MT_PK_BYTES) != 0) printf("  PK mismatch\n");
        if (memcmp(sk1, sk2, MT_SK_BYTES) != 0) printf("  SK mismatch\n");
        if (memcmp(state1, state2, MT_STATE_BYTES) != 0) printf("  state mismatch\n");
        pass = 0;
    }

    return pass;
}

static int test_sign_verify_suite(void) {
    uint8_t seeds[3 * N];
    uint8_t pk[MT_PK_BYTES];
    uint8_t sk[MT_SK_BYTES];
    uint8_t __attribute__((aligned(16))) mt_state[MT_STATE_BYTES];
    uint8_t keygen_scratch[KEYGEN_SCRATCH];
    uint8_t sign_scratch[SIGN_SCRATCH];
    uint8_t verify_scratch[VERIFY_SCRATCH];
    uint8_t sig[MT_SIG_BYTES];
    uint8_t msg[64];
    int pass = 1;
    uint64_t ret;

    fill_deterministic(seeds, N, 0x10);
    fill_deterministic(seeds + N, N, 0x20);
    fill_deterministic(seeds + 2 * N, N, 0x30);

    /* Keygen */
    memset(mt_state, 0, MT_STATE_BYTES);
    memset(keygen_scratch, 0, KEYGEN_SCRATCH);
    test_xmssmt_keygen(pk, sk, mt_state, seeds, keygen_scratch);

    fill_deterministic(msg, sizeof(msg), 0x42);

    /* Test 3: sign + verify roundtrip */
    printf("Test 3: sign+verify roundtrip... ");
    fflush(stdout);
    memset(sign_scratch, 0, SIGN_SCRATCH);
    ret = test_xmssmt_sign(sig, msg, sizeof(msg), sk, mt_state, sign_scratch);
    if (ret != 0) {
        printf("FAIL (sign returned %lu)\n", (unsigned long)ret);
        return 0;
    }

    if (read_be_idx(sig) != 0) {
        printf("FAIL (sig idx: got %u, want 0)\n", read_be_idx(sig));
        pass = 0;
    }

    if (read_be_idx(sk + MT_SK_IDX_OFF) != 1) {
        printf("FAIL (SK idx after sign: got %u, want 1)\n",
               read_be_idx(sk + MT_SK_IDX_OFF));
        pass = 0;
    }

    memset(verify_scratch, 0, VERIFY_SCRATCH);
    ret = test_xmssmt_verify(msg, sizeof(msg), sig, pk, verify_scratch);
    if (ret == 0) {
        printf("OK\n");
    } else {
        printf("FAIL (verify returned %lu)\n", (unsigned long)ret);
        pass = 0;
    }

    /* Test 4: wrong message rejection */
    printf("Test 4: wrong message rejection... ");
    fflush(stdout);
    uint8_t bad_msg[64];
    memcpy(bad_msg, msg, sizeof(msg));
    bad_msg[0] ^= 0x01;
    memset(verify_scratch, 0, VERIFY_SCRATCH);
    ret = test_xmssmt_verify(bad_msg, sizeof(bad_msg), sig, pk, verify_scratch);
    if (ret != 0) {
        printf("OK\n");
    } else {
        printf("FAIL (verify accepted wrong message)\n");
        pass = 0;
    }

    /* Test 5: wrong signature rejection */
    printf("Test 5: wrong signature rejection... ");
    fflush(stdout);
    uint8_t bad_sig[MT_SIG_BYTES];
    memcpy(bad_sig, sig, MT_SIG_BYTES);
    bad_sig[MT_SIG_R_OFF + 5] ^= 0x01;
    memset(verify_scratch, 0, VERIFY_SCRATCH);
    ret = test_xmssmt_verify(msg, sizeof(msg), bad_sig, pk, verify_scratch);
    if (ret != 0) {
        printf("OK\n");
    } else {
        printf("FAIL (verify accepted wrong signature)\n");
        pass = 0;
    }

    /* Test 6: sequential signing — 5 messages, verify each */
    printf("Test 6: sequential signing (5 messages)... ");
    fflush(stdout);
    memset(mt_state, 0, MT_STATE_BYTES);
    memset(keygen_scratch, 0, KEYGEN_SCRATCH);
    test_xmssmt_keygen(pk, sk, mt_state, seeds, keygen_scratch);

    int seq_ok = 1;
    for (int i = 0; i < 5; i++) {
        uint8_t m[32];
        fill_deterministic(m, sizeof(m), (uint8_t)(0x50 + i));

        memset(sign_scratch, 0, SIGN_SCRATCH);
        ret = test_xmssmt_sign(sig, m, sizeof(m), sk, mt_state, sign_scratch);
        if (ret != 0) {
            printf("\n  FAIL: sign %d returned %lu\n", i, (unsigned long)ret);
            seq_ok = 0; break;
        }

        if (read_be_idx(sig) != (uint32_t)i) {
            printf("\n  FAIL: sig %d idx: got %u, want %d\n",
                   i, read_be_idx(sig), i);
            seq_ok = 0; break;
        }

        if (read_be_idx(sk + MT_SK_IDX_OFF) != (uint32_t)(i + 1)) {
            printf("\n  FAIL: SK idx after sign %d: got %u, want %d\n",
                   i, read_be_idx(sk + MT_SK_IDX_OFF), i + 1);
            seq_ok = 0; break;
        }

        memset(verify_scratch, 0, VERIFY_SCRATCH);
        ret = test_xmssmt_verify(m, sizeof(m), sig, pk, verify_scratch);
        if (ret != 0) {
            printf("\n  FAIL: verify %d returned %lu\n", i, (unsigned long)ret);
            seq_ok = 0; break;
        }
    }
    if (seq_ok) printf("OK\n");
    else pass = 0;

    return pass;
}

static int test_boundary_crossing(void) {
    uint8_t seeds[3 * N];
    uint8_t pk[MT_PK_BYTES];
    uint8_t sk[MT_SK_BYTES];
    uint8_t __attribute__((aligned(16))) mt_state[MT_STATE_BYTES];
    uint8_t keygen_scratch[KEYGEN_SCRATCH];
    uint8_t sign_scratch[SIGN_SCRATCH];
    uint8_t verify_scratch[VERIFY_SCRATCH];
    uint8_t sig[MT_SIG_BYTES];
    uint8_t msg[32];
    uint64_t ret;
    int pass = 1;

    fill_deterministic(seeds, N, 0x10);
    fill_deterministic(seeds + N, N, 0x20);
    fill_deterministic(seeds + 2 * N, N, 0x30);

    printf("Test 7: tree boundary crossing (1024 sigs)... ");
    fflush(stdout);

    memset(mt_state, 0, MT_STATE_BYTES);
    memset(keygen_scratch, 0, KEYGEN_SCRATCH);
    test_xmssmt_keygen(pk, sk, mt_state, seeds, keygen_scratch);

    /* Sign 1024 messages — this fills the entire layer-0 tree (2^10 = 1024).
     * The 1024th signature (idx=1023) triggers boundary crossing:
     * the "next" tree becomes current, and a new wots sig is generated. */
    int boundary = (1 << TREE_HEIGHT);
    for (int i = 0; i < boundary + 1; i++) {
        fill_deterministic(msg, sizeof(msg), (uint8_t)(i & 0xFF));

        memset(sign_scratch, 0, SIGN_SCRATCH);
        ret = test_xmssmt_sign(sig, msg, sizeof(msg), sk, mt_state, sign_scratch);
        if (ret != 0) {
            printf("\n  FAIL: sign %d returned %lu\n", i, (unsigned long)ret);
            return 0;
        }

        /* Verify a few signatures around the boundary */
        if (i == 0 || i == boundary - 2 || i == boundary - 1 ||
            i == boundary) {
            memset(verify_scratch, 0, VERIFY_SCRATCH);
            ret = test_xmssmt_verify(msg, sizeof(msg), sig, pk, verify_scratch);
            if (ret != 0) {
                printf("\n  FAIL: verify at idx=%d returned %lu\n",
                       i, (unsigned long)ret);
                pass = 0;
                break;
            }
        }

        /* Progress indicator */
        if (i > 0 && (i % 256) == 0) {
            printf("%d ", i);
            fflush(stdout);
        }
    }

    if (pass) printf("OK\n");

    /* Verify SK idx is boundary+1 */
    uint32_t expected_idx = boundary + 1;
    uint32_t actual_idx = read_be_idx(sk + MT_SK_IDX_OFF);
    if (actual_idx != expected_idx) {
        printf("  WARN: final SK idx: got %u, want %u\n", actual_idx, expected_idx);
        pass = 0;
    }

    return pass;
}

int main(void) {
    int pass = 1;

    printf("=== XMSS-MT Jasmin Test (XMSSMT-SHA2_20/2_256) ===\n");
    printf("SK=%d PK=%d Sig=%d MT_state=%d bytes\n",
           MT_SK_BYTES, MT_PK_BYTES, MT_SIG_BYTES, MT_STATE_BYTES);
    printf("D=%d FULL_H=%d TREE_HEIGHT=%d IDX_BYTES=%d BDS_STATE=%d\n\n",
           D, FULL_H, TREE_HEIGHT, IDX_BYTES, BDS_STATE_BYTES);

    printf("--- keygen ---\n");
    if (!test_keygen_suite()) pass = 0;

    printf("\n--- sign + verify ---\n");
    if (!test_sign_verify_suite()) pass = 0;

    printf("\n--- boundary crossing ---\n");
    if (!test_boundary_crossing()) pass = 0;

    printf("\n%s\n", pass ? "All tests passed." : "SOME TESTS FAILED.");
    return pass ? 0 : 1;
}
