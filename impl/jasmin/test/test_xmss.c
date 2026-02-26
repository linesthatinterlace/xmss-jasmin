/* test_xmss.c — C harness for XMSS keygen/sign/verify Jasmin tests
 *
 * Tests:
 *   1. Keygen smoke: root non-zero, OID correct
 *   2. Keygen determinism: same seeds → same PK, SK, state
 *   3. Sign+verify roundtrip
 *   4. Wrong message rejection
 *   5. Wrong signature rejection
 *   6. Sequential signing: 5 messages, verify each
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define N 32
#define LEN 67
#define TREE_HEIGHT 10
#define BDS_K 2

/* Layout constants — must match xmss.jinc */
#define SK_IDX_OFF      4
#define SK_SEED_OFF     8
#define SK_PRF_OFF      40
#define SK_ROOT_OFF     72
#define SK_PUB_SEED_OFF 104
#define SK_BYTES        136

#define PK_ROOT_OFF     4
#define PK_SEED_OFF     36
#define PK_BYTES        68

#define SIG_R_OFF       4
#define SIG_WOTS_OFF    36
#define SIG_AUTH_OFF    (36 + LEN * N)
#define SIG_BYTES       (36 + LEN * N + TREE_HEIGHT * N)

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

#define XMSS_OID 0x00000001

/* Scratch sizes */
#define KEYGEN_SCRATCH (32 + LEN * N + N)
#define SIGN_SCRATCH   (64 + LEN * N + N)
#define VERIFY_SCRATCH (96 + LEN * N)

/* Jasmin-exported functions */
extern uint64_t test_xmss_keygen(uint8_t *pk, uint8_t *sk, uint8_t *state,
                                  const uint8_t *seeds, uint8_t *scratch);

extern uint64_t test_xmss_sign(uint8_t *sig, const uint8_t *msg,
                                uint64_t msglen, uint8_t *sk,
                                uint8_t *state, uint8_t *scratch);

extern uint64_t test_xmss_verify(const uint8_t *msg, uint64_t msglen,
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

static int test_keygen_suite(void) {
    uint8_t seeds[3 * N];
    uint8_t pk1[PK_BYTES], pk2[PK_BYTES];
    uint8_t sk1[SK_BYTES], sk2[SK_BYTES];
    uint8_t __attribute__((aligned(16))) state1[BDS_STATE_BYTES];
    uint8_t __attribute__((aligned(16))) state2[BDS_STATE_BYTES];
    uint8_t scratch[KEYGEN_SCRATCH];
    int pass = 1;

    /* seeds = SK_SEED(32) || SK_PRF(32) || PUB_SEED(32) */
    fill_deterministic(seeds, N, 0x10);          /* SK_SEED */
    fill_deterministic(seeds + N, N, 0x20);      /* SK_PRF */
    fill_deterministic(seeds + 2 * N, N, 0x30);  /* PUB_SEED */

    /* Test 1: keygen smoke */
    printf("Test 1: keygen smoke... ");
    fflush(stdout);
    memset(state1, 0, BDS_STATE_BYTES);
    memset(scratch, 0, KEYGEN_SCRATCH);
    test_xmss_keygen(pk1, sk1, state1, seeds, scratch);

    if (!is_nonzero(pk1 + PK_ROOT_OFF, N)) {
        printf("FAIL (root all zeros)\n");
        pass = 0;
    } else if (read_be32(pk1) != XMSS_OID) {
        printf("FAIL (PK OID: got 0x%08x, want 0x%08x)\n",
               read_be32(pk1), XMSS_OID);
        pass = 0;
    } else if (read_be32(sk1) != XMSS_OID) {
        printf("FAIL (SK OID: got 0x%08x, want 0x%08x)\n",
               read_be32(sk1), XMSS_OID);
        pass = 0;
    } else if (read_be32(sk1 + SK_IDX_OFF) != 0) {
        printf("FAIL (SK idx: got %u, want 0)\n", read_be32(sk1 + SK_IDX_OFF));
        pass = 0;
    } else {
        printf("OK\n");
    }
    hex_print("  pk root", pk1 + PK_ROOT_OFF, N);

    /* Verify SK fields match seeds */
    if (memcmp(sk1 + SK_SEED_OFF, seeds, N) != 0) {
        printf("  WARN: SK_SEED mismatch\n");
        pass = 0;
    }
    if (memcmp(sk1 + SK_PRF_OFF, seeds + N, N) != 0) {
        printf("  WARN: SK_PRF mismatch\n");
        pass = 0;
    }
    if (memcmp(sk1 + SK_ROOT_OFF, pk1 + PK_ROOT_OFF, N) != 0) {
        printf("  WARN: SK root != PK root\n");
        pass = 0;
    }
    if (memcmp(sk1 + SK_PUB_SEED_OFF, seeds + 2 * N, N) != 0) {
        printf("  WARN: SK PUB_SEED mismatch\n");
        pass = 0;
    }
    if (memcmp(pk1 + PK_SEED_OFF, seeds + 2 * N, N) != 0) {
        printf("  WARN: PK SEED mismatch\n");
        pass = 0;
    }

    /* Test 2: keygen determinism */
    printf("Test 2: keygen determinism... ");
    fflush(stdout);
    memset(state2, 0, BDS_STATE_BYTES);
    memset(scratch, 0, KEYGEN_SCRATCH);
    test_xmss_keygen(pk2, sk2, state2, seeds, scratch);

    if (memcmp(pk1, pk2, PK_BYTES) == 0 &&
        memcmp(sk1, sk2, SK_BYTES) == 0 &&
        memcmp(state1, state2, BDS_STATE_BYTES) == 0) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        if (memcmp(pk1, pk2, PK_BYTES) != 0) printf("  PK mismatch\n");
        if (memcmp(sk1, sk2, SK_BYTES) != 0) printf("  SK mismatch\n");
        if (memcmp(state1, state2, BDS_STATE_BYTES) != 0) printf("  state mismatch\n");
        pass = 0;
    }

    return pass;
}

static int test_sign_verify_suite(void) {
    uint8_t seeds[3 * N];
    uint8_t pk[PK_BYTES];
    uint8_t sk[SK_BYTES];
    uint8_t __attribute__((aligned(16))) state[BDS_STATE_BYTES];
    uint8_t keygen_scratch[KEYGEN_SCRATCH];
    uint8_t sign_scratch[SIGN_SCRATCH];
    uint8_t verify_scratch[VERIFY_SCRATCH];
    uint8_t sig[SIG_BYTES];
    uint8_t msg[64];
    int pass = 1;
    uint64_t ret;

    fill_deterministic(seeds, N, 0x10);
    fill_deterministic(seeds + N, N, 0x20);
    fill_deterministic(seeds + 2 * N, N, 0x30);

    /* Keygen */
    memset(state, 0, BDS_STATE_BYTES);
    memset(keygen_scratch, 0, KEYGEN_SCRATCH);
    test_xmss_keygen(pk, sk, state, seeds, keygen_scratch);

    /* Prepare message */
    fill_deterministic(msg, sizeof(msg), 0x42);

    /* Test 3: sign + verify roundtrip */
    printf("Test 3: sign+verify roundtrip... ");
    fflush(stdout);
    memset(sign_scratch, 0, SIGN_SCRATCH);
    ret = test_xmss_sign(sig, msg, sizeof(msg), sk, state, sign_scratch);
    if (ret != 0) {
        printf("FAIL (sign returned %lu)\n", (unsigned long)ret);
        return 0;
    }

    /* Check sig idx == 0 (first signature) */
    if (read_be32(sig) != 0) {
        printf("FAIL (sig idx: got %u, want 0)\n", read_be32(sig));
        pass = 0;
    }

    /* Check SK idx incremented to 1 */
    if (read_be32(sk + SK_IDX_OFF) != 1) {
        printf("FAIL (SK idx after sign: got %u, want 1)\n",
               read_be32(sk + SK_IDX_OFF));
        pass = 0;
    }

    memset(verify_scratch, 0, VERIFY_SCRATCH);
    ret = test_xmss_verify(msg, sizeof(msg), sig, pk, verify_scratch);
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
    ret = test_xmss_verify(bad_msg, sizeof(bad_msg), sig, pk, verify_scratch);
    if (ret != 0) {
        printf("OK\n");
    } else {
        printf("FAIL (verify accepted wrong message)\n");
        pass = 0;
    }

    /* Test 5: wrong signature rejection */
    printf("Test 5: wrong signature rejection... ");
    fflush(stdout);
    uint8_t bad_sig[SIG_BYTES];
    memcpy(bad_sig, sig, SIG_BYTES);
    bad_sig[SIG_R_OFF + 5] ^= 0x01;  /* flip a bit in r */
    memset(verify_scratch, 0, VERIFY_SCRATCH);
    ret = test_xmss_verify(msg, sizeof(msg), bad_sig, pk, verify_scratch);
    if (ret != 0) {
        printf("OK\n");
    } else {
        printf("FAIL (verify accepted wrong signature)\n");
        pass = 0;
    }

    /* Test 6: sequential signing — sign 5 messages, verify each */
    printf("Test 6: sequential signing (5 messages)... ");
    fflush(stdout);
    /* Reset: re-keygen to get fresh state */
    memset(state, 0, BDS_STATE_BYTES);
    memset(keygen_scratch, 0, KEYGEN_SCRATCH);
    test_xmss_keygen(pk, sk, state, seeds, keygen_scratch);

    int seq_ok = 1;
    for (int i = 0; i < 5; i++) {
        uint8_t m[32];
        fill_deterministic(m, sizeof(m), (uint8_t)(0x50 + i));

        memset(sign_scratch, 0, SIGN_SCRATCH);
        ret = test_xmss_sign(sig, m, sizeof(m), sk, state, sign_scratch);
        if (ret != 0) {
            printf("\n  FAIL: sign %d returned %lu\n", i, (unsigned long)ret);
            seq_ok = 0;
            break;
        }

        /* Check sig idx == i */
        if (read_be32(sig) != (uint32_t)i) {
            printf("\n  FAIL: sig %d idx: got %u, want %d\n",
                   i, read_be32(sig), i);
            seq_ok = 0;
            break;
        }

        /* Check SK idx == i+1 */
        if (read_be32(sk + SK_IDX_OFF) != (uint32_t)(i + 1)) {
            printf("\n  FAIL: SK idx after sign %d: got %u, want %d\n",
                   i, read_be32(sk + SK_IDX_OFF), i + 1);
            seq_ok = 0;
            break;
        }

        memset(verify_scratch, 0, VERIFY_SCRATCH);
        ret = test_xmss_verify(m, sizeof(m), sig, pk, verify_scratch);
        if (ret != 0) {
            printf("\n  FAIL: verify %d returned %lu\n", i, (unsigned long)ret);
            seq_ok = 0;
            break;
        }
    }
    if (seq_ok) {
        printf("OK\n");
    } else {
        pass = 0;
    }

    return pass;
}

int main(void) {
    int pass = 1;

    printf("=== XMSS Jasmin Test ===\n");
    printf("SK=%d PK=%d Sig=%d BDS_state=%d bytes\n\n",
           SK_BYTES, PK_BYTES, SIG_BYTES, BDS_STATE_BYTES);

    printf("--- keygen ---\n");
    if (!test_keygen_suite()) pass = 0;

    printf("\n--- sign + verify ---\n");
    if (!test_sign_verify_suite()) pass = 0;

    printf("\n%s\n", pass ? "All tests passed." : "SOME TESTS FAILED.");
    return pass ? 0 : 1;
}
