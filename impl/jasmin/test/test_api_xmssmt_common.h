/* test_api_xmssmt_common.h — shared XMSS-MT API test logic
 *
 * The caller defines these macros before #include:
 *
 *   XMSSMT_PARAM_N, XMSSMT_PARAM_LEN, XMSSMT_PARAM_TREE_HEIGHT,
 *   XMSSMT_PARAM_BDS_K, XMSSMT_PARAM_D, XMSSMT_PARAM_FULL_H,
 *   XMSSMT_PARAM_IDX_BYTES, XMSSMT_PARAM_OID, XMSSMT_PARAM_NAME
 *   XMSSMT_FN_KEYPAIR, XMSSMT_FN_SIGN, XMSSMT_FN_OPEN
 *
 * Optional: define XMSSMT_TEST_BOUNDARY to enable boundary crossing test (Test 7).
 *
 * Tests 1-6 match test/test_xmssmt.c. Test 7 (boundary) is optional.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* Layout constants */
#define _N          XMSSMT_PARAM_N
#define _LEN        XMSSMT_PARAM_LEN
#define _TH         XMSSMT_PARAM_TREE_HEIGHT
#define _BDS_K      XMSSMT_PARAM_BDS_K
#define _D          XMSSMT_PARAM_D
#define _FULL_H     XMSSMT_PARAM_FULL_H
#define _IDX_BYTES  XMSSMT_PARAM_IDX_BYTES

/* BDS state size */
#define _BDS_AUTH_OFF     0
#define _BDS_KEEP_OFF     (_TH * _N)
#define _BDS_STACK_OFF    ((_TH + _TH / 2) * _N)
#define _BDS_LEVELS_OFF   ((_TH + _TH / 2 + _TH + 1) * _N)
#define _BDS_STKOFF_OFF   (_BDS_LEVELS_OFF + (_TH + 1))
#define _TH_INST_SIZE     (_N + 10)
#define _BDS_TH_OFF       (_BDS_STKOFF_OFF + 4)
#define _NUM_TH           (_TH - _BDS_K)
#define _BDS_RETAIN_OFF   (_BDS_TH_OFF + _NUM_TH * _TH_INST_SIZE)
#define _RETAIN_NODES     ((1 << _BDS_K) - _BDS_K - 1)
#define _BDS_NEXTLEAF_OFF (_BDS_RETAIN_OFF + _RETAIN_NODES * _N)
#define _BDS_STATE_BYTES  (_BDS_NEXTLEAF_OFF + 4)

/* MT state layout */
#define _MT_NUM_BDS       (2 * _D - 1)
#define _MT_BDS_SIZE      (_MT_NUM_BDS * _BDS_STATE_BYTES)
#define _MT_WOTS_SIG_SIZE (_LEN * _N)
#define _MT_STATE_BYTES   (_MT_NUM_BDS * _BDS_STATE_BYTES + (_D - 1) * _LEN * _N)

/* SK layout */
#define _MT_SK_IDX_OFF      4
#define _MT_SK_SEED_OFF     (4 + _IDX_BYTES)
#define _MT_SK_PRF_OFF      (4 + _IDX_BYTES + _N)
#define _MT_SK_ROOT_OFF     (4 + _IDX_BYTES + 2 * _N)
#define _MT_SK_PUB_SEED_OFF (4 + _IDX_BYTES + 3 * _N)
#define _MT_SK_BYTES        (4 + _IDX_BYTES + 4 * _N)

/* PK layout */
#define _MT_PK_ROOT_OFF  4
#define _MT_PK_SEED_OFF  (4 + _N)
#define _MT_PK_BYTES     (4 + 2 * _N)

/* Sig layout */
#define _MT_SIG_R_OFF     _IDX_BYTES
#define _MT_SIG_DATA_OFF  (_IDX_BYTES + _N)
#define _MT_REDUCED_SIG   (_LEN * _N + _TH * _N)
#define _MT_SIG_BYTES     (_IDX_BYTES + _N + _D * (_LEN * _N + _TH * _N))

/* Scratch sizes */
#define _KEYGEN_SCRATCH (32 + _LEN * _N + _N)
#define _SIGN_SCRATCH   (64 + _LEN * _N + _N)
#define _VERIFY_SCRATCH (96 + _LEN * _N)

/* Jasmin-exported functions */
extern uint64_t XMSSMT_FN_KEYPAIR(uint8_t *pk, uint8_t *sk, uint8_t *mt_state,
                                    const uint8_t *seeds, uint8_t *scratch);
extern uint64_t XMSSMT_FN_SIGN(uint8_t *sig, const uint8_t *msg,
                                 uint64_t msglen, uint8_t *sk,
                                 uint8_t *mt_state, uint8_t *scratch);
extern uint64_t XMSSMT_FN_OPEN(const uint8_t *msg, uint64_t msglen,
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
    uint32_t v = 0;
    for (int i = 0; i < _IDX_BYTES; i++)
        v = (v << 8) | p[i];
    return v;
}

static int test_keygen_suite(void) {
    uint8_t seeds[3 * _N];
    uint8_t pk1[_MT_PK_BYTES], pk2[_MT_PK_BYTES];
    uint8_t sk1[_MT_SK_BYTES], sk2[_MT_SK_BYTES];
    uint8_t __attribute__((aligned(16))) state1[_MT_STATE_BYTES];
    uint8_t __attribute__((aligned(16))) state2[_MT_STATE_BYTES];
    uint8_t scratch[_KEYGEN_SCRATCH];
    int pass = 1;

    fill_deterministic(seeds, _N, 0x10);
    fill_deterministic(seeds + _N, _N, 0x20);
    fill_deterministic(seeds + 2 * _N, _N, 0x30);

    /* Test 1: keygen smoke */
    printf("Test 1: keygen smoke... ");
    fflush(stdout);
    memset(state1, 0, _MT_STATE_BYTES);
    memset(scratch, 0, _KEYGEN_SCRATCH);
    XMSSMT_FN_KEYPAIR(pk1, sk1, state1, seeds, scratch);

    if (!is_nonzero(pk1 + _MT_PK_ROOT_OFF, _N)) {
        printf("FAIL (root all zeros)\n");
        pass = 0;
    } else if (read_be32(pk1) != XMSSMT_PARAM_OID) {
        printf("FAIL (PK OID: got 0x%08x, want 0x%08x)\n",
               read_be32(pk1), XMSSMT_PARAM_OID);
        pass = 0;
    } else if (read_be32(sk1) != XMSSMT_PARAM_OID) {
        printf("FAIL (SK OID: got 0x%08x, want 0x%08x)\n",
               read_be32(sk1), XMSSMT_PARAM_OID);
        pass = 0;
    } else if (read_be_idx(sk1 + _MT_SK_IDX_OFF) != 0) {
        printf("FAIL (SK idx: got %u, want 0)\n", read_be_idx(sk1 + _MT_SK_IDX_OFF));
        pass = 0;
    } else {
        printf("OK\n");
    }
    hex_print("  pk root", pk1 + _MT_PK_ROOT_OFF, _N);

    if (memcmp(sk1 + _MT_SK_SEED_OFF, seeds, _N) != 0) {
        printf("  WARN: SK_SEED mismatch\n"); pass = 0;
    }
    if (memcmp(sk1 + _MT_SK_PRF_OFF, seeds + _N, _N) != 0) {
        printf("  WARN: SK_PRF mismatch\n"); pass = 0;
    }
    if (memcmp(sk1 + _MT_SK_ROOT_OFF, pk1 + _MT_PK_ROOT_OFF, _N) != 0) {
        printf("  WARN: SK root != PK root\n"); pass = 0;
    }
    if (memcmp(sk1 + _MT_SK_PUB_SEED_OFF, seeds + 2 * _N, _N) != 0) {
        printf("  WARN: SK PUB_SEED mismatch\n"); pass = 0;
    }
    if (memcmp(pk1 + _MT_PK_SEED_OFF, seeds + 2 * _N, _N) != 0) {
        printf("  WARN: PK SEED mismatch\n"); pass = 0;
    }

    /* Test 2: keygen determinism */
    printf("Test 2: keygen determinism... ");
    fflush(stdout);
    memset(state2, 0, _MT_STATE_BYTES);
    memset(scratch, 0, _KEYGEN_SCRATCH);
    XMSSMT_FN_KEYPAIR(pk2, sk2, state2, seeds, scratch);

    if (memcmp(pk1, pk2, _MT_PK_BYTES) == 0 &&
        memcmp(sk1, sk2, _MT_SK_BYTES) == 0 &&
        memcmp(state1, state2, _MT_STATE_BYTES) == 0) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        if (memcmp(pk1, pk2, _MT_PK_BYTES) != 0) printf("  PK mismatch\n");
        if (memcmp(sk1, sk2, _MT_SK_BYTES) != 0) printf("  SK mismatch\n");
        if (memcmp(state1, state2, _MT_STATE_BYTES) != 0) printf("  state mismatch\n");
        pass = 0;
    }

    return pass;
}

static int test_sign_verify_suite(void) {
    uint8_t seeds[3 * _N];
    uint8_t pk[_MT_PK_BYTES];
    uint8_t sk[_MT_SK_BYTES];
    uint8_t __attribute__((aligned(16))) mt_state[_MT_STATE_BYTES];
    uint8_t keygen_scratch[_KEYGEN_SCRATCH];
    uint8_t sign_scratch[_SIGN_SCRATCH];
    uint8_t verify_scratch[_VERIFY_SCRATCH];
    uint8_t sig[_MT_SIG_BYTES];
    uint8_t msg[64];
    int pass = 1;
    uint64_t ret;

    fill_deterministic(seeds, _N, 0x10);
    fill_deterministic(seeds + _N, _N, 0x20);
    fill_deterministic(seeds + 2 * _N, _N, 0x30);

    memset(mt_state, 0, _MT_STATE_BYTES);
    memset(keygen_scratch, 0, _KEYGEN_SCRATCH);
    XMSSMT_FN_KEYPAIR(pk, sk, mt_state, seeds, keygen_scratch);

    fill_deterministic(msg, sizeof(msg), 0x42);

    /* Test 3: sign + verify roundtrip */
    printf("Test 3: sign+verify roundtrip... ");
    fflush(stdout);
    memset(sign_scratch, 0, _SIGN_SCRATCH);
    ret = XMSSMT_FN_SIGN(sig, msg, sizeof(msg), sk, mt_state, sign_scratch);
    if (ret != 0) {
        printf("FAIL (sign returned %lu)\n", (unsigned long)ret);
        return 0;
    }

    if (read_be_idx(sig) != 0) {
        printf("FAIL (sig idx: got %u, want 0)\n", read_be_idx(sig));
        pass = 0;
    }

    if (read_be_idx(sk + _MT_SK_IDX_OFF) != 1) {
        printf("FAIL (SK idx after sign: got %u, want 1)\n",
               read_be_idx(sk + _MT_SK_IDX_OFF));
        pass = 0;
    }

    memset(verify_scratch, 0, _VERIFY_SCRATCH);
    ret = XMSSMT_FN_OPEN(msg, sizeof(msg), sig, pk, verify_scratch);
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
    memset(verify_scratch, 0, _VERIFY_SCRATCH);
    ret = XMSSMT_FN_OPEN(bad_msg, sizeof(bad_msg), sig, pk, verify_scratch);
    if (ret != 0) {
        printf("OK\n");
    } else {
        printf("FAIL (verify accepted wrong message)\n");
        pass = 0;
    }

    /* Test 5: wrong signature rejection */
    printf("Test 5: wrong signature rejection... ");
    fflush(stdout);
    uint8_t bad_sig[_MT_SIG_BYTES];
    memcpy(bad_sig, sig, _MT_SIG_BYTES);
    bad_sig[_MT_SIG_R_OFF + 5] ^= 0x01;
    memset(verify_scratch, 0, _VERIFY_SCRATCH);
    ret = XMSSMT_FN_OPEN(msg, sizeof(msg), bad_sig, pk, verify_scratch);
    if (ret != 0) {
        printf("OK\n");
    } else {
        printf("FAIL (verify accepted wrong signature)\n");
        pass = 0;
    }

    /* Test 6: sequential signing — 5 messages, verify each */
    printf("Test 6: sequential signing (5 messages)... ");
    fflush(stdout);
    memset(mt_state, 0, _MT_STATE_BYTES);
    memset(keygen_scratch, 0, _KEYGEN_SCRATCH);
    XMSSMT_FN_KEYPAIR(pk, sk, mt_state, seeds, keygen_scratch);

    int seq_ok = 1;
    for (int i = 0; i < 5; i++) {
        uint8_t m[32];
        fill_deterministic(m, sizeof(m), (uint8_t)(0x50 + i));

        memset(sign_scratch, 0, _SIGN_SCRATCH);
        ret = XMSSMT_FN_SIGN(sig, m, sizeof(m), sk, mt_state, sign_scratch);
        if (ret != 0) {
            printf("\n  FAIL: sign %d returned %lu\n", i, (unsigned long)ret);
            seq_ok = 0; break;
        }

        if (read_be_idx(sig) != (uint32_t)i) {
            printf("\n  FAIL: sig %d idx: got %u, want %d\n",
                   i, read_be_idx(sig), i);
            seq_ok = 0; break;
        }

        if (read_be_idx(sk + _MT_SK_IDX_OFF) != (uint32_t)(i + 1)) {
            printf("\n  FAIL: SK idx after sign %d: got %u, want %d\n",
                   i, read_be_idx(sk + _MT_SK_IDX_OFF), i + 1);
            seq_ok = 0; break;
        }

        memset(verify_scratch, 0, _VERIFY_SCRATCH);
        ret = XMSSMT_FN_OPEN(m, sizeof(m), sig, pk, verify_scratch);
        if (ret != 0) {
            printf("\n  FAIL: verify %d returned %lu\n", i, (unsigned long)ret);
            seq_ok = 0; break;
        }
    }
    if (seq_ok) printf("OK\n");
    else pass = 0;

    return pass;
}

#ifdef XMSSMT_TEST_BOUNDARY
static int test_boundary_crossing(void) {
    uint8_t seeds[3 * _N];
    uint8_t pk[_MT_PK_BYTES];
    uint8_t sk[_MT_SK_BYTES];
    uint8_t __attribute__((aligned(16))) mt_state[_MT_STATE_BYTES];
    uint8_t keygen_scratch[_KEYGEN_SCRATCH];
    uint8_t sign_scratch[_SIGN_SCRATCH];
    uint8_t verify_scratch[_VERIFY_SCRATCH];
    uint8_t sig[_MT_SIG_BYTES];
    uint8_t msg[32];
    uint64_t ret;
    int pass = 1;

    fill_deterministic(seeds, _N, 0x10);
    fill_deterministic(seeds + _N, _N, 0x20);
    fill_deterministic(seeds + 2 * _N, _N, 0x30);

    printf("Test 7: tree boundary crossing (%d sigs)... ", 1 << _TH);
    fflush(stdout);

    memset(mt_state, 0, _MT_STATE_BYTES);
    memset(keygen_scratch, 0, _KEYGEN_SCRATCH);
    XMSSMT_FN_KEYPAIR(pk, sk, mt_state, seeds, keygen_scratch);

    int boundary = (1 << _TH);
    for (int i = 0; i < boundary + 1; i++) {
        fill_deterministic(msg, sizeof(msg), (uint8_t)(i & 0xFF));

        memset(sign_scratch, 0, _SIGN_SCRATCH);
        ret = XMSSMT_FN_SIGN(sig, msg, sizeof(msg), sk, mt_state, sign_scratch);
        if (ret != 0) {
            printf("\n  FAIL: sign %d returned %lu\n", i, (unsigned long)ret);
            return 0;
        }

        if (i == 0 || i == boundary - 2 || i == boundary - 1 ||
            i == boundary) {
            memset(verify_scratch, 0, _VERIFY_SCRATCH);
            ret = XMSSMT_FN_OPEN(msg, sizeof(msg), sig, pk, verify_scratch);
            if (ret != 0) {
                printf("\n  FAIL: verify at idx=%d returned %lu\n",
                       i, (unsigned long)ret);
                pass = 0;
                break;
            }
        }

        if (i > 0 && (i % 256) == 0) {
            printf("%d ", i);
            fflush(stdout);
        }
    }

    if (pass) printf("OK\n");

    uint32_t expected_idx = boundary + 1;
    uint32_t actual_idx = read_be_idx(sk + _MT_SK_IDX_OFF);
    if (actual_idx != expected_idx) {
        printf("  WARN: final SK idx: got %u, want %u\n", actual_idx, expected_idx);
        pass = 0;
    }

    return pass;
}
#endif /* XMSSMT_TEST_BOUNDARY */

int main(void) {
    int pass = 1;

    printf("=== %s Jasmin API Test ===\n", XMSSMT_PARAM_NAME);
    printf("SK=%d PK=%d Sig=%d MT_state=%d bytes\n",
           _MT_SK_BYTES, _MT_PK_BYTES, _MT_SIG_BYTES, _MT_STATE_BYTES);
    printf("D=%d FULL_H=%d TREE_HEIGHT=%d IDX_BYTES=%d BDS_STATE=%d\n\n",
           _D, _FULL_H, _TH, _IDX_BYTES, _BDS_STATE_BYTES);

    printf("--- keygen ---\n");
    if (!test_keygen_suite()) pass = 0;

    printf("\n--- sign + verify ---\n");
    if (!test_sign_verify_suite()) pass = 0;

#ifdef XMSSMT_TEST_BOUNDARY
    printf("\n--- boundary crossing ---\n");
    if (!test_boundary_crossing()) pass = 0;
#endif

    printf("\n%s\n", pass ? "All tests passed." : "SOME TESTS FAILED.");
    return pass ? 0 : 1;
}
