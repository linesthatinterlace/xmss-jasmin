/* test_api_xmss_common.h — shared XMSS API test logic
 *
 * The caller defines these macros before #include:
 *
 *   XMSS_PARAM_N, XMSS_PARAM_LEN, XMSS_PARAM_TREE_HEIGHT, XMSS_PARAM_BDS_K
 *   XMSS_PARAM_OID, XMSS_PARAM_NAME
 *   XMSS_FN_KEYPAIR, XMSS_FN_SIGN, XMSS_FN_OPEN
 *
 * Tests 1-6 match test/test_xmss.c exactly.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* Layout constants — derived from params */
#define _N          XMSS_PARAM_N
#define _LEN        XMSS_PARAM_LEN
#define _TH         XMSS_PARAM_TREE_HEIGHT
#define _BDS_K      XMSS_PARAM_BDS_K

#define _SK_IDX_OFF      4
#define _SK_SEED_OFF     8
#define _SK_PRF_OFF      40
#define _SK_ROOT_OFF     72
#define _SK_PUB_SEED_OFF 104
#define _SK_BYTES        136

#define _PK_ROOT_OFF     4
#define _PK_SEED_OFF     36
#define _PK_BYTES        68

#define _SIG_R_OFF       4
#define _SIG_WOTS_OFF    36
#define _SIG_AUTH_OFF    (36 + _LEN * _N)
#define _SIG_BYTES       (36 + _LEN * _N + _TH * _N)

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

/* Scratch sizes */
#define _KEYGEN_SCRATCH (32 + _LEN * _N + _N)
#define _SIGN_SCRATCH   (64 + _LEN * _N + _N)
#define _VERIFY_SCRATCH (96 + _LEN * _N)

/* Jasmin-exported functions */
extern uint64_t XMSS_FN_KEYPAIR(uint8_t *pk, uint8_t *sk, uint8_t *state,
                                  const uint8_t *seeds, uint8_t *scratch);
extern uint64_t XMSS_FN_SIGN(uint8_t *sig, const uint8_t *msg,
                               uint64_t msglen, uint8_t *sk,
                               uint8_t *state, uint8_t *scratch);
extern uint64_t XMSS_FN_OPEN(const uint8_t *msg, uint64_t msglen,
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
    uint8_t seeds[3 * _N];
    uint8_t pk1[_PK_BYTES], pk2[_PK_BYTES];
    uint8_t sk1[_SK_BYTES], sk2[_SK_BYTES];
    uint8_t __attribute__((aligned(16))) state1[_BDS_STATE_BYTES];
    uint8_t __attribute__((aligned(16))) state2[_BDS_STATE_BYTES];
    uint8_t scratch[_KEYGEN_SCRATCH];
    int pass = 1;

    fill_deterministic(seeds, _N, 0x10);
    fill_deterministic(seeds + _N, _N, 0x20);
    fill_deterministic(seeds + 2 * _N, _N, 0x30);

    /* Test 1: keygen smoke */
    printf("Test 1: keygen smoke... ");
    fflush(stdout);
    memset(state1, 0, _BDS_STATE_BYTES);
    memset(scratch, 0, _KEYGEN_SCRATCH);
    XMSS_FN_KEYPAIR(pk1, sk1, state1, seeds, scratch);

    if (!is_nonzero(pk1 + _PK_ROOT_OFF, _N)) {
        printf("FAIL (root all zeros)\n");
        pass = 0;
    } else if (read_be32(pk1) != XMSS_PARAM_OID) {
        printf("FAIL (PK OID: got 0x%08x, want 0x%08x)\n",
               read_be32(pk1), XMSS_PARAM_OID);
        pass = 0;
    } else if (read_be32(sk1) != XMSS_PARAM_OID) {
        printf("FAIL (SK OID: got 0x%08x, want 0x%08x)\n",
               read_be32(sk1), XMSS_PARAM_OID);
        pass = 0;
    } else if (read_be32(sk1 + _SK_IDX_OFF) != 0) {
        printf("FAIL (SK idx: got %u, want 0)\n", read_be32(sk1 + _SK_IDX_OFF));
        pass = 0;
    } else {
        printf("OK\n");
    }
    hex_print("  pk root", pk1 + _PK_ROOT_OFF, _N);

    if (memcmp(sk1 + _SK_SEED_OFF, seeds, _N) != 0) {
        printf("  WARN: SK_SEED mismatch\n"); pass = 0;
    }
    if (memcmp(sk1 + _SK_PRF_OFF, seeds + _N, _N) != 0) {
        printf("  WARN: SK_PRF mismatch\n"); pass = 0;
    }
    if (memcmp(sk1 + _SK_ROOT_OFF, pk1 + _PK_ROOT_OFF, _N) != 0) {
        printf("  WARN: SK root != PK root\n"); pass = 0;
    }
    if (memcmp(sk1 + _SK_PUB_SEED_OFF, seeds + 2 * _N, _N) != 0) {
        printf("  WARN: SK PUB_SEED mismatch\n"); pass = 0;
    }
    if (memcmp(pk1 + _PK_SEED_OFF, seeds + 2 * _N, _N) != 0) {
        printf("  WARN: PK SEED mismatch\n"); pass = 0;
    }

    /* Test 2: keygen determinism */
    printf("Test 2: keygen determinism... ");
    fflush(stdout);
    memset(state2, 0, _BDS_STATE_BYTES);
    memset(scratch, 0, _KEYGEN_SCRATCH);
    XMSS_FN_KEYPAIR(pk2, sk2, state2, seeds, scratch);

    if (memcmp(pk1, pk2, _PK_BYTES) == 0 &&
        memcmp(sk1, sk2, _SK_BYTES) == 0 &&
        memcmp(state1, state2, _BDS_STATE_BYTES) == 0) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        if (memcmp(pk1, pk2, _PK_BYTES) != 0) printf("  PK mismatch\n");
        if (memcmp(sk1, sk2, _SK_BYTES) != 0) printf("  SK mismatch\n");
        if (memcmp(state1, state2, _BDS_STATE_BYTES) != 0) printf("  state mismatch\n");
        pass = 0;
    }

    return pass;
}

static int test_sign_verify_suite(void) {
    uint8_t seeds[3 * _N];
    uint8_t pk[_PK_BYTES];
    uint8_t sk[_SK_BYTES];
    uint8_t __attribute__((aligned(16))) state[_BDS_STATE_BYTES];
    uint8_t keygen_scratch[_KEYGEN_SCRATCH];
    uint8_t sign_scratch[_SIGN_SCRATCH];
    uint8_t verify_scratch[_VERIFY_SCRATCH];
    uint8_t sig[_SIG_BYTES];
    uint8_t msg[64];
    int pass = 1;
    uint64_t ret;

    fill_deterministic(seeds, _N, 0x10);
    fill_deterministic(seeds + _N, _N, 0x20);
    fill_deterministic(seeds + 2 * _N, _N, 0x30);

    memset(state, 0, _BDS_STATE_BYTES);
    memset(keygen_scratch, 0, _KEYGEN_SCRATCH);
    XMSS_FN_KEYPAIR(pk, sk, state, seeds, keygen_scratch);

    fill_deterministic(msg, sizeof(msg), 0x42);

    /* Test 3: sign + verify roundtrip */
    printf("Test 3: sign+verify roundtrip... ");
    fflush(stdout);
    memset(sign_scratch, 0, _SIGN_SCRATCH);
    ret = XMSS_FN_SIGN(sig, msg, sizeof(msg), sk, state, sign_scratch);
    if (ret != 0) {
        printf("FAIL (sign returned %lu)\n", (unsigned long)ret);
        return 0;
    }

    if (read_be32(sig) != 0) {
        printf("FAIL (sig idx: got %u, want 0)\n", read_be32(sig));
        pass = 0;
    }

    if (read_be32(sk + _SK_IDX_OFF) != 1) {
        printf("FAIL (SK idx after sign: got %u, want 1)\n",
               read_be32(sk + _SK_IDX_OFF));
        pass = 0;
    }

    memset(verify_scratch, 0, _VERIFY_SCRATCH);
    ret = XMSS_FN_OPEN(msg, sizeof(msg), sig, pk, verify_scratch);
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
    ret = XMSS_FN_OPEN(bad_msg, sizeof(bad_msg), sig, pk, verify_scratch);
    if (ret != 0) {
        printf("OK\n");
    } else {
        printf("FAIL (verify accepted wrong message)\n");
        pass = 0;
    }

    /* Test 5: wrong signature rejection */
    printf("Test 5: wrong signature rejection... ");
    fflush(stdout);
    uint8_t bad_sig[_SIG_BYTES];
    memcpy(bad_sig, sig, _SIG_BYTES);
    bad_sig[_SIG_R_OFF + 5] ^= 0x01;
    memset(verify_scratch, 0, _VERIFY_SCRATCH);
    ret = XMSS_FN_OPEN(msg, sizeof(msg), bad_sig, pk, verify_scratch);
    if (ret != 0) {
        printf("OK\n");
    } else {
        printf("FAIL (verify accepted wrong signature)\n");
        pass = 0;
    }

    /* Test 6: sequential signing — sign 5 messages, verify each */
    printf("Test 6: sequential signing (5 messages)... ");
    fflush(stdout);
    memset(state, 0, _BDS_STATE_BYTES);
    memset(keygen_scratch, 0, _KEYGEN_SCRATCH);
    XMSS_FN_KEYPAIR(pk, sk, state, seeds, keygen_scratch);

    int seq_ok = 1;
    for (int i = 0; i < 5; i++) {
        uint8_t m[32];
        fill_deterministic(m, sizeof(m), (uint8_t)(0x50 + i));

        memset(sign_scratch, 0, _SIGN_SCRATCH);
        ret = XMSS_FN_SIGN(sig, m, sizeof(m), sk, state, sign_scratch);
        if (ret != 0) {
            printf("\n  FAIL: sign %d returned %lu\n", i, (unsigned long)ret);
            seq_ok = 0; break;
        }

        if (read_be32(sig) != (uint32_t)i) {
            printf("\n  FAIL: sig %d idx: got %u, want %d\n",
                   i, read_be32(sig), i);
            seq_ok = 0; break;
        }

        if (read_be32(sk + _SK_IDX_OFF) != (uint32_t)(i + 1)) {
            printf("\n  FAIL: SK idx after sign %d: got %u, want %d\n",
                   i, read_be32(sk + _SK_IDX_OFF), i + 1);
            seq_ok = 0; break;
        }

        memset(verify_scratch, 0, _VERIFY_SCRATCH);
        ret = XMSS_FN_OPEN(m, sizeof(m), sig, pk, verify_scratch);
        if (ret != 0) {
            printf("\n  FAIL: verify %d returned %lu\n", i, (unsigned long)ret);
            seq_ok = 0; break;
        }
    }
    if (seq_ok) printf("OK\n");
    else pass = 0;

    return pass;
}

int main(void) {
    int pass = 1;

    printf("=== %s Jasmin API Test ===\n", XMSS_PARAM_NAME);
    printf("SK=%d PK=%d Sig=%d BDS_state=%d bytes\n\n",
           _SK_BYTES, _PK_BYTES, _SIG_BYTES, _BDS_STATE_BYTES);

    printf("--- keygen ---\n");
    if (!test_keygen_suite()) pass = 0;

    printf("\n--- sign + verify ---\n");
    if (!test_sign_verify_suite()) pass = 0;

    printf("\n%s\n", pass ? "All tests passed." : "SOME TESTS FAILED.");
    return pass ? 0 : 1;
}
