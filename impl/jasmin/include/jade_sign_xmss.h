/* jade_sign_xmss.h — C API for Jasmin XMSS/XMSS-MT (amd64/ref)
 *
 * Buffer size constants and function declarations for all supported
 * parameter sets. All sizes are in bytes.
 *
 * Usage:
 *   #include "jade_sign_xmss.h"
 *
 *   uint8_t pk[JADE_SIGN_XMSS_SHA2_10_256_PUBLICKEYBYTES];
 *   uint8_t sk[JADE_SIGN_XMSS_SHA2_10_256_SECRETKEYBYTES];
 *   uint8_t state[JADE_SIGN_XMSS_SHA2_10_256_STATEBYTES];
 *   uint8_t seeds[JADE_SIGN_XMSS_SHA2_10_256_SEEDBYTES];
 *   uint8_t scratch[JADE_SIGN_XMSS_SHA2_10_256_SCRATCHBYTES];
 *   jade_sign_xmss_sha2_10_256_amd64_ref_keypair(pk, sk, state, seeds, scratch);
 */

#ifndef JADE_SIGN_XMSS_H
#define JADE_SIGN_XMSS_H

#include <stdint.h>

/* ================================================================
 * XMSS-SHA2_10_256 (OID 0x00000001)
 * h=10, N=32, W=16, LEN=67
 * ================================================================ */

#define JADE_SIGN_XMSS_SHA2_10_256_PUBLICKEYBYTES  68
#define JADE_SIGN_XMSS_SHA2_10_256_SECRETKEYBYTES  136
#define JADE_SIGN_XMSS_SHA2_10_256_BYTES           2500
#define JADE_SIGN_XMSS_SHA2_10_256_STATEBYTES      1219
#define JADE_SIGN_XMSS_SHA2_10_256_SEEDBYTES       96
#define JADE_SIGN_XMSS_SHA2_10_256_SCRATCHBYTES    2240

extern uint64_t jade_sign_xmss_sha2_10_256_amd64_ref_keypair(
    uint8_t *pk, uint8_t *sk, uint8_t *state,
    const uint8_t *seeds, uint8_t *scratch);

extern uint64_t jade_sign_xmss_sha2_10_256_amd64_ref(
    uint8_t *sig, const uint8_t *msg, uint64_t msglen,
    uint8_t *sk, uint8_t *state, uint8_t *scratch);

extern uint64_t jade_sign_xmss_sha2_10_256_amd64_ref_open(
    const uint8_t *msg, uint64_t msglen,
    const uint8_t *sig, const uint8_t *pk, uint8_t *scratch);

/* ================================================================
 * XMSS-SHA2_16_256 (OID 0x00000002)
 * h=16, N=32, W=16, LEN=67
 * ================================================================ */

#define JADE_SIGN_XMSS_SHA2_16_256_PUBLICKEYBYTES  68
#define JADE_SIGN_XMSS_SHA2_16_256_SECRETKEYBYTES  136
#define JADE_SIGN_XMSS_SHA2_16_256_BYTES           2692
#define JADE_SIGN_XMSS_SHA2_16_256_STATEBYTES      1957
#define JADE_SIGN_XMSS_SHA2_16_256_SEEDBYTES       96
#define JADE_SIGN_XMSS_SHA2_16_256_SCRATCHBYTES    2240

extern uint64_t jade_sign_xmss_sha2_16_256_amd64_ref_keypair(
    uint8_t *pk, uint8_t *sk, uint8_t *state,
    const uint8_t *seeds, uint8_t *scratch);

extern uint64_t jade_sign_xmss_sha2_16_256_amd64_ref(
    uint8_t *sig, const uint8_t *msg, uint64_t msglen,
    uint8_t *sk, uint8_t *state, uint8_t *scratch);

extern uint64_t jade_sign_xmss_sha2_16_256_amd64_ref_open(
    const uint8_t *msg, uint64_t msglen,
    const uint8_t *sig, const uint8_t *pk, uint8_t *scratch);

/* ================================================================
 * XMSS-SHA2_20_256 (OID 0x00000003)
 * h=20, N=32, W=16, LEN=67
 * ================================================================ */

#define JADE_SIGN_XMSS_SHA2_20_256_PUBLICKEYBYTES  68
#define JADE_SIGN_XMSS_SHA2_20_256_SECRETKEYBYTES  136
#define JADE_SIGN_XMSS_SHA2_20_256_BYTES           2820
#define JADE_SIGN_XMSS_SHA2_20_256_STATEBYTES      2449
#define JADE_SIGN_XMSS_SHA2_20_256_SEEDBYTES       96
#define JADE_SIGN_XMSS_SHA2_20_256_SCRATCHBYTES    2240

extern uint64_t jade_sign_xmss_sha2_20_256_amd64_ref_keypair(
    uint8_t *pk, uint8_t *sk, uint8_t *state,
    const uint8_t *seeds, uint8_t *scratch);

extern uint64_t jade_sign_xmss_sha2_20_256_amd64_ref(
    uint8_t *sig, const uint8_t *msg, uint64_t msglen,
    uint8_t *sk, uint8_t *state, uint8_t *scratch);

extern uint64_t jade_sign_xmss_sha2_20_256_amd64_ref_open(
    const uint8_t *msg, uint64_t msglen,
    const uint8_t *sig, const uint8_t *pk, uint8_t *scratch);

/* ================================================================
 * XMSSMT-SHA2_20/2_256 (OID 0x00000001)
 * D=2, FULL_H=20, TREE_HEIGHT=10, N=32, W=16, LEN=67
 * ================================================================ */

#define JADE_SIGN_XMSSMT_SHA2_20_2_256_PUBLICKEYBYTES  68
#define JADE_SIGN_XMSSMT_SHA2_20_2_256_SECRETKEYBYTES  135
#define JADE_SIGN_XMSSMT_SHA2_20_2_256_BYTES           4963
#define JADE_SIGN_XMSSMT_SHA2_20_2_256_STATEBYTES      5801
#define JADE_SIGN_XMSSMT_SHA2_20_2_256_SEEDBYTES       96
#define JADE_SIGN_XMSSMT_SHA2_20_2_256_SCRATCHBYTES    2240

extern uint64_t jade_sign_xmssmt_sha2_20_2_256_amd64_ref_keypair(
    uint8_t *pk, uint8_t *sk, uint8_t *mt_state,
    const uint8_t *seeds, uint8_t *scratch);

extern uint64_t jade_sign_xmssmt_sha2_20_2_256_amd64_ref(
    uint8_t *sig, const uint8_t *msg, uint64_t msglen,
    uint8_t *sk, uint8_t *mt_state, uint8_t *scratch);

extern uint64_t jade_sign_xmssmt_sha2_20_2_256_amd64_ref_open(
    const uint8_t *msg, uint64_t msglen,
    const uint8_t *sig, const uint8_t *pk, uint8_t *scratch);

#endif /* JADE_SIGN_XMSS_H */
