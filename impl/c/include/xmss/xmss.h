/**
 * xmss.h - Public XMSS API
 *
 * RFC 8391 XMSS: eXtended Merkle Signature Scheme.
 *
 * All functions return 0 on success and a negative value on failure.
 * No heap allocation is performed; callers must supply correctly-sized buffers.
 * Buffer sizes are determined by xmss_params fields sig_bytes, pk_bytes, sk_bytes.
 *
 * Jasmin portability rules (see implementation plan):
 *   J1: No VLAs
 *   J2: No function pointers in algorithm code (dispatch only in xmss_hash.c)
 *   J3: No malloc
 *   J4: No recursion
 *   J5: Bounded loop counts
 *   J6: Constant-time for secret-dependent operations
 *   J7: ADRS always by pointer, serialised to 32-byte stack buffer for hashing
 *   J8: One C file per algorithm
 */
#ifndef XMSS_H
#define XMSS_H

#include <stddef.h>
#include <stdint.h>

#include "params.h"

/** Error codes */
#define XMSS_OK            0
#define XMSS_ERR_PARAMS   (-1)
#define XMSS_ERR_ENTROPY  (-2)
#define XMSS_ERR_VERIFY   (-3)
#define XMSS_ERR_EXHAUSTED (-4)  /* key index exhausted */

/**
 * Entropy callback type.
 *
 * The caller supplies a function that fills buf[0..len-1] with len bytes of
 * cryptographically secure random data.  Returns 0 on success, non-zero on
 * failure.  This keeps the library bare-metal compatible.
 */
typedef int (*xmss_randombytes_fn)(uint8_t *buf, size_t len);

/**
 * xmss_verify() - Verify an XMSS signature.
 *
 * @p:      Parameter set.
 * @msg:    Message that was signed.
 * @msglen: Message length.
 * @sig:    Signature (p->sig_bytes bytes).
 * @pk:     Public key (p->pk_bytes bytes).
 *
 * Returns XMSS_OK if signature is valid, XMSS_ERR_VERIFY if invalid.
 * Comparison is constant-time (ct_memcmp).
 */
int xmss_verify(const xmss_params *p,
                const uint8_t *msg, size_t msglen,
                const uint8_t *sig, const uint8_t *pk);

/* ====================================================================
 * BDS state types
 *
 * BDS amortises auth path computation: signing is O(h) leaf computations
 * instead of O(h * 2^h).  The BDS state is a separate caller-managed
 * buffer (not stored in SK, which stays RFC-compatible).
 * ==================================================================== */

/** Per-level treehash instance (internal detail exposed for static sizing). */
typedef struct {
    uint8_t  node[XMSS_MAX_N];   /* partial/completed result */
    uint32_t h;                   /* target height */
    uint32_t next_idx;            /* next leaf to process */
    uint8_t  stack_usage;         /* entries this instance has on shared stack */
    uint8_t  completed;           /* 1 if treehash is done */
} xmss_bds_treehash_inst;

/**
 * xmss_bds_state - BDS traversal state.
 *
 * Fixed-size, no pointers, no malloc (J1/J3).  Allocated by the caller
 * on the stack or as a static/global.  Must be initialised by
 * xmss_keygen() and updated by each xmss_sign() call.
 */
typedef struct xmss_bds_state {
    /* Auth path for current leaf: h nodes of n bytes */
    uint8_t auth[XMSS_MAX_H][XMSS_MAX_N];

    /* Keep nodes: floor(h/2) nodes saved during bds_round */
    uint8_t keep[XMSS_MAX_H / 2][XMSS_MAX_N];

    /* Shared stack for treehash instances */
    uint8_t  stack[XMSS_MAX_H + 1][XMSS_MAX_N];
    uint8_t  stack_levels[XMSS_MAX_H + 1];
    uint32_t stack_offset;

    /* Treehash instances: one per level below (h - bds_k) */
    xmss_bds_treehash_inst treehash[XMSS_MAX_H];

    /* Retain stack for top bds_k levels.
     * Size: sum_{j=0}^{k-1} 2^(j) - 1 = 2^k - k - 1 nodes.
     * For k=0 this is unused.  For k=4: 11 nodes. */
    uint8_t retain[((1U << XMSS_MAX_BDS_K) - XMSS_MAX_BDS_K - 1) > 0 ?
                   ((1U << XMSS_MAX_BDS_K) - XMSS_MAX_BDS_K - 1) : 1][XMSS_MAX_N];

    uint32_t next_leaf;  /* next leaf to compute during state_update */
} xmss_bds_state;

/**
 * xmss_keygen() - Generate an XMSS key pair with BDS state.
 *
 * Generates an XMSS key pair and initialises the BDS state for
 * BDS-accelerated signing.
 *
 * @p:           Parameter set.
 * @pk:          Output public key (p->pk_bytes bytes).
 * @sk:          Output secret key (p->sk_bytes bytes).
 * @state:       Output BDS state (caller-allocated).
 * @bds_k:       BDS retain parameter. K=0 always valid (no retain
 *               optimisation). Non-zero K requires: K >= 2, K < tree_height,
 *               and (tree_height - K) even (BDS algorithm precondition).
 * @randombytes: Caller-supplied entropy function.
 *
 * Returns XMSS_OK on success, XMSS_ERR_PARAMS if bds_k is invalid.
 *
 * SK layout (RFC 8391 §4.1.3, Errata 7900):
 *   OID(4) | idx(idx_bytes) | SK_SEED(n) | SK_PRF(n) | root(n) | SEED(n)
 * PK layout:
 *   OID(4) | root(n) | SEED(n)
 */
int xmss_keygen(const xmss_params *p, uint8_t *pk, uint8_t *sk,
                xmss_bds_state *state, uint32_t bds_k,
                xmss_randombytes_fn randombytes);

/**
 * xmss_sign() - Sign a message using BDS-accelerated auth path.
 *
 * Uses and updates the BDS state for O(h) leaf computations per
 * signature instead of O(h * 2^h).
 *
 * @p:      Parameter set.
 * @sig:    Output signature (p->sig_bytes bytes).
 * @msg:    Message to sign.
 * @msglen: Message length in bytes.
 * @sk:     Secret key (p->sk_bytes bytes); leaf index incremented in place.
 * @state:  BDS state (updated in place).
 * @bds_k:  Retain parameter (same value used in xmss_keygen).
 *
 * Returns XMSS_OK on success, XMSS_ERR_EXHAUSTED if key index exhausted.
 *
 * The leaf index in sk is incremented BEFORE returning to the caller.
 * Callers must persist the updated sk immediately to prevent index reuse.
 *
 * Signature layout (RFC 8391 §4.1.8):
 *   idx(idx_bytes) | r(n) | sig_WOTS(len*n) | auth(h*n)
 */
int xmss_sign(const xmss_params *p, uint8_t *sig,
              const uint8_t *msg, size_t msglen,
              uint8_t *sk, xmss_bds_state *state, uint32_t bds_k);

/**
 * xmss_remaining_sigs() - Query how many signatures remain in an XMSS key.
 *
 * Reads the current leaf index from sk and returns the number of signatures
 * that can still be produced: (idx_max - idx + 1), or 0 if exhausted.
 *
 * @p:   Parameter set.
 * @sk:  Secret key (p->sk_bytes bytes); read-only.
 *
 * Returns the number of remaining signatures (0 if key is exhausted).
 */
uint64_t xmss_remaining_sigs(const xmss_params *p, const uint8_t *sk);

/* ====================================================================
 * BDS state serialization
 * ==================================================================== */

/**
 * xmss_bds_serialized_size() - Compute serialized BDS state size.
 *
 * Returns the number of bytes needed to serialize a BDS state for the
 * given parameter set and bds_k value.
 */
uint32_t xmss_bds_serialized_size(const xmss_params *p, uint32_t bds_k);

/**
 * xmss_bds_serialize() - Serialize BDS state to a byte buffer.
 *
 * @p:      Parameter set.
 * @buf:    Output buffer (xmss_bds_serialized_size() bytes).
 * @state:  BDS state to serialize.
 * @bds_k:  Retain parameter (same as used in keygen).
 *
 * Returns XMSS_OK on success.
 */
int xmss_bds_serialize(const xmss_params *p, uint8_t *buf,
                       const xmss_bds_state *state, uint32_t bds_k);

/**
 * xmss_bds_deserialize() - Deserialize BDS state from a byte buffer.
 *
 * @p:      Parameter set.
 * @state:  Output BDS state (caller-allocated).
 * @buf:    Input buffer (xmss_bds_serialized_size() bytes).
 * @bds_k:  Retain parameter (same as used in keygen).
 *
 * Returns XMSS_OK on success.
 */
int xmss_bds_deserialize(const xmss_params *p, xmss_bds_state *state,
                         const uint8_t *buf, uint32_t bds_k);

/* ====================================================================
 * XMSS-MT (Multi-Tree) API
 *
 * XMSS-MT (RFC 8391 §4.2) organises d layers of XMSS trees into a
 * hypertree.  Each layer has tree height h/d.  Total signing capacity
 * is 2^h messages.
 *
 * The xmss_mt_state holds 2*d-1 BDS states (d current + d-1 next)
 * plus d-1 cached WOTS signatures for cross-layer signing.
 * ==================================================================== */

/**
 * xmss_mt_state - XMSS-MT traversal state.
 *
 * Manages BDS states for all d layers plus cached WOTS signatures.
 * Statically sized using XMSS_MAX_D (Jasmin J1/J3).
 * Allocated by the caller; must be initialised by xmss_mt_keygen().
 */
typedef struct xmss_mt_state {
    /* 2*d-1 BDS states:
     * bds[0..d-1]    = current tree state for each layer
     * bds[d..2*d-2]  = "next" tree state for layers 0..d-2 */
    xmss_bds_state bds[2 * XMSS_MAX_D - 1];

    /* Cached WOTS signatures of lower-layer roots.
     * wots_sigs[i] = signature of layer i's root by layer i+1.
     * d-1 cached signatures. */
    uint8_t wots_sigs[XMSS_MAX_D - 1][XMSS_MAX_WOTS_LEN * XMSS_MAX_N];
} xmss_mt_state;

/**
 * xmss_mt_keygen() - Generate an XMSS-MT key pair with hypertree state.
 *
 * @p:           Parameter set (must have d > 1).
 * @pk:          Output public key (p->pk_bytes bytes).
 * @sk:          Output secret key (p->sk_bytes bytes).
 * @state:       Output hypertree state (caller-allocated).
 * @bds_k:       BDS retain parameter. K=0 always valid. Non-zero K requires:
 *               K >= 2, K < tree_height, and (tree_height - K) even.
 * @randombytes: Caller-supplied entropy function.
 *
 * Returns XMSS_OK on success.
 */
int xmss_mt_keygen(const xmss_params *p, uint8_t *pk, uint8_t *sk,
                  xmss_mt_state *state, uint32_t bds_k,
                  xmss_randombytes_fn randombytes);

/**
 * xmss_mt_sign() - Sign a message using XMSS-MT hypertree.
 *
 * @p:      Parameter set (must have d > 1).
 * @sig:    Output signature (p->sig_bytes bytes).
 * @msg:    Message to sign.
 * @msglen: Message length in bytes.
 * @sk:     Secret key (p->sk_bytes bytes); index incremented in place.
 * @state:  Hypertree state (updated in place).
 * @bds_k:  BDS retain parameter (same value used in keygen).
 *
 * Returns XMSS_OK on success, XMSS_ERR_EXHAUSTED if index exhausted.
 */
int xmss_mt_sign(const xmss_params *p, uint8_t *sig,
                const uint8_t *msg, size_t msglen,
                uint8_t *sk, xmss_mt_state *state, uint32_t bds_k);

/**
 * xmss_mt_remaining_sigs() - Query how many signatures remain in an XMSS-MT key.
 *
 * Reads the current index from sk and returns the number of signatures
 * that can still be produced: (idx_max - idx + 1), or 0 if exhausted.
 *
 * @p:   Parameter set (must have d > 1).
 * @sk:  Secret key (p->sk_bytes bytes); read-only.
 *
 * Returns the number of remaining signatures (0 if key is exhausted).
 */
uint64_t xmss_mt_remaining_sigs(const xmss_params *p, const uint8_t *sk);

/**
 * xmss_mt_verify() - Verify an XMSS-MT signature.
 *
 * @p:      Parameter set (must have d > 1).
 * @msg:    Message that was signed.
 * @msglen: Message length.
 * @sig:    Signature (p->sig_bytes bytes).
 * @pk:     Public key (p->pk_bytes bytes).
 *
 * Returns XMSS_OK if valid, XMSS_ERR_VERIFY if invalid.
 * Stateless — no BDS state needed.
 */
int xmss_mt_verify(const xmss_params *p,
                  const uint8_t *msg, size_t msglen,
                  const uint8_t *sig, const uint8_t *pk);

/* ====================================================================
 * Naive API (gated behind XMSS_NAIVE_AUTH_PATH)
 *
 * These use O(h * 2^h) auth path computation per signature.
 * Only available when XMSS_NAIVE_AUTH_PATH is defined.
 * ==================================================================== */
#ifdef XMSS_NAIVE_AUTH_PATH

/**
 * xmss_keygen_naive() - Generate an XMSS key pair (no BDS state).
 */
int xmss_keygen_naive(const xmss_params *p, uint8_t *pk, uint8_t *sk,
                      xmss_randombytes_fn randombytes);

/**
 * xmss_sign_naive() - Sign a message with naive auth path (O(h * 2^h)).
 */
int xmss_sign_naive(const xmss_params *p, uint8_t *sig,
                    const uint8_t *msg, size_t msglen,
                    uint8_t *sk);

#endif /* XMSS_NAIVE_AUTH_PATH */

#endif /* XMSS_H */
