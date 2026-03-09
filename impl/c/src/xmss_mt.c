/**
 * xmss_mt.c - XMSS-MT (Multi-Tree) key generation, signing, verification
 *
 * RFC 8391 §4.2, Algorithms 15, 16, 17.
 *
 * XMSS-MT organises d layers of XMSS trees into a hypertree.
 * Each layer has tree height h/d.  The bottom layer (0) signs messages;
 * each upper layer signs the root of a tree in the layer below.
 *
 * No malloc (J3), no recursion (J4), no VLAs (J1), no function pointers (J2).
 * All loops bounded by params fields or XMSS_MAX_* constants (J5).
 */
#include <string.h>
#include <stdint.h>

#include "../include/xmss/xmss.h"
#include "../include/xmss/params.h"
#include "../include/xmss/types.h"
#include "utils.h"
#include "address.h"
#include "hash/hash_iface.h"
#include "wots.h"
#include "ltree.h"
#include "treehash.h"
#include "bds.h"
#include "sk_offsets.h"

/* ====================================================================
 * deep_state_swap() - Swap two BDS states in place
 * ==================================================================== */
static void deep_state_swap(xmss_bds_state *a, xmss_bds_state *b)
{
    xmss_bds_state tmp;
    memcpy(&tmp, a, sizeof(xmss_bds_state));
    memcpy(a, b, sizeof(xmss_bds_state));
    memcpy(b, &tmp, sizeof(xmss_bds_state));
}

/* ====================================================================
 * xmss_mt_keygen() - Algorithm 15: XMSS-MT Key Generation
 * ==================================================================== */

int xmss_mt_keygen(const xmss_params *p, uint8_t *pk, uint8_t *sk,
                  xmss_mt_state *state, uint32_t bds_k,
                  xmss_randombytes_fn randombytes)
{
    uint8_t  root[XMSS_MAX_N];
    uint8_t  seeds[3 * XMSS_MAX_N];
    xmss_adrs_t adrs;
    uint32_t i;
    int ret;

    /* Validate parameters */
    if (p->d < 2 || p->d > XMSS_MAX_D) {
        return XMSS_ERR_PARAMS;
    }
    /* Validate bds_k (includes XMSS_MAX_BDS_K upper bound check) */
    if (!xmss_bds_k_valid(p, bds_k)) {
        return XMSS_ERR_PARAMS;
    }

    /* Sample 3n random bytes: SK_SEED, SK_PRF, SEED */
    ret = randombytes(seeds, 3 * p->n);
    if (ret != 0) { return XMSS_ERR_ENTROPY; }

    /* Zero entire state */
    memset(state, 0, sizeof(*state));

    /* Set bds_k on all BDS states (2*d-1 total) */
    for (i = 0; i < 2 * p->d - 1; i++) {
        state->bds[i].bds_k = bds_k;
    }

    /* Build trees bottom-up, signing each root at the layer above */
    memset(&adrs, 0, sizeof(adrs));

    for (i = 0; i < p->d - 1; i++) {
        xmss_adrs_set_layer(&adrs, i);
        xmss_adrs_set_tree(&adrs, 0);

        bds_treehash_init(p, root, &state->bds[i], bds_k,
                          seeds,           /* SK_SEED */
                          seeds + 2*p->n,  /* SEED */
                          &adrs);

        /* Sign this layer's root at layer i+1 */
        memset(&adrs, 0, sizeof(adrs));
        xmss_adrs_set_layer(&adrs, i + 1);
        xmss_adrs_set_tree(&adrs, 0);
        xmss_adrs_set_type(&adrs, XMSS_ADRS_TYPE_OTS);
        xmss_adrs_set_ots(&adrs, 0);

        wots_sign(p, state->wots_sigs[i], root,
                  seeds, seeds + 2*p->n, &adrs);
    }

    /* Top layer: just build the tree, no WOTS sig needed */
    memset(&adrs, 0, sizeof(adrs));
    xmss_adrs_set_layer(&adrs, p->d - 1);
    xmss_adrs_set_tree(&adrs, 0);

    bds_treehash_init(p, root, &state->bds[p->d - 1], bds_k,
                      seeds,           /* SK_SEED */
                      seeds + 2*p->n,  /* SEED */
                      &adrs);

    /* Initialise "next" BDS states for tree_idx=1 at layers 0..d-2.
     * These are pre-computed so the next tree is ready when a boundary
     * is crossed.  We don't fully build them here; they start at
     * next_leaf=0 and get built incrementally during signing. */
    for (i = 0; i < p->d - 1; i++) {
        state->bds[p->d + i].next_leaf = 0;
        state->bds[p->d + i].stack_offset = 0;
    }

    /* Serialise PK: OID(4) | root(n) | SEED(n) */
    ull_to_bytes(pk, 4, p->oid);
    memcpy(pk + pk_off_root(p), root, p->n);
    memcpy(pk + pk_off_seed(p), seeds + 2*p->n, p->n);

    /* Serialise SK: OID(4) | idx(idx_bytes) | SK_SEED(n) | SK_PRF(n) | root(n) | SEED(n) */
    ull_to_bytes(sk, 4, p->oid);
    ull_to_bytes(sk + sk_off_idx(p), p->idx_bytes, 0);
    memcpy(sk + sk_off_seed(p),     seeds,          p->n);
    memcpy(sk + sk_off_prf(p),      seeds + p->n,   p->n);
    memcpy(sk + sk_off_root(p),     root,            p->n);
    memcpy(sk + sk_off_pub_seed(p), seeds + 2*p->n, p->n);

    xmss_memzero(seeds, sizeof(seeds));
    return XMSS_OK;
}

/* ====================================================================
 * xmss_mt_sign() - Algorithm 16: XMSS-MT Signature Generation
 * ==================================================================== */

int xmss_mt_sign(const xmss_params *p, uint8_t *sig,
                const uint8_t *msg, size_t msglen,
                uint8_t *sk, xmss_mt_state *state, uint32_t bds_k)
{
    uint64_t idx;
    uint64_t idx_tree;
    uint32_t idx_leaf;
    uint8_t  r[XMSS_MAX_N];
    uint8_t  m_hash[XMSS_MAX_N];
    xmss_adrs_t adrs;
    xmss_adrs_t ots_addr;
    uint32_t i, j;
    uint32_t updates;
    int needswap_upto = -1;
    uint32_t th = p->tree_height;
    uint32_t wots_sig_bytes = p->len * p->n;

    const uint8_t *sk_seed  = sk + sk_off_seed(p);
    const uint8_t *sk_prf   = sk + sk_off_prf(p);
    const uint8_t *root     = sk + sk_off_root(p);
    const uint8_t *pub_seed = sk + sk_off_pub_seed(p);

    /* Validate bds_k and check for keygen/sign mismatch */
    if (!xmss_bds_k_valid(p, bds_k)) { return XMSS_ERR_PARAMS; }
    if (bds_k != state->bds[0].bds_k) { return XMSS_ERR_PARAMS; }

    /* Read current index */
    idx = bytes_to_ull(sk + sk_off_idx(p), p->idx_bytes);

    if (idx > p->idx_max) {
        return XMSS_ERR_EXHAUSTED;
    }

    /* Increment index in SK */
    ull_to_bytes(sk + sk_off_idx(p), p->idx_bytes, idx + 1);

    /* r = PRF(SK_PRF, toByte(idx, 32)) */
    xmss_PRF_idx(p, r, sk_prf, idx);

    /* m_hash = H_msg(r, root, idx, msg) */
    xmss_H_msg(p, m_hash, r, root, idx, msg, msglen);

    /* ---- Build signature ---- */
    /* sig = idx_sig | r | reduced_sig_0 | ... | reduced_sig_{d-1} */
    ull_to_bytes(sig, p->idx_bytes, idx);
    memcpy(sig + p->idx_bytes, r, p->n);

    {
        uint8_t *sig_ptr = sig + p->idx_bytes + p->n;

        /* Layer 0: sign message hash directly */
        idx_tree = idx >> th;
        idx_leaf = (uint32_t)(idx & (((uint64_t)1 << th) - 1));

        memset(&ots_addr, 0, sizeof(ots_addr));
        xmss_adrs_set_layer(&ots_addr, 0);
        xmss_adrs_set_tree(&ots_addr, idx_tree);
        xmss_adrs_set_type(&ots_addr, XMSS_ADRS_TYPE_OTS);
        xmss_adrs_set_ots(&ots_addr, idx_leaf);

        wots_sign(p, sig_ptr, m_hash, sk_seed, pub_seed, &ots_addr);
        sig_ptr += wots_sig_bytes;

        /* Auth path from BDS state[0] */
        for (j = 0; j < th; j++) {
            memcpy(sig_ptr + j * p->n, state->bds[0].auth[j], p->n);
        }
        sig_ptr += th * p->n;

        /* Layers 1..d-1: use cached WOTS signatures */
        for (i = 1; i < p->d; i++) {
            memcpy(sig_ptr, state->wots_sigs[i - 1], wots_sig_bytes);
            sig_ptr += wots_sig_bytes;

            for (j = 0; j < th; j++) {
                memcpy(sig_ptr + j * p->n, state->bds[i].auth[j], p->n);
            }
            sig_ptr += th * p->n;
        }
    }

    /* ---- Update BDS states ---- */
    /* (th - bds_k) / 2: exact because (H - K) is guaranteed even by
     * the bds_k validation (K=0 or (H-K) even). */
    updates = (th - bds_k) >> 1;

    /* Mandatory update for NEXT_0 (layer 0 next tree) */
    idx_tree = idx >> th;
    idx_leaf = (uint32_t)(idx & (((uint64_t)1 << th) - 1));

    memset(&adrs, 0, sizeof(adrs));
    xmss_adrs_set_layer(&adrs, 0);
    xmss_adrs_set_tree(&adrs, idx_tree + 1);

    if ((1 + idx_tree) * ((uint64_t)1 << th) + idx_leaf < ((uint64_t)1 << p->h)) {
        bds_state_update(p, &state->bds[p->d], bds_k, sk_seed, pub_seed, &adrs);
    }

    /* Per-layer state updates */
    for (i = 0; i < p->d; i++) {
        /* Check if we're NOT at a tree boundary at layer i */
        if (!(((idx + 1) & (((uint64_t)1 << ((i + 1) * th)) - 1)) == 0)) {
            /* Not at boundary: advance BDS state */
            idx_leaf = (uint32_t)((idx >> (th * i)) & (((uint64_t)1 << th) - 1));
            idx_tree = idx >> (th * (i + 1));

            memset(&adrs, 0, sizeof(adrs));
            xmss_adrs_set_layer(&adrs, i);
            xmss_adrs_set_tree(&adrs, idx_tree);

            if ((int)i == needswap_upto + 1) {
                bds_round(p, &state->bds[i], bds_k, idx_leaf,
                          sk_seed, pub_seed, &adrs);
            }

            bds_treehash_update(p, &state->bds[i], bds_k, updates,
                                sk_seed, pub_seed, &adrs);

            /* Update "next" tree for this layer (if it exists and i > 0) */
            memset(&adrs, 0, sizeof(adrs));
            xmss_adrs_set_layer(&adrs, i);
            xmss_adrs_set_tree(&adrs, idx_tree + 1);

            if (i > 0 && updates > 0 &&
                (1 + idx_tree) * ((uint64_t)1 << th) + idx_leaf <
                ((uint64_t)1 << (p->h - th * i))) {
                if (state->bds[p->d + i].next_leaf < ((uint32_t)1 << th)) {
                    bds_state_update(p, &state->bds[p->d + i], bds_k,
                                     sk_seed, pub_seed, &adrs);
                    updates--;
                }
            }
        }
        else if (idx < ((uint64_t)1 << p->h) - 1) {
            /* At tree boundary: swap current/next BDS states */
            deep_state_swap(&state->bds[p->d + i], &state->bds[i]);

            /* Sign the completed tree's root at layer i+1 */
            memset(&ots_addr, 0, sizeof(ots_addr));
            xmss_adrs_set_layer(&ots_addr, i + 1);
            xmss_adrs_set_tree(&ots_addr, (idx + 1) >> ((i + 2) * th));
            xmss_adrs_set_type(&ots_addr, XMSS_ADRS_TYPE_OTS);
            xmss_adrs_set_ots(&ots_addr,
                (uint32_t)(((idx >> ((i + 1) * th)) + 1) & (((uint64_t)1 << th) - 1)));

            wots_sign(p, state->wots_sigs[i],
                      state->bds[i].stack[0],
                      sk_seed, pub_seed, &ots_addr);

            /* Reset the swapped-in "next" state for future use */
            state->bds[p->d + i].stack_offset = 0;
            state->bds[p->d + i].next_leaf = 0;

            if (updates > 0) { updates--; }
            needswap_upto = (int)i;

            /* Mark all treehash instances as completed for swapped state */
            for (j = 0; j < th - bds_k; j++) {
                state->bds[i].treehash[j].completed = 1;
            }
        }
    }

    return XMSS_OK;
}

/* ====================================================================
 * xmss_mt_remaining_sigs()
 * ==================================================================== */

uint64_t xmss_mt_remaining_sigs(const xmss_params *p, const uint8_t *sk)
{
    uint64_t idx = bytes_to_ull(sk + sk_off_idx(p), p->idx_bytes);
    if (idx > p->idx_max) {
        return 0;
    }
    return p->idx_max - idx + 1;
}

/* ====================================================================
 * xmss_mt_verify() - Algorithm 17: XMSS-MT Signature Verification
 * ==================================================================== */

int xmss_mt_verify(const xmss_params *p,
                  const uint8_t *msg, size_t msglen,
                  const uint8_t *sig, const uint8_t *pk)
{
    uint64_t idx;
    uint32_t idx_leaf;
    uint8_t  r[XMSS_MAX_N];
    uint8_t  m_hash[XMSS_MAX_N];
    uint8_t  wots_pk[XMSS_MAX_WOTS_LEN * XMSS_MAX_N];
    uint8_t  leaf[XMSS_MAX_N];
    uint8_t  computed_root[XMSS_MAX_N];
    xmss_adrs_t adrs;
    uint32_t i;
    uint32_t th = p->tree_height;
    uint32_t wots_sig_bytes = p->len * p->n;

    const uint8_t *pk_root = pk + pk_off_root(p);
    const uint8_t *pk_seed = pk + pk_off_seed(p);
    const uint8_t *sig_ptr;

    /* Validate PK OID matches params */
    if ((uint32_t)bytes_to_ull(pk, 4) != p->oid) { return XMSS_ERR_VERIFY; }

    /* Extract index */
    idx = bytes_to_ull(sig, p->idx_bytes);
    if (idx > p->idx_max) { return XMSS_ERR_VERIFY; }

    /* Extract r */
    memcpy(r, sig + p->idx_bytes, p->n);

    /* m_hash = H_msg(r, root, idx, msg) */
    xmss_H_msg(p, m_hash, r, pk_root, idx, msg, msglen);

    /* Iterate through d layers */
    sig_ptr = sig + p->idx_bytes + p->n;
    memcpy(computed_root, m_hash, p->n);

    for (i = 0; i < p->d; i++) {
        idx_leaf = (uint32_t)(idx & (((uint64_t)1 << th) - 1));
        idx >>= th;

        /* Recover WOTS+ public key from signature */
        memset(&adrs, 0, sizeof(adrs));
        xmss_adrs_set_layer(&adrs, i);
        xmss_adrs_set_tree(&adrs, idx);
        xmss_adrs_set_type(&adrs, XMSS_ADRS_TYPE_OTS);
        xmss_adrs_set_ots(&adrs, idx_leaf);

        wots_pk_from_sig(p, wots_pk, sig_ptr, computed_root, pk_seed, &adrs);
        sig_ptr += wots_sig_bytes;

        /* Compute leaf from WOTS+ pk via l_tree */
        memset(&adrs, 0, sizeof(adrs));
        xmss_adrs_set_layer(&adrs, i);
        xmss_adrs_set_tree(&adrs, idx);
        xmss_adrs_set_type(&adrs, XMSS_ADRS_TYPE_LTREE);
        xmss_adrs_set_ltree(&adrs, idx_leaf);

        l_tree(p, leaf, wots_pk, pk_seed, &adrs);

        /* Walk auth path to compute root */
        memset(&adrs, 0, sizeof(adrs));
        xmss_adrs_set_layer(&adrs, i);
        xmss_adrs_set_tree(&adrs, idx);

        compute_root(p, computed_root, leaf, idx_leaf, sig_ptr, pk_seed, &adrs);
        sig_ptr += th * p->n;
    }

    /* Constant-time compare (J6) */
    if (ct_memcmp(computed_root, pk_root, p->n) != 0) {
        return XMSS_ERR_VERIFY;
    }
    return XMSS_OK;
}
