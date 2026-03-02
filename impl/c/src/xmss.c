/**
 * xmss.c - XMSS key generation, signing, verification
 *
 * RFC 8391 §4.1, Algorithms 10, 11, 14.
 *
 * SK layout (RFC 8391 §4.1.3, Errata 7900):
 *   OID(4) | idx(idx_bytes) | SK_SEED(n) | SK_PRF(n) | root(n) | SEED(n)
 * PK layout (RFC 8391 §4.1.7):
 *   OID(4) | root(n) | SEED(n)
 * Signature layout (RFC 8391 §4.1.8):
 *   idx(idx_bytes) | r(n) | sig_WOTS(len*n) | auth(h*n)
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
 * Naive keygen/sign — gated behind XMSS_NAIVE_AUTH_PATH
 * ==================================================================== */

#ifdef XMSS_NAIVE_AUTH_PATH

int xmss_keygen_naive(const xmss_params *p, uint8_t *pk, uint8_t *sk,
                      xmss_randombytes_fn randombytes)
{
    uint8_t  root[XMSS_MAX_N];
    uint8_t  seeds[3 * XMSS_MAX_N]; /* SK_SEED || SK_PRF || SEED */
    xmss_adrs_t adrs;
    int ret;

    /* Sample 3n random bytes: SK_SEED, SK_PRF, SEED */
    ret = randombytes(seeds, 3 * p->n);
    if (ret != 0) { return XMSS_ERR_ENTROPY; }

    /* Compute tree root */
    memset(&adrs, 0, sizeof(adrs));
    xmss_adrs_set_layer(&adrs, 0);
    xmss_adrs_set_tree(&adrs, 0);

    treehash(p, root,
             seeds,           /* SK_SEED */
             seeds + 2*p->n,  /* SEED */
             0, (uint32_t)1 << p->tree_height,
             &adrs);

    /* Serialise PK: OID(4) | root(n) | SEED(n) */
    ull_to_bytes(pk, 4, p->oid);
    memcpy(pk + pk_off_root(p), root, p->n);
    memcpy(pk + pk_off_seed(p), seeds + 2*p->n, p->n);

    /* Serialise SK: OID(4) | idx(idx_bytes) | SK_SEED(n) | SK_PRF(n) | root(n) | SEED(n) */
    ull_to_bytes(sk + sk_off_oid(p),  4,            p->oid);
    ull_to_bytes(sk + sk_off_idx(p),  p->idx_bytes, 0);      /* index starts at 0 */
    memcpy(sk + sk_off_seed(p),     seeds,          p->n);   /* SK_SEED */
    memcpy(sk + sk_off_prf(p),      seeds + p->n,   p->n);   /* SK_PRF  */
    memcpy(sk + sk_off_root(p),     root,            p->n);   /* root    */
    memcpy(sk + sk_off_pub_seed(p), seeds + 2*p->n, p->n);   /* SEED    */

    xmss_memzero(seeds, sizeof(seeds));
    return XMSS_OK;
}

int xmss_sign_naive(const xmss_params *p, uint8_t *sig,
                    const uint8_t *msg, size_t msglen,
                    uint8_t *sk)
{
    uint64_t idx;
    uint8_t  r[XMSS_MAX_N];
    uint8_t  m_hash[XMSS_MAX_N];
    xmss_adrs_t adrs;

    const uint8_t *sk_seed    = sk + sk_off_seed(p);
    const uint8_t *sk_prf     = sk + sk_off_prf(p);
    const uint8_t *root       = sk + sk_off_root(p);
    const uint8_t *pub_seed   = sk + sk_off_pub_seed(p);

    /* Read current index */
    idx = bytes_to_ull(sk + sk_off_idx(p), p->idx_bytes);

    /* Check for index exhaustion */
    if (idx > p->idx_max) {
        return XMSS_ERR_EXHAUSTED;
    }

    /* Increment index in SK immediately (RFC 8391 §4.1.9 note) */
    ull_to_bytes(sk + sk_off_idx(p), p->idx_bytes, idx + 1);

    /* r = PRF(SK_PRF, toByte(idx, 32)) */
    xmss_PRF_idx(p, r, sk_prf, idx);

    /* m_hash = H_msg(r, root, idx, msg) */
    xmss_H_msg(p, m_hash, r, root, idx, msg, msglen);

    /* sig = idx || r || WOTS_sign(m_hash) || auth_path */
    ull_to_bytes(sig, p->idx_bytes, idx);
    memcpy(sig + p->idx_bytes, r, p->n);

    /* WOTS+ signature */
    memset(&adrs, 0, sizeof(adrs));
    xmss_adrs_set_layer(&adrs, 0);
    xmss_adrs_set_tree(&adrs, 0);
    xmss_adrs_set_type(&adrs, XMSS_ADRS_TYPE_OTS);
    xmss_adrs_set_ots(&adrs, (uint32_t)idx);

    wots_sign(p,
              sig + p->idx_bytes + p->n,  /* sig_WOTS */
              m_hash,
              sk_seed, pub_seed, &adrs);

    /* Authentication path */
    memset(&adrs, 0, sizeof(adrs));
    xmss_adrs_set_layer(&adrs, 0);
    xmss_adrs_set_tree(&adrs, 0);

    treehash_auth_path(p,
                       sig + p->idx_bytes + p->n + p->len * p->n,  /* auth */
                       sk_seed, pub_seed,
                       (uint32_t)idx, &adrs);

    return XMSS_OK;
}

#endif /* XMSS_NAIVE_AUTH_PATH */

/* ====================================================================
 * xmss_remaining_sigs()
 * ==================================================================== */

uint64_t xmss_remaining_sigs(const xmss_params *p, const uint8_t *sk)
{
    uint64_t idx = bytes_to_ull(sk + sk_off_idx(p), p->idx_bytes);
    if (idx > p->idx_max) {
        return 0;
    }
    return p->idx_max - idx + 1;
}

/* ====================================================================
 * xmss_verify() - Algorithm 14
 * ==================================================================== */

int xmss_verify(const xmss_params *p,
                const uint8_t *msg, size_t msglen,
                const uint8_t *sig, const uint8_t *pk)
{
    uint64_t idx;
    uint8_t  r[XMSS_MAX_N];
    uint8_t  m_hash[XMSS_MAX_N];
    uint8_t  wots_pk[XMSS_MAX_WOTS_LEN * XMSS_MAX_N];
    uint8_t  leaf[XMSS_MAX_N];
    uint8_t  computed_root[XMSS_MAX_N];
    xmss_adrs_t adrs;

    const uint8_t *pk_root = pk + pk_off_root(p);
    const uint8_t *pk_seed = pk + pk_off_seed(p);
    const uint8_t *sig_wots = sig + p->idx_bytes + p->n;
    const uint8_t *auth     = sig + p->idx_bytes + p->n + p->len * p->n;

    /* Validate PK OID matches params */
    if ((uint32_t)bytes_to_ull(pk, 4) != p->oid) { return XMSS_ERR_VERIFY; }

    /* Extract index */
    idx = bytes_to_ull(sig, p->idx_bytes);

    /* Sanity check */
    if (idx > p->idx_max) { return XMSS_ERR_VERIFY; }

    /* Extract r */
    memcpy(r, sig + p->idx_bytes, p->n);

    /* m_hash = H_msg(r, root, idx, msg) */
    xmss_H_msg(p, m_hash, r, pk_root, idx, msg, msglen);

    /* Recover WOTS+ public key from signature */
    memset(&adrs, 0, sizeof(adrs));
    xmss_adrs_set_layer(&adrs, 0);
    xmss_adrs_set_tree(&adrs, 0);
    xmss_adrs_set_type(&adrs, XMSS_ADRS_TYPE_OTS);
    xmss_adrs_set_ots(&adrs, (uint32_t)idx);

    wots_pk_from_sig(p, wots_pk, sig_wots, m_hash, pk_seed, &adrs);

    /* Compute leaf from WOTS+ pk via l_tree */
    memset(&adrs, 0, sizeof(adrs));
    xmss_adrs_set_layer(&adrs, 0);
    xmss_adrs_set_tree(&adrs, 0);
    xmss_adrs_set_type(&adrs, XMSS_ADRS_TYPE_LTREE);
    xmss_adrs_set_ltree(&adrs, (uint32_t)idx);

    l_tree(p, leaf, wots_pk, pk_seed, &adrs);

    /* Walk auth path to compute candidate root */
    memset(&adrs, 0, sizeof(adrs));
    xmss_adrs_set_layer(&adrs, 0);
    xmss_adrs_set_tree(&adrs, 0);

    compute_root(p, computed_root, leaf, (uint32_t)idx, auth, pk_seed, &adrs);

    /* Constant-time compare (J6) */
    if (ct_memcmp(computed_root, pk_root, p->n) != 0) {
        return XMSS_ERR_VERIFY;
    }
    return XMSS_OK;
}

/* ====================================================================
 * xmss_keygen() - BDS-accelerated key generation (Algorithm 10 + BDS)
 * ==================================================================== */

int xmss_keygen(const xmss_params *p, uint8_t *pk, uint8_t *sk,
                    xmss_bds_state *state, uint32_t bds_k,
                    xmss_randombytes_fn randombytes)
{
    uint8_t  root[XMSS_MAX_N];
    uint8_t  seeds[3 * XMSS_MAX_N];
    xmss_adrs_t adrs;
    int ret;

    /* Validate bds_k */
    if ((bds_k & 1) || bds_k > p->tree_height) {
        return XMSS_ERR_PARAMS;
    }

    /* Sample 3n random bytes: SK_SEED, SK_PRF, SEED */
    ret = randombytes(seeds, 3 * p->n);
    if (ret != 0) { return XMSS_ERR_ENTROPY; }

    /* Zero the BDS state */
    memset(state, 0, sizeof(*state));

    /* Compute tree root with BDS state capture */
    memset(&adrs, 0, sizeof(adrs));
    xmss_adrs_set_layer(&adrs, 0);
    xmss_adrs_set_tree(&adrs, 0);

    bds_treehash_init(p, root, state, bds_k,
                      seeds,           /* SK_SEED */
                      seeds + 2*p->n,  /* SEED */
                      &adrs);

    /* Serialise PK */
    ull_to_bytes(pk, 4, p->oid);
    memcpy(pk + pk_off_root(p), root, p->n);
    memcpy(pk + pk_off_seed(p), seeds + 2*p->n, p->n);

    /* Serialise SK */
    ull_to_bytes(sk + sk_off_oid(p),  4,            p->oid);
    ull_to_bytes(sk + sk_off_idx(p),  p->idx_bytes, 0);
    memcpy(sk + sk_off_seed(p),     seeds,          p->n);
    memcpy(sk + sk_off_prf(p),      seeds + p->n,   p->n);
    memcpy(sk + sk_off_root(p),     root,            p->n);
    memcpy(sk + sk_off_pub_seed(p), seeds + 2*p->n, p->n);

    xmss_memzero(seeds, sizeof(seeds));
    return XMSS_OK;
}

/* ====================================================================
 * xmss_sign() - BDS-accelerated signing (Algorithm 11 + BDS)
 * ==================================================================== */

int xmss_sign(const xmss_params *p, uint8_t *sig,
                  const uint8_t *msg, size_t msglen,
                  uint8_t *sk, xmss_bds_state *state, uint32_t bds_k)
{
    uint64_t idx;
    uint8_t  r[XMSS_MAX_N];
    uint8_t  m_hash[XMSS_MAX_N];
    xmss_adrs_t adrs;

    const uint8_t *sk_seed  = sk + sk_off_seed(p);
    const uint8_t *sk_prf   = sk + sk_off_prf(p);
    const uint8_t *root     = sk + sk_off_root(p);
    const uint8_t *pub_seed = sk + sk_off_pub_seed(p);

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

    /* sig = idx || r || WOTS_sign(m_hash) || auth_path */
    ull_to_bytes(sig, p->idx_bytes, idx);
    memcpy(sig + p->idx_bytes, r, p->n);

    /* WOTS+ signature */
    memset(&adrs, 0, sizeof(adrs));
    xmss_adrs_set_layer(&adrs, 0);
    xmss_adrs_set_tree(&adrs, 0);
    xmss_adrs_set_type(&adrs, XMSS_ADRS_TYPE_OTS);
    xmss_adrs_set_ots(&adrs, (uint32_t)idx);

    wots_sign(p,
              sig + p->idx_bytes + p->n,
              m_hash,
              sk_seed, pub_seed, &adrs);

    /* Auth path: copy from BDS state (O(1) instead of O(h * 2^h)) */
    {
        uint32_t i;
        uint8_t *auth_out = sig + p->idx_bytes + p->n + p->len * p->n;
        for (i = 0; i < p->tree_height; i++) {
            memcpy(auth_out + i * p->n, state->auth[i], p->n);
        }
    }

    /* Advance BDS state for next signature */
    memset(&adrs, 0, sizeof(adrs));
    xmss_adrs_set_layer(&adrs, 0);
    xmss_adrs_set_tree(&adrs, 0);

    bds_round(p, state, bds_k, (uint32_t)idx, sk_seed, pub_seed, &adrs);

    /* Run treehash updates: ceil((h - bds_k) / 2) updates per signature.
     * Must round up: floor division starves high treehash instances when
     * (h - bds_k) is odd (e.g. h=5, k=2 → need 2, not 1). */
    if (p->tree_height > bds_k) {
        bds_treehash_update(p, state, bds_k, (p->tree_height - bds_k + 1) / 2,
                            sk_seed, pub_seed, &adrs);
    }

    return XMSS_OK;
}
