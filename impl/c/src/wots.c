/**
 * wots.c - WOTS+ one-time signature scheme
 *
 * RFC 8391 §3.1, Algorithms 2-6.
 *
 * J4: No recursion.
 * J3: No malloc; all buffers on stack or caller-provided.
 * J6: wots_expand_seed iterates exactly len times (secret-independent count).
 *     gen_chain loop count is from message (public).
 */
#include <string.h>
#include <stdint.h>

#include "wots.h"
#include "hash/hash_iface.h"
#include "utils.h"
#include "address.h"
#include "../include/xmss/params.h"
#include "../include/xmss/types.h"

/* ====================================================================
 * base_w() - Alg 1: Convert byte string to base-w digits
 *
 * @out:    Output array of base-w digits (outlen values each in [0, w-1]).
 * @outlen: Number of base-w digits to produce.
 * @in:     Input byte string.
 * @p:      Parameter set (provides w, log2_w).
 * ==================================================================== */
static void base_w(const xmss_params *p,
                   uint32_t *out, uint32_t outlen,
                   const uint8_t *in)
{
    uint32_t in_off  = 0;
    uint32_t total   = 0;
    uint32_t bits    = 0;
    uint32_t consumed;
    uint32_t mask = p->w - 1;

    for (consumed = 0; consumed < outlen; consumed++) {
        if (bits == 0) {
            total = in[in_off++];
            bits  = 8;
        }
        bits       -= p->log2_w;
        out[consumed] = (total >> bits) & mask;
    }
}

/* ====================================================================
 * wots_checksum() - Compute WOTS+ checksum (RFC 8391 §3.1)
 *
 * csum = sum of (w - 1 - msg[i]) for i in 0..len1-1
 * Appended to msg array at positions len1..len1+len2-1 in base-w.
 * ==================================================================== */
static void wots_checksum(const xmss_params *p,
                          uint32_t *msg_and_csum) /* len1 entries already filled */
{
    uint64_t csum = 0;
    uint8_t  csum_bytes[8]; /* ceil(len2 * log2_w / 8) <= 8 bytes */
    uint32_t csum_bytes_len;
    uint32_t i;

    /* Sum */
    for (i = 0; i < p->len1; i++) {
        csum += (p->w - 1) - msg_and_csum[i];
    }

    /* csum is shifted left so that it fits in len2 * log2_w bits */
    /* Left-align in bytes: shift csum by (8 - (len2 * log2_w % 8)) % 8 */
    uint32_t csum_bits = p->len2 * p->log2_w;
    csum_bytes_len = (csum_bits + 7) / 8;
    csum <<= (8 - (csum_bits % 8)) % 8;

    ull_to_bytes(csum_bytes, csum_bytes_len, csum);
    base_w(p, msg_and_csum + p->len1, p->len2, csum_bytes);
}

/* ====================================================================
 * gen_chain() - Alg 2: Compute one chain step of the WOTS+ chain
 *
 * Applies the F function s times starting from input X.
 * Loop count s is derived from the public message hash — not secret.
 *
 * @p:    Parameter set.
 * @out:  Output n-byte chain element.
 * @in:   Input n-byte chain element.
 * @start: Starting index i.
 * @steps: Number of steps s (must have start + steps <= w - 1).
 * @seed: n-byte SEED.
 * @adrs: Address (chain and hash fields are updated by this function).
 * ==================================================================== */
static void gen_chain(const xmss_params *p,
                      uint8_t *out, const uint8_t *in,
                      uint32_t start, uint32_t steps,
                      const uint8_t *seed, xmss_adrs_t *adrs)
{
    uint8_t  tmp[XMSS_MAX_N];
    uint32_t i;

    memcpy(tmp, in, p->n);

    /* J5: loop bound = steps <= w-1 <= 15 */
    for (i = start; i < (start + steps) && i < p->w; i++) {
        xmss_adrs_set_hash(adrs, i);
        xmss_adrs_set_key_and_mask(adrs, 0);
        xmss_F(p, tmp, seed, adrs, tmp);
    }

    memcpy(out, tmp, p->n);
}

/* ====================================================================
 * wots_expand_seed() - Expand SK_SEED into len private key elements
 *
 * sk[i] = PRF_keygen(SK_SEED, ADRS[chain=i, hash=0])
 *
 * J6: Always exactly len iterations regardless of secret value.
 * ==================================================================== */
static void wots_expand_seed(const xmss_params *p,
                             uint8_t sk[][XMSS_MAX_N],
                             const uint8_t *sk_seed,
                             const uint8_t *pub_seed,
                             xmss_adrs_t *adrs)
{
    uint32_t i;
    xmss_adrs_t a;

    /* J5: len is bounded by XMSS_MAX_WOTS_LEN */
    for (i = 0; i < p->len; i++) {
        a = *adrs;
        xmss_adrs_set_chain(&a, i);
        xmss_adrs_set_hash(&a, 0);
        xmss_adrs_set_key_and_mask(&a, 0);
        xmss_PRF_keygen(p, sk[i], sk_seed, pub_seed, &a);
    }
}

/* ====================================================================
 * wots_gen_pk() - Alg 4: Generate WOTS+ public key
 * ==================================================================== */
void wots_gen_pk(const xmss_params *p, uint8_t *pk,
                 const uint8_t *sk_seed, const uint8_t *seed,
                 xmss_adrs_t *adrs)
{
    /* Stack buffers: sk[XMSS_MAX_WOTS_LEN][XMSS_MAX_N] */
    uint8_t sk[XMSS_MAX_WOTS_LEN][XMSS_MAX_N];
    uint32_t i;
    xmss_adrs_t a;

    /* Step 1: expand SK_SEED */
    a = *adrs;
    wots_expand_seed(p, sk, sk_seed, seed, &a);

    /* Step 2: for each element, run full chain of w-1 steps */
    for (i = 0; i < p->len; i++) {
        a = *adrs;
        xmss_adrs_set_chain(&a, i);
        gen_chain(p,
                  pk + i * p->n, /* output to pk[i] */
                  sk[i],          /* from sk[i] */
                  0,              /* start at 0 */
                  p->w - 1,       /* run w-1 steps */
                  seed, &a);
    }

    xmss_memzero(sk, sizeof(sk));
}

/* ====================================================================
 * wots_sign() - Alg 5: Generate WOTS+ signature
 * ==================================================================== */
void wots_sign(const xmss_params *p, uint8_t *sig,
               const uint8_t *msg,
               const uint8_t *sk_seed, const uint8_t *seed,
               xmss_adrs_t *adrs)
{
    uint8_t  sk[XMSS_MAX_WOTS_LEN][XMSS_MAX_N];
    uint32_t lengths[XMSS_MAX_WOTS_LEN];
    uint32_t i;
    xmss_adrs_t a;

    /* Compute base-w message representation */
    base_w(p, lengths, p->len1, msg);
    wots_checksum(p, lengths);

    /* Expand seed */
    a = *adrs;
    wots_expand_seed(p, sk, sk_seed, seed, &a);

    /* For each position: chain from 0 to lengths[i] steps */
    for (i = 0; i < p->len; i++) {
        a = *adrs;
        xmss_adrs_set_chain(&a, i);
        gen_chain(p,
                  sig + i * p->n,
                  sk[i],
                  0, lengths[i],
                  seed, &a);
    }

    xmss_memzero(sk, sizeof(sk));
}

/* ====================================================================
 * wots_pk_from_sig() - Alg 6: Recover public key from signature
 * ==================================================================== */
void wots_pk_from_sig(const xmss_params *p, uint8_t *pk,
                      const uint8_t *sig, const uint8_t *msg,
                      const uint8_t *seed, xmss_adrs_t *adrs)
{
    uint32_t lengths[XMSS_MAX_WOTS_LEN];
    uint32_t i;
    xmss_adrs_t a;

    /* Recompute chain lengths */
    base_w(p, lengths, p->len1, msg);
    wots_checksum(p, lengths);

    /* Complete chains from lengths[i] to w-1 */
    for (i = 0; i < p->len; i++) {
        a = *adrs;
        xmss_adrs_set_chain(&a, i);
        gen_chain(p,
                  pk + i * p->n,
                  sig + i * p->n,
                  lengths[i],           /* start at lengths[i] */
                  (p->w - 1) - lengths[i], /* remaining steps */
                  seed, &a);
    }
}
