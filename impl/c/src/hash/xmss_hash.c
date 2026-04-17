/**
 * xmss_hash.c - XMSS hash function dispatch
 *
 * This is the SOLE location of hash backend dispatch.
 * Implements F, H, H_msg, PRF, PRF_keygen for SHA-2 and SHAKE backends.
 *
 * All backends (SHA-2 and SHAKE) use the same thash construction for F and H:
 *   key = PRF(PUB_SEED, ADRS[key_and_mask=0])
 *   bm  = PRF(PUB_SEED, ADRS[key_and_mask=1])   (F: one mask; H: two masks at km=1,2)
 *   out = core_hash(toByte(dom, n) || key || (M XOR bm))
 *
 * JASMIN: replace this file with a .jazz file per parameter set.
 * Mark each dispatch point with: JASMIN-direct-call
 */
#include <stddef.h>
#include <string.h>
#include <stdint.h>

#include "hash_iface.h"
#include "sha2_local.h"
#include "shake_local.h"
#include "../utils.h"
#include "../address.h"
#include "../../include/xmss/params.h"
#include "../../include/xmss/types.h"

/* Domain constants (RFC 8391 §5.1) */
#define DOM_F         0x00U
#define DOM_H         0x01U
#define DOM_H_MSG     0x02U
#define DOM_PRF       0x03U
#define DOM_PRF_KEYGEN 0x04U

/* ====================================================================
 * core_hash_local() - Dispatch to SHA-256/SHA-512/SHAKE-128/SHAKE-256
 *
 * For SHA-2: outputs n bytes (SHA-256 for n=32, SHA-512 for n=64).
 * For SHAKE: outputs n bytes via SHAKE-128 (n=32) or SHAKE-256 (n=64).
 * ==================================================================== */
static void core_hash_local(const xmss_params *p, uint8_t *out,
                            const uint8_t *in, uint32_t inlen)
{
    /* JASMIN: replace dispatch with direct call */
    if (p->func == XMSS_FUNC_SHA2) {
        if (p->n == 32) { sha256_local(out, in, inlen); }
        else            { sha512_local(out, in, inlen); }
    } else if (p->func == XMSS_FUNC_SHAKE128) {
        shake128_local(out, p->n, in, inlen);
    } else {
        shake256_local(out, p->n, in, inlen);
    }
}

/* ====================================================================
 * prf_local() - PRF(KEY, ADRS) = core_hash(toByte(3, n) || KEY || ADRS)
 *
 * Used internally by F and H for key and bitmask generation.
 * ==================================================================== */
static void prf_local(const xmss_params *p, uint8_t *out,
                      const uint8_t *key, const xmss_adrs_t *adrs)
{
    uint8_t  buf[XMSS_MAX_N + XMSS_MAX_N + 32];
    uint8_t  adrs_bytes[32];
    uint32_t off = 0;
    uint32_t i;

    /* toByte(3, n) */
    for (i = 0; i < p->n - 1; i++) { buf[off++] = 0x00; }
    buf[off++] = DOM_PRF;

    memcpy(buf + off, key, p->n);
    off += p->n;

    xmss_adrs_to_bytes(adrs, adrs_bytes);
    memcpy(buf + off, adrs_bytes, 32);
    off += 32;

    core_hash_local(p, out, buf, off);
    xmss_memzero(buf, sizeof(buf));
    xmss_memzero(adrs_bytes, sizeof(adrs_bytes));
}

/* ====================================================================
 * F - WOTS+ chaining function
 *
 * key  = PRF(PUB_SEED, ADRS[key_and_mask=0])
 * bm   = PRF(PUB_SEED, ADRS[key_and_mask=1])
 * F    = core_hash(toByte(0, n) || key || (M XOR bm))
 * ==================================================================== */

int xmss_F(const xmss_params *p, uint8_t *out,
           const uint8_t *key, const xmss_adrs_t *adrs,
           const uint8_t *in)
{
    uint8_t  prf_key[XMSS_MAX_N];
    uint8_t  bm[XMSS_MAX_N];
    uint8_t  buf[XMSS_MAX_N + XMSS_MAX_N + XMSS_MAX_N];
    uint32_t off = 0;
    uint32_t i;
    xmss_adrs_t a;

    /* Generate key: PRF(PUB_SEED, ADRS[key_and_mask=0]) */
    a = *adrs;
    xmss_adrs_set_key_and_mask(&a, 0);
    prf_local(p, prf_key, key, &a);

    /* Generate bitmask: PRF(PUB_SEED, ADRS[key_and_mask=1]) */
    a = *adrs;
    xmss_adrs_set_key_and_mask(&a, 1);
    prf_local(p, bm, key, &a);

    /* Outer hash: toByte(0, n) || prf_key || (M XOR bm) */
    for (i = 0; i < p->n - 1; i++) { buf[off++] = 0x00; }
    buf[off++] = DOM_F;
    memcpy(buf + off, prf_key, p->n); off += p->n;
    for (i = 0; i < p->n; i++) { buf[off++] = in[i] ^ bm[i]; }

    core_hash_local(p, out, buf, off);
    xmss_memzero(prf_key, sizeof(prf_key));
    xmss_memzero(bm, sizeof(bm));
    xmss_memzero(buf, sizeof(buf));
    return 0;
}

/* ====================================================================
 * H - Tree hash function
 *
 * key  = PRF(PUB_SEED, ADRS[key_and_mask=0])
 * bm_l = PRF(PUB_SEED, ADRS[key_and_mask=1])
 * bm_r = PRF(PUB_SEED, ADRS[key_and_mask=2])
 * H    = core_hash(toByte(1, n) || key || (M_l XOR bm_l) || (M_r XOR bm_r))
 * ==================================================================== */

int xmss_H(const xmss_params *p, uint8_t *out,
           const uint8_t *key, const xmss_adrs_t *adrs,
           const uint8_t *in_l, const uint8_t *in_r)
{
    uint8_t  prf_key[XMSS_MAX_N];
    uint8_t  bm_l[XMSS_MAX_N], bm_r[XMSS_MAX_N];
    uint8_t  buf[XMSS_MAX_N + XMSS_MAX_N + 2 * XMSS_MAX_N];
    uint32_t off = 0;
    uint32_t i;
    xmss_adrs_t a;

    /* Generate key: PRF(PUB_SEED, ADRS[key_and_mask=0]) */
    a = *adrs;
    xmss_adrs_set_key_and_mask(&a, 0);
    prf_local(p, prf_key, key, &a);

    /* Generate left bitmask: PRF(PUB_SEED, ADRS[key_and_mask=1]) */
    a = *adrs;
    xmss_adrs_set_key_and_mask(&a, 1);
    prf_local(p, bm_l, key, &a);

    /* Generate right bitmask: PRF(PUB_SEED, ADRS[key_and_mask=2]) */
    a = *adrs;
    xmss_adrs_set_key_and_mask(&a, 2);
    prf_local(p, bm_r, key, &a);

    /* Outer hash: toByte(1, n) || prf_key || (M_l XOR bm_l) || (M_r XOR bm_r) */
    for (i = 0; i < p->n - 1; i++) { buf[off++] = 0x00; }
    buf[off++] = DOM_H;
    memcpy(buf + off, prf_key, p->n); off += p->n;
    for (i = 0; i < p->n; i++) { buf[off++] = in_l[i] ^ bm_l[i]; }
    for (i = 0; i < p->n; i++) { buf[off++] = in_r[i] ^ bm_r[i]; }

    core_hash_local(p, out, buf, off);
    xmss_memzero(prf_key, sizeof(prf_key));
    xmss_memzero(bm_l, sizeof(bm_l));
    xmss_memzero(bm_r, sizeof(bm_r));
    xmss_memzero(buf, sizeof(buf));
    return 0;
}

/* ====================================================================
 * H_msg - Message hash function
 *
 * H_msg = core_hash(toByte(2, n) || r || root || toByte(idx, n) || msg)
 * ==================================================================== */

int xmss_H_msg(const xmss_params *p, uint8_t *out,
               const uint8_t *r, const uint8_t *root, uint64_t idx,
               const uint8_t *msg, size_t msglen)
{
    uint8_t  idx_bytes[XMSS_MAX_N];
    uint32_t i;

    /* Encode idx as n bytes (not 32) to match reference */
    ull_to_bytes(idx_bytes, p->n, idx);

    if (p->func == XMSS_FUNC_SHA2) {
        sha256_ctx_t ctx256;
        sha512_ctx_t ctx512;
        uint8_t  dom[XMSS_MAX_N]; /* toByte(2, n) */

        for (i = 0; i < p->n - 1; i++) { dom[i] = 0x00; }
        dom[p->n - 1] = DOM_H_MSG;

        if (p->n == 32) {
            sha256_ctx_init(&ctx256);
            sha256_ctx_update(&ctx256, dom, p->n);
            sha256_ctx_update(&ctx256, r, p->n);
            sha256_ctx_update(&ctx256, root, p->n);
            sha256_ctx_update(&ctx256, idx_bytes, p->n);
            sha256_ctx_update(&ctx256, msg, msglen);
            sha256_ctx_final(&ctx256, out);
        } else {
            sha512_ctx_init(&ctx512);
            sha512_ctx_update(&ctx512, dom, p->n);
            sha512_ctx_update(&ctx512, r, p->n);
            sha512_ctx_update(&ctx512, root, p->n);
            sha512_ctx_update(&ctx512, idx_bytes, p->n);
            sha512_ctx_update(&ctx512, msg, msglen);
            sha512_ctx_final(&ctx512, out);
        }
    } else {
        /* SHAKE: toByte(2, n) prefix, idx encoded as n bytes */
        uint8_t dom[XMSS_MAX_N];
        for (i = 0; i < p->n - 1; i++) { dom[i] = 0x00; }
        dom[p->n - 1] = DOM_H_MSG;

        if (p->func == XMSS_FUNC_SHAKE128) {
            shake128_ctx_t ctx;
            shake128_ctx_init(&ctx);
            shake128_ctx_absorb(&ctx, dom, p->n);
            shake128_ctx_absorb(&ctx, r, p->n);
            shake128_ctx_absorb(&ctx, root, p->n);
            shake128_ctx_absorb(&ctx, idx_bytes, p->n);
            shake128_ctx_absorb(&ctx, msg, msglen);
            shake128_ctx_finalize(&ctx);
            shake128_ctx_squeeze(&ctx, out, p->n);
        } else {
            shake256_ctx_t ctx;
            shake256_ctx_init(&ctx);
            shake256_ctx_absorb(&ctx, dom, p->n);
            shake256_ctx_absorb(&ctx, r, p->n);
            shake256_ctx_absorb(&ctx, root, p->n);
            shake256_ctx_absorb(&ctx, idx_bytes, p->n);
            shake256_ctx_absorb(&ctx, msg, msglen);
            shake256_ctx_finalize(&ctx);
            shake256_ctx_squeeze(&ctx, out, p->n);
        }
    }
    return 0;
}

/* ====================================================================
 * PRF - Pseudorandom function
 *
 * PRF(KEY, ADRS) = core_hash(toByte(3, n) || KEY || ADRS)
 * ==================================================================== */

int xmss_PRF(const xmss_params *p, uint8_t *out,
             const uint8_t *key, const xmss_adrs_t *adrs)
{
    prf_local(p, out, key, adrs);
    return 0;
}

/* ====================================================================
 * PRF_keygen - Key generation PRF
 *
 * PRF_keygen(SK_SEED, PUB_SEED, ADRS) =
 *   core_hash(toByte(4, n) || SK_SEED || PUB_SEED || ADRS)
 * ==================================================================== */

int xmss_PRF_keygen(const xmss_params *p, uint8_t *out,
                    const uint8_t *sk_seed, const uint8_t *pub_seed,
                    const xmss_adrs_t *adrs)
{
    /* Max: pad(n=64) + sk_seed(64) + pub_seed(64) + adrs(32) = 224 */
    uint8_t  buf[XMSS_MAX_N + XMSS_MAX_N + XMSS_MAX_N + 32];
    uint8_t  adrs_bytes[32];
    uint32_t off = 0;
    uint32_t i;

    /* toByte(4, n) */
    for (i = 0; i < p->n - 1; i++) { buf[off++] = 0x00; }
    buf[off++] = DOM_PRF_KEYGEN;

    memcpy(buf + off, sk_seed, p->n);  off += p->n;
    memcpy(buf + off, pub_seed, p->n); off += p->n;

    xmss_adrs_to_bytes(adrs, adrs_bytes);
    memcpy(buf + off, adrs_bytes, 32); off += 32;

    core_hash_local(p, out, buf, off);
    xmss_memzero(buf, sizeof(buf));
    xmss_memzero(adrs_bytes, sizeof(adrs_bytes));
    return 0;
}

/* ====================================================================
 * xmss_PRF_idx() - PRF with index as raw 32-byte message
 * Used for computing r = PRF(SK_PRF, toByte(idx, 32)) in signing.
 * ==================================================================== */
int xmss_PRF_idx(const xmss_params *p, uint8_t *out,
                 const uint8_t *sk_prf, uint64_t idx)
{
    /* toByte(3, n) || SK_PRF || toByte(idx, 32) */
    uint8_t  buf[XMSS_MAX_N + XMSS_MAX_N + 32];
    uint32_t off = 0;
    uint32_t i;

    /* toByte(3, n): domain for PRF */
    for (i = 0; i < p->n - 1; i++) { buf[off++] = 0x00; }
    buf[off++] = DOM_PRF;

    memcpy(buf + off, sk_prf, p->n); off += p->n;

    /* Encode idx as 32-byte big-endian */
    ull_to_bytes(buf + off, 32, idx);
    off += 32;

    core_hash_local(p, out, buf, off);
    xmss_memzero(buf, sizeof(buf));
    return 0;
}
