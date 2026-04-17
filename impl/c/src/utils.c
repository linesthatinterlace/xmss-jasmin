/**
 * utils.c - XMSS utility functions
 *
 * ull_to_bytes, bytes_to_ull: big-endian integer encoding (RFC 8391 §2.4).
 * xmss_memzero: secure memory clearing (volatile-pointer idiom).
 * ct_memcmp: constant-time memory comparison (for signature verification).
 */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "utils.h"

/**
 * ull_to_bytes() - Encode a uint64_t in big-endian into len bytes.
 *
 * RFC 8391 §2.4: toByte(x, n) converts x to an n-byte big-endian string.
 * Writes exactly len bytes; asserts len <= 8 and that val fits in len bytes.
 */
void ull_to_bytes(uint8_t *out, uint32_t len, uint64_t val)
{
    uint32_t i;
    assert(len <= 8);
    assert(len == 8 || (val >> (len * 8)) == 0);
    for (i = len; i > 0; i--) {
        out[i - 1] = (uint8_t)(val & 0xFF);
        val >>= 8;
    }
}

/**
 * bytes_to_ull() - Decode a big-endian byte string to uint64_t.
 *
 * Reads exactly len bytes; len must be <= 8.
 */
uint64_t bytes_to_ull(const uint8_t *in, uint32_t len)
{
    uint64_t val = 0;
    uint32_t i;
    assert(len <= 8);
    for (i = 0; i < len; i++) {
        val = (val << 8) | in[i];
    }
    return val;
}

/**
 * xmss_memzero() - Securely zero len bytes at ptr.
 *
 * Uses the volatile-pointer idiom plus a compiler memory barrier to prevent
 * the compiler from optimising this away.  The volatile qualifier prevents
 * dead-store elimination of the writes; the barrier prevents the compiler
 * from proving the writes are unobservable and removing them at a higher
 * optimisation level.
 */
void xmss_memzero(void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    size_t i;
    for (i = 0; i < len; i++) {
        p[i] = 0;
    }
    __asm__ __volatile__("" ::: "memory");
}

/**
 * ct_memcmp() - Constant-time memory comparison.
 *
 * Returns 0 if the first len bytes of a and b are identical, non-zero
 * otherwise.  Evaluates all len bytes regardless of early differences
 * (no short-circuit).
 *
 * The volatile accumulator prevents dead-store elimination of intermediate
 * writes to diff.  The compiler memory barrier prevents the compiler from
 * short-circuiting the loop if it can prove diff is already non-zero.
 *
 * J6: constant-time required for signature verification (prevents timing
 * oracle distinguishing valid from invalid signatures).
 */
int ct_memcmp(const uint8_t *a, const uint8_t *b, size_t len)
{
    volatile uint8_t diff = 0;
    size_t i;
    for (i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    __asm__ __volatile__("" ::: "memory");
    return (int)diff;
}
