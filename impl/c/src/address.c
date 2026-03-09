/**
 * address.c - XMSS ADRS (address) manipulation
 *
 * RFC 8391 §2.5: ADRS is a 32-byte structure of 8 big-endian 32-bit words.
 * Words 0-3: layer, tree (64-bit), type.
 * Words 4-7: type-specific fields (zeroed by set_type()).
 *
 * IMPORTANT: set_type() MUST zero words 4-6 to ensure domain separation
 * (RFC 8391 §2.5). xmss-reference does NOT do this; we do.
 */
#include <string.h>
#include <stdint.h>

#include "../include/xmss/types.h"
#include "address.h"

/* Store a 32-bit value in a word slot (native; serialised big-endian by xmss_adrs_to_bytes) */
static void set_word(xmss_adrs_t *a, uint32_t idx, uint32_t val)
{
    a->w[idx] = val;
}

void xmss_adrs_set_layer(xmss_adrs_t *a, uint32_t layer)
{
    set_word(a, 0, layer);
}

void xmss_adrs_set_tree(xmss_adrs_t *a, uint64_t tree)
{
    /* Tree address is 64-bit, stored in words 1 (high) and 2 (low) */
    set_word(a, 1, (uint32_t)(tree >> 32));
    set_word(a, 2, (uint32_t)(tree & 0xFFFFFFFFU));
}

void xmss_adrs_set_type(xmss_adrs_t *a, uint32_t type)
{
    set_word(a, 3, type);
    /* RFC 8391 §2.5: zero type-specific fields on type change */
    set_word(a, 4, 0);
    set_word(a, 5, 0);
    set_word(a, 6, 0);
    set_word(a, 7, 0);
}

/* OTS address: word 4 = OTS address */
void xmss_adrs_set_ots(xmss_adrs_t *a, uint32_t ots)
{
    set_word(a, 4, ots);
}

/* Chain address: word 5 */
void xmss_adrs_set_chain(xmss_adrs_t *a, uint32_t chain)
{
    set_word(a, 5, chain);
}

/* Hash address: word 6 */
void xmss_adrs_set_hash(xmss_adrs_t *a, uint32_t hash)
{
    set_word(a, 6, hash);
}

/* L-tree address: word 4 (same slot as OTS address) */
void xmss_adrs_set_ltree(xmss_adrs_t *a, uint32_t ltree)
{
    set_word(a, 4, ltree);
}

/* Tree height: word 5 (for hash tree address) */
void xmss_adrs_set_tree_height(xmss_adrs_t *a, uint32_t height)
{
    set_word(a, 5, height);
}

/* Tree index: word 6 (for hash tree address) */
void xmss_adrs_set_tree_index(xmss_adrs_t *a, uint32_t index)
{
    set_word(a, 6, index);
}

/* Key-and-mask: word 7 */
void xmss_adrs_set_key_and_mask(xmss_adrs_t *a, uint32_t key_and_mask)
{
    set_word(a, 7, key_and_mask);
}

/*
 * Serialise ADRS to 32 bytes in big-endian.
 * JASMIN: this buffer is the only form of ADRS passed to hash functions.
 */
void xmss_adrs_to_bytes(const xmss_adrs_t *a, uint8_t out[32])
{
    uint32_t i;
    for (i = 0; i < 8; i++) {
        out[4*i + 0] = (uint8_t)(a->w[i] >> 24);
        out[4*i + 1] = (uint8_t)(a->w[i] >> 16);
        out[4*i + 2] = (uint8_t)(a->w[i] >>  8);
        out[4*i + 3] = (uint8_t)(a->w[i]       );
    }
}
