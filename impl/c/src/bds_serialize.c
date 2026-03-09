/**
 * bds_serialize.c - BDS state serialization/deserialization
 *
 * Converts xmss_bds_state to/from a flat, platform-independent byte buffer.
 * All integers are stored big-endian. Format is parameterised by (n, h, bds_k).
 *
 * No malloc (J3), no VLAs (J1), no recursion (J4), no function pointers (J2).
 */
#include <assert.h>
#include <string.h>
#include <stdint.h>

#include "utils.h"
#include "../include/xmss/params.h"
#include "../include/xmss/xmss.h"

/**
 * retain_count() - Number of retain nodes stored for a given bds_k.
 *
 * The BDS algorithm caches right-sibling nodes at the top bds_k levels of
 * the tree.  At level i (counting from tree_height - bds_k), there are
 * 2^(tree_height - 1 - i) - 1 right-sibling nodes to retain, but the
 * total across all bds_k levels sums to 2^bds_k - bds_k - 1.
 */
static uint32_t retain_count(uint32_t bds_k)
{
    if (bds_k == 0) return 0;
    return ((uint32_t)1 << bds_k) - bds_k - 1;
}

uint32_t xmss_bds_serialized_size(const xmss_params *p, uint32_t bds_k)
{
    assert(xmss_bds_k_valid(p, bds_k));
    uint32_t n = p->n;
    uint32_t h = p->tree_height;
    uint32_t th_count = h - bds_k;
    uint32_t rc = retain_count(bds_k);

    return h * n                          /* auth */
         + (h / 2) * n                    /* keep */
         + (h + 1) * n                    /* stack nodes */
         + (h + 1)                        /* stack_levels */
         + 4                              /* stack_offset */
         + th_count * (n + 4 + 4 + 1 + 1) /* treehash instances */
         + rc * n                         /* retain */
         + 4;                             /* next_leaf */
}

int xmss_bds_serialize(const xmss_params *p, uint8_t *buf,
                       const xmss_bds_state *state, uint32_t bds_k)
{
    if (!xmss_bds_k_valid(p, bds_k)) { return XMSS_ERR_PARAMS; }

    uint32_t n = p->n;
    uint32_t h = p->tree_height;
    uint32_t th_count = h - bds_k;
    uint32_t rc = retain_count(bds_k);
    uint32_t off = 0;
    uint32_t i;

    /* auth */
    for (i = 0; i < h; i++) {
        memcpy(buf + off, state->auth[i], n);
        off += n;
    }

    /* keep */
    for (i = 0; i < h / 2; i++) {
        memcpy(buf + off, state->keep[i], n);
        off += n;
    }

    /* stack nodes */
    for (i = 0; i < h + 1; i++) {
        memcpy(buf + off, state->stack[i], n);
        off += n;
    }

    /* stack_levels */
    for (i = 0; i < h + 1; i++) {
        buf[off++] = state->stack_levels[i];
    }

    /* stack_offset */
    ull_to_bytes(buf + off, 4, state->stack_offset);
    off += 4;

    /* treehash instances */
    for (i = 0; i < th_count; i++) {
        memcpy(buf + off, state->treehash[i].node, n);
        off += n;
        ull_to_bytes(buf + off, 4, state->treehash[i].h);
        off += 4;
        ull_to_bytes(buf + off, 4, state->treehash[i].next_idx);
        off += 4;
        buf[off++] = state->treehash[i].stack_usage;
        buf[off++] = state->treehash[i].completed;
    }

    /* retain */
    for (i = 0; i < rc; i++) {
        memcpy(buf + off, state->retain[i], n);
        off += n;
    }

    /* next_leaf */
    ull_to_bytes(buf + off, 4, state->next_leaf);
    off += 4;

    return XMSS_OK;
}

int xmss_bds_deserialize(const xmss_params *p, xmss_bds_state *state,
                         const uint8_t *buf, uint32_t bds_k)
{
    if (!xmss_bds_k_valid(p, bds_k)) { return XMSS_ERR_PARAMS; }

    uint32_t n = p->n;
    uint32_t h = p->tree_height;
    uint32_t th_count = h - bds_k;
    uint32_t rc = retain_count(bds_k);
    uint32_t off = 0;
    uint32_t i;

    /* Zero entire state to clear MAX-sized padding */
    memset(state, 0, sizeof(xmss_bds_state));
    state->bds_k = bds_k;

    /* auth */
    for (i = 0; i < h; i++) {
        memcpy(state->auth[i], buf + off, n);
        off += n;
    }

    /* keep */
    for (i = 0; i < h / 2; i++) {
        memcpy(state->keep[i], buf + off, n);
        off += n;
    }

    /* stack nodes */
    for (i = 0; i < h + 1; i++) {
        memcpy(state->stack[i], buf + off, n);
        off += n;
    }

    /* stack_levels */
    for (i = 0; i < h + 1; i++) {
        state->stack_levels[i] = buf[off++];
    }

    /* stack_offset */
    state->stack_offset = (uint32_t)bytes_to_ull(buf + off, 4);
    off += 4;

    /* treehash instances */
    for (i = 0; i < th_count; i++) {
        memcpy(state->treehash[i].node, buf + off, n);
        off += n;
        state->treehash[i].h = (uint32_t)bytes_to_ull(buf + off, 4);
        off += 4;
        state->treehash[i].next_idx = (uint32_t)bytes_to_ull(buf + off, 4);
        off += 4;
        state->treehash[i].stack_usage = buf[off++];
        state->treehash[i].completed = buf[off++];
    }

    /* retain */
    for (i = 0; i < rc; i++) {
        memcpy(state->retain[i], buf + off, n);
        off += n;
    }

    /* next_leaf */
    state->next_leaf = (uint32_t)bytes_to_ull(buf + off, 4);
    off += 4;

    return XMSS_OK;
}
