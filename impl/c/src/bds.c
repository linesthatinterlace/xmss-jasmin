/**
 * bds.c - BDS tree traversal algorithm
 *
 * Implements the BDS algorithm from Buchmann, Dahmen, Szydlo
 * ("Post Quantum Cryptography", Springer 2009).
 *
 * No malloc (J3), no recursion (J4), no VLAs (J1), no function pointers (J2).
 * All loops bounded by params fields or XMSS_MAX_* constants (J5).
 */
#include <string.h>
#include <stdint.h>
#include <assert.h>

#include "bds.h"
#include "wots.h"
#include "ltree.h"
#include "hash/hash_iface.h"
#include "address.h"
#include "utils.h"
#include "../include/xmss/params.h"
#include "../include/xmss/types.h"
#include "../include/xmss/xmss.h"   /* xmss_bds_state */

/* ====================================================================
 * gen_leaf() - Compute a single leaf: l_tree(WOTS_genPK(...))
 * ==================================================================== */
static void gen_leaf(const xmss_params *p, uint8_t *leaf,
                     const uint8_t *sk_seed, const uint8_t *seed,
                     uint32_t leaf_idx, xmss_adrs_t *adrs)
{
    uint8_t wots_pk[XMSS_MAX_WOTS_LEN * XMSS_MAX_N];
    xmss_adrs_t a;

    a = *adrs;
    xmss_adrs_set_type(&a, XMSS_ADRS_TYPE_OTS);
    xmss_adrs_set_ots(&a, leaf_idx);
    wots_gen_pk(p, wots_pk, sk_seed, seed, &a);

    a = *adrs;
    xmss_adrs_set_type(&a, XMSS_ADRS_TYPE_LTREE);
    xmss_adrs_set_ltree(&a, leaf_idx);
    l_tree(p, leaf, wots_pk, seed, &a);
}

/* ====================================================================
 * treehash_minheight_on_stack() - Find minimum height among a treehash
 * instance's entries on the shared stack.
 * ==================================================================== */
static uint32_t treehash_minheight_on_stack(
    const xmss_bds_state *state, const xmss_bds_treehash_inst *th)
{
    uint32_t r = XMSS_MAX_H;
    uint32_t i;

    for (i = 0; i < th->stack_usage; i++) {
        uint32_t lev = state->stack_levels[state->stack_offset - i - 1];
        if (lev < r) {
            r = lev;
        }
    }
    return r;
}

/* ====================================================================
 * treehash_update_one() - Process one leaf for a treehash instance.
 *
 * Generates the leaf at th->next_idx, merges with the shared stack
 * as far as possible.  If the target height is reached, marks completed
 * and stores the result in th->node.
 * ==================================================================== */
static void treehash_update_one(const xmss_params *p,
                                xmss_bds_treehash_inst *th,
                                xmss_bds_state *state,
                                const uint8_t *sk_seed, const uint8_t *seed,
                                xmss_adrs_t *adrs)
{
    uint8_t nodebuf[2 * XMSS_MAX_N];
    uint32_t nodeheight = 0;
    xmss_adrs_t a;

    /* Generate leaf */
    gen_leaf(p, nodebuf, sk_seed, seed, th->next_idx, adrs);

    /* Merge with stack while heights match */
    while (th->stack_usage > 0 &&
           state->stack_levels[state->stack_offset - 1] == nodeheight) {
        /* Current node becomes right child, stack top becomes left */
        memcpy(nodebuf + p->n, nodebuf, p->n);
        memcpy(nodebuf, state->stack[state->stack_offset - 1], p->n);

        a = *adrs;
        xmss_adrs_set_type(&a, XMSS_ADRS_TYPE_HASH);
        xmss_adrs_set_tree_height(&a, nodeheight);
        xmss_adrs_set_tree_index(&a, th->next_idx >> (nodeheight + 1));

        xmss_H(p, nodebuf, seed, &a, nodebuf, nodebuf + p->n);
        nodeheight++;
        th->stack_usage--;
        state->stack_offset--;
    }

    if (nodeheight == th->h) {
        /* Reached target height: save result */
        memcpy(th->node, nodebuf, p->n);
        th->completed = 1;
    } else {
        /* Push partial result onto shared stack */
        memcpy(state->stack[state->stack_offset], nodebuf, p->n);
        th->stack_usage++;
        state->stack_levels[state->stack_offset] = (uint8_t)nodeheight;
        state->stack_offset++;
        th->next_idx++;
    }
}

/* ====================================================================
 * bds_treehash_init() - Build full tree, capturing BDS state
 * ==================================================================== */
void bds_treehash_init(const xmss_params *p, uint8_t *root,
                       xmss_bds_state *state, uint32_t bds_k,
                       const uint8_t *sk_seed, const uint8_t *seed,
                       xmss_adrs_t *adrs)
{
    /* Local stack for the full tree build (not the BDS shared stack) */
    uint8_t  stack[(XMSS_MAX_H + 1)][XMSS_MAX_N];
    uint32_t stack_levels[XMSS_MAX_H + 1];
    uint32_t stack_offset = 0;

    uint32_t lastnode = (uint32_t)1 << p->tree_height;
    uint32_t idx, i;
    uint32_t nodeh;
    xmss_adrs_t a;

    /* Initialise treehash instances as completed */
    for (i = 0; i < p->tree_height - bds_k; i++) {
        state->treehash[i].h = i;
        state->treehash[i].completed = 1;
        state->treehash[i].stack_usage = 0;
    }

    /* Initialise shared stack */
    state->stack_offset = 0;
    state->next_leaf = 0;

    i = 0;
    for (idx = 0; idx < lastnode; idx++) {
        /* Generate leaf */
        gen_leaf(p, stack[stack_offset], sk_seed, seed, idx, adrs);
        stack_levels[stack_offset] = 0;
        stack_offset++;

        /* Merge while top two have equal height */
        while (stack_offset > 1 &&
               stack_levels[stack_offset - 1] == stack_levels[stack_offset - 2]) {
            nodeh = stack_levels[stack_offset - 1];

            /* Capture auth path: first right sibling at each height */
            if ((i >> nodeh) == 1) {
                memcpy(state->auth[nodeh], stack[stack_offset - 1], p->n);
            } else if (nodeh < p->tree_height - bds_k && (i >> nodeh) == 3) {
                /* Capture treehash starting node */
                memcpy(state->treehash[nodeh].node,
                       stack[stack_offset - 1], p->n);
            } else if (nodeh >= p->tree_height - bds_k) {
                /* Capture retain node */
                uint32_t off = ((uint32_t)1 << (p->tree_height - 1 - nodeh))
                             + nodeh - p->tree_height;
                uint32_t row = ((i >> nodeh) - 3) >> 1;
                memcpy(state->retain[off + row],
                       stack[stack_offset - 1], p->n);
            }

            /* Merge: H(left, right) -> left slot */
            a = *adrs;
            xmss_adrs_set_type(&a, XMSS_ADRS_TYPE_HASH);
            xmss_adrs_set_tree_height(&a, nodeh);
            xmss_adrs_set_tree_index(&a, idx >> (nodeh + 1));

            xmss_H(p, stack[stack_offset - 2], seed, &a,
                    stack[stack_offset - 2], stack[stack_offset - 1]);
            stack_levels[stack_offset - 2]++;
            stack_offset--;
        }
        i++;
    }

    /* Root is the sole stack element */
    memcpy(root, stack[0], p->n);
}

/* ====================================================================
 * bds_round() - Update auth path after signing leaf_idx
 * ==================================================================== */
void bds_round(const xmss_params *p, xmss_bds_state *state,
               uint32_t bds_k, uint32_t leaf_idx,
               const uint8_t *sk_seed, const uint8_t *seed,
               xmss_adrs_t *adrs)
{
    uint32_t tau, i;
    uint8_t buf[2 * XMSS_MAX_N];
    xmss_adrs_t a;

    /* Find tau: lowest bit position where leaf_idx has a 0 */
    tau = p->tree_height;
    for (i = 0; i < p->tree_height; i++) {
        if (!((leaf_idx >> i) & 1)) {
            tau = i;
            break;
        }
    }

    /* Save nodes needed for merge before overwriting */
    if (tau > 0) {
        memcpy(buf, state->auth[tau - 1], p->n);
        memcpy(buf + p->n, state->keep[(tau - 1) >> 1], p->n);
    }

    /* Possibly save current auth[tau] to keep for future use */
    if (!((leaf_idx >> (tau + 1)) & 1) && tau < p->tree_height - 1) {
        memcpy(state->keep[tau >> 1], state->auth[tau], p->n);
    }

    if (tau == 0) {
        /* Compute the new leaf directly */
        gen_leaf(p, state->auth[0], sk_seed, seed, leaf_idx, adrs);
    } else {
        /* Merge auth[tau-1] and keep[(tau-1)/2] to get new auth[tau] */
        a = *adrs;
        xmss_adrs_set_type(&a, XMSS_ADRS_TYPE_HASH);
        xmss_adrs_set_tree_height(&a, tau - 1);
        xmss_adrs_set_tree_index(&a, leaf_idx >> tau);

        xmss_H(p, state->auth[tau], seed, &a, buf, buf + p->n);

        /* Fill auth[0..tau-1] from treehash nodes or retain */
        for (i = 0; i < tau; i++) {
            if (i < p->tree_height - bds_k) {
                /* BDS invariant: treehash[i] must be completed before we
                 * consume its node.  A violation here means the update budget
                 * was insufficient — the exact class of bug that floor-vs-ceil
                 * division causes (e.g. h=5, k=2). */
                assert(state->treehash[i].completed &&
                       "BDS invariant violated: treehash[i] not completed "
                       "before node consumed in bds_round");
                memcpy(state->auth[i], state->treehash[i].node, p->n);
            } else {
                uint32_t off = ((uint32_t)1 << (p->tree_height - 1 - i)) + i - p->tree_height;
                uint32_t row = ((leaf_idx >> i) - 1) >> 1;
                memcpy(state->auth[i], state->retain[off + row], p->n);
            }
        }

        /* Reinitialise treehash instances for levels below tau */
        for (i = 0; i < tau && i < p->tree_height - bds_k; i++) {
            uint32_t startidx = leaf_idx + 1 + 3 * ((uint32_t)1 << i);
            if (startidx < (uint32_t)1 << p->tree_height) {
                state->treehash[i].h = i;
                state->treehash[i].next_idx = startidx;
                state->treehash[i].completed = 0;
                state->treehash[i].stack_usage = 0;
            }
        }
    }
}

/* ====================================================================
 * bds_treehash_update() - Run incremental treehash updates
 * ==================================================================== */
void bds_treehash_update(const xmss_params *p, xmss_bds_state *state,
                         uint32_t bds_k, uint32_t updates,
                         const uint8_t *sk_seed, const uint8_t *seed,
                         xmss_adrs_t *adrs)
{
    uint32_t j, i;
    uint32_t level, l_min, low;

    for (j = 0; j < updates; j++) {
        l_min = p->tree_height;
        level = p->tree_height - bds_k;

        /* Find the treehash instance with lowest priority (most urgent) */
        for (i = 0; i < p->tree_height - bds_k; i++) {
            if (state->treehash[i].completed) {
                low = p->tree_height;
            } else if (state->treehash[i].stack_usage == 0) {
                low = i;
            } else {
                low = treehash_minheight_on_stack(state, &state->treehash[i]);
            }
            if (low < l_min) {
                level = i;
                l_min = low;
            }
        }

        /* No incomplete instance found */
        if (level == p->tree_height - bds_k) {
            break;
        }

        treehash_update_one(p, &state->treehash[level], state,
                            sk_seed, seed, adrs);
    }
}

/* ====================================================================
 * bds_state_update() - Process one leaf for incremental tree building
 *
 * Used by XMSS-MT to incrementally build "next" trees during signing.
 * Each call generates one leaf (at index state->next_leaf) and merges
 * it onto the BDS state's own stack, capturing auth/treehash/retain
 * nodes along the way.  After 2^tree_height calls, the tree is fully
 * built and the root sits in state->stack[0].
 *
 * Returns 0 on success, -1 if the tree is already complete.
 * ==================================================================== */
int bds_state_update(const xmss_params *p, xmss_bds_state *state,
                     uint32_t bds_k,
                     const uint8_t *sk_seed, const uint8_t *seed,
                     xmss_adrs_t *adrs)
{
    uint32_t idx = state->next_leaf;
    uint32_t nodeh;
    xmss_adrs_t a;

    if (idx >= (uint32_t)1 << p->tree_height) {
        return -1;
    }

    /* Generate leaf onto stack top */
    gen_leaf(p, state->stack[state->stack_offset], sk_seed, seed, idx, adrs);
    state->stack_levels[state->stack_offset] = 0;
    state->stack_offset++;

    /* Special case: capture treehash[0] starting node at idx=3 */
    if (p->tree_height > bds_k && idx == 3) {
        memcpy(state->treehash[0].node,
               state->stack[state->stack_offset - 1], p->n);
    }

    /* Merge while top two stack entries have equal height */
    while (state->stack_offset > 1 &&
           state->stack_levels[state->stack_offset - 1] ==
           state->stack_levels[state->stack_offset - 2]) {
        nodeh = state->stack_levels[state->stack_offset - 1];

        /* Capture BDS state nodes */
        if ((idx >> nodeh) == 1) {
            /* Auth path node */
            memcpy(state->auth[nodeh],
                   state->stack[state->stack_offset - 1], p->n);
        } else if (nodeh < p->tree_height - bds_k && (idx >> nodeh) == 3) {
            /* Treehash starting node */
            memcpy(state->treehash[nodeh].node,
                   state->stack[state->stack_offset - 1], p->n);
        } else if (nodeh >= p->tree_height - bds_k) {
            /* Retain node */
            uint32_t off = ((uint32_t)1 << (p->tree_height - 1 - nodeh))
                         + nodeh - p->tree_height;
            uint32_t row = ((idx >> nodeh) - 3) >> 1;
            memcpy(state->retain[off + row],
                   state->stack[state->stack_offset - 1], p->n);
        }

        /* Merge: H(left, right) -> left slot */
        a = *adrs;
        xmss_adrs_set_type(&a, XMSS_ADRS_TYPE_HASH);
        xmss_adrs_set_tree_height(&a, nodeh);
        xmss_adrs_set_tree_index(&a, idx >> (nodeh + 1));

        xmss_H(p, state->stack[state->stack_offset - 2], seed, &a,
                state->stack[state->stack_offset - 2],
                state->stack[state->stack_offset - 1]);
        state->stack_levels[state->stack_offset - 2]++;
        state->stack_offset--;
    }

    state->next_leaf++;
    return 0;
}
