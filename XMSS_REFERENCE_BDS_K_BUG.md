# BDS treehash update budget bug in xmss-reference for bds_k > 0

## Summary

The XMSS reference implementation
([XMSS/xmss-reference](https://github.com/XMSS/xmss-reference), commit
`171ccbd`) contains a latent bug in the BDS treehash update budget
calculation. The bug is currently dormant because the reference hardcodes
`bds_k = 0` for all parameter sets, but it will produce incorrect
signatures for any downstream implementation that sets `bds_k` to a value
where `(tree_height - bds_k)` is odd.

## The bug

In `xmss_core_fast.c`, the number of treehash updates per signature is
computed using floor division:

```c
// Line 707 (single-tree XMSS):
bds_treehash_update(params, &state,
    (params->tree_height - params->bds_k) >> 1,
    sk_seed, pub_seed, ots_addr);

// Line 934 (XMSS-MT):
updates = (params->tree_height - params->bds_k) >> 1;
```

This should be ceiling division:

```c
(params->tree_height - params->bds_k + 1) >> 1
```

## Why it matters

The BDS algorithm maintains `(tree_height - bds_k)` treehash instances,
each pre-computing a subtree root needed for future authentication paths.
The treehash update budget per signature must be sufficient for all
instances to complete before their values are read by `bds_round()`.

When `(tree_height - bds_k)` is odd, floor division gives one fewer
update per signature than required. The priority scheduler always favours
lower-indexed treehash instances (they have lower `low` values), so the
highest-indexed instance is starved. It never completes, and `bds_round()`
reads stale data from its `node` field, producing a wrong authentication
path.

### Concrete example: tree_height=5, bds_k=2

- `num_treehash = 5 - 2 = 3` instances (th[0], th[1], th[2])
- `updates = (5 - 2) >> 1 = 1` per signature (should be 2)
- After signing index 7 (tau=3), all three instances are reinitialised
- Between index 7 and index 15 (tau=4), there are 8 available updates
- th[0] (target height 0, priority 0) consumes 4 updates
- th[1] (target height 1, priority 1) consumes 4 updates
- th[2] (target height 2, priority 2) gets **zero** updates
- At index 15, `bds_round()` reads `th[2].node` unconditionally
- The value is stale (from the initial tree build), not the required
  subtree root for the next authentication path
- Verification fails from index 16 onward

## Why it is latent in the reference

The reference hardcodes `bds_k = 0` in `params.c` (lines 372 and 695):

```c
// TODO figure out sensible and legal values for this based on the above
params->bds_k = 0;
```

With `bds_k = 0`, `(tree_height - 0)` equals `tree_height`, and all RFC
8391 tree heights are even (10, 20), so floor and ceiling division give
the same result. The bug cannot trigger.

However, `bds_k` is exposed as a parameter throughout the codebase (it
is an argument to `bds_round`, `bds_treehash_update`, `bds_treehash_init`,
etc.), and the BDS algorithm is designed to work for any even `bds_k`
satisfying `0 <= bds_k <= tree_height`. Any user of the reference who
sets `bds_k > 0` with an odd `(tree_height - bds_k)` will hit this bug.

## Affected configurations

The bug triggers when `(tree_height - bds_k)` is odd. For RFC 8391
parameter sets:

| tree_height | bds_k | (H-K) | Floor div | Ceil div | Bug? |
|-------------|-------|-------|-----------|----------|------|
| 10          | 0     | 10    | 5         | 5        | No   |
| 10          | 2     | 8     | 4         | 4        | No   |
| 10          | 4     | 6     | 3         | 3        | No   |
| 5           | 0     | 5     | 2         | 3        | **Yes** |
| 5           | 2     | 3     | 1         | 2        | **Yes** |
| 5           | 4     | 1     | 0         | 1        | **Yes** |
| 20          | 0     | 20    | 10        | 10       | No   |
| 20          | 2     | 18    | 9         | 9        | No   |

`tree_height = 5` arises in XMSS-MT parameter sets with `d = 4`
(full_height=20, tree_height=20/4=5). Any `bds_k` value gives an odd
`(H-K)` for `tree_height = 5`.

## Fix

Replace floor division with ceiling division in the two locations:

```diff
- (params->tree_height - params->bds_k) >> 1
+ (params->tree_height - params->bds_k + 1) >> 1
```

This is safe for all parameter sets: when `(H-K)` is even, the result is
unchanged.

## Verification

We confirmed this bug by compiling the reference-derived C implementation
in this repository with `bds_k = 2` and `tree_height = 5`
(XMSSMT-SHA2_20/4_256). Without the fix, `xmss_mt_verify()` fails at
index 16. With the fix, all 33 signatures (indices 0-32, crossing the
tree boundary) verify correctly.
