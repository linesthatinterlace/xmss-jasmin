# Retraction: BDS treehash update budget in xmss-reference is NOT a bug

## Summary

This document previously reported a bug in the xmss-reference implementation's
BDS treehash update budget calculation (`>> 1` floor division). **That report
was incorrect.** The reference implementation is correct: the BDS algorithm
requires `(H - K)` to be even as a precondition, making the `>> 1` division
exact (not a floor approximation).

## What we got wrong

We observed that `(tree_height - bds_k) >> 1` gives too few treehash updates
when `(tree_height - bds_k)` is odd (e.g., H=5, K=2 → H-K=3 → 1 update
instead of the 2 needed). We concluded this was a bug in the reference and
applied a ceiling-division fix: `(tree_height - bds_k + 1) >> 1`.

**The actual problem**: we were using `bds_k = 2` with `tree_height = 5`,
which violates the BDS algorithm's precondition that `(H - K)` must be even.
For `tree_height = 5`, no even K > 0 satisfies this, so `K = 0` is the only
valid choice.

## Why the reference is correct

The xmss-reference validates the bds_k parameter in `xmss_set_params` (older
commit `4c19fe61e4`, `xmss_fast.c`):

```c
if (k >= h || k < 2 || (h - k) % 2) {
    // reject invalid k
}
```

This means valid non-zero K requires: `K >= 2`, `K < H`, and `(H - K)` even.
K=0 bypasses the BDS retain optimisation entirely and is always valid.

The `(H - K)` even precondition is fundamental to the BDS algorithm as
described in the XMSS-MT paper [ePrint 2017/966]. When `(H - K)` is even,
`>> 1` is exact — not an approximation.

The reference's `bds_k = 0` default is correct for all parameter sets, since
all RFC 8391 tree heights (5, 10, 20) have K=0 as a valid choice.

## What we fixed

1. **Replaced** our ceiling division (`+ 1`) with the reference's exact
   division in both C and Jasmin implementations.
2. **Strengthened** bds_k validation to match the reference:
   `K=0 || (K >= 2 && K < H && (H-K) % 2 == 0)`.
3. **Changed** XMSSMT-SHA2_20/4_256 (tree_height=5) from `bds_k=2` to
   `bds_k=0` — the only valid value for this tree height.
4. **Updated** the exhaustive BDS test matrix: H=5 now only tests K=0.
