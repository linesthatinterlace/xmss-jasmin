import TreehashEquivalence.Basic

/-!
# Iterative treehash implementations

Two stack-based models of RFC 8391 Algorithm 9. Both produce the
same `TreehashResult` shape; the substantive difference is how
each computes the `treeIdx` field of the address at every merge.

* `treehashGlobal` — **global-address** model, matching the
  xmss-reference implementations (`xmss_core.c`,
  `xmss_core_fast.c`). The inner merge loop keeps the leaf index
  `leafIdx` (a global coordinate into the whole tree's leaf
  sequence) in scope as a *constant*, and at each merge computes
  the address treeIdx directly as `leafIdx / 2^(h + 1)`.

* `treehashLocal` — **local-address** model, matching Algorithm 9
  as literally written in RFC 8391 §4.1.6. The inner merge loop
  threads a *mutating* `treeIdx`, updated as
  `treeIdx ← (treeIdx - 1) / 2` immediately before each merge step
  and never referring back to `leafIdx`. Each merge only sees the
  previous merge's output index.

Both compute the same global parent index at every merge — the
local form is just an unrolled iteration of `(x - 1)/2` starting
from `leafIdx`, which agrees with shifting under the alignment
condition `s % 2^h = 0`. The bridge
`treehashLocal_eq_treehashGlobal` (in `Statements.lean`) is where
that arithmetic identity becomes load-bearing.

Note that the inner loops are *not* equal as functions of their
threading parameter: at a fresh leaf push with `leafIdx` even,
`(leafIdx - 1)/2 ≠ leafIdx >> 1`. They agree only at the values
of `leafIdx` for which a merge actually fires, i.e. those with
enough trailing 1-bits. The bridge has to carry that invariant;
no pointwise loop equality is available.

`localMergeLoop` performs a `Nat` subtraction whose
well-definedness relies on the merge guard (`treeIdx ≥ 1`
whenever a height-`treeHeight` left sibling exists on the stack).
This invariant holds whenever the caller's alignment hypothesis
(`s % 2^h = 0`) holds.

This module deliberately does not import `Spec`: implementation
and spec share only the data types in `Basic`.
-/

namespace TreehashEquivalence

section
universe u
variable {Node : Type u}
variable (P : Params Node)

/-! ## Global-address model (`treehashGlobal`)

The inner merge loop keeps `leafIdx` in scope (the leaf index
that triggered this chain of merges) and computes each merge's
address treeIdx directly as `leafIdx / 2^(h + 1)`. This matches
the reference implementation pattern in `xmss_core.c`. -/

/-- Inner merge loop, global-address variant. The address at each
merge is `mergeAddr P.ℓ P.τ h leafIdx` — the spec's address
constructor applied to the cascade-triggering leaf, which is one
leaf of the subtree being built and therefore gives the parent's
correct `treeIdx` directly. -/
def globalMergeLoop (leafIdx : Nat) :
    StackEntry Node → TreehashResult Node → TreehashResult Node
  | ⟨h, v⟩, ⟨⟨h', v'⟩ :: rest, trace⟩ =>
      if h' = h then
        let addr := mergeAddr P.ℓ P.τ h leafIdx
        globalMergeLoop leafIdx ⟨h + 1, P.H addr v' v⟩ ⟨rest, ⟨addr, v', v⟩ :: trace⟩
      else ⟨⟨h, v⟩ :: ⟨h', v'⟩ :: rest, trace⟩
  | ⟨h, v⟩, ⟨[], trace⟩ => ⟨[⟨h, v⟩], trace⟩
termination_by _ stk => stk.stack.length

/-- One iteration of the global-address model: push `leaf leafIdx`,
keep `leafIdx` in scope, run the inner merge loop starting at
`h = 0`. -/
def treehashGlobalStep
    (r : TreehashResult Node) (leafIdx : Nat) : TreehashResult Node :=
  globalMergeLoop P leafIdx ⟨0, P.leaf leafIdx⟩ r

/-- Push `2^h` leaves starting at `s`. The address handed to `H`
at every merge is derived directly from the global leaf index
that triggered the merge chain. -/
def treehashGlobal (h s : Nat) : TreehashResult Node :=
  (List.range (2 ^ h)).foldl
  (fun r i => treehashGlobalStep P r (s + i)) ⟨[], []⟩

/-! ## Local-address model (`treehashLocal`)

The inner merge loop threads `treeIdx`: the RFC's address-state
field, pre-updated by `(idx - 1) / 2` before each merge step.
`h` is post-incremented after. The computation is purely local:
each merge only sees the previous merge's output index, never the
originating leaf index. -/

/-- Inner merge loop, local-address (RFC) variant. Maintains the
mutating `h` and `treeIdx` exactly as Algorithm 9 prescribes. -/
def localMergeLoop (treeIdx : Nat) :
    StackEntry Node → TreehashResult Node → TreehashResult Node
  | ⟨h, v⟩, ⟨⟨h', v'⟩ :: rest, trace⟩ =>
      if h' = h then
        let treeIdx' := (treeIdx - 1) / 2
        let addr     : Address := ⟨P.ℓ, P.τ, h, treeIdx'⟩
        localMergeLoop treeIdx' ⟨h + 1, P.H addr v' v⟩ ⟨rest, ⟨addr, v', v⟩ :: trace⟩
      else ⟨⟨h, v⟩ :: ⟨h', v'⟩ :: rest, trace⟩
  | ⟨h, v⟩, ⟨[], trace⟩ => ⟨[⟨h, v⟩], trace⟩
termination_by _ stk => stk.stack.length

/-- One iteration of Algorithm 9: push `leaf leafIdx` with initial
`treeHeight = 0`, `treeIdx = leafIdx`, and run the inner merge
loop. The initial `treeIdx = leafIdx` is the only point where the
local model touches the global leaf index; after that it walks
purely locally. -/
def treehashLocalStep
    (r : TreehashResult Node) (leafIdx : Nat) : TreehashResult Node :=
  localMergeLoop P leafIdx ⟨0, P.leaf leafIdx⟩ r

/-- Algorithm 9 (treeHash) as written in RFC 8391. Pushes `2^h`
leaves starting at `s`, with the local stateful address update on
each merge. -/
def treehashLocal (h s : Nat) : TreehashResult Node :=
  (List.range (2 ^ h)).foldl
  (fun r i => treehashLocalStep P r (s + i)) ⟨[], []⟩

end

end TreehashEquivalence
