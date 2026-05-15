import TreehashEquivalence.Basic

/-!
# Iterative treehash implementations

Two stack-based models of RFC 8391 Algorithm 9. Both produce the
same `TreehashResult` shape; the substantive difference is how
each computes the address at every merge.

* `treehashCF` — **closed-form** addresses, modelling what the
  xmss-reference implementations (`xmss_core.c`, `xmss_core_fast.c`)
  actually do: the inner merge loop keeps the leaf index `leafIdx`
  in scope as a constant and computes each merge's address index
  by shifting, `leafIdx >> (curHeight + 1)`. No per-merge
  accumulator.

* `treehash` — **RFC-faithful**, modelling Algorithm 9 as written
  in RFC 8391 §4.1.6: the inner merge loop threads `treeIndex`,
  mutating it via `treeIndex ← (treeIndex - 1) / 2` *before* each
  RAND_HASH and incrementing `treeHeight` *after*.

The bridge `treehash_eq_treehashCF` (proven in `Statements.lean`)
asserts the two models produce the same `TreehashResult`. It is
where the arithmetic identity "iterating `(x - 1) / 2` agrees
with `leafIdx >> (curHeight + 1)`" becomes load-bearing — the
gap between what the RFC specifies and what every real
implementation does.

`rfcMergeLoop` performs a `Nat` subtraction whose well-definedness
relies on the merge guard (`treeIndex ≥ 1` whenever a height-`treeHeight`
left sibling exists on the stack). This invariant holds whenever the
caller's alignment hypothesis (`s % 2^h = 0`) holds.

This module deliberately does not import `Spec`: implementation
and spec share only the data types in `Basic`.
-/

namespace TreehashEquivalence

section
universe u
variable {Node : Type u}
variable (leaf : Nat → Node)
variable (H : Address → Node → Node → Node)
variable (ℓ τ : Nat)

/-! ## Closed-form-addressed model (`treehashCF`)

The inner merge loop keeps `leafIdx` in scope (the leaf index that
triggered this chain of merges) and computes each merge's address
treeIndex directly as `leafIdx >> (curHeight + 1)`. This matches
the reference implementation pattern in `xmss_core.c`. -/

/-- Inner merge loop, closed-form variant. The address at each
merge has `treeIndex = leafIdx >> (curHeight + 1)`, computed
directly without a per-merge accumulator. -/
def cfMergeLoop
    (leafIdx curHeight : Nat) (curNode : Node) :
    List (StackEntry Node) → List (HashCall Node) →
    List (StackEntry Node) × List (HashCall Node)
  | top :: rest, trace =>
      if top.height = curHeight then
        let addr     : Address := ⟨ℓ, τ, curHeight, leafIdx / 2 ^ (curHeight + 1)⟩
        let newNode  := H addr top.value curNode
        cfMergeLoop leafIdx (curHeight + 1) newNode rest
          (trace ++ [⟨addr, top.value, curNode⟩])
      else
        (⟨curHeight, curNode⟩ :: top :: rest, trace)
  | [], trace =>
      ([⟨curHeight, curNode⟩], trace)
termination_by stk _ => stk.length

/-- One iteration of the closed-form model: push `leaf leafIdx`,
keep `leafIdx` in scope, run the inner merge loop starting at
`curHeight = 0`. -/
def treehashCFStep
    (r : TreehashResult Node) (leafIdx : Nat) : TreehashResult Node :=
  let (stk', trace') :=
    cfMergeLoop (Node := Node) H ℓ τ leafIdx 0 (leaf leafIdx) r.stack r.trace
  ⟨stk', trace'⟩

/-- Push `2^h` leaves starting at `s`. The address handed to `H`
at every merge is computed in closed form from the loop-threaded
`curStart`. -/
def treehashCF (h s : Nat) : TreehashResult Node :=
  (List.range (2 ^ h)).foldl
    (fun r i => treehashCFStep (Node := Node) leaf H ℓ τ r (s + i))
    ⟨[], []⟩

/-! ## RFC-faithful model (`treehash`)

The inner merge loop threads `treeIndex`: the RFC's address-state
field, pre-decremented by `(idx - 1) / 2` before each RAND_HASH.
`treeHeight` is post-incremented after. -/

/-- Inner merge loop, RFC variant. Maintains the mutating
`treeHeight` and `treeIndex` exactly as Algorithm 9 prescribes. -/
def rfcMergeLoop
    (treeHeight treeIndex : Nat) (curNode : Node) :
    List (StackEntry Node) → List (HashCall Node) →
    List (StackEntry Node) × List (HashCall Node)
  | top :: rest, trace =>
      if top.height = treeHeight then
        let treeIndex' := (treeIndex - 1) / 2
        let addr       : Address := ⟨ℓ, τ, treeHeight, treeIndex'⟩
        let newNode    := H addr top.value curNode
        rfcMergeLoop (treeHeight + 1) treeIndex' newNode rest
          (trace ++ [⟨addr, top.value, curNode⟩])
      else
        (⟨treeHeight, curNode⟩ :: top :: rest, trace)
  | [], trace =>
      ([⟨treeHeight, curNode⟩], trace)
termination_by stk _ => stk.length

/-- One iteration of Algorithm 9: push `leaf leafIdx` with initial
`treeHeight = 0`, `treeIndex = leafIdx`, and run the inner merge
loop. -/
def treehashStep
    (r : TreehashResult Node) (leafIdx : Nat) : TreehashResult Node :=
  let (stk', trace') :=
    rfcMergeLoop (Node := Node) H ℓ τ 0 leafIdx (leaf leafIdx) r.stack r.trace
  ⟨stk', trace'⟩

/-- Algorithm 9 (treeHash) as written in RFC 8391. Pushes `2^h`
leaves starting at `s`, with the stateful address update on each
merge. -/
def treehash (h s : Nat) : TreehashResult Node :=
  (List.range (2 ^ h)).foldl
    (fun r i => treehashStep (Node := Node) leaf H ℓ τ r (s + i))
    ⟨[], []⟩

end

end TreehashEquivalence
