import TreehashEquivalence.Spec
import TreehashEquivalence.Impl

/-!
# Statements of the lemmas and theorems

The headline is `treehash_eq_treehashSpec`: RFC Algorithm 9
(`treehash`) produces the same `TreehashResult` as the recursive
spec (`treehashSpec`).

The proof routes through a closed-form-addressed intermediate
(`treehashCF`), splitting two independent obligations:

1. `treehash_eq_treehashCF` — Algorithm 9's stateful
   `treeIndex ← (treeIndex - 1) / 2` iteration produces the same
   addresses as the closed-form variant that computes each
   merge's index directly as `leafIdx >> (curHeight + 1)`
   (matching the reference C implementation). **Pure arithmetic.**

2. `treehashCF_eq_treehashSpec` — the closed-form iterative
   algorithm produces the same final result as the recursive spec.
   **Combinatorial:** stack invariant, carry propagation,
   canonical-block decomposition of `[s, s + 2^h)`.

The headline `treehash_eq_treehashSpec` chains these two whole-
`TreehashResult` equalities. Trace and stack projections are
one-line corollaries.

Outer-field facts (`layer`, `tree`) are corollaries via the
`mergeAddr` projection simps.

Every `sorry` is a stated obligation. None should be silently
strengthened, weakened, or removed.
-/

namespace TreehashEquivalence

section
universe u
variable {Node : Type u}
variable (leaf : Nat → Node)
variable (H : Address → Node → Node → Node)
variable (ℓ τ : Nat)

/-! ## Closed-form ↔ recursive spec -/

/-- **Closed-form ↔ spec.** For an aligned starting index `s`
(`2^h ∣ s`), the closed-form iterative algorithm produces the
same `TreehashResult` as the recursive spec. The combinatorial
heart of the development. -/
theorem treehashCF_eq_treehashSpec
    (h s : Nat) (_halign : s % 2 ^ h = 0) :
    treehashCF leaf H ℓ τ h s = treehashSpec leaf H ℓ τ h s := by
  sorry

/-! ## Stateful ↔ closed-form (bridge) -/

/-- **Bridge.** Algorithm 9's stateful address update
`treeIndex ← (treeIndex - 1) / 2` produces the same
`TreehashResult` as the closed-form variant that keeps `leafIdx`
in scope and computes each merge's address treeIndex as
`leafIdx >> (curHeight + 1)`.

A pure-arithmetic fact: iterating `f(x) = (x - 1) / 2` `k` times
on the leaf index agrees with `leafIdx / 2^k`, under the alignment
conditions arising in Algorithm 9. This is the gap between RFC
8391 Algorithm 9 as literally written and what every reference
implementation (`xmss_core.c`, `xmss_core_fast.c`) actually does. -/
theorem treehash_eq_treehashCF
    (h s : Nat) (_halign : s % 2 ^ h = 0) :
    treehash leaf H ℓ τ h s = treehashCF leaf H ℓ τ h s := by
  sorry

/-! ## Headline -/

/-- **RFC ↔ spec.** Algorithm 9's result equals the recursive
spec's result. Chains the bridge with the closed-form
equivalence. -/
theorem treehash_eq_treehashSpec
    (h s : Nat) (halign : s % 2 ^ h = 0) :
    treehash leaf H ℓ τ h s = treehashSpec leaf H ℓ τ h s :=
  (treehash_eq_treehashCF leaf H ℓ τ h s halign).trans
    (treehashCF_eq_treehashSpec leaf H ℓ τ h s halign)

/-- Trace projection. -/
theorem treehash_trace_eq_specTrace
    (h s : Nat) (halign : s % 2 ^ h = 0) :
    (treehash leaf H ℓ τ h s).trace = specTrace leaf H ℓ τ h s :=
  congrArg TreehashResult.trace
    (treehash_eq_treehashSpec leaf H ℓ τ h s halign)

/-- Stack projection: after a complete run, the final stack holds
exactly the singleton root entry. -/
theorem treehash_stack_eq_specRoot
    (h s : Nat) (halign : s % 2 ^ h = 0) :
    (treehash leaf H ℓ τ h s).stack =
      [⟨h, specRoot leaf H ℓ τ h s⟩] :=
  congrArg TreehashResult.stack
    (treehash_eq_treehashSpec leaf H ℓ τ h s halign)

/-! ## Outer-field invariant

`treehashSpec`, by construction, only emits addresses built via
`mergeAddr ℓ τ _ _`; their `layer` and `tree` fields are `ℓ` and
`τ` by the `mergeAddr` projection simps. Combined with trace
equality, every address in the RFC trace inherits the caller-
supplied outer fields. -/

/-- Every address in `specTrace` has the caller-supplied outer
fields. By induction on `h`, using `mergeAddr_layer` /
`mergeAddr_tree` from the `@[simps]` on `mergeAddr`. -/
theorem specTrace_outer_fields
    (h s : Nat) {c : HashCall Node}
    (_hin : c ∈ specTrace leaf H ℓ τ h s) :
    c.addr.layer = ℓ ∧ c.addr.tree = τ := by
  sorry

/-- Every address in the RFC trace has the caller-supplied outer
fields. Follows from `treehash_trace_eq_specTrace` plus
`specTrace_outer_fields`. -/
theorem treehash_outer_fields
    (h s : Nat) (_halign : s % 2 ^ h = 0)
    {c : HashCall Node}
    (_hin : c ∈ (treehash leaf H ℓ τ h s).trace) :
    c.addr.layer = ℓ ∧ c.addr.tree = τ := by
  sorry

/-! ## Arithmetic helper

The closed-form merge-index identity used implicitly at every
merge in `specTrace`: for aligned `s` and any leaf offset `k`
within the block, the parent-index of the merge at children's
height `t` equals `(s + k) / 2^(t+1)`. -/

theorem mergeAddr_index_add
    (h t s k : Nat)
    (_halign : s % 2 ^ h = 0)
    (_hk     : k < 2 ^ h)
    (_ht     : t + 1 ≤ h) :
    s / 2 ^ (t + 1) + k / 2 ^ (t + 1) = (s + k) / 2 ^ (t + 1) := by
  sorry

end

end TreehashEquivalence
