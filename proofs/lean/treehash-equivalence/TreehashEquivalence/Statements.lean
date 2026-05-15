import TreehashEquivalence.Spec
import TreehashEquivalence.Impl

/-!
# Statements of the lemmas and theorems

The headline is `treehashLocal_eq_treehashSpec`: RFC Algorithm 9
(`treehashLocal`) produces the same `TreehashResult` as the
recursive spec (`treehashSpec`).

The proof routes through the global-address intermediate
(`treehashGlobal`), splitting two independent obligations:

1. `treehashLocal_eq_treehashGlobal` — Algorithm 9's local
   `treeIdx ← (treeIdx - 1) / 2` iteration produces the same
   addresses as the global variant that computes each merge's
   index directly as `leafIdx / 2^(h + 1)` (matching the
   reference C implementation). **Pure arithmetic.**

2. `treehashGlobal_eq_treehashSpec` — the global-address
   iterative algorithm produces the same final result as the
   recursive spec. **Combinatorial:** stack invariant, carry
   propagation, canonical-block decomposition of `[s, s + 2^h)`.

The headline `treehashLocal_eq_treehashSpec` chains these two
whole-`TreehashResult` equalities. Trace and stack projections
are one-line corollaries.

Outer-field facts (`layer`, `tree`) are corollaries via the
`mergeAddr` projection simps: every address emitted by `specCore`
goes through `mergeAddr P.ℓ P.τ _ _`, so its `layer` and `tree`
fields are `P.ℓ` and `P.τ`.

Every `sorry` is a stated obligation. None should be silently
strengthened, weakened, or removed.
-/

namespace TreehashEquivalence

section
universe u
variable {Node : Type u}
variable (P : Params Node)

/-! ## Global-address ↔ recursive spec -/

/-- **Global ↔ spec.** For an aligned starting index `s`
(`2^h ∣ s`), the global-address iterative algorithm produces the
same `TreehashResult` as the recursive spec. The combinatorial
heart of the development. -/
theorem treehashGlobal_eq_treehashSpec
    (h s : Nat) (_halign : s % 2 ^ h = 0) :
    treehashGlobal P h s = treehashSpec P h s := by
  sorry

/-! ## Local ↔ global (bridge) -/

/-- **Bridge.** Algorithm 9's local address update
`treeIdx ← (treeIdx - 1) / 2` produces the same `TreehashResult`
as the global variant that keeps `leafIdx` in scope and computes
each merge's address treeIdx as `leafIdx / 2^(h + 1)`.

A pure-arithmetic fact: iterating `f(x) = (x - 1) / 2` `k` times
on the leaf index agrees with `leafIdx / 2^k`, under the
alignment conditions arising in Algorithm 9. This is the gap
between RFC 8391 Algorithm 9 as literally written and what every
reference implementation (`xmss_core.c`, `xmss_core_fast.c`)
actually does. -/
theorem treehashLocal_eq_treehashGlobal
    (h s : Nat) (_halign : s % 2 ^ h = 0) :
    treehashLocal P h s = treehashGlobal P h s := by
  sorry

/-! ## Headline -/

/-- **RFC ↔ spec.** Algorithm 9's result equals the recursive
spec's result. Chains the bridge with the global-address
equivalence. -/
theorem treehashLocal_eq_treehashSpec
    (h s : Nat) (halign : s % 2 ^ h = 0) :
    treehashLocal P h s = treehashSpec P h s :=
  (treehashLocal_eq_treehashGlobal P h s halign).trans
    (treehashGlobal_eq_treehashSpec P h s halign)

/-- Trace projection. -/
theorem treehashLocal_trace_eq_specTrace
    (h s : Nat) (halign : s % 2 ^ h = 0) :
    (treehashLocal P h s).trace = specTrace P h s :=
  congrArg TreehashResult.trace (treehashLocal_eq_treehashSpec P h s halign)

/-- Stack projection: after a complete run, the final stack holds
exactly the singleton root entry. -/
theorem treehashLocal_stack_eq_specRoot
    (h s : Nat) (halign : s % 2 ^ h = 0) :
    (treehashLocal P h s).stack = [⟨h, specRoot P h s⟩] :=
  congrArg TreehashResult.stack (treehashLocal_eq_treehashSpec P h s halign)

/-! ## Outer-field invariant -/

/-- Every address in `specTrace` has `layer = P.ℓ` and
`tree = P.τ`. By induction on `h`, using `mergeAddr_layer` /
`mergeAddr_tree` from the `@[simps]` on `mergeAddr`. -/
theorem specTrace_outer_fields
    (h s : Nat) {c : HashCall Node}
    (_hin : c ∈ specTrace P h s) :
    c.addr.layer = P.ℓ ∧ c.addr.tree = P.τ := by
  sorry

/-- Every address in the RFC trace has `layer = P.ℓ` and
`tree = P.τ`. Follows from `treehashLocal_trace_eq_specTrace` plus
`specTrace_outer_fields`. -/
theorem treehashLocal_outer_fields
    (h s : Nat) (_halign : s % 2 ^ h = 0)
    {c : HashCall Node}
    (_hin : c ∈ (treehashLocal P h s).trace) :
    c.addr.layer = P.ℓ ∧ c.addr.tree = P.τ := by
  sorry

end

end TreehashEquivalence
