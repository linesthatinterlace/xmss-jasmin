import Treehash.Basic
import Treehash.Recursive
import Treehash.Iter
import Mathlib.Logic.Function.Iterate
import Mathlib.Data.List.Basic
import Mathlib.Data.Nat.ModEq

/-!
# Equivalence theorems

Two main equivalences between the three models defined in `Basic`,
`Recursive`, and `Iter`:

* `treehashLocal_eq_treehashRecursive` — **unconditional**.
  The RFC-style iterated `(treeIdx - 1) / 2` happens to compute the
  same `treeIdx` as the recursive definition's leftmost-leaf closed
  form, for any starting leaf `s`. The arithmetic identity behind
  this is that `(s_L + 2^k - 1)` reduces under `k` applications of
  `(x - 1) / 2` to `s_L / 2^k`, with no divisibility hypothesis on
  `s_L`.

* `treehashGlobal_eq_treehashRecursive` — **requires `2^h ∣ s`**.
  The global model computes `treeIdx = leafIdx / 2^(m+1)` from the
  *rightmost* (triggering) leaf, whereas Recursive (and Local) use
  the *leftmost*. The two coincide exactly when the merge-block
  boundary aligns, i.e. when `2^h ∣ s` at the top level (which then
  implies alignment at every sub-merge).

The proofs of `treehashLocalOn_eq` and `treehashGlobalOn_eq` are
intentionally written in parallel: the same induction skeleton, the
same merge-cascade rewrites, differing only in the per-step address
arithmetic.
-/

namespace Treehash

section
universe u
variable {Node : Type u} {l t : Nat}
variable {P : Params Node l t}

/-! ## Per-stack equivalence

Running each iterative model on a stack whose entries all have height
`≥ h` is the same as feeding the recursive root through that model's
merge loop. -/

/-- Local model: agrees with the recursive root unconditionally,
threading `treeIdx = s / 2^h` into the merge cascade. -/
theorem treehashLocalOn_eq (h s : Nat) (stk : Stack Node)
    (hstk : ∀ p ∈ stk, h ≤ p.1) :
    treehashLocalOn P h s stk =
      localMerge P (s / 2^h) h (treehashRecursive P h s) stk := by
  induction h generalizing s stk with
  | zero => simp
  | succ h IH =>
    have H1 := IH s stk (by grind)
    have H2 := IH (s + 2^h) ((h, treehashRecursive P h s) :: stk) (by grind)
    rw [localMerge_cons, if_pos rfl, Nat.add_div_right _ (Nat.two_pow_pos h),
      Nat.add_one_sub_one (s / 2^h)] at H2
    rw [treehashLocalOn_succ, IH s stk (by grind),
        localMerge_of_fst_head_ne (by grind), H2,
        treehashRecursive_succ, Nat.pow_succ, Nat.div_div_eq_div_mul]

/-- Global model: agrees with the recursive root when `2^h ∣ s`,
threading `leafIdx = s + 2^h - 1` (the *rightmost* leaf) into the
merge cascade. -/
theorem treehashGlobalOn_eq (h s : Nat) (stk : Stack Node)
    (hstk : ∀ p ∈ stk, h ≤ p.1) (h2s : 2^h ∣ s) :
    treehashGlobalOn P h s stk =
      globalMerge P (s + (2^h - 1)) h (treehashRecursive P h s) stk := by
  induction h generalizing s stk with
  | zero => simp
  | succ h IH =>
    have h2h  : 2^h ∣ s         := Nat.dvd_trans (Nat.pow_dvd_pow _ (Nat.le_succ _)) h2s
    have h2hr : 2^h ∣ (s + 2^h) := Nat.dvd_add h2h (Nat.dvd_refl _)
    have H1 := IH s stk (by grind) h2h
    have H2 := IH (s + 2^h) ((h, treehashRecursive P h s) :: stk) (by grind) h2hr
    rw [add_assoc, ← Nat.add_sub_assoc Nat.one_le_two_pow, ← Nat.two_pow_succ,
      globalMerge_cons, if_pos rfl, Nat.add_div_of_dvd_right h2s,
      Nat.div_eq_of_lt (Nat.sub_one_lt (Nat.two_pow_pos _).ne'), add_zero] at H2
    rw [treehashGlobalOn_succ, H1, globalMerge_of_fst_head_ne (by grind), H2,
      treehashRecursive_succ]

/-! ## Main equivalences -/

/-- The RFC-style local treehash agrees with the recursive
definition for every starting leaf `s` — no alignment hypothesis
required. -/
theorem treehashLocal_eq_treehashRecursive (h s : Nat) :
    treehashLocal P h s = [⟨h, treehashRecursive P h s⟩] := by
  grind [treehashLocal, treehashLocalOn_eq]

/-- The global treehash agrees with the recursive definition when
`2^h ∣ s` — the alignment hypothesis from `treehashGlobalOn_eq`. -/
theorem treehashGlobal_eq_treehashRecursive (h s : Nat) (h2s : 2^h ∣ s) :
    treehashGlobal P h s = [⟨h, treehashRecursive P h s⟩] := by
  grind [treehashGlobal, treehashGlobalOn_eq]

/-- The two iterative models agree on the empty stack when `2^h ∣ s`. -/
theorem treehashGlobal_eq_treehashLocal (h s : Nat) (h2s : 2^h ∣ s) :
    treehashGlobal P h s = treehashLocal P h s := by
  grind [treehashGlobal_eq_treehashRecursive, treehashLocal_eq_treehashRecursive]

end

end Treehash
