import TreehashEquivalence.Impl
import Mathlib.Tactic.Linarith
import Mathlib.Algebra.Order.Group.Nat
import Mathlib.Data.Nat.Basic
import Mathlib.Data.Nat.Bits

/-!
# Local ↔ Global bridge

Helpers used to prove `treehashLocal_eq_treehashGlobal`.

The proof has two ingredients:

* `mergeLoop_eq` — under an address-consistency invariant `MergeOK`,
  the local and global inner merge loops agree pointwise.

* `stackBitInv` — the running stack's heights, after `i` pushes,
  are exactly the positions of the set bits of `i`. This invariant
  (combined with the alignment hypothesis on `s`) discharges
  `MergeOK` at every outer iteration.
-/

namespace TreehashEquivalence

universe u
variable {Node : Type u}

/-! ## Merge-loop equivalence -/

/-- Address-consistency invariant for the merge cascade.

Every stack entry at height `≥ h` has its corresponding bit set in
`leafIdx`. This is the single fact needed at each merge step to turn
the local update `(leafIdx/2^k - 1) / 2` into the global formula
`leafIdx / 2^(k+1)` — because that identity holds iff `leafIdx.testBit k`. -/
def MergeOK (leafIdx h : Nat) (stack : List (StackEntry Node)) : Prop :=
  ∀ e ∈ stack, h ≤ e.height → leafIdx.testBit e.height

private lemma div_pow_succ (leafIdx h : Nat) :
    leafIdx / 2 ^ (h + 1) = leafIdx / 2 ^ h / 2 := by
  rw [pow_succ, Nat.div_div_eq_div_mul]

private lemma sub_one_div_two_of_odd {n : Nat} (h : n % 2 = 1) :
    (n - 1) / 2 = n / 2 := by
  omega

/-- The merge-step bridge: when the merge is "ready to fire"
(`leafIdx.testBit h` is true), the local update `(leafIdx/2^h - 1) / 2`
lands exactly on `leafIdx / 2^(h+1)`. -/
private lemma local_step_eq_global
    {leafIdx h : Nat} (hodd : leafIdx.testBit h) :
    (leafIdx / 2 ^ h - 1) / 2 = leafIdx / 2 ^ (h + 1) := by
  have hodd' : leafIdx / 2 ^ h % 2 = 1 := by
    rwa [Nat.testBit_eq_true_iff] at hodd
  rw [sub_one_div_two_of_odd hodd', ← div_pow_succ]

/-- **Merge-loop equivalence.** Under the address-consistency
invariant, the local and global inner merge loops produce the same
`TreehashResult`. Proof is by induction on the stack length: the
no-merge branch is identical between the two; the merge branch
matches because `MergeOK` provides the oddness that turns the
local update into the global formula. -/
theorem mergeLoop_eq (P : Params Node) :
    ∀ (stack : List (StackEntry Node)) (trace : List (HashCall Node))
      (h : Nat) (v : Node) (leafIdx : Nat),
      MergeOK leafIdx h stack →
      localMergeLoop P (leafIdx / 2 ^ h) ⟨h, v⟩ ⟨stack, trace⟩
        = globalMergeLoop P leafIdx ⟨h, v⟩ ⟨stack, trace⟩ := by
  intro stack
  induction stack with
  | nil =>
    intro trace h v leafIdx _
    simp [localMergeLoop, globalMergeLoop]
  | cons hd tl ih =>
    intro trace h v leafIdx hOK
    obtain ⟨h', v'⟩ := hd
    by_cases heq : h' = h
    · -- Merge fires; addresses must agree.
      subst heq
      -- Oddness at this merge: apply MergeOK to the head.
      have hodd : leafIdx.testBit h' :=
        hOK ⟨h', v'⟩ (List.mem_cons_self _ _) (le_refl _)
      have ht' : (leafIdx / 2 ^ h' - 1) / 2 = leafIdx / 2 ^ (h' + 1) :=
        local_step_eq_global hodd
      -- Unfold both loops on the merge branch.
      simp only [localMergeLoop, globalMergeLoop, if_true, ht']
      -- Apply IH at height h'+1; tail invariant follows from MergeOK on tl.
      apply ih _ (h' + 1) _ leafIdx
      intro e he hle
      exact hOK e (List.mem_cons_of_mem _ he) (by omega)
    · -- No merge; both loops just push.
      simp [localMergeLoop, globalMergeLoop, heq]

/-! ## Outer-fold stack-shape invariant

After `i` pushes (starting from any aligned base), the running
stack's heights are the bit positions of `i`, lowest bit at the
top. We capture this as a recursive predicate `stackBits` on
`(i, stack)`; combined with the alignment of `s`, it discharges
`MergeOK (s + i) 0 stack` at every iteration.
-/

/-- The heights of the stack are exactly the set-bit positions of `i`:
`i.testBit n` iff some entry in `stack` has height `n`. -/
def stackBits (i : Nat) (stack : List (StackEntry Node)) : Prop :=
  ∀ n, i.testBit n ↔ ∃ e ∈ stack, e.height = n

private lemma two_pow_pos (h : Nat) : 0 < 2 ^ h := Nat.two_pow_pos h

/-- A useful divisibility-shifting fact: if `s % 2 ^ H = 0` and
`j < H`, then `(s + i) / 2 ^ j` has the same parity as `i / 2 ^ j`.
Concretely we use this in the form `((s + i) / 2 ^ j) % 2 =
(i / 2 ^ j) % 2`. -/
private lemma add_aligned_div_mod_two
    {s i H j : Nat} (hs : s % 2 ^ H = 0) (hj : j + 1 ≤ H) :
    (s + i) / 2 ^ j % 2 = i / 2 ^ j % 2 := by
  -- `2 ^ (j+1) ∣ s`, and `(s + i) / 2 ^ j = s / 2 ^ j + i / 2 ^ j`
  -- with `s / 2 ^ j` even.
  have hdvd : 2 ^ (j + 1) ∣ s := by
    have : 2 ^ (j + 1) ∣ 2 ^ H := Nat.pow_dvd_pow 2 hj
    exact this.trans (Nat.dvd_of_mod_eq_zero hs)
  -- `2 ^ j ∣ s`
  have hdvdj : 2 ^ j ∣ s := dvd_trans (Nat.pow_dvd_pow 2 (Nat.le_succ _)) hdvd
  -- split the division
  have hsplit : (s + i) / 2 ^ j = s / 2 ^ j + i / 2 ^ j := by
    rw [Nat.add_div_of_dvd_right hdvdj]
  -- `s / 2 ^ j` is even, since `2 ^ (j+1) ∣ s`.
  have heven : s / 2 ^ j % 2 = 0 := by
    obtain ⟨k, hk⟩ := hdvd
    have : s / 2 ^ j = 2 * k := by
      rw [hk, pow_succ, Nat.mul_assoc, Nat.mul_div_cancel_left _ (two_pow_pos j)]
    rw [this]; omega
  rw [hsplit, Nat.add_mod, heven, Nat.zero_add, Nat.mod_mod]

end TreehashEquivalence
