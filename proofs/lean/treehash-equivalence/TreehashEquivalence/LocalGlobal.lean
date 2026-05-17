import TreehashEquivalence.Impl
import Mathlib.Tactic.Linarith
import Mathlib.Algebra.Order.Group.Nat
import Mathlib.Data.Nat.Basic
import Mathlib.Data.Nat.ModEq

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

For every depth `i`, if the stack entry at that depth has height
exactly `h + i`, then bit `h + i` of `leafIdx` is set. This is the
single fact needed at every merge step to turn the local update
`(leafIdx/2^k - 1) / 2` into the global formula `leafIdx / 2^(k+1)`
— because that identity holds iff `leafIdx / 2^k` is odd. -/
def MergeOK (leafIdx h : Nat) (stack : Stack Node) : Prop :=
  ∀ i v, stack[i]? = some ⟨h + i, v⟩ → leafIdx / 2 ^ (h + i) % 2 = 1

private lemma div_pow_succ (leafIdx h : Nat) :
    leafIdx / 2 ^ (h + 1) = leafIdx / 2 ^ h / 2 := by
  rw [pow_succ, Nat.div_div_eq_div_mul]

private lemma sub_one_div_two_of_odd {n : Nat} (h : n % 2 = 1) :
    (n - 1) / 2 = n / 2 := by
  omega

/-- The merge-step bridge: when the merge is "ready to fire"
(`leafIdx / 2^h` is odd), the local update `(leafIdx/2^h - 1) / 2`
lands exactly on `leafIdx / 2^(h+1)`. -/
private lemma local_step_eq_global
    {leafIdx h : Nat} (hodd : leafIdx / 2 ^ h % 2 = 1) :
    (leafIdx / 2 ^ h - 1) / 2 = leafIdx / 2 ^ (h + 1) := by
  rw [sub_one_div_two_of_odd hodd, ← div_pow_succ]

/-- **Merge-loop equivalence.** Under the address-consistency
invariant, the local and global inner merge loops produce the same
`TreehashResult`. Proof is by induction on the stack length: the
no-merge branch is identical between the two; the merge branch
matches because `MergeOK` provides the oddness that turns the
local update into the global formula. -/
theorem mergeLoop_eq (P : Params Node) :
    ∀ (stack : Stack Node) (trace : List (HashCall Node))
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
      -- Oddness at this merge: instantiate MergeOK at depth 0.
      have hodd : leafIdx / 2 ^ h' % 2 = 1 := by
        have := hOK 0 v' (by simp)
        simpa using this
      have ht' : (leafIdx / 2 ^ h' - 1) / 2 = leafIdx / 2 ^ (h' + 1) :=
        local_step_eq_global hodd
      -- Unfold both loops on the merge branch.
      simp only [localMergeLoop, globalMergeLoop, if_true, ht']
      -- Apply IH at height h'+1; the tail invariant follows by index shift.
      apply ih _ (h' + 1) _ leafIdx
      intro i w hi
      have hadd : (h' + 1) + i = h' + (i + 1) := by omega
      have h_idx : ((⟨h', v'⟩ : StackEntry Node) :: tl)[i + 1]? =
          some ⟨h' + (i + 1), w⟩ := by
        rw [← hadd]; simpa using hi
      have hres := hOK (i + 1) w h_idx
      rw [← hadd] at hres
      exact hres
    · -- No merge; both loops just push.
      simp [localMergeLoop, globalMergeLoop, heq]

/-! ## Outer-fold stack-shape invariant

After `i` pushes (starting from any aligned base), the running
stack's heights are the bit positions of `i`, lowest bit at the
top. We capture this as a recursive predicate `stackBits` on
`(i, stack)`; combined with the alignment of `s`, it discharges
`MergeOK (s + i) 0 stack` at every iteration.
-/

/-- The heights of the stack are the set-bit positions of `i`,
lowest first (top of stack). Recursively: the top entry's height
is the trailing-zero count of `i`, and the rest of the stack tracks
`i` with that lowest bit cleared. -/
def stackBits : Nat → Stack Node → Prop
  | 0, [] => True
  | 0, _ :: _ => False
  | _ + 1, [] => False
  | n + 1, ⟨h, _⟩ :: rest =>
      (n + 1) / 2 ^ h % 2 = 1 ∧
      (n + 1) % 2 ^ h = 0 ∧
      stackBits (n + 1 - 2 ^ h) rest

/-- Trailing-zero invariant used inside `stackBits`: a positive
`i` has `i % 2 ^ h = 0 ∧ i / 2 ^ h % 2 = 1` iff `h` is the index
of the lowest set bit. We use the conjunction directly as input to
the recursive case, so no separate lemma is needed. -/

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
