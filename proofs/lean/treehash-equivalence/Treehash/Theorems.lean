import Treehash.Basic
import Treehash.Recursive
import Treehash.IterLocal
import Treehash.IterGlobal

/-!
# Equivalence theorems

Two main equivalences between the three models defined in `Basic`,
`Recursive`, `IterLocal`, `IterGlobal`:

* `treehashLocal_eq_treehashRecursive` — **unconditional**.
  The RFC-style iterated `(treeIdx - 1) / 2` happens to compute the
  same `treeIdx` as the recursive definition's leftmost-leaf
  closed form, for any starting leaf `s`. The arithmetic identity
  behind this is `(s_L + 2^k - 1)` reduces under `k` applications of
  `(x - 1) / 2` to `s_L / 2^k`, with no divisibility hypothesis on
  `s_L`.

* `treehashGlobal_eq_treehashRecursive` — **requires `2^h ∣ s`**.
  The global model computes `treeIdx = leafIdx / 2^(m+1)` from the
  *rightmost* (triggering) leaf, whereas Recursive (and Local) use
  the *leftmost*. The two coincide exactly when the merge-block
  boundary aligns, i.e. when `2^h ∣ s` at the top level (which then
  implies alignment at every sub-merge).
-/

namespace Treehash

section
universe u
variable {Node : Type u} {l t : Nat}
variable (P : Params Node l t)

/-! ## Main equivalences -/

/-- The RFC-style local treehash agrees with the recursive
definition for every starting leaf `s` — no alignment hypothesis
required. -/
theorem treehashLocal_eq_treehashRecursive (h s : Nat) :
    treehashLocal P h s = treehashRecursive P h s := by
  sorry

/-- The global-address iterative treehash agrees with the
recursive definition when the starting leaf `s` is a multiple of
`2^h`. Without that alignment, the rightmost-leaf division Global
uses diverges from the leftmost-leaf division Recursive uses. -/
theorem treehashGlobal_eq_treehashRecursive (h s : Nat) (h2s : 2^h ∣ s) :
    treehashGlobal P h s = treehashRecursive P h s := by
  sorry

end

end Treehash
