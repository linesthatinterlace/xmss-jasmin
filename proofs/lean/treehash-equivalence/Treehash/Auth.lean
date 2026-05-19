import Treehash.Recursive
import Mathlib.Tactic.SplitIfs
import Mathlib.Tactic.Ring
import Mathlib.Data.Nat.Bitwise

/-!
# Authentication path — declarative spec

RFC 8391 §4.1.8 (line 1486-1488) defines the authentication path
for the `L`-th WOTS+ key pair as the array `auth[0], …, auth[h-1]`
with

    auth[j] = Node(j, floor(L / 2^j) XOR 1)

i.e. the level-`j` ancestor of leaf `L` has a sibling at level `j`,
index `(L >>> j) XOR 1`, and that node *is* `auth[j]`. The RFC also
notes (line 1561) that the node values "MAY be computed in any
way" — `buildAuth` (line 1589) and `treeSig` (Algorithm 11) are
implementation suggestions, not normative.

This file gives the spec only. Anything iterative (single-pass
extraction during a sweep, BDS, …) gets related back to `authNode`.
-/

namespace Treehash

section
universe u
variable {Node : Type u} {l t : Nat}
variable (P : Params Node l t)

/-- The `j`-th authentication-path node for leaf `L`: the root of
the height-`j` sibling subtree, whose starting leaf is
`((L >>> j) XOR 1) <<< j` = `k * 2^j` with `k = floor(L / 2^j) XOR 1`
(RFC 8391 §4.1.8, line 1488). -/
def authNode (L : Nat) (j : Nat) : Node :=
  treehashRecursive P j (((L >>> j) ^^^ 1) <<< j)

/-! ## Recursive extraction

The recursive extraction comes in two pieces: an internal auxiliary
function `treehashRecursiveWithAuthAux` that carries a subtree start
`s` (needed for the recursion to refer to non-zero offsets), and a
user-facing wrapper `treehashRecursiveWithAuth` that fixes `s = 0`.

`treehashRecursiveWithAuthAux P L h s` mirrors `treehashRecursive`
but also returns an `h`-entry authentication path. It is total: at
each merge it picks one side to descend (based on `L < s + 2^h`),
fills the other side via plain `treehashRecursive`, and captures
the non-descended child as `auth[h]`. The root is correct
unconditionally; the captured nodes match the spec `authNode` only
when `L` actually lies in `[s, s + 2^h)` and `s` is `2^h`-aligned —
both conditions trivially hold at the top-level `s = 0` invocation.

At each merge producing a node at height `h + 1` from two height-`h`
children:

* `L < s + 2^h` → descend into the left subtree, capture the right
  child as the level-`h` sibling.
* otherwise → descend into the right, capture the left.

The captured node is placed at `Fin.last h` (the top of the
`Fin (h+1)` auth path), and the recursive call's `Fin h → Node` is
slotted in below it via `Fin.lastCases`. -/

def treehashRecursiveWithAuthAux (L h s : Nat) : Node × (Fin h → Node) :=
  match h with
  | 0 => (P.leaf s, Fin.elim0)
  | h + 1 =>
    if L < s + 2 ^ h then
      let (lnode, lauth) := treehashRecursiveWithAuthAux L h s
      let rnode := treehashRecursive P h (s + 2 ^ h)
      let node := P.H (mkCall h (s / 2 ^ (h + 1)) lnode rnode)
      (node, Fin.lastCases rnode lauth)
    else
      let lnode := treehashRecursive P h s
      let (rnode, rauth) := treehashRecursiveWithAuthAux L h (s + 2 ^ h)
      let node := P.H (mkCall h (s / 2 ^ (h + 1)) lnode rnode)
      (node, Fin.lastCases lnode rauth)

/-- Compute the root and `h`-entry authentication path for leaf `L`
in the height-`h` tree (starting at leaf `0`). -/
def treehashRecursiveWithAuth (L h : Nat) : Node × (Fin h → Node) :=
  treehashRecursiveWithAuthAux P L h 0

/-! ## Equivalence to `authNode` -/

variable {P}

/-- Auxiliary: the first component of the s-generalised
extraction agrees with `treehashRecursive`, unconditionally. -/
theorem treehashRecursiveWithAuthAux_fst (L h s : Nat) :
    (treehashRecursiveWithAuthAux P L h s).fst = treehashRecursive P h s := by
 induction h generalizing s <;> grind [treehashRecursiveWithAuthAux]

/-- The first component agrees with `treehashRecursive` (at the
top-level `s = 0`). -/
theorem treehashRecursiveWithAuth_fst (L h : Nat) :
    (treehashRecursiveWithAuth P L h).fst = treehashRecursive P h 0 :=
  treehashRecursiveWithAuthAux_fst L h 0

/-! ### Bit arithmetic helpers for the second component -/

/-- Within an aligned `2^(h+1)`-block (`2^(h+1) ∣ s`, `L ∈ [s, s+2^h)`),
the level-`h` sibling subtree of `L` starts at `s + 2^h`. -/
private lemma siblingStart_left (s L h : Nat)
    (h2s : 2 ^ (h + 1) ∣ s) (hl : s ≤ L) (hu : L < s + 2 ^ h) :
    ((L >>> h) ^^^ 1) <<< h = s + 2 ^ h := by
  obtain ⟨q, rfl⟩ := Nat.pow_add_one _ _ ▸ h2s
  have hLdiv : L / 2 ^ h = 2 * q := Nat.div_eq_of_lt_le (by grind) (by grind)
  rw [Nat.shiftRight_eq_div_pow, Nat.shiftLeft_eq, hLdiv]
  grind [Nat.xor_one_of_even]

/-- Within an aligned `2^(h+1)`-block (`2^(h+1) ∣ s`, `L ∈ [s+2^h, s+2^(h+1))`),
the level-`h` sibling subtree of `L` starts at `s`. -/
private lemma siblingStart_right (s L h : Nat)
    (h2s : 2 ^ (h + 1) ∣ s) (hl : s + 2 ^ h ≤ L) (hu : L < s + 2 ^ (h + 1)) :
    ((L >>> h) ^^^ 1) <<< h = s := by
  obtain ⟨q, rfl⟩ := Nat.pow_add_one _ _ ▸ h2s
  have hLdiv : L / 2 ^ h = 2 * q + 1 := Nat.div_eq_of_lt_le (by grind) (by grind)
  rw [Nat.shiftRight_eq_div_pow, Nat.shiftLeft_eq, hLdiv]
  grind [Nat.xor_one_of_odd]

/-- Auxiliary: the second component agrees with `authNode` on
`Fin h`, provided `s` is `2^h`-aligned and `L` lies in the
subtree `[s, s + 2^h)`. -/
theorem treehashRecursiveWithAuthAux_snd (L h s : Nat)
    (h2s : 2 ^ h ∣ s) (hL : s ≤ L ∧ L < s + 2 ^ h) (j : Fin h) :
    (treehashRecursiveWithAuthAux P L h s).snd j = authNode P L j.val := by
  induction h generalizing s with
  | zero => exact j.elim0
  | succ h IH =>
    have h2s' : 2 ^ h ∣ s :=
      Nat.dvd_trans (Nat.pow_dvd_pow 2 (Nat.le_succ _)) h2s
    unfold treehashRecursiveWithAuthAux
    induction j using Fin.lastCases with
    | last =>
      split_ifs with hLeft
      · grind [siblingStart_left, authNode]
      · grind [siblingStart_right, authNode]
    | cast j' =>
      split_ifs with hLeft
      · grind
      · simp only [Fin.lastCases_castSucc]
        apply IH (s + 2 ^ h) (Nat.dvd_add h2s' (dvd_refl _))
        grind

/-- The second component agrees with `authNode` (at the top-level
`s = 0`). -/
theorem treehashRecursiveWithAuth_snd (L H : Nat) (hL : L < 2 ^ H) (j : Fin H) :
    (treehashRecursiveWithAuth P L H).snd j = authNode P L j.val := by
  apply treehashRecursiveWithAuthAux_snd L H 0
  · exact ⟨0, by simp⟩
  · exact ⟨Nat.zero_le _, by simpa using hL⟩

end

end Treehash
