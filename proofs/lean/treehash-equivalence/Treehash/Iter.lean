import Treehash.Basic

/-!
# Iterative treehash models

The two stack-based models of RFC 8391 Algorithm 9 that we relate to
the recursive specification:

* `localMerge` — RFC 8391 §4.1.6 Algorithm 9 in its literal form.
  A mutating `treeIdx` is threaded through the merge loop, updated
  as `treeIdx ← (treeIdx - 1) / 2` before each merge. Purely local:
  each merge only sees the previous merge's output index, never the
  triggering leaf.
* `globalMerge` — the variant matching the xmss-reference C code
  (`xmss_core.c`, `xmss_core_fast.c`): the triggering leaf index
  stays in scope, and each merge's address is computed directly as
  `leafIdx / 2^(h+1)`.

Both share the same surrounding fold over `2^h` leaves, factored out
as `treehashIter`. The two iterative variants instantiate it with
`localMerge` and `globalMerge` respectively, and inherit the
`_zero` / `_succ` unfolding lemmas proved here.

`localMerge` does a `Nat` subtraction; it stays well-defined because
the merge guard only fires when a left sibling exists, which means at
least two leaves have been pushed since the last stack-clearing — so
`treeIdx ≥ 1` whenever the subtraction runs. No alignment hypothesis
on `s` is needed for well-definedness, and the model agrees with
`treehashRecursive` for *every* `s` (see `Treehash.Theorems`).
-/

namespace Treehash

section
universe u
variable {Node : Type u} {l t : Nat}
variable (P : Params Node l t)

/-! ## Merge operations -/

/-- RFC-literal merge step: `treeIdx` is updated by `(prev - 1) / 2`
at each cascade level. -/
def localMerge (treeIdx : Nat) (h : Nat) (v : Node) : Stack Node → Stack Node
  | [] => [⟨h, v⟩] | ⟨h', v'⟩ :: rest =>
    if h' = h then
      let treeIdx' := (treeIdx - 1) / 2
      localMerge treeIdx' (h + 1) (P.H (mkCall h treeIdx' v' v)) rest
    else ⟨h, v⟩ :: ⟨h', v'⟩ :: rest

/-- xmss-reference-style merge step: each cascade level computes its
address directly from the fixed triggering leaf index. -/
def globalMerge (leafIdx : Nat) (h : Nat) (v : Node) : Stack Node → Stack Node
  | [] => [⟨h, v⟩] | ⟨h', v'⟩ :: rest =>
    if h' = h then
      globalMerge leafIdx (h + 1) (P.H (mkCall h (leafIdx / 2^(h + 1)) v' v)) rest
    else  ⟨h, v⟩ :: ⟨h', v'⟩ :: rest

/-! ## Merge unfolding lemmas -/

variable {P}

@[simp, grind =] theorem localMerge_nil (i h : Nat) (v : Node) :
    localMerge P i h v [] = [(h, v)] := rfl

@[grind =] theorem localMerge_cons (i h : Nat) (v : Node) (se : Nat × Node)
    (rest : Stack Node) :
    localMerge P i h v (se :: rest) = if se.1 = h then
      localMerge P ((i - 1) / 2) (h + 1) (P.H (mkCall h  ((i - 1) / 2) se.2 v)) rest else
      (h, v) :: se :: rest := rfl

@[grind =] theorem localMerge_of_fst_head_ne {i h : Nat} {v : Node} {stk : Stack Node}
    (hstk : ∀ hs : stk ≠ [], (stk.head hs).1 ≠ h) :
    localMerge P i h v stk = (h, v) :: stk := by
  cases stk with | nil => rfl | cons p _ => grind

@[simp, grind =] theorem globalMerge_nil (li h : Nat) (v : Node) :
    globalMerge P li h v [] = [(h, v)] := rfl

@[grind =] theorem globalMerge_cons (li h : Nat) (v : Node) (se : Nat × Node)
    (rest : Stack Node) :
    globalMerge P li h v (se :: rest) = if se.1 = h then
      globalMerge P li (h + 1)
        (P.H (mkCall h (li / 2^(h + 1)) se.2 v)) rest else
      (h, v) :: se :: rest := rfl

@[grind =] theorem globalMerge_of_fst_head_ne {li h : Nat} {v : Node} {stk : Stack Node}
    (hstk : ∀ hs : stk ≠ [], (stk.head hs).1 ≠ h) :
    globalMerge P li h v stk = (h, v) :: stk := by
  cases stk with | nil => rfl | cons p _ => grind

variable (P)

/-! ## The shared fold -/

/-- Iterated treehash, parameterised over the per-leaf merge operation
`merge li h v stk`. For each leaf `s, s+1, …, s+2^h-1`, push the leaf
onto the stack at height `0` and cascade merges as `merge` directs. -/
def treehashIter (merge : Nat → Nat → Node → Stack Node → Stack Node)
    (h s : Nat) (stk : Stack Node) : Stack Node :=
  Nat.fold (2 ^ h) (fun i _ => let li := s + i; merge li 0 (P.leaf li)) stk

variable {P}
variable (merge : Nat → Nat → Node → Stack Node → Stack Node)

@[simp, grind =] theorem treehashIter_zero (s : Nat) (stk : Stack Node) :
    treehashIter P merge 0 s stk = merge s 0 (P.leaf s) stk := rfl

@[simp, grind =] theorem treehashIter_succ (h s : Nat) (stk : Stack Node) :
    treehashIter P merge (h + 1) s stk =
    treehashIter P merge h (s + 2^h) (treehashIter P merge h s stk) := by
  unfold treehashIter
  rw [Nat.two_pow_succ]
  simp [Nat.fold_add, Nat.add_assoc]

variable (P)

/-! ## Single-call entry points -/

def treehashLocalOn (h s : Nat) (stk : Stack Node) : Stack Node :=
  treehashIter P (localMerge P) h s stk

def treehashLocal (h s : Nat) : Stack Node := treehashLocalOn P h s []

def treehashGlobalOn (h s : Nat) (stk : Stack Node) : Stack Node :=
  treehashIter P (globalMerge P) h s stk

def treehashGlobal (h s : Nat) : Stack Node := treehashGlobalOn P h s []

@[simp, grind =] theorem treehashLocalOn_zero (s : Nat) (stk : Stack Node) :
    treehashLocalOn P 0 s stk = localMerge P s 0 (P.leaf s) stk := rfl

@[simp, grind =] theorem treehashLocalOn_succ (h s : Nat) (stk : Stack Node) :
    treehashLocalOn P (h + 1) s stk =
    treehashLocalOn P h (s + 2^h) (treehashLocalOn P h s stk) :=
  treehashIter_succ _ h s stk

@[simp, grind =] theorem treehashGlobalOn_zero (s : Nat) (stk : Stack Node) :
    treehashGlobalOn P 0 s stk = globalMerge P s 0 (P.leaf s) stk := rfl

@[simp, grind =] theorem treehashGlobalOn_succ (h s : Nat) (stk : Stack Node) :
    treehashGlobalOn P (h + 1) s stk =
    treehashGlobalOn P h (s + 2^h) (treehashGlobalOn P h s stk) :=
  treehashIter_succ _ h s stk

end

end Treehash
