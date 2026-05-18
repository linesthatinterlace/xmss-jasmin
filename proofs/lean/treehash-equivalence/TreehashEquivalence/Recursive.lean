import TreehashEquivalence.Basic

/-!
# Recursive treehash

The recursive definition of what RFC 8391 Algorithm 9 (`treehash`)
is supposed to compute. The iterative variants
(`TreehashEquivalence.IterLocal`, `TreehashEquivalence.IterGlobal`)
are proven equivalent to this definition elsewhere.

A single recursion `recursiveCore` builds root and trace together
in one pass; `recursiveRoot`, `recursiveTrace`, and
`treehashRecursive` are projections / wrappers on top of it.

* `recursiveCore P h s` — `(root, trace)` for the height-`h`
  subtree over leaves `[s, 2^h + s)`.
* `recursiveRoot P h s` / `recursiveTrace P h s` — projections.
* `treehashRecursive P h s` — wraps `recursiveCore` into a
  `TreehashResult`, matching the iterative variants.

Traversal is left-to-right post-order (left subtree, right
subtree, root); the trace accumulates newest-first (root
prepended), matching the iterative variants. So at the top level
it reads as `root :: reverse(post-order traversal)`.

Parameters travel in a `Params Node` record — see `Basic.lean`.

This module deliberately does not import the iterative variants:
recursive and iterative share only the data types in `Basic`.
-/

namespace TreehashEquivalence

section
universe u
variable {Node : Type u} {l t : Nat}
variable (P : Params Node l t)

/-- Build the root value and H-call trace for the height-`h`
subtree over leaves `[s, 2^h + s)` in a single pass. Trace is
newest-first (this subtree's root prepended). -/
def recursiveCore : (h : Nat) → Nat → Node × List (HashCall Node l t)
  | 0,     s => (P.leaf s, [])
  | h + 1, s =>
      let l := recursiveCore h s
      let r := recursiveCore h (2 ^ h + s)
      let call := ⟨⟨h, s / 2^h / 2⟩, l.1, r.1⟩
      (P.H call, call :: r.2 ++ l.2)

/-- Merkle root at height `h` over leaves `[s, 2^h + s)`. -/
def recursiveRoot (h s : Nat) : Node :=
  (recursiveCore P h s).1

/-- Newest-first H-call trace from a left-to-right post-order
unfolding of the height-`h` tree starting at leaf `s`. -/
def recursiveTrace (h s : Nat) : List (HashCall Node l t) :=
  (recursiveCore P h s).2

/-! ## Recursive characterisations of the projections

These were the original definitions of `recursiveRoot` and
`recursiveTrace`. With `recursiveCore` in place they become small
unfoldings. -/

@[simp] theorem recursiveRoot_zero (s : Nat) :
    recursiveRoot P 0 s = P.leaf s := rfl

@[simp] theorem recursiveRoot_succ (h s : Nat) :
    recursiveRoot P (h + 1) s =
      P.H ⟨mergeAddr h s, recursiveRoot P h s, recursiveRoot P h (2 ^ h + s)⟩ := rfl

@[simp] theorem recursiveTrace_zero (s : Nat) :
    recursiveTrace P 0 s = [] := rfl

@[simp] theorem recursiveTrace_succ (h s : Nat) :
    recursiveTrace P (h + 1) s =
      ⟨mergeAddr h s, recursiveRoot P h s,
        recursiveRoot P h (2 ^ h + s)⟩ :: recursiveTrace P h (2 ^ h + s) ++
        recursiveTrace P h s := rfl

/-- Recursive result in `TreehashResult` shape: singleton root
stack plus trace. -/
def treehashRecursive (h s : Nat) : TreehashResult Node l t :=
  let p := recursiveCore P h s
  ⟨[⟨h, p.1⟩], p.2⟩

end

end TreehashEquivalence
