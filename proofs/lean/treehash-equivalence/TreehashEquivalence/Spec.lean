import TreehashEquivalence.Basic

/-!
# Recursive treehash specification

The recursive mathematical definition of what RFC 8391 Algorithm 9
(`treehash`) is supposed to compute. The iterative implementations
in `TreehashEquivalence.Impl` are proven equivalent to this spec
in `TreehashEquivalence.Statements`.

A single recursion `specCore` builds root and trace together in
one pass over the tree. The public-facing names `specRoot`,
`specTrace`, and `treehashSpec` are thin projections / wrappers
on top of it.

* `specCore P h s` — the (root, trace) pair for the height-`h`
  subtree over leaves `[s, s + 2^h)`. The single source of truth.
* `specRoot P h s` / `specTrace P h s` — first / second projections.
* `treehashSpec P h s` — wraps `specCore` into a `TreehashResult`,
  matching the shape produced by `treehashGlobal` / `treehashLocal`.

The traversal order baked into `specCore` is left-to-right
post-order (left subtree, then right subtree, then root), and the
trace is accumulated *newest-first* (root prepended), matching
the iterative implementations' convention. So at the top level
the trace reads as `root :: reverse(post-order traversal)`.

Everything here is parameterised by a `Params Node` record
bundling the leaf function, the keyed combiner `H`, and the
layer/tree coordinates `ℓ τ`. See `Basic.lean` for why those four
travel together.

This module deliberately does not import `Impl`: spec and
implementation share only the data types in `Basic`.
-/

namespace TreehashEquivalence

section
universe u
variable {Node : Type u}
variable (P : Params Node)

/-- Recursive core: build the root value and the H-call trace for
the height-`h` subtree over leaves `[s, s + 2^h)` in a single
pass. The trace is newest-first (root of this subtree prepended),
matching the iterative-impl convention. -/
def specCore : Nat → Nat → Node × List (HashCall Node)
  | 0,     s => (P.leaf s, [])
  | h + 1, s =>
      let l := specCore h s
      let r := specCore h (s + 2 ^ h)
      let addr := mergeAddr P.ℓ P.τ h s
      (P.H addr l.1 r.1, ⟨addr, l.1, r.1⟩ :: r.2 ++ l.2)

/-- Value of the Merkle root at height `h` over leaves
`[s, s + 2^h)`. First projection of `specCore`. -/
def specRoot (h s : Nat) : Node :=
  (specCore P h s).1

/-- Newest-first list of H-calls induced by a left-to-right
post-order unfolding of the height-`h` tree starting at leaf `s`.
Second projection of `specCore`. -/
def specTrace (h s : Nat) : List (HashCall Node) :=
  (specCore P h s).2

/-- The full spec result, in the same shape as `treehashGlobal` /
`treehashLocal`: a singleton stack containing the root entry,
plus the trace. -/
def treehashSpec (h s : Nat) : TreehashResult Node :=
  let p := specCore P h s
  ⟨[⟨h, p.1⟩], p.2⟩

/-! ## Recursive characterisations of the projections

These were the original definitions of `specRoot` and `specTrace`.
With the single-recursion `specCore` in place, they become
theorems: small unfoldings of the projection through one step of
`specCore`. -/

@[simp] theorem specRoot_zero (s : Nat) :
    specRoot P 0 s = P.leaf s := rfl

@[simp] theorem specRoot_succ (h s : Nat) :
    specRoot P (h + 1) s =
      P.H (mergeAddr P.ℓ P.τ h s)
        (specRoot P h s)
        (specRoot P h (s + 2 ^ h)) := by
  simp [specRoot, specCore]

@[simp] theorem specTrace_zero (s : Nat) :
    specTrace P 0 s = [] := rfl

@[simp] theorem specTrace_succ (h s : Nat) :
    specTrace P (h + 1) s =
      ⟨mergeAddr P.ℓ P.τ h s,
        specRoot P h s,
        specRoot P h (s + 2 ^ h)⟩ ::
        specTrace P h (s + 2 ^ h) ++
        specTrace P h s := by
  simp [specTrace, specRoot, specCore]

end

end TreehashEquivalence
