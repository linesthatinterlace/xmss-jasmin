import TreehashEquivalence.Basic

/-!
# Recursive treehash specification

The recursive mathematical definition of what RFC 8391 Algorithm 9
(`treehash`) is supposed to compute. The iterative implementations
in `TreehashEquivalence.Impl` are proven equivalent to this spec
in `TreehashEquivalence.Statements`.

Three definitions, layered:

* `specRoot h s` — the value of the Merkle root at height `h` over
  leaves `[s, s + 2^h)`. Recursive in `h`.
* `specTrace h s` — the ordered list of H-calls performed by a
  left-to-right post-order unfolding of the same tree.
* `treehashSpec h s` — packages the above into a `TreehashResult`
  matching the shape of `treehashCF`: a singleton stack containing
  the root entry, plus the trace.

The post-order on `specTrace` (left subtree, then right subtree,
then root) matches Algorithm 9's call order: left leaves are pushed
first, and the carry chain merges them up completely before any
right-subtree leaf is touched.

Everything here is parameterised by:
* `Node` — the type of hash outputs;
* `leaf` — the leaf function (abstract);
* `H`    — the keyed two-child hash (one call ≡ one RAND_HASH
  invocation in RFC terms);
* `ℓ τ` — the layer / tree-within-layer indices, inherited unchanged
  by every emitted address.

This module deliberately does not import `Impl`: spec and
implementation share only the data types in `Basic`.
-/

namespace TreehashEquivalence

section
universe u
variable {Node : Type u}
variable (leaf : Nat → Node)
variable (H : Address → Node → Node → Node)
variable (ℓ τ : Nat)

/-- Value of the Merkle root at height `h` over leaves `[s, s + 2^h)`. -/
def specRoot : Nat → Nat → Node
  | 0,     s => leaf s
  | h + 1, s =>
      H (mergeAddr ℓ τ h s)
        (specRoot h s)
        (specRoot h (s + 2 ^ h))

/-- Ordered list of H-calls induced by a left-to-right post-order
unfolding of the height-`h` tree starting at leaf `s`. -/
def specTrace : Nat → Nat → List (HashCall Node)
  | 0,     _ => []
  | h + 1, s =>
      specTrace h s ++
      specTrace h (s + 2 ^ h) ++
      [⟨mergeAddr ℓ τ h s,
        specRoot (Node := Node) leaf H ℓ τ h s,
        specRoot (Node := Node) leaf H ℓ τ h (s + 2 ^ h)⟩]

/-- The full spec result, in the same shape as `treehashCF`. The
stack is the singleton containing the root entry; the trace is
`specTrace`. -/
def treehashSpec (h s : Nat) : TreehashResult Node :=
  ⟨[⟨h, specRoot (Node := Node) leaf H ℓ τ h s⟩],
   specTrace (Node := Node) leaf H ℓ τ h s⟩

end

end TreehashEquivalence
