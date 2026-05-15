import Mathlib.Tactic.Simps.Basic

/-!
# Basic data types

The shared data underpinning both the recursive treehash spec
(`Spec.lean`) and the iterative implementations (`Impl.lean`):

* `Address`           — RFC 8391 §2.5 hash-tree address (type 2).
* `mergeAddr`         — global-coordinate constructor for merge
                        addresses.
* `HashCall`          — one keyed-merge call: address + two child
                        values.
* `StackEntry`        — a (height, value) pair, matching what RFC
                        §4.1.6 line 1330 says is stored on the
                        treehash stack.
* `TreehashResult`    — final stack + reverse-ordered H-call trace.
* `Params`            — the four ambient parameters of a treehash
                        run (`leaf`, `H`, `ℓ`, `τ`) bundled into a
                        single record. They are fixed for the
                        whole run and never interact, so bundling
                        them avoids threading four section
                        variables through every signature.

All three of the spec, the global-address implementation, and the
local-address implementation produce results in this shape. The
information about where each subtree's leaf-span starts is
threaded through the inner merge loop as a parameter (`leafIdx`
in the global model; `treeIdx` in the local / RFC model) rather
than stored on the stack.
-/

namespace TreehashEquivalence

/-! ## Address (RFC 8391 §2.5)

`Address` is the abstract representation of an RFC 8391 hash-tree
(type-2) `ADRS` value used inside Algorithm 9. The four fields
modelled are:

* `layer`      — XMSS-MT layer (`0` for single-tree XMSS).
* `tree`       — XMSS-MT tree index within the layer.
* `treeHeight` — the children's height at a merge. RFC convention:
  `ADRS.getTreeHeight()` during a hash call equals the height of
  the *children* being combined, not the parent being produced.
  (Algorithm 9 initialises it to `0` and post-increments after
  each call.)
* `treeIdx`  — the parent node's index at the layer above the
  children. The RFC computes this *locally* by iterating
  `(idx - 1) / 2` from the leaf index; `mergeAddr` gives the same
  value directly from *global* coordinates, and `Impl.lean`
  bridges the two.

### What this model omits

* `type` — constant (=2) throughout Algorithm 9. Eliding is sound
  because the proof's scope is one type-2 address; the OTS / L-tree
  cases are out of scope.
* `keyAndMask` — mutated inside the underlying RFC `RAND_HASH`
  procedure across three PRF calls (RFC §4.1.4, Algorithm 7).
  Eliding collapses the (3 PRF + 1 raw hash) expansion into a
  single abstract call, matching the type signature of the
  combiner `H` used throughout this development.
* Padding (always zero).

### Granularity

`H : Address → Node → Node → Node` corresponds to **one keyed
merge step** — what the RFC calls one `RAND_HASH` invocation —
not one raw hash. Every entry of a trace is one merge.
Unfolding the keyed step into its underlying primitives is out
of scope.

### Field types

All four fields are `Nat`. The RFC representation is 32 bytes,
eight 32-bit big-endian words. Bridging this abstract `Address`
to the byte layout (including the "fits in u32" obligation per
field) is a separate, currently unaddressed concern.
-/

/-- Hash-tree address (RFC 8391 §2.5, type 2). See the section
docstring above for what is and is not modelled. -/
structure Address where
  layer      : Nat
  tree       : Nat
  treeHeight : Nat
  treeIdx    : Nat
  deriving DecidableEq, Repr

/-- The address used for a single hash-tree merge, expressed in
global coordinates.

Given the merge combines two height-`childHeight` siblings whose
**left** child starts at leaf-index `leftStart`, the resulting
parent has index `leftStart / 2^(childHeight + 1)` at the layer
above.

`childHeight` matches the RFC's `ADRS.getTreeHeight()` *during*
the merge call (Algorithm 9 sets it to `0` initially and
post-increments after each call).

The global-form `treeIdx` here is what the RFC computes locally
by iterating `(idx - 1) / 2` (line 1370) from the leaf index. The
equivalence of the two formulations is proven as
`treehashLocal_eq_treehashGlobal` in `Statements.lean`. -/
@[simps]
def mergeAddr (ℓ τ childHeight leftStart : Nat) : Address where
  layer      := ℓ
  tree       := τ
  treeHeight := childHeight
  treeIdx    := leftStart / 2 ^ (childHeight + 1)

/-! ## H-call trace -/

/-- A single keyed-merge call: the address used and the two child
values passed (left, right). One per merge step in the trace. -/
structure HashCall (Node : Type u) where
  addr  : Address
  left  : Node
  right : Node
  deriving Repr

/-! ## Stack and result -/

/-- Stack entry: just height and value, matching RFC 8391 §4.1.6
line 1330 ("the height of a node is stored alongside a node's
value on the stack"). -/
structure StackEntry (Node : Type u) where
  height : Nat
  value  : Node
  deriving Repr

/-- The treehash working stack: a list of `StackEntry`s, top-of-stack
at the head. Abbreviation for ergonomic signatures and for
namespacing invariants (e.g. `Stack.Encodes`). -/
abbrev Stack (Node : Type u) := List (StackEntry Node)

/-- A treehash result: final stack plus reverse-ordered H-call trace. -/
structure TreehashResult (Node : Type u) where
  stack : List (StackEntry Node)
  trace : List (HashCall Node)
  deriving Repr

/-! ## Run parameters

The four pieces of configuration for a single treehash run:

* `leaf` — the leaf function. Different trees use different leaf
  functions in real XMSS (`gen_leaf_wots` keyed by an OTS address
  that embeds `ℓ`, `τ`, the leaf index, and the seeds); that
  dependence is baked into the *choice* of function value and is
  invisible to the proof, which treats `leaf` opaquely.
* `H` — the keyed two-child hash (one call ≡ one RAND_HASH
  invocation in RFC terms). Universal across trees: the address
  argument carries the per-call keying material.
* `ℓ`, `τ` — XMSS-MT layer and tree-within-layer. Inherited
  unchanged by every emitted address.

These four are fixed for the duration of one treehash call and
never interact with each other inside the computation; bundling
them is purely an ergonomic move to avoid threading four section
variables through every signature. -/

/-- Bundle of the four parameters needed to run treehash:
the leaf function, the keyed combiner, and the XMSS-MT
layer/tree coordinates. -/
structure Params (Node : Type u) where
  leaf : Nat → Node
  H    : Address → Node → Node → Node
  ℓ    : Nat
  τ    : Nat

end TreehashEquivalence
