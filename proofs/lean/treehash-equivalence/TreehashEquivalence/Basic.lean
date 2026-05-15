import Mathlib.Tactic.Simps.Basic

/-!
# Basic data types

The shared data underpinning both the recursive treehash spec
(`Spec.lean`) and the iterative implementations (`Impl.lean`):

* `Address`           — RFC 8391 §2.5 hash-tree address (type 2).
* `mergeAddr`         — closed-form constructor for merge addresses.
* `HashCall`          — one RAND_HASH invocation: address + two
                        child values.
* `StackEntry`        — a (height, value) pair, matching what RFC
                        §4.1.6 line 1330 says is stored on the
                        treehash stack.
* `TreehashResult`    — final stack + ordered H-call trace.

All three of the spec, the closed-form implementation, and the
RFC-faithful implementation produce results in this shape. The
information about where each subtree's leaf-span starts is
threaded through the inner merge loop as a parameter (`curStart`
in the closed form; `treeIndex` in the RFC) rather than stored
on the stack.
-/

namespace TreehashEquivalence

/-! ## Address (RFC 8391 §2.5)

`Address` is the abstract representation of an RFC 8391 hash-tree
(type-2) `ADRS` value used inside Algorithm 9. The four fields
modelled are:

* `layer`      — XMSS-MT layer (`0` for single-tree XMSS).
* `tree`       — XMSS-MT tree index within the layer.
* `treeHeight` — the children's height at a merge. RFC convention:
  `ADRS.getTreeHeight()` during a RAND_HASH call equals the height
  of the *children* being combined, not the parent being produced.
  (Algorithm 9 initialises it to `0` and post-increments after each
  RAND_HASH.)
* `treeIndex`  — the parent node's index at the layer above the
  children. The RFC computes this statefully via `(idx - 1) / 2`;
  we model it in closed form via `mergeAddr` and bridge to the
  stateful form in `Impl.lean`.

### What this model omits

* `type` — constant (=2) throughout Algorithm 9. Eliding is sound
  because the proof's scope is one type-2 address; the OTS / L-tree
  cases are out of scope.
* `keyAndMask` — mutated *inside* RAND_HASH across three PRF calls
  (RFC §4.1.4, Algorithm 7). Eliding collapses the (3 PRF + 1 H)
  expansion of one RAND_HASH into a single abstract call, matching
  the type signature of the abstract `H` used throughout this
  development.
* Padding (always zero).

### Granularity

`H : Address → Node → Node → Node` corresponds to **one RAND_HASH
invocation**, not one raw hash. Every entry of a trace is one
merge. Unfolding RAND_HASH into its underlying primitives is out
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
  treeIndex  : Nat
  deriving DecidableEq, Repr

/-- The address used for a single hash-tree merge, in closed form.

Given the merge combines two height-`childHeight` siblings whose
**left** child starts at leaf-index `leftStart`, the resulting
parent has index `leftStart / 2^(childHeight + 1)` at the layer
above.

`childHeight` matches the RFC's `ADRS.getTreeHeight()` *during*
the RAND_HASH call (Algorithm 9 sets it to `0` initially and
post-increments after each call).

The closed-form `treeIndex` here is what the RFC computes
statefully via iterated `(idx - 1) / 2` (line 1370). The
equivalence of the two formulations is proven as
`treehash_trace_eq_treehashCF_trace` in `Statements.lean`. -/
@[simps]
def mergeAddr (ℓ τ childHeight leftStart : Nat) : Address where
  layer      := ℓ
  tree       := τ
  treeHeight := childHeight
  treeIndex  := leftStart / 2 ^ (childHeight + 1)

/-! ## H-call trace -/

/-- A single H call: the address used and the two child values
passed (left, right). One per RAND_HASH invocation. -/
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

/-- A treehash result: final stack plus ordered H-call trace. -/
structure TreehashResult (Node : Type u) where
  stack : List (StackEntry Node)
  trace : List (HashCall Node)
  deriving Repr

end TreehashEquivalence
