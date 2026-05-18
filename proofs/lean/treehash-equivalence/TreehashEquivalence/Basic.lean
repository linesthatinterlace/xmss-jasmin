import Mathlib.Tactic.Simps.Basic

/-!
# Basic data types

Shared definitions used by the recursive spec (`Spec.lean`) and
the iterative implementations (`Impl.lean`):

* `Address`        — RFC 8391 §2.5 hash-tree address (type 2).
* `mergeAddr`      — builds the address for a merge from global
                     coordinates.
* `HashCall`       — one merge call: address + two children.
* `StackEntry`     — `(height, value)` pair held on the treehash
                     stack (RFC §4.1.6, line 1330).
* `TreehashResult` — final stack + reverse-ordered call trace.
* `Params`         — the four run-wide parameters (`leaf`, `H`,
                     `l`, `t`), bundled to avoid threading them
                     through every signature.

All three models produce results in this shape. The starting
leaf of each subtree is threaded as a parameter to the merge
loop (`leafIdx` in the global model, `treeIdx` in the local /
RFC model) rather than stored on the stack.
-/

namespace TreehashEquivalence

/-! ## Address (RFC 8391 §2.5)

Abstract model of the type-2 `ADRS` value used in Algorithm 9.
Fields:

* `layer`      — XMSS-MT layer (`0` for single-tree XMSS).
* `tree`       — XMSS-MT tree index within the layer.
* `treeHeight` — at a merge that produces a height-`(h+1)`
  parent, this field is set to `h`, the *children's* height.
  The convention comes from RFC Algorithm 9 (the field starts at
  `0` and is only incremented after each call returns) and is
  followed throughout this development — spec and implementations
  alike — via the `mergeAddr` constructor.
* `treeIdx`    — index of the parent node. The RFC computes this
  locally by iterating `(idx - 1) / 2` from the leaf; `mergeAddr`
  computes it directly from global coordinates, and `Impl.lean`
  proves the two agree.

### Omitted from the model

* `type` — always `2` in Algorithm 9; OTS / L-tree are out of
  scope.
* `keyAndMask` — mutated inside `RAND_HASH` across three PRF
  calls (RFC §4.1.4). Collapsed into a single abstract `H`,
  matching the combiner used throughout this development.
* Padding — always zero.

### Granularity

`H : Address → Node → Node → Node` is one keyed merge step (one
`RAND_HASH` invocation), not one raw hash. Each trace entry is
one merge.

### Field types

All `Nat`. The RFC wire format is 32 bytes (eight 32-bit
big-endian words). Bridging this model to the byte layout (and
the "fits in u32" obligation) is out of scope.
-/

/-- Hash-tree address (RFC 8391 §2.5, type 2). See the section
docstring above for what is modelled. -/
structure Address (l : Nat) (t : Nat) where
  treeHeight : Nat
  treeIdx    : Nat
  deriving DecidableEq, Repr

instance : ToString (Address l t) := ⟨fun a => toString (a.treeHeight, a.treeIdx)⟩

/-! ## H-call trace -/

/-- One merge call: the address used and the two children
(left, right). -/
structure HashCall (Node : Type u) (l : Nat) (t : Nat) where
  addr  : Address l t
  left  : Node
  right : Node
  deriving Repr

instance [ToString Node] : ToString (HashCall Node l t) :=
  ⟨fun h => toString (h.addr, h.left, h.right)⟩

/-! ## Stack and result -/

/-- A node value paired with its height. -/
structure StackEntry (Node : Type u) where
  height : Nat
  value  : Node
  deriving Repr

/-- Treehash working stack; top-of-stack at the head. An
abbreviation, mainly so invariants can live in a `Stack`
namespace. -/
abbrev Stack (Node : Type u) := List (StackEntry Node)

/-- Treehash output: the final stack and the trace of merge calls
(reverse order, newest first). -/
structure TreehashResult (Node : Type u) (l : Nat) (t : Nat) where
  stack : Stack Node
  trace : List (HashCall Node l t)
  deriving Repr

/-! ## Run parameters

Four pieces of configuration for one treehash run:

* `leaf` — the leaf function. In real XMSS this is
  `gen_leaf_wots` keyed by an OTS address embedding `l`, `t`,
  the leaf index, and the seeds; the proof treats `leaf` as
  opaque, so that dependence is hidden in the chosen function
  value.
* `H` — the keyed merge (one call ≡ one RAND_HASH). Universal
  across trees: the address argument carries the per-call key.
* `l`, `t` — XMSS-MT layer and tree. Inherited unchanged by
  every emitted address.

These never interact during the computation. Bundling is purely
ergonomic — it avoids threading four section variables through
every signature. -/

/-- The four parameters of a treehash run. -/
structure Params (Node : Type u) (l : Nat) (t : Nat) where
  leaf : Nat → Node
  H    : HashCall Node l t → Node

end TreehashEquivalence
