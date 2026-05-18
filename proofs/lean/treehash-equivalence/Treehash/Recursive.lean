import Treehash.Basic

/-!
# Recursive treehash

The recursive definition of what RFC 8391 Algorithm 9 (`treehash`)
is supposed to compute. The iterative variants
(`Treehash.IterLocal`, `Treehash.IterGlobal`)
are proven equivalent to this definition elsewhere.

A single recursion `recursiveCore` builds the subtree's stack
entry and trace together in one pass; `treehashRecursive` wraps
that into a `TreehashState`.

* `recursiveCore P h s` — `(stackEntry, trace)` for the height-`h`
  subtree over leaves `[s, 2^h + s)`. The first component is
  `⟨h, root⟩`, ready to push directly onto a stack.
* `treehashRecursive P h s` — wraps `recursiveCore` into a
  `TreehashState`, matching the iterative variants.

Traversal is left-to-right post-order (left subtree, right
subtree, root); the trace accumulates newest-first (root
prepended), matching the iterative variants. So at the top level
it reads as `root :: reverse(post-order traversal)`.

Parameters travel in a `Params Node` record — see `Basic.lean`.

This module deliberately does not import the iterative variants:
recursive and iterative share only the data types in `Basic`.
-/

namespace Treehash

section
universe u
variable {Node : Type u} {l t : Nat}
variable (P : Params Node l t)

/-- Build the height-`h` subtree's stack entry and H-call trace
over leaves `[s, 2^h + s)` in a single pass. Trace is
newest-first (this subtree's root prepended). The first
component is `(h, root)`, ready to push directly onto a stack. -/
def recursiveCore (h : Nat) (s : Nat) : Nat × Node × List (HashCall Node l t) := match h with
  | 0 => (0, P.leaf s, []) | h + 1 =>
    let (_, leftRoot,  leftTrace)  := recursiveCore h s
    let (_, rightRoot, rightTrace) := recursiveCore h (2 ^ h + s)
    let call := ⟨⟨h, s / 2^h / 2⟩, leftRoot, rightRoot⟩
    (h + 1, P.H call, call :: rightTrace ++ leftTrace)

/-- Recursive result in `TreehashState` shape: singleton stack
entry plus trace. -/
def treehashRecursive (h s : Nat) : TreehashState Node l t :=
  let p := recursiveCore P h s
  ⟨[p.1], p.2⟩

end

end Treehash
