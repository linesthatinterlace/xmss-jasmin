import TreehashEquivalence.Basic

/-!
# Local-address iterative treehash (RFC 8391 Algorithm 9, literal)

Stack-based model of RFC 8391 §4.1.6 Algorithm 9 in its literal
form: a mutating `treeIdx` is threaded through the merge loop,
updated as `treeIdx ← (treeIdx - 1) / 2` before each merge; `h` is
post-incremented after. Purely local — each merge only sees the
previous merge's output index, never the triggering leaf.

`localMergeLoop` does a `Nat` subtraction; it stays well-defined
because the merge guard ensures `treeIdx ≥ 1` whenever a left sibling
exists, which the caller's alignment hypothesis (`s % 2^h = 0`)
supplies.
-/

namespace TreehashEquivalence

section
universe u
variable {Node : Type u} {l t : Nat}
variable (P : Params Node l t)

/-- Inner merge loop, local-address (RFC) variant. Maintains the
mutating `h` and `treeIdx` exactly as Algorithm 9 prescribes. -/
def localMergeLoop (treeIdx : Nat) :
    StackEntry Node → TreehashResult Node l t → TreehashResult Node l t
  | ⟨h, v⟩, ⟨⟨h', v'⟩ :: rest, trace⟩ =>
      if h' = h then
        let treeIdx' := (treeIdx - 1) / 2
        let call := ⟨⟨h, treeIdx'⟩, v', v⟩
        localMergeLoop treeIdx' ⟨h + 1, P.H call⟩ ⟨rest, call :: trace⟩
      else ⟨⟨h, v⟩ :: ⟨h', v'⟩ :: rest, trace⟩
  | ⟨h, v⟩, ⟨[], trace⟩ => ⟨[⟨h, v⟩], trace⟩
termination_by _ stk => stk.stack.length

/-- Push `2^h` leaves starting at `s`. Each outer step pushes one leaf and seeds
the merge loop with `treeHeight = 0`, `treeIdx = leafIdx`; the loop
then runs locally, never re-reading the leaf index. -/
def treehashLocal (h s : Nat) : TreehashResult Node l t :=
  (List.range (2 ^ h)).foldl
    (fun r i => let treeIdx := i + s
      localMergeLoop P treeIdx ⟨0, P.leaf treeIdx⟩ r) ⟨[], []⟩

end

end TreehashEquivalence
