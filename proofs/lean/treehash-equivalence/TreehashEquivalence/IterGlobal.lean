import TreehashEquivalence.Basic

/-!
# Global-address iterative treehash

Stack-based model of RFC 8391 Algorithm 9 that keeps the triggering
leaf index in scope and computes each merge's address `treeIdx`
directly as `leafIdx / 2^(h + 1)`. Matches the xmss-reference C code
(`xmss_core.c`, `xmss_core_fast.c`).
-/

namespace TreehashEquivalence

section
universe u
variable {Node : Type u} {l t : Nat}
variable (P : Params Node l t)

def stackEntryMerge (leafIdx : Nat) :
    StackEntry Node → Stack Node → Stack Node
  | ⟨h, v⟩, ⟨h', v'⟩ :: rest =>
      if h' = h then
        let call := ⟨⟨h, leafIdx / 2^h / 2⟩, v', v⟩
        stackEntryMerge leafIdx ⟨h + 1, P.H call⟩ rest
      else ⟨h, v⟩ :: ⟨h', v'⟩ :: rest
  | ⟨h, v⟩, [] => [⟨h, v⟩]
termination_by _ stk => stk.length

/-- Inner merge loop, global-address variant. Each merge uses
`mergeAddr P.l P.t h leafIdx`: `leafIdx` is a leaf of the parent's
subtree, so it gives the parent's correct `treeIdx` directly. -/
def globalMergeLoop (leafIdx : Nat) :
    StackEntry Node → TreehashResult Node l t → TreehashResult Node l t
  | ⟨h, v⟩, ⟨⟨h', v'⟩ :: rest, trace⟩ =>
      if h' = h then
        let call := ⟨mergeAddr h leafIdx, v', v⟩
        globalMergeLoop leafIdx ⟨h + 1, P.H call⟩ ⟨rest, call :: trace⟩
      else ⟨⟨h, v⟩ :: ⟨h', v'⟩ :: rest, trace⟩
  | ⟨h, v⟩, ⟨[], trace⟩ => ⟨[⟨h, v⟩], trace⟩
termination_by _ stk => stk.stack.length

/-- Push `2^h` leaves starting at `s`. Each outer step pushes one
leaf and runs the merge loop from `h = 0`; the merge loop derives its
address from the triggering leaf's global index. -/
def treehashGlobal (h s : Nat) : TreehashResult Node l t :=
  (List.range (2 ^ h)).foldl
    (fun r i => let leafIdx := i + s
      globalMergeLoop P leafIdx ⟨0, P.leaf leafIdx⟩ r) ⟨[], []⟩

end

end TreehashEquivalence
