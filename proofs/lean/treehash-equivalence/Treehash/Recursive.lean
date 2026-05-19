import Treehash.Basic

/-!
# Recursive treehash

The recursive definition of what RFC 8391 Algorithm 9 (`treehash`)
is supposed to compute. The iterative variants
(`Treehash.IterLocal`, `Treehash.IterGlobal`)
are proven equivalent to this definition elsewhere.

* `treehashRecursive P h s` — `root` for the height-`h`
  subtree over leaves `[s, s + 2 ^ h)`.
* `treehashRecursive P h s` — wraps `treehashRecursive` into a
  `TreehashState`, matching the iterative variants.

Traversal is left-to-right post-order (left subtree, right subtree, root).

Parameters travel in a `Params Node` record — see `Basic.lean`.
-/

namespace Treehash

section
universe u
variable {Node : Type u} {l t : Nat}
variable (P : Params Node l t)

def treehashRecursive (h : Nat) (s : Nat) : Node := match h with
  | 0 => P.leaf s | h + 1 =>
    P.H (mkCall h (s / 2^(h + 1)) (treehashRecursive h s) (treehashRecursive h (s + 2 ^ h)))

variable {P}

@[simp, grind =] theorem treehashRecursive_zero (s : Nat) :
    treehashRecursive P 0 s = P.leaf s := rfl

@[simp, grind =] theorem treehashRecursive_succ (h s : Nat) :
    treehashRecursive P (h + 1) s = P.H (mkCall h (s / 2^(h + 1))
    (treehashRecursive P h s) (treehashRecursive P h (s + 2 ^ h))) := rfl

end

end Treehash
