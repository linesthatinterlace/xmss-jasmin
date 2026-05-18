# CLAUDE.md — treehash-equivalence (Lean)

Active formalisation of the treehash equivalence in Lean 4 + mathlib.

## Working with this code

**Treat the current files as the source of truth.** The structure here
is being actively refactored. Definitions, file layouts, and lemma names
get renamed, moved, or deleted between sessions.

When the user asks for advice or a change:

- Read the actual files in `Treehash/` with `Read`.
- Run `lake build` to see what is actually wired up — the working tree
  may compile, or may be mid-refactor with dangling references (e.g.
  a deleted helper still mentioned in a docstring or a simp lemma).
  Mid-refactor breakage is normal; don't "fix" it by reintroducing
  removed definitions unless the user asks.
- **Do not** reconstruct deleted definitions from `git show <prev>:path`
  and then reason as if they still exist. A definition not present in
  the current files is gone on purpose. If you need historical context
  for *why* something changed, read the commit message, not the deleted
  code.

If a referenced symbol is missing and the user hasn't asked you to
restore it, flag it and ask — they may have deleted it deliberately and
plan to put it back, or replace it, in a later step.
