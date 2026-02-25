# BDS Jasmin Implementation — WIP Notes

**Status**: does not compile yet (register allocation error)

## What's done
- `src/bds.jinc`: all 6 functions (gen_leaf, bds_treehash_init, treehash_update_one, bds_treehash_update, bds_round) + flat-buffer layout + field accessors
- `test/test_bds.jazz`: export wrappers for C harness
- `test/test_bds.c`: 6 self-consistency tests

## Current blocker: register allocation conflict

Error: `conflicting variables "out_p" and "in_l_p" must be merged` across __xmss_H call sites in bds.jinc, ltree.jinc, treehash.jinc.

### What was tried
Changed all 3 bds.jinc __xmss_H calls to use fresh `h_out, h_left, h_right, h_seed, h_adrs` variables loaded from stack spills (distinct from each other). This ensures arg1 and arg4 are always distinct variables. **Not yet tested** — compilation was interrupted before retry.

### Next steps
1. Try compiling — the h_out/h_left/h_right fix may resolve the conflict
2. If not, the issue is computation chains feeding h_out (e.g. `__bds_auth_ptr_rt` does `p += state`). Fix: spill the computed pointer to a stack slot, reload into fresh reg before passing to H
3. Expect several more compile-fix rounds after that
4. Once it compiles to .s: `gcc -o test/test_bds test/test_bds.c test/test_bds.s -no-pie` then `./test/test_bds`
5. bds_treehash_init iterates 1024 leaves — will take seconds, not instant

## Key design decisions
- BDS state = flat byte buffer. All access via pointer arithmetic inline fn accessors.
- gen_leaf writes to `root` ptr as temp leaf buffer in bds_treehash_init, then copies to local `nodes` stack array
- Merge operations copy stack array data to wots_buf[0..2N-1], call __xmss_H, copy back (avoids stack→reg u64 limitation)
- wots_buf + LEN*N used as temp leaf output in treehash_update_one (caller provides LEN*N + N bytes)
- All variable shifts use constant-shift loops

## Potential correctness bugs to check once it compiles
- gen_leaf: verify set_type(1) + set_ltree sequence after wots_gen_pk
- bds_treehash_init capture conditions: `idx32 >> nodeh == 1` for auth, `== 3` for treehash. In C, `i` == `idx` so this maps correctly
- bds_round tau break: uses `i32 = TREE_HEIGHT` to exit loop — verify
- Retain offset: `(1 << (H-1-nodeh)) + nodeh - H` — verify no underflow for H=10, K=2

## Delete this file
Once bds.jinc compiles and tests pass, delete this file.
