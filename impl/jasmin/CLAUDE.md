# CLAUDE.md — xmss-jasmin Jasmin implementation

Context for Claude Code when working on the Jasmin implementation of XMSS/XMSS-MT. All paths below are relative to `impl/jasmin/`.

Status: **early / in progress**.

## What Jasmin is

[Jasmin](https://github.com/jasmin-lang/jasmin) is a programming language and compiler for writing formally verified cryptographic assembly. `.jazz` source files compile to native assembly (`.s`) via `jasminc`. The formal semantics of the language enable machine-checked proofs of functional correctness and security (constant-time, etc.) in EasyCrypt.

Key properties of the language that align with our J1–J8 rules:
- No heap allocation, no VLAs, no recursion, no function pointers
- All loop bounds must be statically determined or loop-invariant parameters
- Security annotations (`#secret`, `#public`, `#msf`) for information-flow tracking
- Constant-time enforcement is a first-class concern, not an afterthought

## Target architecture

**Current target: x86-64.** The Jasmin RISC-V backend exists but is immature. We develop and verify on x86-64 first, then port once the RISC-V backend matures.

The x86-64 implementation will be tested natively. RISC-V will eventually be tested under QEMU (consistent with the C implementation).

## Toolchain

Install Jasmin via opam (recommended):

```bash
opam install jasmin
```

Or via Nix if the project adopts a Nix shell (TBD). The compiler binary is `jasminc`.

Check version:
```bash
jasminc --version
```

Formal verification (optional, later):
- **EasyCrypt** — for functional correctness and CT proofs. Installed via opam, but pinned to a dev version (the released opam package lags behind). Check the current pin before updating:
  ```bash
  opam pin list | grep easycrypt
  opam show easycrypt
  ```
  Do not run `opam upgrade easycrypt` without checking — the pin may be intentional.

## Architecture design decisions

### Algorithm / hash boundary

The implementation is split into two layers:

- **Algorithm layer** (`wots.jinc`, `bds.jinc`, `xmss.jinc`, etc.) — written using only basic Jasmin operations (`+`, `-`, `^`, `&`, `|`, `>>`, `<<`, array access). No architecture-specific intrinsics. This layer is portable across x86-64 and RISC-V without modification.

- **Hash layer** (`src/hash/sha256.jinc`, `sha512.jinc`, `shake128.jinc`, `shake256.jinc`) — architecture-specific. These are the only files that change between targets.

**Pluggability**: Jasmin has no function pointers (J2 rule). Hash backends are selected by which `.jinc` the top-level `.jazz` file `require`s — i.e., by separate compilation, mirroring the C implementation's `hash_iface.h` / `xmss_hash.c` split.

**libjade as a hash source**: The libjade `amd64/ref/` hash implementations are worth checking for portability. If they implement rotation as `(x >> n) | (x << (32-n))` rather than using `#ROR` intrinsics, they may compile for RISC-V unchanged. If they use `#ROR`, we write portable-from-scratch alternatives (the rotation trick is trivial). Check before writing anything new.

**RISC-V path**: only the hash `.jinc` files need a RISC-V variant. The entire algorithm layer ports for free.

### RISC-V instruction analysis (separate workstream)

Before (or alongside) writing Jasmin code, we want to analyse what instructions the C compiler actually emits when targeting RISC-V, by disassembling the RISC-V binaries we already build in `impl/c/`. This tells us:

- Which base ISA instructions XMSS actually uses
- Which extensions (B for bitmanip/rotate, V for vector, etc.) could help or are required
- What patterns Jasmin's RISC-V backend will need to handle — and where it may currently fall short or need extension

This analysis is a prerequisite to any work on extending or contributing to Jasmin's RISC-V backend. It lives in `impl/c/` (compile + disassemble) but informs the Jasmin roadmap here.

## Build commands

> **Note**: Build system is not yet established. This section will be updated as it develops.

Intended workflow:

```bash
# Compile a single Jasmin source file to x86-64 assembly
jasminc -arch x86-64 src/foo.jazz -o src/foo.s

# Compile everything (once Makefile exists)
make

# Run tests (C harnesses linking against generated assembly)
make test
```

## Directory structure (planned)

```
impl/jasmin/
  CLAUDE.md
  Makefile              (to be created)
  src/
    hash/
      sha256.jazz       SHA-256 compression function
      sha512.jazz       SHA-512 compression function
      shake128.jazz     SHAKE-128 (Keccak-based)
      shake256.jazz     SHAKE-256 (Keccak-based)
    address.jazz        ADRS type and setters
    utils.jazz          ull_to_bytes, bytes_to_ull, ct_memcmp, memzero
    wots.jazz           WOTS+ sign, pkFromSig
    ltree.jazz          L-tree hash
    treehash.jazz       treehash and stack
    bds.jazz            BDS state, bds_update, bds_treehash_update
    xmss.jazz           XMSS keygen, sign, verify
    xmssmt.jazz         XMSS-MT keygen, sign, verify
  test/
    (C harnesses that link against generated .s files and call exported Jasmin functions)
  proof/
    (EasyCrypt proof files — later)
```

Hash implementations should be written from scratch in Jasmin (not auto-generated wrappers), consistent with the rest of the project.

## Jasmin language notes

### Types

```
u8, u16, u32, u64          -- unsigned integers
bool                       -- booleans (flags)
u8[N]                      -- fixed-size byte arrays (stack-allocated)
```

### Functions

```
fn foo(reg u64 x, stack u8[32] buf) -> reg u64 { ... }
```

- `reg` — lives in a register
- `stack` — lives on the stack (fixed-size array)
- `inline` — inlined at call site (like a macro; used for small helpers)
- `export` — exported with C calling convention (callable from C)

### Security annotations

```
#[secret]   // value is secret; must not be used in branches or memory addresses
#[public]   // value is public
#[msf]      // mask speculative flow (Spectre mitigation)
```

### Control flow

Only `for`, `while`, `if` — no recursion. Loop bounds must be public (not secret-dependent).

### Calling from C

`export fn` generates a C-callable symbol. The ABI follows the platform's standard (System V AMD64 for x86-64). Test harnesses in `test/` are C files that `#include` the function declarations and link against the `.s` files.

## Relationship to C implementation

The Jasmin implementation targets functional equivalence with `impl/c/`. All algorithm logic, parameter sets, SK/PK layout (Errata 7900), and domain separation constants must match exactly.

The C implementation is the **reference**: when in doubt about algorithm details, read `impl/c/src/` and `doc/rfc8391.txt`. Do not copy C code into Jasmin — reimplement from RFC + C understanding.

KAT cross-validation against `third_party/xmss-reference/` applies equally to the Jasmin implementation.

## Jasmin portability and style rules

These parallel the C implementation's J1–J8 rules:

| Rule | Requirement |
|------|-------------|
| J1 | No heap. All arrays are stack-allocated, sized by `XMSS_MAX_*` constants declared as Jasmin `param int`. |
| J2 | No function pointers. Hash dispatch is done by separate compilation (SHA-2 and SHAKE variants compiled and linked separately). |
| J3 | No recursion. All tree algorithms are iterative. |
| J4 | All loop bounds are `param int` constants or public function arguments. No secret-dependent loop counts. |
| J5 | Secret-dependent branches and memory accesses are forbidden. Use `#[secret]` annotations. CT comparison via a dedicated `ct_memcmp` function. |
| J6 | `xmss_adrs_t` is an `u32[8]` on the stack; always manipulate via setter `inline fn`s; serialise to `u8[32]` before passing to hash functions. |
| J7 | One algorithm per `.jazz` file. |
| J8 | `export fn` functions are the sole ABI boundary. Internal helpers are `fn` or `inline fn`. |

## Resources

- **Jasmin language reference for this project**: `SKILL.md` (in this directory) — read this first when writing Jasmin code.
- Full language docs: https://jasmin-lang.readthedocs.io
- libjade (canonical Jasmin crypto implementations): https://github.com/formosa-crypto/libjade
  - Use the **`release/2023.05` branch** — `main` is mid-restructure and has no `.jazz` source files.
  - SHA-256: `src/crypto_hash/sha256/amd64/ref/`
  - SHAKE-256: `src/crypto_xof/shake256/amd64/ref/`
  - Keccak-f[1600]: `src/common/keccak/keccak1600/amd64/ref/`
- formosa-crypto organisation: https://github.com/formosa-crypto
- **formosa-xmss**: https://github.com/formosa-crypto/formosa-xmss — a human-authored Jasmin implementation of XMSS, subject to active research. Scope and parameter coverage TBD. **Do not treat as a template or copy from it** — our implementation is independent — but it is prior art worth being aware of and potentially cross-validating against.

## WWW/EBI (accumulated session learnings)

### What Went Well
- **Non-inline `fn` for hot loop bodies**: Using `fn` (not `inline fn`) for `gen_chain` and `expand_seed_one` prevents compiler stack overflow from inlining hash code 67× in unrolled loops. Do this for any function called inside a `for i = 0 to LEN` or equivalent while loop.
- **Inline wrappers for the stack↔reg-u64 bridge**: The `__xmss_F_rp` / `__xmss_PRF_keygen_rp` pattern (inline fn accepting `reg ptr`/`stack`, copying into `ibuf`, calling the inner hash primitive) cleanly separates the algorithm layer from the hash layer's pointer conventions. Note: this only works for hash functions with ≤2 PRF calls (F). For H (3 PRF calls), use the non-inline `fn __xmss_H` with a caller-provided scratch buffer instead.
- **Caller-provided scratch buffers for the stack→reg-u64 gap**: When algorithm code needs to pass stack-local data (e.g. serialized ADRS) to a `fn` expecting `reg u64`, have the caller provide a scratch pointer. This avoids the stack-address-to-reg-u64 limitation without inline wrappers. In ltree, the test harness's own `adrs_ptr` doubles as scratch — zero extra allocation.
- **Sign→pk_from_sig roundtrip as first test**: This single test exercises gen_pk, sign, and pk_from_sig together, catching most algorithmic bugs immediately.
- **Cataloguing compiler pitfalls in SKILL.md**: Each hard-won lesson (single-region rule, constant-minus-reg, variable shifts, etc.) documented with concrete examples prevents repeating mistakes.

- **Wrapper `fn`s to isolate register allocation domains**: When multiple functions (ltree, compute_root, treehash) call the same `fn` (e.g. `__xmss_H`), Jasmin propagates parameter register constraints inter-procedurally, creating irreconcilable conflicts. Thin forwarder wrappers (`fn __xmss_H_cr(...)  { __xmss_H(...); }`) give each caller its own callee with independent register allocation. One wrapper per calling context.
- **Spill/reload to eliminate parameter-swapping conflicts**: When an `if/else` passes the same variables to a `fn` in different parameter positions (e.g. `H(a, b)` vs `H(b, a)`), the allocator can't put one variable in two registers. Fix: spill both to stack in the if/else, reload into fresh registers after, then make one call.
- **Constant-shift loops for variable shifts**: `x >>= runtime_count` requires CL on x86-64 and the allocator often can't guarantee it. Replace with `while (count > 0) { x >>= 1; count--; }`. Bounded by TREE_HEIGHT so performance is fine.
- **Zero-extension before ADD**: `idx64 += (64u)t` isn't a valid x86 instruction (ADD can't zero-extend an operand). Store the extension in a temp register first: `tmp = (64u)t; idx64 += tmp;`.

### Even Better If
- **Study libjade patterns BEFORE writing code**: The `reg ptr` single-region rule would have been obvious from reading libjade's `_blocks_0_ref` SHA-256 function upfront. Always read canonical examples in libjade before designing a new function's signature.
- **Reason about compiler behaviour before trial-and-error**: When hitting an error, stop and think about *why* it occurs (what does the compiler need to prove? what invariant is violated?). Don't try random fixes hoping one sticks.
- **Count registers before writing inline wrappers**: F (2 PRF calls) fits in 16 registers when inlined; H (3 PRF calls) does not. Before creating a new `inline fn` that calls hash primitives, estimate whether the combined register pressure fits x86-64's 16 GPRs. If not, use a non-inline `fn` with the scratch-buffer pattern instead.
- **Anticipate code size**: 67 iterations × inlined SHA-256 = obvious blowup. Think about inlining depth before choosing `inline fn` vs `fn`.
- **Test each function in isolation**: Compile and test `gen_chain` alone before building `gen_pk` on top of it. Small compilation units catch errors faster and with clearer messages.
- **Use `reg u64` for loop counters from the start**: `reg u32` counters cause SIB addressing issues and require `(64u)` casts everywhere. Default to `reg u64` for any counter used in pointer arithmetic or array indexing.
- **Truncate jasminc error output**: Jasmin produces very verbose compilation errors (hundreds of lines). Use `| head -15` to see only the root cause. The first error is usually the important one; the rest is dependency chain noise.

## Open questions / future work

- Decide on build system (simple Makefile vs CMake integration with the rest of the project).
- Decide whether to share the CMake `XMSS_TEST_TIMEOUT_SCALE` mechanism or keep Jasmin tests independent.
- EasyCrypt proof strategy: which properties to prove first (CT? functional correctness of WOTS+?).
- RISC-V backend: track Jasmin upstream; port once backend is stable. **Prerequisite**: complete the RISC-V instruction analysis (see Architecture section above) to understand what backend support is actually needed.
- Possible libjade integration or contribution.
