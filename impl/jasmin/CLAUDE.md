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

See `SKILL.md` for the full Jasmin language reference, type system, pitfalls, and design patterns.

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

## WWW/EBI

Principles, not recipes. Code-level patterns live in `SKILL.md`.

### What Went Well
- **Caller-provided scratch buffers as the standard pattern for the stack→reg-u64 gap.** This is an architectural decision that applies everywhere the algorithm layer needs to pass stack-local data to a `fn` expecting `reg u64`. The caller provides a pointer; the callee writes through it. No wrappers needed.
- **Test each function in isolation before combining.** Compile minimal `.jazz` files with one function at a time. Small compilation units catch errors faster and with clearer messages.
- **Roundtrip tests as first validation.** A sign→pk_from_sig roundtrip exercises multiple components at once, catching most algorithmic bugs immediately.

### Even Better If
- **Think in x86 instructions before writing Jasmin.** Jasmin compiles to assembly — every construct maps to real instructions. Before writing a line, ask: "What instruction does this become? Does that instruction exist?" This prevents most linearization/asmgen errors.
- **State the root cause in one sentence before attempting a fix.** If you can't articulate *why* the compiler is rejecting the code, you don't understand the problem yet. Don't try fixes until you can.
- **Isolate before debugging.** Compile minimal `.jazz` files with one function at a time. Bisect which combination causes the conflict. This is fast and eliminates speculation.
- **Truncate error output ruthlessly.** `| head -15`. The first error is the real one. The rest is dependency chain noise that causes context overload.
- **Don't add complexity you haven't proven necessary.** Test the simpler hypothesis first. The wrapper functions were added because the error messages *mentioned* cross-function variables, but the actual root cause was the if/else parameter swap within a single function. One minimal test would have ruled out the cross-function theory.
- **Jasmin is not a fast-iteration language.** The compile-read-error-fix cycle that works for Python/JS/Rust burns tokens here. Think more, compile less.

## Open questions / future work

- Decide on build system (simple Makefile vs CMake integration with the rest of the project).
- Decide whether to share the CMake `XMSS_TEST_TIMEOUT_SCALE` mechanism or keep Jasmin tests independent.
- EasyCrypt proof strategy: which properties to prove first (CT? functional correctness of WOTS+?).
- RISC-V backend: track Jasmin upstream; port once backend is stable. **Prerequisite**: complete the RISC-V instruction analysis (see Architecture section above) to understand what backend support is actually needed.
- Possible libjade integration or contribution.
