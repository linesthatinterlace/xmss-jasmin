# CLAUDE.md — xmss-jasmin Jasmin implementation

Context for Claude Code when working on the Jasmin implementation of XMSS/XMSS-MT. All paths below are relative to `impl/jasmin/`.

Status: **XMSS single-tree and XMSS-MT complete** (keygen, sign, verify — all tested). XMSSMT-SHA2_20/2_256 tested with boundary crossing (1024+ signatures). **Production API exports** for 4 parameter sets with libjade naming convention.

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

```bash
cd impl/jasmin
make              # compile all tests + API binaries
make test         # build + run 9 unit tests + 2 fast API tests
make test-api     # fast API tests only (h=10 XMSS + XMSS-MT 20/2)
make test-api-slow  # slow API tests (h=16: ~20s keygen, h=20: ~4min keygen)
make ct           # CT checks on all 13 .jazz files (9 unit + 4 API)
make clean        # remove .s and binaries
make test/test_X  # build a single test (e.g. test/test_xmss)
```

The Makefile uses conservative dependency tracking: all `.jinc` files are deps of every `.jazz` → `.s` rule (jasminc has no `-MMD`).

## Directory structure

```
impl/jasmin/
  CLAUDE.md
  blueprint.md          Implementation blueprint (design decisions, full implementation order)
  SKILL.md              Jasmin language reference, pitfalls, patterns
  Makefile
  api/                  Production .jazz files with libjade naming
    xmss_sha2_10_256.jazz     XMSS-SHA2_10_256 (h=10, OID=1)
    xmss_sha2_16_256.jazz     XMSS-SHA2_16_256 (h=16, OID=2)
    xmss_sha2_20_256.jazz     XMSS-SHA2_20_256 (h=20, OID=3)
    xmssmt_sha2_20_2_256.jazz XMSSMT-SHA2_20/2_256 (D=2, h=10, OID=1)
  include/
    jade_sign_xmss.h   C header with buffer sizes and extern declarations
  src/
    hash/
      sha256_n32.jinc   SHA-256 backend (N=32) — DONE
    address.jinc        ADRS type and setters — DONE
    utils.jinc          ull_to_bytes, bytes_to_ull, ct_memcmp, memzero — DONE
    wots.jinc           WOTS+ gen_pk, sign, pk_from_sig — DONE
    ltree.jinc          L-tree hash — DONE
    treehash.jinc       treehash and compute_root — DONE
    bds.jinc            BDS state management (incl. bds_state_update for XMSS-MT) — DONE
    xmss.jinc           XMSS keygen/sign/verify — DONE
    xmssmt.jinc         XMSS-MT keygen/sign/verify — DONE
  test/
    test_*.jazz         Jasmin unit test wrappers (export fn for C harness)
    test_*.c            C unit test harnesses
    test_api_xmss_common.h    Shared XMSS API test logic (parameterized)
    test_api_xmssmt_common.h  Shared XMSS-MT API test logic (parameterized)
    test_api_*.c        Per-parameter-set API test wrappers
  proof/
    (EasyCrypt proof files — later)
```

## Production API

The `api/` directory contains production `.jazz` files that export functions with libjade/NaCl/SUPERCOP naming. Each file sets `param int` values for one parameter set and requires the shared `.jinc` modules.

### Export symbol naming

```
jade_sign_xmss_sha2_{h}_256_amd64_ref_keypair   (keygen)
jade_sign_xmss_sha2_{h}_256_amd64_ref            (sign)
jade_sign_xmss_sha2_{h}_256_amd64_ref_open       (verify)
jade_sign_xmssmt_sha2_{h}_{d}_256_amd64_ref_*    (XMSS-MT variants)
```

### Parameter set summary

| Set | OID | h | D | SK | PK | Sig | State | Scratch |
|-----|-----|---|---|----|----|-----|-------|---------|
| XMSS-SHA2_10_256 | 0x01 | 10 | 1 | 136 | 68 | 2500 | 1219 | 2240 |
| XMSS-SHA2_16_256 | 0x02 | 16 | 1 | 136 | 68 | 2692 | 1957 | 2240 |
| XMSS-SHA2_20_256 | 0x03 | 20 | 1 | 136 | 68 | 2820 | 2449 | 2240 |
| XMSSMT-SHA2_20/2_256 | 0x01 | 10 | 2 | 135 | 68 | 4963 | 5801 | 2240 |

Buffer sizes are defined in `include/jade_sign_xmss.h`.

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
- **Front-load understanding of the problem domain before writing.** Investing in reading the reference implementation, all existing code, and test patterns before writing a single line meant structural correctness on the first draft. Mechanical errors are cheaper to fix than architectural ones.
- **Characterise the failure pattern before diving into root cause.** A small diagnostic (call 3 times, compare pairs) immediately revealed: root non-deterministic, state always correct, calls 1 and 3 match but 2 differs. This ruled out algorithmic errors and pointed directly at uninitialized memory — saving hours of fruitless code review.
- **Architecture that composes cleanly pays off at integration time.** The xmss.jinc session assembled keygen/sign/verify from existing building blocks with zero algorithmic bugs — all 6 tests passed on the first run. This was a direct result of the scratch-buffer convention, consistent function signatures, and testing each layer before building on it.
- **Reading the reference implementation thoroughly before writing scales to complex functions.** XMSS-MT sign has boundary-crossing swap logic, `needswap_upto` tracking, per-layer BDS updates, and cached WOTS signature management. Understanding the C implementation's control flow *completely* before writing Jasmin meant the sign function was algorithmically correct on first run — all 7 tests passed including 1024-signature boundary crossing.

### Even Better If
- **Think in x86 instructions before writing Jasmin.** Jasmin compiles to assembly — every construct maps to real instructions. Before writing a line, ask: "What instruction does this become? Does that instruction exist?" This prevents most linearization/asmgen errors.
- **State the root cause in one sentence before attempting a fix.** If you can't articulate *why* the compiler is rejecting the code, you don't understand the problem yet. Don't try fixes until you can.
- **Isolate before debugging.** Compile minimal `.jazz` files with one function at a time. Bisect which combination causes the conflict. This is fast and eliminates speculation.
- **Truncate error output ruthlessly.** `| head -15`. The first error is the real one. The rest is dependency chain noise that causes context overload.
- **Don't add complexity you haven't proven necessary.** Test the simpler hypothesis first. The wrapper functions were added because the error messages *mentioned* cross-function variables, but the actual root cause was the if/else parameter swap within a single function. One minimal test would have ruled out the cross-function theory.
- **Jasmin is not a fast-iteration language.** The compile-read-error-fix cycle that works for Python/JS/Rust burns tokens here. Think more, compile less.
- **Shorten the feedback loop, especially in unforgiving languages.** Writing everything before the first compile trades a fast "does this approach work?" signal for a large, tangled error. Validate the riskiest integration point first (here: the first fn that calls into existing code), then build outward.
- **Use runtime tools before code review for runtime bugs.** Valgrind found the uninitialized-stack-read in seconds; manual code review of 1100 lines of register-spill-heavy Jasmin could not. When a bug manifests at runtime (wrong output, non-determinism, crashes), reach for `valgrind`, `gdb`, or targeted printfs *first*. Reserve code review for compile-time errors and design issues where tools can't help.
- **Consult your own notes before debugging.** When hitting a compiler error, check MEMORY.md and SKILL.md *first* — don't start reading source code and exploring. Three of four compile errors in the xmss.jinc session were already-documented patterns (no early returns, u64 for stack indexing, require chain). Reading notes for 10 seconds beats a debug chain.
- **Discover all project documents at session start.** Missing `blueprint.md` meant missing the full implementation order, phase gates, and cross-implementation verification requirements. At the start of a session, glob for `*.md` in the working directory — don't assume CLAUDE.md is the only guide.
- **Read each warning individually, not by category.** "Dead variable warning" does not mean "the usual `#set0()` pattern." Read the *line number*. Two warnings in XMSS-MT were genuine dead stores (an unused spill and an overwritten assignment), not the benign `#set0()` pattern. Pattern-matching on warning type instead of reading the specific instance is how real issues get shipped.
- **Compile each function before writing the next.** Writing verify + keygen + sign in one pass before compiling meant the verify register-pressure bug (inline `for` unroll) and the sign register-pressure bug (`updates` live across SHA-256) were tangled together. Compiling verify alone first would have isolated and fixed it in seconds.

## What's next

See `blueprint.md` for the full implementation plan including design decisions and implementation order. We are through item 11 of 14. Remaining work:

### Phase 1 completion (XMSS single-tree)

- [ ] **KAT cross-validation** (blueprint item 12): Jasmin output must match C KAT fingerprints from `test_xmss_kat`. Requires building a Jasmin `.jazz` that produces the same output format as the C KAT generator.
- [ ] **Cross-implementation verification** (blueprint §10): C sign → Jasmin verify, Jasmin sign → C verify, using identical seeds. Currently we only test Jasmin→Jasmin roundtrips.
- [ ] **CT check** (blueprint item 13): Run `jasminc -CT` on all `.jazz` files. Any violation is a blocker.
- [ ] **Additional parameter sets** (blueprint item 14): h=16 and h=20 `.jazz` files, reusing all `.jinc` unchanged.
- [ ] **CI integration**: Add a Jasmin job to `.github/workflows/ci.yml` that installs `jasminc` and runs `make test`. Currently CI only covers the C implementation.
- [ ] **Code review**: Full review of all Jasmin code once Phase 1 is complete.

### Phase 2 completion (XMSS-MT) — DONE

- [x] **`src/xmssmt.jinc`**: XMSS-MT keygen, sign, verify with hypertree structure.
- [x] **`__bds_state_update`** in `bds.jinc`: Incremental tree building for XMSS-MT.
- [x] **Test harness**: 7 tests including 1024-signature boundary crossing.
- [ ] **KAT cross-validation**: Jasmin XMSS-MT output must match C KAT fingerprints.
- [ ] **Cross-implementation verification**: C sign → Jasmin verify, Jasmin sign → C verify.
- [ ] **Additional XMSS-MT parameter sets**: d=4, d=8 `.jazz` files.

### Phase 3 (additional hash backends)

- [ ] SHA-512 backend (`src/hash/sha512_n64.jinc`)
- [ ] SHAKE-128/256 backends

### Longer-term

- EasyCrypt proof strategy: which properties to prove first (CT? functional correctness of WOTS+?).
- RISC-V backend: track Jasmin upstream; port once backend is stable. **Prerequisite**: complete the RISC-V instruction analysis (see Architecture section) to understand what backend support is actually needed.
- Possible libjade integration or contribution.
