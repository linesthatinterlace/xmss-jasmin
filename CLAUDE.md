# CLAUDE.md — xmss-jasmin

Multi-implementation XMSS/XMSS-MT project (RFC 8391).

## Implementation routing

Read the CLAUDE.md in the relevant implementation directory for build commands, architecture details, and coding rules.

- **C implementation** (`impl/c/`): Complete C99 reference. See `impl/c/CLAUDE.md` for build commands, architecture, Jasmin portability rules, and test structure.
- **Rust implementation** (`impl/rust/`): Planned. See `impl/rust/CLAUDE.md` for build commands, architecture, and Rust-specific rules.
- **Jasmin implementation** (`impl/jasmin/`): XMSS and XMSS-MT complete (keygen, sign, verify tested). Targets x86-64 first (mature backend); RISC-V port planned once the Jasmin RISC-V backend matures. See `impl/jasmin/CLAUDE.md` and `impl/jasmin/SPEC.md`.

## Shared resources

- `doc/rfc8391.txt` -- the RFC 8391 specification. All implementations target this spec including Errata 7900 (SK serialisation byte layout).
- `third_party/xmss-reference/` -- git submodule of the XMSS reference C implementation. **Read-only**: used to understand algorithm logic and regenerate KAT fingerprints. **Do NOT copy code from it** -- our implementations must follow stricter rules (no VLAs, no malloc, no function pointers, etc.) which the reference violates. Only read it to understand algorithm logic, then reimplement from scratch. See `third_party/CLAUDE.md` for how to compile and run the KAT fingerprint generator.
- **formosa-xmss** (`https://github.com/formosa-crypto/formosa-xmss`) -- a human-authored Jasmin implementation of XMSS by the formosa-crypto team, subject to active research. Scope TBD. Relevant prior art for the Jasmin implementation; do not copy from it.

## CI

GitHub Actions CI runs on every push and PR:

- **`ci.yml`**:
  - **C (native)**: gcc + clang (`-Werror`), three-tier test organisation:
    - Tier 1 "fast" (< 30s): params, address, hash, wots, utils — fail fast.
    - Tier 2 "core" (< 5 min): sign/verify roundtrips, BDS serial, BDS exhaustive (H=5+H=10), XMSS-MT boundary.
    - Tier 3 "deep" (5-15 min): KAT (512 sigs), XMSS-MT KAT, ACVP cross-checks.
  - **Jasmin**: build job (compile + CT checks) → three parallel test jobs via artifact sharing:
    - `jasmin-unit`: 9 unit tests (seconds)
    - `jasmin-api`: fast + slow API tests (h=10/16/20, MT 20/2, MT 20/4)
    - `jasmin-interop`: shallow + deep interop (64 sigs + BDS state comparison) + KAT
- **`ci-weekly.yml`**: Deep tests on Sunday 04:00 UTC + manual trigger. C exhaustive BDS (debug build, assertions enabled). Jasmin deep interop + slow API + full boundary verification.
- **`riscv.yml`**: RISC-V cross-compile + QEMU (fast tests + sign/verify roundtrips). Weekly Monday + manual trigger.

**Prefer pushing and letting CI run the full test suite** rather than running slow tests locally. Use `ctest -L fast` (C) or `make test` (Jasmin) locally for quick smoke checks, then push to get full coverage across compilers.

Check CI status: `gh run list` / `gh run view <id>` / `gh run watch <id>`

## Cross-cutting research

### RISC-V instruction analysis

Analyses which RISC-V ISA extensions `libxmss.a` actually requires, informing the Jasmin port's target ISA. Artifacts live in `isa/`:

- `isa/scripts/gen_lookup.sh` — generates authoritative mnemonic→extension lookup from `third_party/riscv-opcodes/`
- `isa/scripts/analyse.sh` — disassembles `impl/c/build-rv/libxmss.a`, classifies by extension, detects C encoding from byte width
- `isa/reports/xmss_rv64_isa_profile.md` — full per-object-file results with extension breakdown
**Key findings**: XMSS uses only I + M (M only for compiler address arithmetic). 48% of instructions use C encoding. No A/F/D/Zb*. Zbb (`ror`/`rev8`) is relevant for SHA-2 but not compiler-emitted with `-march=rv64gc`. PDF report completed.

See `impl/jasmin/CLAUDE.md` for how these findings affect the Jasmin port strategy.

## WWW/EBI

WWW/EBI (What Went Well / Even Better If) is a reflective evaluation framework. After completing a significant piece of work, write WWW items (things that worked, to do more of) and EBI items (things to improve next time). Store these in the relevant implementation's CLAUDE.md so future sessions benefit.

### Writing effective reflections

- Capture **working principles and process**, not code-level recipes. Code patterns belong in language references (SKILL.md, pitfall docs).
- A good item should be **transferable** — applicable to the next problem, not just a replay of the last one. Test: "Would this help someone who hits a *different* problem?" If no, it's a recipe, not a principle.
- Anti-pattern: "Use X pattern to fix Y error" (recipe). Better: "Identify the root constraint before attempting fixes" (principle).
- When a session produces both a process insight and a code pattern, put the process insight in WWW/EBI and the code pattern in the language reference.

## Test coverage

### What's been done

A ceiling-vs-floor division bug in the BDS treehash update budget survived because no test exercised (H=5, K=2, ≥16 signatures). The following defences are now in place:

1. **Treehash completion assertion** (C, `bds.c`): `assert(treehash[i].completed)` before consuming the node in `bds_round()`. Active in debug builds (`NDEBUG`), zero cost in release. Catches budget starvation at the point of corruption.

2. **Exhaustive (H, K) matrix** (C, `test_bds_exhaustive.c`): Signs and verifies EVERY index through a full tree for 6 (H, K) combos — H=5 K=0/2/4 (32 sigs each, <1s) and H=10 K=0/2/4 (1024 sigs each, ~2-4 min). Includes post-sign BDS state validation and key exhaustion checks.

3. **Deep cross-implementation interop** (Jasmin, `test_interop_deep_xmss_sha2_10_256.c`): Signs 64 messages with both C and Jasmin from the same seed. After EACH signature, compares:
   - Signatures byte-for-byte (auth path divergence = BDS state bug)
   - BDS state byte-for-byte (C serialized vs Jasmin flat buffer, with LE→BE integer conversion)
   - Treehash completion invariants on the Jasmin state (next_idx bounds, target height, stack_offset)

4. **Boundary test verification** (Jasmin, `test_api_xmssmt_common.h`): XMSS-MT 20/4 boundary test now verifies EVERY signature through the tree boundary, not just 4 spot-check indices.

5. **Three-tier C test labelling**: `ctest -L fast` (seconds), `ctest -L core` (<5 min), `ctest -L deep` (5-15 min). CI runs all three tiers sequentially — a BDS bug in H=5 fails in Tier 2 within seconds.

### Remaining gaps

- **Golden BDS state snapshots**: Pre-computed expected state at high-tau indices (idx=15, 16, 31 for H=5 K=2). Would catch subtle state differences that don't affect signatures. Low priority — the deep interop state comparison catches the same class of bugs more maintainably.

- **Endianness note for cross-implementation state comparison**: C serializes integers big-endian; Jasmin stores them little-endian (native). The deep interop test handles this by byte-swapping the Jasmin buffer's integer fields (stack_offset, treehash[i].h, treehash[i].next_idx, next_leaf) before comparing. If the Jasmin layout changes, update the `jasmin_state_to_be()` function in the deep interop test.

## Cross-cutting rules

These apply to ALL implementations regardless of language:

- All implementations must target RFC 8391 including Errata 7900.
- Secret-dependent branches and memory accesses must be constant-time. Verification uses constant-time comparison. Annotate any deviations.
- No implementation should depend on `third_party/xmss-reference/` at build time -- it is a development reference only.
