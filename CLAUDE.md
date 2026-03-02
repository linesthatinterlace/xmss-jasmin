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

- **`ci.yml`**: gcc and clang (native, `-Werror`), all 12 C tests (~4 min each). Jasmin job: installs jasminc via opam, runs 9 unit tests + 2 fast API + 2 KAT + 2 interop + CT checks (~17 min).
- **`riscv.yml`**: RISC-V cross-compile + QEMU (fast tests + sign/verify roundtrips). Weekly + manual trigger.

**Prefer pushing and letting CI run the full test suite** rather than running slow tests locally. Use `make test-fast` locally for quick smoke checks, then push to get full coverage across compilers.

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

## Test coverage gaps

The current test suite is wide (many parameter sets, many features) but shallow (1-5 signatures per set). The BDS algorithm's complexity lives in state machine transitions over dozens of signatures. A ceiling-vs-floor division bug in the treehash update count survived because no test exercised (H=5, K=2, ≥16 signatures) — each axis was tested in isolation but never together.

### What we need

1. **Every (H, K) combination through a full tree boundary.** Not just 1-signature smoke tests. Any parameter set where `(H - K)` is odd is a candidate for update budget bugs. At minimum: sign and verify every index from 0 to 2^H for each parameter set. The C tests should test both bds_k=0 and bds_k=2 for parameter sets where H is small enough to be practical.

2. **BDS state comparison between C and Jasmin.** Currently interop tests verify 1 signature. A state divergence after 5+ signatures is invisible. Add a test that signs N messages with both implementations from the same seed and compares the BDS state byte-for-byte after each signature.

3. **Intermediate BDS state assertions.** We only test final output (does verify pass?). If treehash nodes or retain nodes are wrong but haven't been consumed yet, we don't know. Add tests that dump and compare treehash[i].node, retain[i], and auth[i] against known-good values at key indices (especially at high-tau events like idx=2^k - 1).

4. **Treehash completion invariant check.** Before bds_round reads th[i].node, assert `th[i].completed == 1`. This is the invariant the algorithm relies on but never checks. A debug-mode assertion here would have caught this bug immediately.

5. **BDS exhaustion edge cases.** What happens when `startidx >= 1 << H` during treehash reinit? The guard exists in both implementations but is untested. Test the last few signatures in a tree where some treehash instances can't be reinitialised.

### Priority

Items 1 and 4 are highest priority — they directly prevent recurrence of the class of bug we just found. Item 2 is the strongest cross-implementation check. Items 3 and 5 are hardening.

## Cross-cutting rules

These apply to ALL implementations regardless of language:

- All implementations must target RFC 8391 including Errata 7900.
- Secret-dependent branches and memory accesses must be constant-time. Verification uses constant-time comparison. Annotate any deviations.
- No implementation should depend on `third_party/xmss-reference/` at build time -- it is a development reference only.
