# Scoping a Jasmin XMSS port: hash layer only, or full stack?

**Status:** Recorded observation. Not a recommendation. Revisit when planning
the RV64 port of the Jasmin implementation.

**Author:** Wrenna Robson, April 2026. Arose from the RISC-V ISA profile
comparison (`isa/reports/xmss_rv64_isa_profile_comparison.tex`).

## The question

A full Jasmin XMSS/XMSS-MT port already exists in `impl/jasmin/`, verified
constant-time on x86-64. The obvious plan for a RISC-V port is to recompile
the same Jasmin sources once the Jasmin RV64 backend is production-ready.

The ISA profile comparison against the upstream XMSS reference implementation
raises a different question: **is the upper algorithm layer worth porting at
all, or should a Jasmin RV64 port be scoped to the hash primitives (SHA-2,
Keccak-f[1600]) and nothing else?**

This note records the evidence and the tradeoffs. It does not decide.

## Three observations from the ISA profile

### 1. Zbb uptake concentrates in the hash layer.

With `-march=rv64gc_zbb`, both our C implementation and the reference place
≥82% of Zbb-extension instructions (`rolw`, `roriw`, `rev8`, `rol`, `rori`,
`andn`) inside SHA-2 / Keccak cores. The algorithm layer sees only
opportunistic `maxu`/`minu`/`andn` uses that do not materially affect
correctness or performance.

Consequence: the ISA-specific optimisation story for XMSS is **entirely** in
the hash layer. The algorithm layer (WOTS+, L-tree, treehash, BDS, XMSS,
XMSS-MT) compiles to portable RV64I and does not benefit from ISA tuning.

### 2. Upper-layer code-size differences are design tax, not algorithm cost.

Every module-level delta between our implementation and the reference traces
back to a deliberate design choice tied to Jasmin-portability rules:

| Module               | Delta | Source of the difference |
|----------------------|------:|--------------------------|
| `params`             | −791  | Jump table vs switch cascade (C-level choice) |
| Hash wrappers        | +398  | Pre-serialised ADRS (Jasmin-friendly calling convention) |
| WOTS+                | +262  | Defensive chain-length bounds + ADRS-by-pointer |
| SHAKE module         | +458  | Incremental ctx API (no VLAs, no message-length stack buffers) |

The reference can be terser because it uses VLAs, packs hash inputs into
single contiguous caller-allocated buffers, and passes ADRS as
`uint32_t[8]`. These are patterns a Jasmin port cannot use. The extra
instructions in our C implementation are the cost of *making the C look like
what the Jasmin code will look like* — they carry no algorithmic content.

### 3. Upper-layer code is ISA-neutral I-code.

Disassembly of `wots.o`, `bds.o`, `treehash.o`, `xmss.o`, `xmss_mt.o` shows
pointer arithmetic, byte-level XORs, 32-bit loop counters, and compile-time
offset multiplications. No instruction mix there benefits from any extension
beyond base I (with a handful of `mulw` for offset computation, a small
enough count that even RV64I with shift-and-add expansion would compile the
same C).

## What Jasmin buys at each layer

| Layer | What Jasmin provides |
|-------|----------------------|
| Hash cores (SHA-2, Keccak) | (a) ISA-tuned code generation for the one layer where ISA actually matters; (b) formally checked constant-time; (c) stable input/output layouts that let the rest of the system be built against a fixed ABI. |
| Algorithm layer (WOTS+, BDS, XMSS, XMSS-MT) | Constant-time guarantees where secrets flow (WOTS chaining, BDS state transitions), plus the type-safety guarantees of a restricted language. The CT guarantee is a *source-level property* that Jasmin's compiler preserves across backends. |

The decisive point for an RV64 port: **the CT guarantees already earned on
x86-64 carry to RV64 when the Jasmin backend matures.** Nothing about the
algorithm-layer proof has to be redone. The ISA-tuning work, by contrast,
is backend-specific — but as observation 1 established, that work only pays
off at the hash layer.

## The libjade-shaped alternative

Assume a future where the Jasmin ecosystem ships formally verified hash
primitives (SHA-256, SHA-512, Keccak-f[1600]) with CT proofs and
ISA-specific code generation. libjade already points in this direction,
and the formosa-crypto group is now actively exploring a **Rust upper
layer calling Jasmin lower layers** as a general paradigm for
high-assurance post-quantum cryptography. That direction is relevant
here: it says the split we are describing is not a local cost-cutting
exercise but a pattern the verification community is converging on
independently.

In that world, an XMSS implementation could be:

- **Hash layer:** Jasmin-verified primitives from a shared library, with
  RV64-tuned (Zbb-using) code generation.
- **Algorithm layer:** Rust — or, as a simpler short-term option,
  ordinary C — free of Jasmin-portability constraints. VLAs (in C) or
  bounded slices (in Rust) allowed, heap allocation allowed where
  useful, switch-cascade parameter derivation if that reads more
  clearly than a lookup table, ADRS passed as `uint32_t[8]` or
  `[u32; 8]` with inline serialisation — in short, the reference's
  shape, without apology.

Rust brings the additional win of memory-safety guarantees at the
algorithm layer that C cannot offer, at the cost of an FFI story that
is slightly more work than C-to-Jasmin. The formosa-crypto exploration
of this pattern is the main reason it is worth naming here rather than
treating the C option as the only alternative.

The ISA profile would barely change under either upper-layer choice.
The algorithm layer would shrink by some hundreds of instructions per
module, because it would no longer be paying design tax for a
Jasmin-portability budget it does not benefit from. The overall binary
would be smaller and the upper-layer source easier to read.

## What this gives up

The libjade-shaped alternative loses three things:

1. **End-to-end CT via Jasmin.** Jasmin's CT checker operates over Jasmin
   source. Once control crosses an FFI boundary into C, any CT property of
   the C side has to be argued separately. In practice this is not a large
   loss: the algorithm layer's CT obligations (WOTS chaining index, BDS
   array indexing) are simple enough to audit by inspection or with tools
   like ct-verif. The hard CT cases — variable-time instructions inside
   hash rounds — are all in the hash layer, which stays under Jasmin.

2. **The completed Jasmin upper layer.** The existing `impl/jasmin/` port
   covers keygen/sign/verify for XMSS and XMSS-MT, is CT-checked, and has
   cross-implementation interop tests against our C. Backing it out in
   favour of a C upper layer would discard a finished, tested body of
   work. That's a real cost even if the forward case is strong.

3. **Symmetry with the formal-verification roadmap.** If there are plans
   to extend the Jasmin implementation toward a full EasyCrypt-style
   correctness proof, a non-Jasmin upper layer puts those plans out of
   reach for the upper layer (the EasyCrypt proof infrastructure is for
   Jasmin). We have no active such plan today, but formosa-crypto's work
   on XMSS is ongoing and may produce one. Note that the Rust-over-Jasmin
   direction they are exploring explicitly accepts this boundary: formal
   CT and correctness proofs for the primitives, type-system-level
   guarantees (memory safety, absence of unsafe aliasing) from Rust for
   the composition layer.

## Why this is worth writing down

The observation is non-obvious: "the RV64 port should cover the whole
stack" sounds like the default and requires no argument. The ISA evidence
says that default is wrong, or at least unmotivated — the upper layers
are paying for Jasmin constraints that buy them no RV64-specific benefit.

But the counter-evidence (existing complete port, end-to-end CT, formal
roadmap) is also real, and may dominate once weighed. The point of this
note is to ensure that when someone — human or AI — picks up the RV64 port
planning, the ISA evidence is part of the weighing, not lost between
sessions.

## References

Companion ISA reports:

- `isa/reports/xmss_rv64_isa_profile.tex` — self profile of
  `impl/c/libxmss.a` on RV64, including the Zbb data summarised above.
- `isa/reports/xmss_rv64_isa_profile_reference.tex` — same profile for
  the upstream XMSS reference implementation.
- `isa/reports/xmss_rv64_isa_profile_comparison.tex` — side-by-side
  analysis that surfaces the module-level deltas cited in the "design
  tax" table.

Elsewhere:

- `impl/jasmin/SPEC.md` — current Jasmin scope.
- `third_party/libjade` — Jasmin primitives shaped for C composition.
