# CLAUDE.md — third_party/

This directory contains third-party reference material used **only** during development.
No implementation in `impl/` depends on anything here at build time. Everything here is a submodule.

## libjade

A git submodule tracking the [libjade](https://github.com/formosa-crypto/libjade)
cryptographic library — a formally verified, high-assurance collection of
cryptographic primitives written in Jasmin. Developed by the formosa-crypto team.

**Pinned to**: `release/2023.05-2` (the latest tagged release). HEAD is mid-refactor
(`src/` renamed to `oldsrc-should-delete/`), so do not update past this tag without
checking that the directory layout is stable.

**Status**: Read-only reference. Used as a source of idiomatic Jasmin patterns
for the `impl/jasmin/` port. Any code adapted from libjade must be cited
(file and function) in a comment at the point of use.

### What we use from it

- `src/crypto_hash/sha256/amd64/ref/sha256.jinc` — reference Jasmin SHA-256
  implementation. Our `impl/jasmin/sha256_n32.jinc` was informed by this but
  reimplemented from scratch for XMSS-specific requirements (fixed-length
  inputs, PRF/F/H wrappers, no heap allocation).
- `src/crypto_hash/sha256/amd64/ref/sha256_globals.jinc` — SHA-256 round
  constants (`K`) and initial hash values (`H`). These are standard FIPS 180-4
  constants.

### Other contents (not currently used)

SHA-512, SHA-3, Kyber/ML-KEM, Dilithium/ML-DSA, Curve25519, Poly1305,
ChaCha20, XSalsa20, and more. These may be useful reference material for
future Jasmin work but are not dependencies of our XMSS port.

### Updating

```bash
cd third_party/libjade
git fetch origin
git checkout <tag>
cd ../..
git add third_party/libjade
```

## xmss-reference

A git submodule tracking the upstream XMSS reference implementation.

**Status**: Read-only reference. Do NOT copy code into `impl/`.
See the top-level `CLAUDE.md` for the cross-cutting rules about its use.

### What it is used for

1. **Understanding algorithm logic** — the reference is the authoritative
   companion to RFC 8391 for understanding how WOTS+, XMSS, and XMSS-MT work.
   Read it; do not derive implementation code from it.

2. **Regenerating KAT fingerprints** — `test/gen_mt_kat.c` (our file, not part
   of the upstream reference) generates the reference fingerprints checked in
   `impl/c/test/test_xmss_mt_kat.c`.

### Compiling test/gen_mt_kat

Run from `third_party/xmss-reference/`:

```bash
gcc -Wall -O3 \
    -o test/gen_mt_kat \
    test/gen_mt_kat.c \
    params.c hash.c fips202.c hash_address.c \
    utils.c xmss_core.c xmss_commons.c wots.c randombytes.c \
    -lcrypto
```

**Key requirement**: include `randombytes.c` — the core files call `randombytes()`
and the linker will error without it even though `gen_mt_kat.c` itself uses only
`xmssmt_core_seed_keypair` (which takes an explicit seed and does not call
`randombytes` directly; it is pulled in transitively via `xmssmt_core_keypair`).

Then run:

```bash
./test/gen_mt_kat
```

Output is the `mt_vectors[]` table to paste into
`impl/c/test/test_xmss_mt_kat.c`.

### Wire OIDs used by gen_mt_kat

The reference uses wire OIDs (not our internal `0x01xxxxxx` OIDs):

| Wire OID | Parameter set |
|----------|---------------|
| 0x01 (1) | XMSSMT-SHA2_20/2_256  (n=32, h=20, d=2) |
| 0x09 (9) | XMSSMT-SHA2_20/2_512  (n=64, h=20, d=2) |
| 0x11 (17)| XMSSMT-SHAKE_20/2_256 (n=32, h=20, d=2) |
| 0x19 (25)| XMSSMT-SHAKE_20/2_512 (n=64, h=20, d=2) |

Our internal OIDs add a `0x01000000` prefix (see `impl/c/include/xmss/params.h`).

### Other reference test binaries

The upstream reference ships its own tests (wots, oid, xmss, xmssmt, …).
These are built via its own `Makefile` and are useful for spot-checking but
are not part of our test suite.

```bash
# Build the reference's own tests (from third_party/xmss-reference/)
make
```

The Makefile links `-lcrypto` (OpenSSL) for SHA-2; SHAKE is handled by
the bundled `fips202.c`.

## post-quantum-crypto-kat

A git submodule containing NIST ACVP Known Answer Test vectors for post-quantum
algorithms, including XMSS.

**Status**: Read-only. Used by `impl/c/test/test_xmss_acvp_kat.c` for
independent cross-validation of XMSS (SHA2, N32) against NIST ACVP vectors.

### What is used

Only the `XMSS/XMSS-{keyGen,sigGen,sigVer}-SHA256-N32-H{10,16,20}/` directories.
SHAKE256 N32 vectors (ACVP OIDs 16-18) are excluded: they use NIST SP 800-208's
SHAKE256 hash function, whereas RFC 8391 XMSS-SHAKE uses SHAKE128.

### Regenerating the C header

Run from the repository root:

```bash
python3 impl/c/test/gen_acvp_vectors.py
```

This writes `impl/c/test/xmss_acvp_vectors.h`. Commit the generated file —
no JSON parsing is needed at build time.

### ACVP signature format

ACVP "signature" fields are `RFC_sig || message` (message appended).
For XMSS-SHA2_10_256 (N32, H10): RFC sig = 2500 bytes, message = 128 bytes,
total = 2628 bytes. `gen_acvp_vectors.py` splits these and stores only the
RFC sig portion.

## riscv-opcodes

A git submodule tracking the upstream RISC-V opcodes database
(`riscv/riscv-opcodes` on GitHub).

**Status**: Read-only. Used by `isa/scripts/gen_lookup.sh` to generate
an authoritative mnemonic→extension lookup table for the ISA analysis.

### What it contains

The `extensions/` directory has one file per ISA extension (`rv_i`, `rv64_i`,
`rv_m`, `rv64_m`, `rv_zbb`, `rv64_zbb`, etc.). Each file lists instructions
with their mnemonic, operands, and encoding fields.

Lines starting with `$pseudo_op` define pseudo-instructions (e.g. `mv`, `ret`,
`sext.w`). Lines starting with `$import` or `#` are directives/comments.

### Updating

```bash
cd third_party/riscv-opcodes
git fetch origin
git checkout <tag-or-commit>
cd ../..
git add third_party/riscv-opcodes
```

Then regenerate the lookup table: `isa/scripts/gen_lookup.sh`
