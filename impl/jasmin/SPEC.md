# SPEC.md — Jasmin XMSS/XMSS-MT Implementation Specification

This is the authoritative specification for the Jasmin implementation of
XMSS and XMSS-MT (RFC 8391, including Errata 7900). Code review should
evaluate the implementation against this document.

All normative requirements come from RFC 8391 and Errata 7900. The design
decisions (D1–D7) describe how the Jasmin implementation maps the RFC to
Jasmin language constructs.

---

## 1. Design decisions

These are fixed architectural choices. They are not RFC requirements but
determine the shape of the implementation.

### D1 — Compile-time parameter specialization

There are no runtime-dispatched params. The C `xmss_params *p` struct does
not exist. Every parameter (`N`, `W`, `LOG2_W`, `LEN`, `LEN1`, `LEN2`,
`H`, `D`, `IDX_BYTES`, `PAD_LEN`) is a Jasmin `param int` declared in the
top-level `.jazz` file. Each parameter set gets its own compiled `.s` file.

The algorithm `.jinc` files refer to these `param int` names. They are not
self-contained — they are included by a `.jazz` file that defines the params.

### D2 — Hash dispatch by separate compilation

The C `xmss_hash.c` dispatch switch is replaced by `require` selection. Each
top-level `.jazz` file includes exactly one hash backend `.jinc`. The algorithm
`.jinc` files call `__xmss_F`, `__xmss_H`, `__xmss_H_msg`, `__xmss_PRF`,
`__xmss_PRF_keygen`, `__xmss_PRF_idx` — names defined by whichever hash
backend is required. No other form of dispatch exists.

### D3 — No entropy callback

Jasmin has no function pointers. Keygen takes a pre-filled seed buffer:

```
export fn keypair(reg u64 pk sk state seeds scratch) -> reg u64
```

where `seeds` points to `3*N` random bytes (`SK_SEED || SK_PRF || SEED`) that
the caller is responsible for generating.

### D4 — BDS state as a caller-supplied flat buffer

The BDS state is passed as a `reg u64` pointer to a flat byte buffer. Field
access is done via pointer arithmetic in `inline fn` accessors in `bds.jinc`.
The caller allocates and persists the buffer.

### D5 — Algorithm layer is architecture-neutral

No x86-specific intrinsics (`#ROR`, `#BSWAP`, etc.) appear in any `.jinc` file
outside `src/hash/`. The algorithm layer uses only `+`, `-`, `^`, `&`, `|`,
`>>`, `<<`, and array accesses. Only `src/hash/*.jinc` changes when retargeting.

### D6 — Constant-time annotations on all export functions

Every `export fn` that handles secret key material annotates the relevant
inputs with `#[secret]` (or `#[ct = "..."]`) and calls `#init_msf()` at entry.
The compiler enforces that secret values do not reach branches or memory
addresses. Any declassification (`#declassify`) must be justified in a comment.

### D7 — Caller-provided scratch buffer

A scratch buffer (caller-allocated, passed as `reg u64`) is used by functions
that need temporary space for ADRS serialization when calling non-inline hash
functions. This works around Jasmin's inability to take the address of a
stack-local variable as a `reg u64` pointer.

---

## 2. RFC algorithm compliance

The implementation MUST be functionally equivalent to the following RFC 8391
algorithms. Section numbers refer to RFC 8391.

| Algorithm | RFC Section | RFC Algorithm # |
|-----------|-------------|-----------------|
| base_w | §2.6 | 1 |
| WOTS_genPK | §3.1.4 | 4 |
| WOTS_sign | §3.1.5 | 5 |
| WOTS_pkFromSig | §3.1.6 | 6 |
| RAND_HASH | §4.1.4 | 7 |
| ltree | §4.1.5 | 8 |
| treeHash | §4.1.6 | 9 |
| XMSS_keyGen | §4.1.7 | 10 |
| treeSig | §4.1.9 | 11 |
| XMSS_sign | §4.1.9 | 12 |
| XMSS_rootFromSig | §4.1.10 | 13 |
| XMSS_verify | §4.1.10 | 14 |
| XMSSMT_keyGen | §4.2.2 | 15 |
| XMSSMT_sign | §4.2.4 | 16 |
| XMSSMT_verify | §4.2.5 | 17 |

Authentication path computation uses the BDS algorithm ([BDS09]) rather than
the naive buildAuth from the RFC, for efficiency.

---

## 3. Hash function interface

Per RFC 8391 §5.1, for SHA2 with n=32:

```
F:     SHA2-256(toByte(0, 32) || KEY || M)
H:     SHA2-256(toByte(1, 32) || KEY || M)
H_msg: SHA2-256(toByte(2, 32) || KEY || M)
PRF:   SHA2-256(toByte(3, 32) || KEY || M)
```

The hash backend MUST implement these six internal functions:

| Function | Domain | Input | Output |
|----------|--------|-------|--------|
| `__xmss_F` | 0x00 | `toByte(0,N) \|\| key(N) \|\| adrs(32) \|\| in(N)` = 3N+32 bytes | N bytes |
| `__xmss_H` | 0x01 | `toByte(1,N) \|\| key(N) \|\| adrs(32) \|\| left(N) \|\| right(N)` = 4N+32 bytes | N bytes |
| `__xmss_H_msg` | 0x02 | `toByte(2,N) \|\| r(N) \|\| root(N) \|\| idx(32) \|\| msg(variable)` | N bytes |
| `__xmss_PRF` | 0x03 | `toByte(3,N) \|\| key(N) \|\| adrs(32)` = 2N+32 bytes | N bytes |
| `__xmss_PRF_keygen` | 0x04 | `toByte(4,N) \|\| sk_seed(N) \|\| pub_seed(N) \|\| adrs(32)` = 3N+32 bytes | N bytes |
| `__xmss_PRF_idx` | 0x03 | `toByte(3,N) \|\| sk_prf(N) \|\| idx_32bytes(32)` = 2N+32 bytes | N bytes |

Note: `F` and `H` internally compute key and bitmask(s) via PRF with
`keyAndMask` = 0, 1, (2 for H). The algorithm layer calls `__xmss_F` /
`__xmss_H` — bitmask logic is encapsulated in the hash backend.

---

## 4. Address scheme (ADRS)

Per RFC 8391 §2.5. ADRS is 8 × 32-bit words, big-endian serialized to 32
bytes for hash function input.

### Word layout

| Word | Field |
|------|-------|
| 0 | layer address |
| 1 | tree address high (bits 63:32 of 64-bit tree index) |
| 2 | tree address low (bits 31:0) |
| 3 | type (0=OTS, 1=LTREE, 2=HASH) |
| 4–7 | type-specific (see below) |

### Type-specific fields

| Type | w[4] | w[5] | w[6] | w[7] |
|------|------|------|------|------|
| 0 (OTS) | OTS address | chain address | hash address | keyAndMask |
| 1 (LTREE) | L-tree address | tree height | tree index | keyAndMask |
| 2 (HASH) | padding (0) | tree height | tree index | keyAndMask |

**`setType()` MUST zero words 4–7** (RFC 8391 §2.5).

---

## 5. Data layouts

### 5.1 Secret key (Errata 7900)

```
Offset  Size         Field
------  -----------  -----
0       4            OID (big-endian u32)
4       IDX_BYTES    idx (big-endian, leaf index of next unused WOTS+ key)
4+IB    N            SK_SEED
4+IB+N  N            SK_PRF
4+IB+2N N            root
4+IB+3N N            SEED
```

Total: `4 + IDX_BYTES + 4*N` bytes.

**Errata 7900**: The field order above (`SK_SEED || SK_PRF || root || SEED`)
is the corrected layout. The original RFC text at §4.1.7 Algorithm 10 listed
`idx || wots_sk || SK_PRF || root || SEED` but this was ambiguous about the
compact representation. Errata 7900 clarifies the serialization as shown above.

For XMSS, `IDX_BYTES = 4`. For XMSS-MT, `IDX_BYTES = ceil(h / 8)`.

### 5.2 Public key

```
Offset  Size  Field
------  ----  -----
0       4     OID (big-endian u32)
4       N     root
4+N     N     SEED
```

Total: `4 + 2*N` bytes.

### 5.3 XMSS Signature (RFC 8391 §4.1.8)

```
Offset          Size      Field
------          ----      -----
0               4         idx_sig (big-endian u32)
4               N         randomness r
4+N             LEN*N     WOTS+ signature sig_ots
4+N+LEN*N      H*N       authentication path auth[0..H-1]
```

Total: `4 + N + (LEN + H) * N` bytes.

### 5.4 XMSS-MT Signature (RFC 8391 §4.2.3)

```
Offset             Size              Field
------             ----              -----
0                  IDX_BYTES         idx_sig (big-endian)
IDX_BYTES          N                 randomness r
IDX_BYTES+N        (H/D+LEN)*N      reduced XMSS sig (layer 0)
...                (H/D+LEN)*N      reduced XMSS sig (layer 1)
...                ...               ...
...                (H/D+LEN)*N      reduced XMSS sig (layer D-1)
```

Total: `IDX_BYTES + N + D * (H/D + LEN) * N` bytes, where `H/D` is the
per-tree height (= `TREE_HEIGHT` param int).

Each reduced XMSS signature = `sig_ots(LEN*N) || auth(TREE_HEIGHT*N)`.

### 5.5 OID values

Per RFC 8391 Appendix B.1 and C.1:

**XMSS** (4-byte big-endian):

| Parameter set | OID |
|---------------|-----|
| XMSS-SHA2_10_256 | 0x00000001 |
| XMSS-SHA2_16_256 | 0x00000002 |
| XMSS-SHA2_20_256 | 0x00000003 |

**XMSS-MT** (4-byte big-endian):

| Parameter set | OID |
|---------------|-----|
| XMSSMT-SHA2_20/2_256 | 0x00000001 |
| XMSSMT-SHA2_20/4_256 | 0x00000002 |

---

## 6. Parameter sets (currently implemented)

All use `W=16`, `LOG2_W=4`, `PAD_LEN=N`.

| Set | OID | N | W | LEN1 | LEN2 | LEN | H | D | TREE_HEIGHT | BDS_K | IDX_BYTES |
|-----|-----|---|---|------|------|-----|---|---|-------------|-------|-----------|
| XMSS-SHA2_10_256 | 0x01 | 32 | 16 | 64 | 3 | 67 | 10 | 1 | 10 | 2 | 4 |
| XMSS-SHA2_16_256 | 0x02 | 32 | 16 | 64 | 3 | 67 | 16 | 1 | 16 | 2 | 4 |
| XMSS-SHA2_20_256 | 0x03 | 32 | 16 | 64 | 3 | 67 | 20 | 1 | 20 | 2 | 4 |
| XMSSMT-SHA2_20/2_256 | 0x01 | 32 | 16 | 64 | 3 | 67 | 20 | 2 | 10 | 2 | 3 |
| XMSSMT-SHA2_20/4_256 | 0x02 | 32 | 16 | 64 | 3 | 67 | 20 | 4 | 5 | 0 | 3 |

Derived values: `TREE_HEIGHT = H/D`, `FULL_H = H`.

XMSS-MT IDX_BYTES = `ceil(h/8) = ceil(20/8) = 3`.

Note on BDS_K: XMSSMT-SHA2_20/4_256 uses `BDS_K=0` because `TREE_HEIGHT=5` and BDS
requires `(TREE_HEIGHT - BDS_K)` to be even. With `TREE_HEIGHT=5`, `BDS_K=2` would give
odd `TREE_HEIGHT - BDS_K = 3`, violating the precondition. `BDS_K=0` is always valid.

### Buffer sizes

| Set | SK | PK | Sig | State (BDS) |
|-----|----|----|-----|-------------|
| XMSS-SHA2_10_256 | 136 | 68 | 2500 | 1219 |
| XMSS-SHA2_16_256 | 136 | 68 | 2692 | 1957 |
| XMSS-SHA2_20_256 | 136 | 68 | 2820 | 2449 |
| XMSSMT-SHA2_20/2_256 | 135 | 68 | 4963 | 5801 |
| XMSSMT-SHA2_20/4_256 | 135 | 68 | 9251 | 10912 |

Note: XMSS-MT SK is 135 bytes (not 136) because `IDX_BYTES=3` (not 4).

---

## 7. BDS state layout

The BDS state is a flat byte buffer. All integers stored in native
(little-endian) byte order — they are internal state, not wire format.

```
Offset                          Size              Field
------                          ----              -----
0                               H*N               auth[0..H-1]
H*N                             (H/2)*N           keep[0..H/2-1]
(H + H/2)*N                    (H+1)*N           stack[0..H] (node values)
(H + H/2 + H+1)*N              H+1               stack_levels[0..H]
... + 4                         4                 stack_offset (u32)
... + (H-K)*TH_INST_SIZE        (H-K)*TH_INST_SIZE treehash[0..H-K-1]
... + RETAIN_NODES*N            RETAIN_NODES*N    retain nodes
... + 4                         4                 next_leaf (u32)
```

Where:
- `TH_INST_SIZE = N + 4 + 4 + 1 + 1` (node || target_h || next_idx || stack_usage || completed)
- `RETAIN_NODES = 2^BDS_K - BDS_K - 1` where `BDS_K` is a compile-time parameter (`BDS_K = 0` or: `BDS_K >= 2`, `BDS_K < TREE_HEIGHT`, and `(TREE_HEIGHT - BDS_K)` even)
- For `BDS_K=0`: `RETAIN_NODES = 0` (retain array unused; retain code paths are dead)
- For `BDS_K=2`: `RETAIN_NODES = 1`

For XMSS-MT, the multi-tree state contains `D` BDS states plus per-layer
WOTS signature caches. Layout is defined by `param int` offset constants.

---

## 8. Export ABI

Export function naming follows the libjade/NaCl/SUPERCOP convention:

```
jade_sign_xmss_sha2_{h}_256_amd64_ref_keypair    (keygen)
jade_sign_xmss_sha2_{h}_256_amd64_ref             (sign)
jade_sign_xmss_sha2_{h}_256_amd64_ref_open        (verify)
jade_sign_xmssmt_sha2_{h}_{d}_256_amd64_ref_*     (XMSS-MT variants)
```

### Keygen

```
export fn keypair(reg u64 pk, reg u64 sk, reg u64 state,
                  reg u64 seeds, reg u64 scratch) -> reg u64
```

- `seeds`: 3*N bytes of caller-generated randomness (`SK_SEED || SK_PRF || SEED`)
- Returns 0 on success
- Writes OID into both SK and PK
- Computes tree root via BDS-augmented treehash, populating BDS state

### Sign

```
export fn sign(reg u64 sig, reg u64 msg, reg u64 msglen,
               reg u64 sk, reg u64 state, reg u64 scratch) -> reg u64
```

- Reads and increments idx in SK (MUST update before outputting signature)
- Returns 0 on success, non-zero if key exhausted (`idx > 2^H - 1`)
- Computes `r = PRF(SK_PRF, toByte(idx, 32))`
- Computes `M' = H_msg(r || root || toByte(idx, N), msg)`
- Writes sig: `idx || r || WOTS_sign(M') || auth_path`
- Updates BDS state (`bds_round` + `bds_treehash_update`)

### Verify

```
export fn verify(reg u64 msg, reg u64 msglen,
                 reg u64 sig, reg u64 pk, reg u64 scratch) -> reg u64
```

- Stateless
- Validates OID in PK
- Returns 0 if valid, non-zero if invalid
- Root comparison MUST use constant-time comparison (`ct_memcmp`)

---

## 9. Security properties

### 9.1 Constant-time

- No secret-dependent branches or memory accesses (enforced by Jasmin
  `#[secret]` / `#[ct]` annotations and `jasmin-ct` checker)
- Signature verification uses `ct_memcmp` for root comparison — prevents
  timing oracle on which byte differed
- The leaf index `idx` is secret until written into the signature, then public.
  The exhaustion check (`idx > max`) branches on a value that becomes public
  via the signature. `#declassify` is acceptable here.
- WOTS+ chain lengths are derived from the message hash, which is public
  (included in the signature). No CT issue with variable loop counts.

### 9.2 Portability rules (J1–J8)

| Rule | Requirement |
|------|-------------|
| J1 | No heap allocation. All arrays stack-allocated, sized by `param int`. |
| J2 | No function pointers. Hash dispatch by separate compilation. |
| J3 | No recursion. All tree algorithms iterative. |
| J4 | All loop bounds are `param int` or public function arguments. |
| J5 | No secret-dependent branches or memory accesses. |
| J6 | ADRS is `u32[8]` on stack; manipulated via setter `inline fn`s; serialized to `u8[32]` before hashing. |
| J7 | One algorithm per `.jinc` file. |
| J8 | `export fn` is the sole ABI boundary. Internal helpers are `fn` or `inline fn`. |

---

## 10. Test requirements

### Unit tests

One test per algorithm module, verifying against known-good C implementation
output for identical seeds.

### API tests

Full keygen → sign → verify roundtrip for each parameter set. Deterministic
keygen (same seeds produce same PK/SK). Sequential signing (multiple
signatures from one key).

### KAT cross-validation

Output (PK, signature at a specific index) must match fingerprints generated
by `third_party/xmss-reference/` for identical seeds. Verified via SHAKE128
digest comparison.

### Interop tests

- C sign → Jasmin verify (accept)
- Jasmin sign → C verify (accept)
- Identical seeds produce byte-identical PK and SK across implementations

### CT checks

`jasmin-ct` must pass on all `.jazz` files (unit tests and production API)
with no violations.
