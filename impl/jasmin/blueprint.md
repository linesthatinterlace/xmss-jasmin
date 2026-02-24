# Jasmin XMSS Port — Implementation Blueprint

This document is the authoritative implementation guide for the Jasmin port. It
is written for the implementer (Opus) and assumes familiarity with the Jasmin
language reference (`jasmin-reference.md`) and the C implementation
(`impl/c/`). Read those first.

---

## 1. Foundational design decisions

These decisions are fixed. Do not revisit them during implementation.

### D1 — Compile-time parameter specialization

There are no runtime-dispatched params in the Jasmin implementation. The C
`xmss_params *p` struct does not exist. Every parameter (`n`, `w`, `log2_w`,
`len`, `len1`, `len2`, `tree_height`, `d`, `idx_bytes`, `pad_len`) is a Jasmin
`param int` declared at the top of the top-level `.jazz` file. Each parameter
set gets its own compiled `.s` file.

Consequence: the algorithm `.jinc` files refer to `param int N`, `param int W`,
etc. They are not self-contained — they are included by a `.jazz` file that
defines those params first.

### D2 — Hash dispatch by separate compilation

The C `xmss_hash.c` dispatch switch is replaced by `require` selection. Each
top-level `.jazz` file includes exactly one hash backend `.jinc`. The algorithm
`.jinc` files call `__xmss_F`, `__xmss_H`, `__xmss_H_msg`, `__xmss_PRF`,
`__xmss_PRF_keygen`, `__xmss_PRF_idx` — names defined in whichever hash
backend is required. No other form of dispatch exists. This is J2.

### D3 — No entropy callback

Jasmin has no function pointers (J2). The C `xmss_randombytes_fn` callback
cannot be expressed. Keygen instead takes a pre-filled seed buffer:

```
export fn jade_xmss_keygen(reg u64 pk sk state seeds) -> reg u64
```

where `seeds` points to `3*n` random bytes (SK_SEED || SK_PRF || SEED) that
the caller is responsible for generating. The C test harness reads from
`/dev/urandom` and passes the buffer in. This is cleaner for formal
verification because entropy is a caller responsibility.

### D4 — BDS state as a caller-supplied flat buffer

The C `xmss_bds_state` (~1-5 KB depending on parameter set) is passed as a
`reg u64` pointer to a flat byte buffer whose layout is defined in Section 4.
Field access is done via pointer arithmetic in `inline fn` accessors defined
in `bds.jinc`. The caller is responsible for allocating and persisting the
buffer (same contract as the C implementation).

The `xmss_mt_state` (up to ~780 KB for max params) is handled identically.

### D5 — Algorithm layer is architecture-neutral

No x86-specific intrinsics (`#ROR`, `#BSWAP`, etc.) appear in any `.jinc` file
outside `src/hash/`. The algorithm layer uses only `+`, `-`, `^`, `&`, `|`,
`>>`, `<<`, and array accesses. This is the portability boundary — only
`src/hash/*.jinc` changes when targeting RISC-V.

### D6 — `#[secret]` on all secret material from entry points

Every `export fn` that handles secret key material must annotate the relevant
inputs `#[secret]` and call `#init_msf()` at entry. The compiler then
enforces that secret values do not reach branches or memory addresses. Any
declassification (`#declassify`) must be explicitly justified in a comment.

---

## 2. Scope

**Phase 1 (this blueprint targets)**: XMSS single-tree only (not XMSS-MT), with
SHA-256 (n=32) as the sole hash backend. This covers 3 parameter sets:
`XMSS-SHA2_10_256`, `XMSS-SHA2_16_256`, `XMSS-SHA2_20_256`.

XMSS-MT and additional hash backends (SHA-512, SHAKE-128, SHAKE-256) are
Phase 2 and Phase 3 work. The architecture must accommodate them without
rework.

---

## 3. Parameter encoding

### `param int` constants for each specialization

The following `param int` declarations appear at the top of each `.jazz` file
before any `require` directives. Values shown are for `XMSS-SHA2_10_256`.

```jasmin
param int N       = 32;   /* hash output size in bytes (n) */
param int W       = 16;   /* Winternitz parameter */
param int LOG2_W  = 4;    /* log2(W) */
param int LEN1    = 64;   /* ceil(8*N/LOG2_W) */
param int LEN2    = 3;    /* floor(log2(LEN1*(W-1))/LOG2_W) + 1 */
param int LEN     = 67;   /* LEN1 + LEN2 */
param int H       = 10;   /* per-tree height (tree_height in C params) */
param int IDX_BYTES = 4;  /* bytes to encode leaf index */
param int PAD_LEN = 32;   /* PRF padding length (= N for standard SHA-2 sets) */
```

For SHA-2 parameter sets, `PAD_LEN = N`. For the SHAKE parameter sets it
is also `N`. There are no non-standard pad lengths in the 12 RFC OIDs.

### Table of values for the 12 XMSS OIDs (Phase 1: SHA2/SHA512)

| Name                  | OID | N  | W  | LEN1 | LEN2 | LEN | H  | IDX_BYTES |
|-----------------------|-----|----|----|------|------|-----|----|-----------|
| XMSS-SHA2_10_256      | 1   | 32 | 16 | 64   | 3    | 67  | 10 | 4         |
| XMSS-SHA2_16_256      | 2   | 32 | 16 | 64   | 3    | 67  | 16 | 4         |
| XMSS-SHA2_20_256      | 3   | 32 | 16 | 64   | 3    | 67  | 20 | 4         |
| XMSS-SHA2_10_512      | 4   | 64 | 16 | 128  | 3    | 131 | 10 | 4         |
| XMSS-SHA2_16_512      | 5   | 64 | 16 | 128  | 3    | 131 | 16 | 4         |
| XMSS-SHA2_20_512      | 6   | 64 | 16 | 128  | 3    | 131 | 20 | 4         |
| XMSS-SHAKE_10_256     | 7   | 32 | 16 | 64   | 3    | 67  | 10 | 4         |
| XMSS-SHAKE_16_256     | 8   | 32 | 16 | 64   | 3    | 67  | 16 | 4         |
| XMSS-SHAKE_20_256     | 9   | 32 | 16 | 64   | 3    | 67  | 20 | 4         |
| XMSS-SHAKE_10_512     | 10  | 64 | 16 | 128  | 3    | 131 | 10 | 4         |
| XMSS-SHAKE_16_512     | 11  | 64 | 16 | 128  | 3    | 131 | 16 | 4         |
| XMSS-SHAKE_20_512     | 12  | 64 | 16 | 128  | 3    | 131 | 20 | 4         |

Note: all RFC 8391 XMSS parameter sets use `W=16`, so `LOG2_W=4` throughout.

### BDS retain-size constant

```jasmin
param int BDS_K          = 2;   /* retain parameter (even, 0 <= BDS_K <= H) */
param int RETAIN_NODES   = ...;  /* (2^BDS_K - BDS_K - 1); 0 if BDS_K <= 1 */
```

`RETAIN_NODES` for `BDS_K=2` is 1; for `BDS_K=4` it is 11. It must be
at least 1 (use 1 as the lower bound to avoid zero-size arrays).

The `BDS_K` value is fixed at compile time per specialization. The C
implementation accepts it as a runtime argument; the Jasmin implementation
bakes it in. The test harness will compile several `BDS_K` variants.

---

## 4. Data layout

### 4.1 ADRS

`xmss_adrs_t` is a `u32[8]` on the stack. It is always manipulated through
`inline fn` setters. Before passing to any hash function it is serialised to
a `u8[32]` stack buffer (big-endian, one `#BSWAP` per word).

Word indices (same as C `XMSS_ADRS_W_*` constants):

```
w[0]  layer
w[1]  tree address high (bits 63:32 of 64-bit tree index)
w[2]  tree address low  (bits 31:0)
w[3]  type (0=OTS, 1=LTREE, 2=HASH)
w[4]  type-specific field 0
w[5]  type-specific field 1
w[6]  type-specific field 2
w[7]  type-specific field 3
```

`set_type` must zero words 4–7 (RFC 8391 §2.5).

Type-specific fields by type:

| Type  | w[4]        | w[5]  | w[6]          | w[7]          |
|-------|-------------|-------|---------------|---------------|
| OTS   | OTS address | chain | hash (0 or 1 for key/mask) | — |
| LTREE | L-tree addr | height| tree index    | —             |
| HASH  | padding(0)  | height| tree index    | —             |

### 4.2 BDS state flat buffer layout

The BDS state is serialised as a flat `u8` buffer. Field offsets are
`param int` constants derived from `N`, `H`, and `BDS_K`.

```
Offset  Size              Field
------  ----------------  ----------------------------------------------
0       H*N               auth[0..H-1]: current auth path nodes
H*N     (H/2)*N           keep[0..H/2-1]: retained nodes from bds_round
(H + H/2)*N  (H+1)*N      stack[0..H]: BDS merge stack (node values)
(H + H/2 + H+1)*N  H+1   stack_levels[0..H]: height of each stack entry
... +4                    stack_offset: u32, number of valid entries on stack
... + TREEHASH_INST_SIZE*H  treehash[0..H-1]: treehash instances
... + RETAIN_NODES*N      retain[0..RETAIN_NODES-1]: top-k retained nodes
... + 4                   next_leaf: u32
```

Each treehash instance occupies `TREEHASH_INST_SIZE = N + 4 + 4 + 1 + 1`
bytes (node || target_h || next_idx || stack_usage || completed).

Define `param int` values for every field offset before writing `bds.jinc`.

**Total size formula** (call it `BDS_STATE_BYTES`):
```
BDS_STATE_BYTES =
    H*N             /* auth */
  + (H/2)*N         /* keep */
  + (H+1)*N         /* stack nodes */
  + (H+1)           /* stack_levels */
  + 4               /* stack_offset (u32) */
  + H*(N+4+4+1+1)   /* treehash instances */
  + RETAIN_NODES*N  /* retain */
  + 4               /* next_leaf (u32) */
```

The Jasmin `export fn` API takes a `reg u64 state` argument that points to
a caller-allocated buffer of exactly `BDS_STATE_BYTES` bytes. The C test
harness derives this size from the same formula.

All `inline fn` accessors use `(u8)[state + OFFSET]`, `(u32)[state + OFFSET]`,
or `(u64)[state + OFFSET]` as appropriate, with explicit little-endian ↔
big-endian handling where needed. Integers stored in the BDS state (heights,
indices, offsets) are stored in native (little-endian) byte order — they are
internal state, not serialised on the wire.

### 4.3 SK and PK layout

These live in caller-supplied `u8` buffers. The Jasmin code reads/writes them
using pointer arithmetic with `param int` offset constants derived from the
same formulas as `sk_offsets.h` in the C implementation:

```
SK: OID(4) | idx(IDX_BYTES) | SK_SEED(N) | SK_PRF(N) | root(N) | SEED(N)
    Total: 4 + IDX_BYTES + 4*N bytes

PK: OID(4) | root(N) | SEED(N)
    Total: 4 + 2*N bytes
```

Define `param int` SK/PK offset constants at the top of `xmss.jinc`.

---

## 5. Hash layer (`src/hash/`)

### 5.1 Required interface

Every hash backend must define the following `fn` symbols (not `export fn`
— they are called within Jasmin, not from C):

```jasmin
/* F: one-shot padding || key || adrs_bytes || in -> N bytes */
fn __xmss_F(reg u64 out, reg u64 key, reg u64 adrs_bytes, reg u64 inp)

/* H: one-shot padding || key || adrs_bytes || left || right -> N bytes */
fn __xmss_H(reg u64 out, reg u64 key, reg u64 adrs_bytes,
            reg u64 in_l, reg u64 in_r)

/* H_msg: padding || r || root || idx_bytes || msg -> N bytes
   msglen is a reg u64 because message length is variable */
fn __xmss_H_msg(reg u64 out, reg u64 r, reg u64 root,
                reg u64 idx_bytes_buf, reg u64 msg, reg u64 msglen)

/* PRF: padding || key || adrs_bytes -> N bytes */
fn __xmss_PRF(reg u64 out, reg u64 key, reg u64 adrs_bytes)

/* PRF_keygen: padding || sk_seed || pub_seed || adrs_bytes -> N bytes */
fn __xmss_PRF_keygen(reg u64 out, reg u64 sk_seed, reg u64 pub_seed,
                     reg u64 adrs_bytes)

/* PRF_idx: padding || sk_prf || idx_32bytes -> N bytes
   idx_32bytes is a pointer to a 32-byte big-endian index encoding */
fn __xmss_PRF_idx(reg u64 out, reg u64 sk_prf, reg u64 idx_32bytes)
```

In each case:
- `out` points to an `N`-byte output buffer
- All key/input pointer arguments point to `N`-byte buffers (except
  `msg` which is `msglen` bytes, and `idx_32bytes` which is 32 bytes)
- `adrs_bytes` points to a 32-byte serialised ADRS buffer

These signatures use only `reg u64` pointer arguments (not Jasmin arrays)
because the hash functions are called with pointers into larger buffers
(e.g., into the signature byte array) and Jasmin arrays have fixed sizes
that would require copying.

### 5.2 SHA-256 backend (`src/hash/sha256_n32.jinc`)

Start from the libjade `release/2023.05` SHA-256 implementation at
`src/crypto_hash/sha256/amd64/ref/`. Check whether the compression function
uses `#ROR` or the portable `(x >> n) | (x << (32-n))` pattern. If it uses
`#ROR`, note that this is x86-specific, but `#ROR` on 32-bit values in SHA-256
is fine for the Phase 1 x86-64 target. Document this in a comment so the
RISC-V porter knows to replace it.

For each of the six XMSS SHA-2 functions, implement as follows:

**`__xmss_F`** (RFC 8391 §5.1, F = 0x00):
```
input: N-byte padding prefix (toByte(0x00, N)) || N-byte key || 32-byte ADRS || N-byte in
```
Build the padded input in a stack buffer: `toByte(0, N) || key || adrs_bytes || in`.
Total input is `3N + 32` bytes. For N=32: 128 bytes = 2 × 64-byte SHA-256 blocks;
SHA-256 appends a third padding block (128 mod 64 = 0, so no room to append
the 0x80 bit in-band). Total: 3 SHA-256 compression calls.

**`__xmss_H`** (RFC 8391 §5.1, H = 0x01):
```
input: toByte(0x01, N) || key || adrs_bytes || in_l || in_r
```
Total: `4N + 32` bytes. For N=32: 160 bytes. 160 mod 64 = 32; padding fits in
the third block (32 < 56). Total: 3 SHA-256 compression calls.

**`__xmss_PRF`** (domain tag 0x03):
```
input: toByte(0x03, N) || key || adrs_bytes
```
Total: `2N + 32` bytes. For N=32: 96 bytes. 96 mod 64 = 32; padding fits in
the second block. Total: 2 SHA-256 compression calls. (No bitmask needed;
PRF output is determined solely by key and ADRS.)

**`__xmss_PRF_keygen`** (domain tag 0x04, RFC 8391 §4.1.11):
```
input: toByte(0x04, N) || sk_seed || pub_seed || adrs_bytes
```
Total: `2N + 32` bytes = 96 bytes for N=32. Same as PRF: 2 compression calls.

**`__xmss_PRF_idx`** (used for `r = PRF(SK_PRF, toByte(idx, 32))`):
```
input: toByte(0x03, N) || sk_prf || idx_32bytes
```
Total: `2N` bytes = 64 bytes for N=32. 64 mod 64 = 0; needs a dedicated padding
block. Total: 2 SHA-256 compression calls. (Same domain tag as PRF, different
message format.)

**`__xmss_H_msg`** (domain tag 0x02):
```
input: toByte(0x02, N) || r || root || toByte(idx, 32) || msg
```
Variable length (arbitrary `msglen`). The `idx_bytes_buf` argument is a
32-byte buffer pre-filled with `toByte(idx, 32)` (caller's responsibility).
Implement as an incremental SHA-256: init, absorb prefix (`3N + 32` bytes),
absorb `msg` in chunks, finalise.

### 5.3 SHA-512 backend (`src/hash/sha512_n64.jinc`)

Same structure as SHA-256, but `N=64`, using SHA-512 (512-bit compression
function). For N=64:
- F: `3*64 + 32 = 224` bytes input = 2 SHA-512 blocks
- H: `4*64 + 32 = 288` bytes input = 3 SHA-512 blocks (? check padding)
- PRF/PRF_keygen: `2*64 + 32 = 160` bytes = 2 SHA-512 blocks

Phase 2 work.

### 5.4 SHAKE backends (`src/hash/shake128_n32.jinc`, `shake256_n64.jinc`)

SHAKE-128 for N=32, SHAKE-256 for N=64. No bitmask operations in SHAKE
(unlike SHA-2). Same interface. Phase 2 work. Start from libjade Keccak-f[1600]
at `src/common/keccak/keccak1600/amd64/ref/`. Check portability of that
implementation before using it.

---

## 6. Algorithm layer

The algorithm `.jinc` files must use only the `param int` constants and
standard arithmetic. No architecture intrinsics. Functions are `fn` (internal)
unless specified as `export fn`.

### 6.1 `src/address.jinc`

All functions are `inline fn`. No `export fn`.

```jasmin
inline fn __adrs_set_layer(stack u32[8] adrs, reg u32 layer)
    -> stack u32[8]
    /* adrs[0] = layer */

inline fn __adrs_set_tree(stack u32[8] adrs, reg u64 tree)
    -> stack u32[8]
    /* adrs[1] = (u32)(tree >> 32); adrs[2] = (u32)(tree & 0xffffffff) */

inline fn __adrs_set_type(stack u32[8] adrs, inline int t)
    -> stack u32[8]
    /* adrs[3] = t; adrs[4]=adrs[5]=adrs[6]=adrs[7]=0 */

inline fn __adrs_set_ots(stack u32[8] adrs, reg u32 ots)
    -> stack u32[8]
    /* adrs[4] = ots  (type must be OTS) */

inline fn __adrs_set_chain(stack u32[8] adrs, reg u32 chain)
    -> stack u32[8]
    /* adrs[5] = chain */

inline fn __adrs_set_hash(stack u32[8] adrs, reg u32 h)
    -> stack u32[8]
    /* adrs[6] = h  (key_and_mask) */

inline fn __adrs_set_ltree(stack u32[8] adrs, reg u32 ltree)
    -> stack u32[8]
    /* adrs[4] = ltree  (type must be LTREE) */

inline fn __adrs_set_tree_height(stack u32[8] adrs, reg u32 height)
    -> stack u32[8]
    /* adrs[5] = height  (type must be HASH or LTREE) */

inline fn __adrs_set_tree_index(stack u32[8] adrs, reg u32 index)
    -> stack u32[8]
    /* adrs[6] = index  (type must be HASH or LTREE) */

inline fn __adrs_to_bytes(stack u32[8] adrs) -> stack u8[32]
    /* for i in 0..8: store adrs[i] in big-endian at bytes[4*i..4*i+3]
       use #BSWAP on u32 for x86-64 */
```

The `#BSWAP` in `__adrs_to_bytes` is the ONLY x86-specific operation in the
algorithm layer. It must be isolated. When porting to RISC-V, replace
`#BSWAP(w32)` with `((w >> 24) | ((w >> 8) & 0xff00) | ((w << 8) & 0xff0000) | (w << 24))`.
Comment this explicitly.

**Alternative for portability**: implement `__adrs_to_bytes` entirely without
`#BSWAP` by using byte-level writes. This is slightly slower on x86-64 but
ports for free. Let the implementer choose, but document the trade-off.

### 6.2 `src/utils.jinc`

```jasmin
/* Write val as len-byte big-endian into out[0..len-1].
   len must be a param int (known at compile time). */
inline fn __ull_to_bytes(reg u64 out, inline int len, reg u64 val)

/* Read len-byte big-endian from in[0..len-1] as u64.
   len must be a param int. */
inline fn __bytes_to_ull(reg u64 inp, inline int len) -> reg u64

/* Constant-time compare: return 0 if equal, non-zero if different.
   len must be a param int.
   Must not use secret-dependent branches — OR all byte differences. */
inline fn __ct_memcmp(reg u64 a, reg u64 b, inline int len) -> reg u64

/* Zero a buffer. len must be a param int. */
inline fn __memzero(reg u64 ptr, inline int len)
```

**CT obligation for `__ct_memcmp`**: The loop accumulates `acc |= (a[i] ^ b[i])`
using `reg u8` or `reg u64` chunks. The final test `acc != 0` is the only
branch and its result is returned as a public integer. Mark input pointers
`#[secret]` at the call site in `xmss.jinc` where roots are compared.

### 6.3 `src/wots.jinc`

Internal functions only. No `export fn`.

**`__base_w`** (RFC 8391 Algorithm 1):
```jasmin
/* Extract LEN1 base-W digits from an N-byte input.
   out is a stack u32[LEN] (only first LEN1 entries filled).
   in is a reg u64 pointer to N bytes. */
fn __base_w(reg u64 inp) -> stack u32[LEN]
```
Loop: `for i = 0 to LEN1`. Each byte of `inp` yields `8/LOG2_W` digits.
For W=16 (LOG2_W=4): each byte gives 2 digits. The loop processes one
byte per 2 output digits.

No secret-dependent branches. `inp` (the message hash) is public in the
context of `wots_sign` because it's derived from `H_msg` which produces a
public-ish value... Actually: the message hash is the input to WOTS+ signing.
The chain iteration count derived from it determines how many times each chain
is applied. **This count is public** — it depends on the message (public after
signing), not on the secret key. Verify this is consistent with RFC 8391. Yes:
the chain lengths are derived from the message hash, which becomes public in
the signature (the verifier also computes them). So `base_w` output is public.

**`__wots_checksum`** (appends len2 checksum digits):
```jasmin
/* msg_and_csum is a stack u32[LEN] with [0..LEN1-1] already filled.
   Fills [LEN1..LEN-1] with the checksum in base W.
   Returns the filled array. */
inline fn __wots_checksum(stack u32[LEN] msg_and_csum) -> stack u32[LEN]
```
Compute `csum = sum(W-1 - msg_and_csum[i])` for i in 0..LEN1-1.
`csum` is at most `LEN1 * (W-1) = 64 * 15 = 960` for N=32; fits in u32.
Left-shift by `(8 - (LEN2 * LOG2_W % 8)) % 8` bits. For standard params
(LEN2=3, LOG2_W=4): shift by `(8 - 12%8)%8 = (8-4)%8 = 4`. Write
`(LEN2 * LOG2_W + 7)/8 = 2` bytes big-endian. Then call `__base_w` on those
2 bytes to produce LEN2=3 digits? No — call `base_w` on the csum bytes to
fill positions LEN1..LEN-1. Implement `base_w` to accept an arbitrary
starting offset, or inline the extraction.

**`__gen_chain`** (RFC 8391 Algorithm 2 — compute chain from start for steps):
```jasmin
/* Apply F repeatedly, starting at `start`, for `steps` steps.
   input/output: N-byte node (in-place update).
   adrs: stack u32[8] with chain/type fields set by caller.
   seed: pointer to N bytes (public seed).
   Loop count `start+steps` <= W (public — message-derived). */
fn __gen_chain(stack u8[N] node, reg u32 start, reg u32 steps,
               reg u64 seed, stack u32[8] adrs)
    -> stack u8[N]
```
Loop `for i = start to start+steps` is NOT a static `for` (bounds are runtime
values). Use a `while` loop: `while (start < start+steps)`. Actually in Jasmin,
`while (count < steps)` where `count` starts at 0 and increments. The bound
`steps` is public (message-derived). Must not be secret. Mark accordingly.

Inside the loop:
1. Set `adrs` chain_hash word to `start + count` (the current step index)
2. Set `adrs` hash word to 0 (key), compute `key = PRF(seed, adrs_bytes)`
3. Set `adrs` hash word to 1 (bitmask), compute `bitmask = PRF(seed, adrs_bytes)`
4. `node[i] ^= bitmask[i]` for each byte
5. Call `__xmss_F(node, key, adrs_bytes_for_F, node)`

Wait — re-read the C implementation `wots.c` more carefully for the exact
call pattern. The C implementation (`gen_chain`) updates the ADRS set_hash
word before each PRF call. The F function receives the ADRS with key_and_mask
set. This is the SHA-2 path; SHAKE does not use bitmasks. The hash backend
handles this detail — the algorithm layer just calls `__xmss_F`.

Actually re-reading `hash_iface.h`: `xmss_F(p, out, key, adrs, in)` — the key
and bitmask computation is INSIDE `xmss_F`, not visible to the algorithm layer.
The C `xmss_F` internally calls PRF twice (with key_and_mask=0,1), XORs the
input, then hashes. So the algorithm layer just calls `__xmss_F` with the raw
node value and the hash backend handles the bitmask internally.

Consequence: `__gen_chain` just calls `__xmss_F` in a loop; no bitmask logic
in the algorithm layer.

```jasmin
fn __gen_chain(stack u8[N] node, reg u32 start, reg u32 steps,
               reg u64 seed, stack u32[8] adrs)
    -> stack u8[N]
{
  /* stack buffers for F's in/out */
  stack u8[N] out;
  stack u8[32] adrs_bytes;
  reg u32 i;
  i = 0;
  while (i < steps) {
      adrs = __adrs_set_hash(adrs, start + i);   /* chain position */
      adrs_bytes = __adrs_to_bytes(adrs);
      out = /* __xmss_F(seed, adrs_bytes, node) */;
      node = out;
      i += 1;
  }
  return node;
}
```

(The exact Jasmin for calling `__xmss_F` with pointer arguments needs care —
see Section 8.)

**`__wots_expand_seed`** (RFC 8391 Algorithm 3):
```jasmin
/* Generate len secret chain seeds from sk_seed and seed.
   Output: LEN nodes of N bytes each. */
fn __wots_expand_seed(reg u64 out, reg u64 sk_seed, reg u64 seed,
                      stack u32[8] adrs)
```
Loop `for i = 0 to LEN`: call `__xmss_PRF_keygen(out + i*N, sk_seed, seed, adrs_bytes)`.
This loop count is `LEN` (a `param int`), so it is a `for` loop.

**`__wots_gen_pk`** (RFC 8391 Algorithm 4):
```jasmin
fn __wots_gen_pk(reg u64 pk, reg u64 sk_seed, reg u64 seed,
                 stack u32[8] adrs)
```
1. Expand seed to get LEN chain seeds (local buffer of LEN*N bytes)
2. For each chain i (for i = 0 to LEN): apply gen_chain from 0 for W-1 steps

**`__wots_sign`** (RFC 8391 Algorithm 5):
```jasmin
fn __wots_sign(reg u64 sig, reg u64 msg, reg u64 sk_seed, reg u64 seed,
               stack u32[8] adrs)
```
`msg` points to N bytes (the message hash). Apply base_w + checksum. Then
for each chain i: gen_chain from `msg_base_w[i]` for `W-1-msg_base_w[i]` steps.

**CT note**: `msg_base_w[i]` determines `start` in gen_chain. This value is
message-derived (public). The number of hash calls per chain is `W-1-start`,
also public. No secret-dependent loop count.

**`__wots_pk_from_sig`** (RFC 8391 Algorithm 6):
```jasmin
fn __wots_pk_from_sig(reg u64 pk, reg u64 sig, reg u64 msg,
                      reg u64 seed, stack u32[8] adrs)
```
Same as gen_pk but `start = msg_base_w[i]`, `steps = W-1-msg_base_w[i]`.

### 6.4 `src/ltree.jinc`

**`__l_tree`** (RFC 8391 Algorithm 8):
```jasmin
fn __l_tree(reg u64 out, reg u64 pk, reg u64 seed, stack u32[8] adrs)
```
`pk` points to LEN*N bytes (WOTS+ public key). `out` receives N bytes (leaf).
Uses a local stack of LEN nodes, merged pairwise via `__xmss_H` from bottom up.
Loop height from 0 to `ceil(log2(LEN))`. At each height, XOR+hash pairs.
The loop bound is `ceil_log2(LEN)` — a `param int`. The inner loop count
decreases: `ceil(current_len / 2)`. Use while loops for inner, for loop for outer.

**Odd-element handling**: when current level has odd count, the last element
is carried up unchanged (not hashed). This is a branch on a public value
(the parity of the current level's count, which is determined by `LEN` which
is a `param int`). No CT issue.

### 6.5 `src/treehash.jinc`

**`__treehash`** (RFC 8391 Algorithm 9 — naive, direct):
```jasmin
fn __treehash(reg u64 root, reg u64 sk_seed, reg u64 seed,
              reg u32 s, reg u32 t, stack u32[8] adrs)
```
`s` is start leaf index (0 for full tree), `t` is number of leaves (2^H for
full tree). Uses a local stack of H+1 nodes plus H+1 level indicators.
For each leaf l from s to s+t-1:
1. Generate leaf: `gen_leaf(leaf, sk_seed, seed, s+l, adrs)`
2. Merge with stack as far as possible (same height)
Output: root in `root[0..N-1]`.

Note: `t` is a public runtime value (it equals `1 << H` for full-tree calls,
passed as a reg u32). The loop count is `t`, which is large (`2^10 = 1024`
for h=10). This is fine — it is public.

**`__gen_leaf`** (internal helper, not in C headers):
```jasmin
fn __gen_leaf(reg u64 out, reg u64 sk_seed, reg u64 seed,
              reg u32 leaf_idx, stack u32[8] adrs)
```
1. Copy adrs, set type=OTS, ots=leaf_idx; call `__wots_gen_pk`
2. Copy adrs, set type=LTREE, ltree=leaf_idx; call `__l_tree`

**`__compute_root`** (used in verify — Algorithm 14 step):
```jasmin
fn __compute_root(reg u64 root, reg u64 leaf, reg u32 leaf_idx,
                  reg u64 auth, reg u64 seed, stack u32[8] adrs)
```
Walk auth path: at each height h, hash `(node, auth[h*N])` or
`(auth[h*N], node)` depending on the bit of `leaf_idx` at position h.
The bit test `(leaf_idx >> h) & 1` is on a public value (idx is in the
signature, which is public). No CT issue.

### 6.6 `src/bds.jinc`

This is the most complex file. Defines `inline fn` field accessors and the
four BDS operations.

#### Field accessors

Using the flat buffer layout from Section 4.2, define:

```jasmin
inline fn __bds_auth_node(reg u64 state, inline int level)
    -> reg u64  /* pointer to N-byte auth node at given level */

inline fn __bds_keep_node(reg u64 state, inline int level)
    -> reg u64

inline fn __bds_stack_node(reg u64 state, reg u32 off)
    -> reg u64  /* off is a runtime value (stack_offset) */

inline fn __bds_stack_level_get(reg u64 state, reg u32 off)
    -> reg u8

inline fn __bds_stack_level_set(reg u64 state, reg u32 off, reg u8 level)

inline fn __bds_stack_offset_get(reg u64 state) -> reg u32
inline fn __bds_stack_offset_set(reg u64 state, reg u32 off)

/* Treehash instance access */
inline fn __th_node(reg u64 state, inline int i) -> reg u64
inline fn __th_target_h_get(reg u64 state, inline int i) -> reg u32
inline fn __th_next_idx_get(reg u64 state, inline int i) -> reg u32
inline fn __th_next_idx_set(reg u64 state, inline int i, reg u32 v)
inline fn __th_stack_usage_get(reg u64 state, inline int i) -> reg u8
inline fn __th_stack_usage_set(reg u64 state, inline int i, reg u8 v)
inline fn __th_completed_get(reg u64 state, inline int i) -> reg u8
inline fn __th_completed_set(reg u64 state, inline int i, reg u8 v)

inline fn __bds_retain_node(reg u64 state, inline int i) -> reg u64
inline fn __bds_next_leaf_get(reg u64 state) -> reg u32
inline fn __bds_next_leaf_set(reg u64 state, reg u32 v)
```

Note: `inline int` parameters restrict these to call sites where the index is
a compile-time constant. For runtime-indexed access (e.g., stack_offset-based
access), the arithmetic must be done explicitly.

#### `__bds_treehash_init`

This is the BDS-augmented keygen treehash (replaces C `bds_treehash_init`).
It runs Algorithm 9 on the full tree while capturing BDS state.

```jasmin
fn __bds_treehash_init(reg u64 root, reg u64 state,
                       reg u64 sk_seed, reg u64 seed,
                       stack u32[8] adrs)
```

The algorithm (Algorithm 9 modified for BDS) is described in
"Post-Quantum Cryptography" (Buchmann-Dahmen-Szydlo) and the BDS paper.
The key behaviour:
- Traverses all 2^H leaves
- At each leaf, updates the auth path (right-sibling capture), the treehash
  instances, and the retain stack
- At the end, `state->auth` contains the auth path for leaf index 0

See C `bds.c:bds_treehash_init` for the reference implementation. Translate
structurally, replacing struct field accesses with inline fn calls.

The treehash instances are initialised: `th[i].h = i`, `th[i].next_idx = 1 << i`,
`th[i].completed = 0`, for i in 0 .. H-1-BDS_K (those below the k top levels).

#### `__bds_round`

Called after each signature (after copying auth path). Updates `state->auth`
to contain the auth path for the next leaf.

```jasmin
fn __bds_round(reg u64 state, reg u32 leaf_idx,
               reg u64 sk_seed, reg u64 seed,
               stack u32[8] adrs)
```

Translate C `bds_round` structurally.

#### `__bds_treehash_update`

Runs `updates` leaf computations distributed across the treehash instances.

```jasmin
fn __bds_treehash_update(reg u64 state, reg u32 updates,
                         reg u64 sk_seed, reg u64 seed,
                         stack u32[8] adrs)
```

#### `__bds_state_update`

Used by XMSS-MT only (Phase 2). Can be stubbed in Phase 1.

### 6.7 `src/xmss.jinc`

**`__xmss_keygen`**:
```jasmin
/* seeds: pointer to 3*N random bytes (SK_SEED || SK_PRF || SEED)
   Returns 0 on success.
   sk_seed = seeds[0..N-1]
   sk_prf  = seeds[N..2N-1]
   pub_seed = seeds[2N..3N-1] */
fn __xmss_keygen(reg u64 pk, reg u64 sk, reg u64 state, reg u64 seeds)
    -> reg u64
```
1. Init ADRS to zero; set layer=0, tree=0
2. Call `__bds_treehash_init(root, state, seeds, seeds+2N, adrs)`
3. Serialise PK: `OID(4) | root(N) | SEED(N)`
4. Serialise SK: `OID(4) | 0(IDX_BYTES) | SK_SEED(N) | SK_PRF(N) | root(N) | SEED(N)`
5. Memzero the seeds buffer (`__memzero`)
6. Return 0

The OID is a `param int` (compile-time constant per specialization).

**`__xmss_sign`**:
```jasmin
fn __xmss_sign(reg u64 sig, reg u64 msg, reg u64 msglen,
               reg u64 sk, reg u64 state)
    -> reg u64  /* 0 = ok, negative = error */
```
1. Read idx from SK (IDX_BYTES bytes, big-endian)
2. If idx > IDX_MAX (a `param int`): return error code
3. Increment idx in SK immediately (write IDX_BYTES bytes big-endian)
4. Compute `r = PRF_idx(sk_prf, idx)`  — `r` is N bytes
5. Compute `m_hash = H_msg(r, root, toByte(idx,32), msg, msglen)` — N bytes
6. Serialise sig prefix: `ull_to_bytes(sig, IDX_BYTES, idx); sig[IDX_BYTES..] = r`
7. WOTS+ sign: call `__wots_sign(sig + IDX_BYTES + N, m_hash, sk_seed, pub_seed, adrs)`
8. Copy auth path from BDS state into sig (H*N bytes)
9. Call `__bds_round(state, (u32)idx, sk_seed, pub_seed, adrs)`
10. Call `__bds_treehash_update(state, (H-BDS_K)/2, sk_seed, pub_seed, adrs)`
11. Return 0

**CT obligation**: idx (read from SK) is secret until it is written into the
signature (step 6), at which point it becomes public. Steps 2–3 involve a
branch on idx — this is unavoidable (must not sign with exhausted key).
Mark idx `#[secret]` initially, then `#declassify` before the comparison? No —
the comparison IS security-critical but it is on a monotone counter. The
result of the comparison is a public fact (either we sign or we return an
error — the caller knows). Use `#declassify` with a comment that the counter
value leaks at most to the error return path, which is acceptable.

Actually: the leaf index is included in the signature in plaintext, so it is
public from the moment of signing. The RFC requires the signer to leak the
index. `#declassify(idx)` after reading is correct.

**`__xmss_verify`**:
```jasmin
fn __xmss_verify(reg u64 msg, reg u64 msglen,
                 reg u64 sig, reg u64 pk)
    -> reg u64  /* 0 = ok, negative = invalid */
```
1. Validate PK OID (compare first 4 bytes to `param int OID`)
2. Extract idx from sig (IDX_BYTES bytes, big-endian); check `idx <= IDX_MAX`
3. Extract r from sig (N bytes)
4. `m_hash = H_msg(r, pk_root, toByte(idx,32), msg, msglen)`
5. WOTS+ pk recovery: `__wots_pk_from_sig(wots_pk, sig_wots, m_hash, pk_seed, adrs)`
6. L-tree: `__l_tree(leaf, wots_pk, pk_seed, adrs)`
7. Compute root: `__compute_root(computed_root, leaf, idx, auth, pk_seed, adrs)`
8. CT compare: `__ct_memcmp(computed_root, pk_root, N)` — return 0 iff equal

**CT obligation**: the computed root and pk_root are both public. The
comparison result is public (valid/invalid). `ct_memcmp` is required to
prevent timing oracle on which byte differed. No `#[secret]` annotation
needed on the root values, but the implementation of `ct_memcmp` must not
branch on individual bytes.

### 6.8 `src/xmssmt.jinc`

Phase 2. Covers XMSS-MT keygen, sign, verify with the hypertree structure.

---

## 7. Export ABI (`.jazz` files)

Top-level `.jazz` files define `export fn` symbols with the C calling
convention. One `.jazz` file per parameter set.

### Naming convention

```
src/xmss_sha2_10_256.jazz    XMSS-SHA2_10_256 (OID 0x01)
src/xmss_sha2_16_256.jazz    XMSS-SHA2_16_256 (OID 0x02)
src/xmss_sha2_20_256.jazz    XMSS-SHA2_20_256 (OID 0x03)
...
```

### Export function signatures

```jasmin
/* Key generation.
   pk:    output, 4+2*N bytes
   sk:    output, 4+IDX_BYTES+4*N bytes
   state: output, BDS_STATE_BYTES bytes (caller-allocated)
   seeds: input, 3*N bytes of caller-generated randomness
   Returns 0 on success. */
export fn jade_xmss_keypair(reg u64 pk sk state seeds) -> reg u64

/* Signing.
   sig:    output, IDX_BYTES+N+LEN*N+H*N bytes
   msg:    input, msglen bytes
   msglen: message length
   sk:     input/output (leaf index incremented in place)
   state:  input/output (BDS state updated)
   Returns 0 on success, -1 if key exhausted. */
export fn jade_xmss_sign(reg u64 sig msg msglen sk state) -> reg u64

/* Verification. Stateless.
   msg, msglen: message
   sig: signature
   pk:  public key
   Returns 0 if valid, -1 if invalid. */
export fn jade_xmss_verify(reg u64 msg msglen sig pk) -> reg u64
```

Each `export fn` body:
1. Calls `_ = #init_msf();`
2. Calls the corresponding `__xmss_*` internal function
3. Returns the result

The internal functions handle all logic; the export wrapper is minimal.

### C header for test harness

Each compiled parameter set gets a corresponding C header, e.g.,
`test/xmss_sha2_10_256.h`:

```c
/* Auto-generated or manually written: declarations for the Jasmin exports */
#define JADE_XMSS_SHA2_10_256_PK_BYTES   (4 + 2*32)
#define JADE_XMSS_SHA2_10_256_SK_BYTES   (4 + 4 + 4*32)
#define JADE_XMSS_SHA2_10_256_SIG_BYTES  (4 + 32 + 67*32 + 10*32)
#define JADE_XMSS_SHA2_10_256_BDS_BYTES  /* computed */

int jade_xmss_keypair(uint8_t *pk, uint8_t *sk, uint8_t *state,
                      const uint8_t *seeds);
int jade_xmss_sign(uint8_t *sig, const uint8_t *msg, size_t msglen,
                   uint8_t *sk, uint8_t *state);
int jade_xmss_verify(const uint8_t *msg, size_t msglen,
                     const uint8_t *sig, const uint8_t *pk);
```

---

## 8. Calling hash functions from algorithm code

The hash backend `fn`s take `reg u64` pointer arguments. The algorithm code
has data in `stack u8[N]` local arrays. To pass a stack array to a function
expecting `reg u64`:

```jasmin
stack u8[N] node;
stack u8[32] adrs_bytes;
reg u64 node_ptr;
node_ptr = (u64) &node;   /* take address of stack array */
__xmss_F(out_ptr, seed_ptr, adrs_bytes_ptr, node_ptr);
```

Taking the address of a stack variable (`(u64) &var`) is valid in Jasmin.
Be careful: after `__xmss_F` writes to `out_ptr` (which may alias `node_ptr`),
the Jasmin compiler may not know about the alias — use separate buffers for
input and output in `gen_chain`.

---

## 9. Build system

### Directory structure (final)

```
impl/jasmin/
  blueprint.md                      (this file)
  CLAUDE.md
  jasmin-reference.md
  Makefile
  src/
    address.jinc
    utils.jinc
    wots.jinc
    ltree.jinc
    treehash.jinc
    bds.jinc
    xmss.jinc
    xmssmt.jinc                     (Phase 2)
    hash/
      sha256_n32.jinc               (SHA-256, N=32)
      sha512_n64.jinc               (SHA-512, N=64, Phase 2)
      shake128_n32.jinc             (SHAKE-128, N=32, Phase 2)
      shake256_n64.jinc             (SHAKE-256, N=64, Phase 2)
    xmss_sha2_10_256.jazz
    xmss_sha2_16_256.jazz
    xmss_sha2_20_256.jazz
    ... (one per param set)
  test/
    test_utils.c                    (compile-time size checks, ct_memcmp test)
    test_wots.c                     (WOTS+ sign/verify roundtrip vs C impl)
    test_xmss_sha2_10_256.c         (keygen/sign/verify roundtrip + KAT)
    ... (one per param set)
  proof/                            (EasyCrypt — later)
```

### Makefile sketch

```makefile
JASMINC  ?= jasminc
ARCH     ?= x86-64
CFLAGS   ?= -O2 -Wall -Wextra -Werror

SETS := sha2_10_256 sha2_16_256 sha2_20_256

SOURCES := $(patsubst %,src/xmss_%.jazz,$(SETS))
ASM     := $(patsubst %.jazz,%.s,$(SOURCES))

all: $(ASM)

src/xmss_%.s: src/xmss_%.jazz src/xmss.jinc src/bds.jinc \
              src/wots.jinc src/ltree.jinc src/treehash.jinc \
              src/address.jinc src/utils.jinc src/hash/sha256_n32.jinc
	$(JASMINC) -arch $(ARCH) $< -o $@

# CT check target
ct: $(SOURCES)
	$(JASMINC) -arch $(ARCH) -CT $<

test: $(ASM) test/test_xmss_sha2_10_256
	./test/test_xmss_sha2_10_256

clean:
	rm -f src/*.s test/test_*
```

---

## 10. Test strategy

### Phase gates

Each phase must pass its tests before starting the next phase.

| Phase | Tests to pass before proceeding |
|-------|----------------------------------|
| Hash  | SHA-256 FIPS 180-4 vectors (reuse C `test_hash` expected values) |
| ADRS + utils | Manual inspection of `__adrs_to_bytes` output; ct_memcmp unit test |
| WOTS+ | Sign→pkFromSig roundtrip for n=32; compare leaf output against C impl for same seeds |
| L-tree | Output of `l_tree(wots_gen_pk(...))` matches C `gen_leaf` for same params |
| Treehash + verify | `xmss_verify` accepts signatures produced by the C `xmss_sign` for same parameter set (cross-impl verify) |
| Keygen + sign | Jasmin keygen → Jasmin sign → Jasmin verify roundtrip; also Jasmin sign → C verify and C sign → Jasmin verify |
| KAT | Outputs match C KAT fingerprints from `test_xmss_kat` |

### Cross-implementation verification

The C implementation is the reference. The primary correctness test is:

1. C keygen → Jasmin verify (does Jasmin verify accept a C-produced signature?)
2. Jasmin keygen → C verify (does C verify accept a Jasmin-produced signature?)
3. Jasmin keygen → Jasmin sign → Jasmin verify roundtrip

For (1) and (2), use the same seeds (pass the 3n-byte seed buffer to Jasmin
keygen, and to C keygen via the `randombytes` stub that returns a fixed buffer).

### CT check

Run `jasminc -CT` on every `.jazz` file before declaring a phase complete.
Any CT violation is a blocker.

### Test harness structure

C test files link against the compiled `.s` files. They use the same
`test_randombytes` / `test_rng_reset` infrastructure as the C tests
(`impl/c/test/test_utils.h`) to get deterministic seeds. Include that header
directly (the C test utilities are reusable).

---

## 11. Implementation order

Work through the following items in order. Each item has a clear completion
criterion.

1. **SHA-256 backend** (`src/hash/sha256_n32.jinc`)
   - Done when: FIPS 180-4 vectors pass.

2. **`address.jinc`**
   - Done when: `__adrs_to_bytes(zero_adrs)` produces 32 zero bytes;
     `__adrs_set_type` followed by `__adrs_to_bytes` matches C reference output.

3. **`utils.jinc`**
   - Done when: `__ct_memcmp` passes CT check and correctly distinguishes equal
     vs different buffers; `__ull_to_bytes`/`__bytes_to_ull` match C for
     8-byte values.

4. **`wots.jinc`**
   - Done when: WOTS+ sign→pkFromSig roundtrip passes for fixed seeds (n=32).
     Cross-check output of `__wots_gen_pk` against C for same seed.

5. **`ltree.jinc`**
   - Done when: output of `__l_tree(wots_gen_pk(...))` matches C `gen_leaf`
     for same inputs.

6. **`treehash.jinc` — `__compute_root` only**
   - Done when: `__compute_root` produces expected root given a known leaf +
     auth path (use C-generated data).

7. **`xmss.jinc` — `__xmss_verify` only (stateless, no BDS)**
   - Done when: Jasmin verify accepts signatures produced by C sign.

8. **`treehash.jinc` — `__treehash`**
   - Done when: `__treehash(root, ...)` matches C `treehash(...)` output for
     n=32, h=10, s=0, t=1024.

9. **`bds.jinc` — `__bds_treehash_init`**
   - Done when: root from `__bds_treehash_init` matches C `bds_treehash_init`.
     Auth path at index 0 matches.

10. **`bds.jinc` — `__bds_round` + `__bds_treehash_update`**
    - Done when: auth path after 20 BDS rounds matches C state for n=32, h=10.

11. **`xmss.jinc` — `__xmss_keygen` + `__xmss_sign`**
    - Done when: full keygen→sign→verify roundtrip passes (all three
      cross-impl combinations).

12. **KAT cross-validation**
    - Done when: Jasmin output matches existing C KAT fingerprints.

13. **CT check pass**
    - Done when: `jasminc -CT` passes on all `.jazz` files with no violations.

14. **Additional parameter sets (h=16, h=20)**
    - Add two more `.jazz` files, reusing all `.jinc` files unchanged.

---

## 12. Open questions (for Opus to resolve during implementation)

1. **`#BSWAP` in `__adrs_to_bytes`**: Use `#BSWAP` (x86-only, fast) or
   portable byte-level writes? Recommendation: use `#BSWAP` with a comment
   tagging it as the RISC-V portability point, then write a portable alternative
   in a comment.

2. **Stack depth in `bds.jinc`**: Some BDS operations allocate substantial
   stack space (auth path: H*N bytes; stack: (H+1)*N bytes). For h=20, n=32:
   auth is 640 bytes, stack is 672 bytes — both fine for Jasmin. Verify Jasmin
   does not hit stack-size limits for the n=64 cases.

3. **`BDS_K` exposure**: The C API accepts `bds_k` at runtime; the Jasmin API
   bakes it in as a `param int`. The test harness must compile a separate `.s`
   for each `(param_set, bds_k)` combination tested. For the Phase 1 test
   suite, fix `BDS_K = 2` unless there is a specific reason to test `BDS_K = 4`.

4. **Error handling in export fns**: The C API returns negative int codes. In
   Jasmin, `reg u64` return values are unsigned. Use `(reg u64)(-1)` (all-ones)
   for error, 0 for success, consistent with what the C test harness checks
   as non-zero.
