---
name: jasmin-lang
description: >
  Write and modify Jasmin (.jazz / .jinc) cryptographic assembly code.
  Trigger when working with .jazz or .jinc files, jasminc compilation,
  Jasmin type system (reg, stack, reg ptr, inline fn), or x86-64 intrinsics
  like #ROR_32, #BSWAP_32, #set0. Also trigger for XMSS hash functions,
  WOTS+, or ADRS manipulation in Jasmin.
tools: Read, Edit, Write, Bash, Glob, Grep
---

# Jasmin Language

Jasmin is a language for writing formally verified cryptographic assembly. Source `.jazz` files compile to native `.s` assembly via `jasminc`. The formal semantics enable machine-checked proofs in EasyCrypt.

## File conventions

- `.jazz` — compilation unit. Contains `export fn` wrappers and `require` statements.
- `.jinc` — included file. Contains algorithm logic. Not compiled directly.

```jasmin
// foo.jazz
require "foo.jinc"

export fn my_function(reg u64 out inp len) -> reg u64 {
  reg u64 r;
  _ = #init_msf();
  __my_function_impl(out, inp, len);
  ?{}, r = #set0();
  return r;
}
```

## Build

```bash
jasminc -arch x86-64 foo.jazz -o foo.s
gcc -o foo foo.c foo.s -no-pie
```

## Types

```jasmin
bool                    // condition flag
u8  u16  u32  u64      // unsigned integers
int                     // compile-time only (inline int / param)

// Storage qualifiers
reg u64                 // register variable
stack u8[32]            // stack-allocated fixed array
reg ptr u8[32]          // register holding pointer to stack array
stack ptr u8[32]        // stack slot holding pointer (survives calls)

// Compile-time constants
param int N = 32;       // usable as array size, loop bound
```

## Functions

```jasmin
fn __my_fn(reg u64 x) -> reg u64 { ... }              // generates call
inline fn __helper(inline int n, reg u64 x) -> reg u64 { ... }  // inlined
export fn my_api(reg u64 out inp len) -> reg u64 { ... }        // C ABI
```

### Function rules

- Multiple returns: `fn foo() -> reg u64, reg u64 { return a, b; }`
- Discard returns: `_, r = some_fn();`
- Flags: `?{cf, zf}, r = #ADD(a, b);` or `?{}, r = #set0();`
- **Non-inline `fn` params must be `reg` or `reg ptr`** — not `stack`. Convert:
  ```jasmin
  stack u8[64] blk;
  reg ptr u8[64] blkp;
  blkp = blk;              // convert stack to reg ptr
  state = __compress(state, blkp);
  ```
- **No early returns** — `return` must be at function end, not inside `if`/`while`
- **No recursion, no goto, no function pointers**

## Control flow

```jasmin
for i = 0 to 64 { ... }           // inline int i; compile-time bounds
while (cond) { ... }               // runtime condition
if (x == 0) { ... } else { ... }
```

Loop bounds must be public (not secret-dependent).

## Array access

### Named arrays — element access (compile-time index)
```jasmin
// Plain index — i must be inline int
H[0] = 0x6a09e667;
tmp = W[t-2];

// [:TYPE i] syntax — element access, TYPE must match array element type
blk[:u64 i] = v;       // write i-th u64 of blk
tmp = block[:u32 i];   // read i-th u32 of block
```

### Pointer-based memory access (byte offset)
Two equivalent notations — both work, `[:TYPE ...]` is the newer form:
```jasmin
v = [:u64 src + 8 * i];      // new: load u64 at byte offset 8*i
[:u8 out + i] = b;            // new: store byte at byte offset i
v = (u64)[src + 8 * i];      // old: same thing (seen in libjade)
(u32)[out + i*4] = v;         // old: same thing
```

### Runtime array indexing
When the index is a `reg` variable (not `inline int`), cast it with `(int)`:
```jasmin
tmp = Kp[(int)tr];            // reg ptr u32[64] Kp; reg u64 tr
tmp = W[(int)tr];             // stack u32[64] W; reg u64 tr
sblocks[u8 (int)i] = v;      // byte-level write into u32 array
```

## Operators and intrinsics

```jasmin
// Arithmetic: +, -, *, &, |, ^, !, >>, <<
r = (32u)x;                    // truncate to 32 bits
r = (64u)x;                    // zero-extend to 64 bits
r = (uint)x;                   // coerce type in expression context

// x86 intrinsics — ALWAYS capture ALL return values
_, _, r = #ROR_32(x, 3);       // rotate right 32 → (OF, CF, result)
_, _, r = #ROL_32(x, 3);       // rotate left 32 → (OF, CF, result)
r = #BSWAP_32(r);              // byte-swap u32 → result only
r = #BSWAP_64(r);              // byte-swap u64 → result only
?{}, r = #set0();              // xor reg,reg (zero, no dependency)
_ = #init_msf();               // Spectre v1 init (required at export fn entry)
```

Run `jasminc -help-intrinsics` to list all intrinsics.

## Global arrays

```jasmin
u32[64] SHA256_K = { 0x428a2f98, 0x71374491, ... };

// Compile-time index:
tmp = SHA256_K[i];         // inline int i

// Runtime index — requires reg ptr:
reg ptr u32[64] Kp;
Kp = SHA256_K;
tmp = Kp[(int)tr];         // reg u64 tr
```

## Pitfalls

### Zero-extend into compound operation
x86 can't zero-extend and OR in one instruction:
```jasmin
// WRONG: diff |= (64u)byte_val;     // asmgen error
tmp = (64u)byte_val; diff |= tmp;    // RIGHT
```

### `ptr` is a keyword
Use `p`, `outp`, `blkp` — never `ptr` as a variable name.

### Shift destroys the original value
```jasmin
// WRONG: hi = (32u)(tree >> 32); lo = (32u)tree;  // tree already shifted
lo = (32u)tree; hi64 = tree; hi64 >>= 32; hi = (32u)hi64;  // RIGHT
```

### Preserve `reg ptr` across calls
`reg ptr` is clobbered by function calls. Spill to `stack ptr`:
```jasmin
stack ptr u32[8] Hp;
Hp = H;                // save before call
// ... call ...
H = Hp;                // restore
```

## Design patterns

### Two-tier hash pattern
Non-inline `fn` can't take/return `stack` arrays. Split into:
1. **Internal `inline fn`**: works with `stack` arrays, returns `stack` result
2. **External `fn`**: takes `reg u64` pointers, copies data in/out

```jasmin
inline fn __sha256_hash96(stack u8[96] ibuf) -> stack u8[N] { ... }

fn __xmss_PRF(reg u64 out, reg u64 key, reg u64 adrs_bytes) {
  stack u8[N] result;
  result = __sha256_prf_internal(0x03, key, adrs_bytes);
  __store_n(out, result);
}
```

### Named SHA-256 helpers
Factor out CH, MAJ, Sigma functions as inline fns for readability and reuse:
```jasmin
inline fn __ROTR(reg u32 x, inline int c) -> reg u32 {
  reg u32 r; r = x; _, _, r = #ROR_32(r, c); return r;
}
inline fn __CH(reg u32 x y z) -> reg u32 {
  reg u32 r s;
  r = x; r &= y; s = x; s = !s; s &= z; r ^= s;
  return r;
}
inline fn __MAJ(reg u32 x y z) -> reg u32 {
  reg u32 r s;
  r = x; r &= y; s = x; s &= z; r ^= s; s = y; s &= z; r ^= s;
  return r;
}
```

### Non-inline compression for code size
Use `fn` (not `inline fn`) for the compression function to avoid duplicating it at every callsite:
```jasmin
fn _sha256_compress(reg ptr u32[8] state, reg u64 block_ptr)
    -> reg ptr u32[8] { ... }
```

### ADRS convention
ADRS is `u32[8]` on stack. Inline setters + serialise to `u8[32]` before hashing:
```jasmin
inline fn __adrs_set_type(stack u32[8] adrs, inline int t) -> stack u32[8] {
  adrs[3] = (u32) t;
  adrs[4] = 0; adrs[5] = 0; adrs[6] = 0; adrs[7] = 0;
  return adrs;
}
inline fn __adrs_to_bytes(stack u32[8] adrs) -> stack u8[32] {
  stack u8[32] buf; reg u32 w; inline int i;
  for i = 0 to 8 { w = adrs[i]; w = #BSWAP_32(w); buf[:u32 i] = w; }
  return buf;
}
```

## Security annotations

```jasmin
#[secret] reg u64 key;         // no branches or address-dependent access
#[public] reg u64 i;           // safe for control flow
r = #declassify(secret_val);   // explicit declassification (prove safety)
_ = #init_msf();               // Spectre v1 mitigation (every export fn)
```

Jasmin enforces constant-time via information-flow type checking at compile time.

## Resources

- Jasmin docs: https://jasmin-lang.readthedocs.io
- libjade: https://github.com/formosa-crypto/libjade (`release/2023.05-2` branch)
- formosa-crypto: https://github.com/formosa-crypto
- List intrinsics: `jasminc -help-intrinsics`
