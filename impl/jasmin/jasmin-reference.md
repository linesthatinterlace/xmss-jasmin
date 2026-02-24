# Jasmin Language Reference for XMSS

A working reference for writing Jasmin code in this project. Not a substitute for
the full docs at https://jasmin-lang.readthedocs.io — use those for anything not here.

Primary reference implementations: https://github.com/formosa-crypto/libjade

---

## File conventions

| Extension | Role |
|-----------|------|
| `.jazz`   | Top-level file. Defines `export fn` symbols with C ABI. Minimal code — just imports and the export wrapper. |
| `.jinc`   | Included implementation. Contains the actual algorithm. Not compiled directly. |

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

```
// In a Makefile:
jasminc -arch x86-64 foo.jazz -o foo.s
```

---

## Types

```jasmin
bool          // condition flag (from comparisons)
u8  u16  u32  u64    // unsigned integers
int           // compile-time integer (param only)

// Arrays — always fixed size, always on stack or register file
u8[32]        // 32-byte array
u64[4]        // four 64-bit words

// Storage qualifiers
reg u64       // lives in a register
stack u8[32]  // lives on the stack (fixed size required)
reg ptr u8[32]  // register holding a pointer to a stack array
stack ptr u8[32]  // stack slot holding a pointer to a stack array
```

---

## Functions

```jasmin
// Internal function (not exported)
fn __my_fn(reg u64 x) -> reg u64 { ... }

// Inlined at every call site (like a macro — no call instruction generated)
inline fn __helper(inline int n, reg u64 x) -> reg u64 { ... }

// Exported with C calling convention
export fn jade_xmss_sign(reg u64 sig sk msg mlen) -> reg u64 { ... }
```

Key points:
- `inline int` parameters are compile-time constants (usable as array sizes, loop bounds)
- Multiple return values: `fn foo() -> reg u64, reg u64 { ... return a, b; }`
- Discard a return value: `_, r = some_fn();`
- Assign flags: `?{cf, zf}, r = #ADD(a, b);` or discard all: `?{}, r = #set0();`

### Non-inline `fn` parameter restrictions

Non-inline functions can **only** take `reg` or `reg ptr` parameters — **not** `stack`.
To pass a stack array to a non-inline `fn`, convert to `reg ptr` first:

```jasmin
fn __compress(reg ptr u32[8] state, reg ptr u8[64] block) -> reg ptr u32[8] { ... }

// Caller:
stack u32[8] st;
stack u8[64] blk;
reg ptr u8[64] blkp;
blkp = blk;
st = __compress(st, blkp);  // implicit reg ptr conversion for st
```

If a function needs to accept and return `stack` types, make it `inline fn`.

---

## Control flow

```jasmin
// For loop — bounds must be public (not secret-dependent)
for i = 0 to 64 { ... }

// While loop
while (cond) { ... }

// If/else
if (x == 0) { ... } else { ... }
```

No recursion. No goto. Loops must terminate with public bounds.

**No early returns**: `return` cannot appear inside `if` blocks. Structure code so the
single `return` is at the end of the function.

---

## Arrays — scaled vs unscaled access

This is a critical distinction. Jasmin has two array access syntaxes:

### Scaled access (element index) — `[:u32 i]`

```jasmin
stack u8[64] buf;

// buf[:u32 i] accesses the i-th u32 element (byte offset = 4*i)
buf[:u32 0] = val;   // writes bytes 0-3
buf[:u32 1] = val;   // writes bytes 4-7
buf[:u64 0] = val;   // writes bytes 0-7
buf[:u64 1] = val;   // writes bytes 8-15
```

This is the **preferred** form for most code. The index is an element count.

### Unscaled access (byte offset) — `.[:u32 i]`

```jasmin
// buf.[:u32 i] uses i as a raw BYTE offset
buf.[:u32 0] = val;  // writes bytes 0-3
buf.[:u32 4] = val;  // writes bytes 4-7  (same as buf[:u32 1])
```

Note the `.` before `[` — this signals unscaled (byte offset) mode.

### Pointer-based memory access

```jasmin
reg u64 ptr;
r = [:u64 ptr];            // load 64-bit word from address ptr
[:u64 ptr] = r;            // store
r = [:u64 ptr + 8 * i];   // indexed load (byte offset, NOT scaled)
[:u32 ptr + 28] = 0;      // store u32 at byte offset 28
```

**Pointer access is always unscaled** (byte offsets). The `+` offset is in bytes.

### Summary table

| Syntax | Index type | Example |
|--------|-----------|---------|
| `buf[:u32 i]` | Element index (scaled) | `buf[:u32 2]` = bytes 8-11 |
| `buf.[:u32 i]` | Byte offset (unscaled) | `buf.[:u32 8]` = bytes 8-11 |
| `[:u32 ptr + off]` | Byte offset (always) | `[:u32 ptr + 8]` = bytes 8-11 |

**NOTE**: The old syntaxes `(u64)[ptr + offset]` and `buf.[u32 i]` (without colon) are deprecated.

---

## Operators and intrinsics

```jasmin
// Arithmetic
r = x + y;       // addition (also: -, *, &, |, ^)
r = !x;          // bitwise NOT
r = x >> 3;      // logical shift right
r = x << 3;      // shift left

// Cast / truncate / extend
r = (32u)x;      // truncate to 32 bits
r = (64u)x;      // zero-extend to 64 bits
r = (uint)x;     // runtime cast (replaces deprecated (int) cast)

// x86 intrinsics — ALWAYS capture all return values
_, _, r = #ROR_32(x, 3);    // rotate right 32-bit (returns: OF, CF, result)
_, _, r = #ROL_32(x, 3);    // rotate left 32-bit
r = #BSWAP_32(r);           // byte-swap u32 (1 return value)
r = #BSWAP_64(r);           // byte-swap u64 (1 return value)
?{}, r = #set0();            // xor reg,reg (zero without data dependency)
_ = #init_msf();             // Spectre v1 mitigation init

// Memory (pointer-based — ptr is a reg u64)
r = [:u64 ptr];              // load 64-bit word
[:u64 ptr] = r;              // store
r = [:u64 ptr + 8 * i];     // indexed load (byte offset)
```

### Intrinsic return values

Use `jasminc -help-intrinsics` to list all available intrinsics.
Most x86 intrinsics return flags alongside the result. Common patterns:

| Intrinsic | Returns | Usage |
|-----------|---------|-------|
| `#ROR_32(x, n)` | OF, CF, result | `_, _, r = #ROR_32(x, n);` |
| `#ROL_32(x, n)` | OF, CF, result | `_, _, r = #ROL_32(x, n);` |
| `#BSWAP_32(x)` | result only | `r = #BSWAP_32(x);` |
| `#BSWAP_64(x)` | result only | `r = #BSWAP_64(x);` |
| `#set0()` | result | `?{}, r = #set0();` |

---

## Common pitfalls

### Zero-extend into compound operation

x86 can't zero-extend and OR/AND in one instruction. Use a temp:

```jasmin
// WRONG: diff |= (64u)byte_val;   // asmgen error
// RIGHT:
tmp = (64u)byte_val;
diff |= tmp;
```

### `ptr` is a keyword

Don't use `ptr` as a variable name — it's reserved syntax. Use `p` or descriptive names.

### In-place shift

`>>` on x86 is destructive (SHR). If you need the original value after shifting:

```jasmin
// WRONG:
hi = (32u)(tree >> 32);  // tree is destroyed
lo = (32u)tree;           // too late

// RIGHT:
lo = (32u)tree;           // use before shift
hi64 = tree;
hi64 >>= 32;
hi = (32u)hi64;
```

### Non-inline fn restrictions

Non-inline functions cannot take `stack` parameters or return `stack` types.
Only `reg` and `reg ptr` are allowed. If you need stack parameters, use `inline fn`.

### Deprecated `(int)` cast

Use `(uint)` or `(sint)` instead of `(int)`:

```jasmin
// WRONG: blk[(int)remaining] = b;    // deprecated warning
// RIGHT: blk[(uint)remaining] = b;
```

### No early returns

Jasmin does not support `return` inside `if` or `while` blocks. The return
statement must be at the very end of the function body.

---

## Global arrays

Constant lookup tables can be declared at file scope:

```jasmin
u32[64] SHA256_K = {
  0x428a2f98, 0x71374491, ...
};
```

Access from inside functions:

```jasmin
tmp = SHA256_K[i];   // inline int i only (compile-time)
```

---

## Security annotations (CT enforcement)

Jasmin enforces constant-time via an information-flow type system.

```jasmin
// Declare a variable as secret (must not flow to branches or memory addresses)
#[secret] reg u64 key;

// Declare as public (default for indices, lengths, etc.)
#[public] reg u64 i;

// Declassify: assert a secret value is safe to reveal (use sparingly, prove it)
r = #declassify(secret_val);

// init_msf: initialise speculative flow mask (required at every export fn entry)
_ = #init_msf();
```

---

## Params (compile-time constants)

```jasmin
param int N = 32;    // usable as array size or loop bound
param int W = 16;    // Winternitz parameter

stack u8[N] buf;     // OK — N is a compile-time constant
for i = 0 to N { }  // OK
```

Our XMSS `XMSS_MAX_*` constants map directly to Jasmin `param int`.

---

## ADRS convention

Following C implementation rule J6 — ADRS is a `u32[8]` on the stack, manipulated
via `inline fn` setters, then serialised to `u8[32]` before passing to hash functions:

```jasmin
inline fn __adrs_set_type(stack u32[8] adrs, inline int t) -> stack u32[8] {
  adrs[3] = (u32) t;
  // zero words 4-7 as required by RFC 8391 §2.5
  adrs[4] = 0;  adrs[5] = 0;  adrs[6] = 0;  adrs[7] = 0;
  return adrs;
}

// Serialise to bytes before hashing
inline fn __adrs_to_bytes(stack u32[8] adrs) -> stack u8[32] {
  stack u8[32] buf;
  reg u32 w;
  inline int i;
  for i = 0 to 8 {
    w = adrs[i];
    w = #BSWAP_32(w);
    buf[:u32 i] = w;    // scaled: element index i → byte offset 4*i
  }
  return buf;
}
```

---

## Hash function design pattern

Non-inline `fn` can't take/return `stack` arrays. For hash functions that build
their input on the stack, use a two-tier pattern:

1. **Internal `inline fn`**: takes `stack u8[N]` input, returns `stack u8[N]` output
2. **External `fn`**: takes `reg u64` pointers, copies data in, calls internal, copies out

```jasmin
// Internal: works entirely with stack arrays
inline fn __sha256_hash96(stack u8[96] ibuf) -> stack u8[N] {
  // ... hash ibuf, return result as stack array
}

// External: bridges pointer world to stack world
fn __xmss_PRF(reg u64 out, reg u64 key, reg u64 adrs_bytes) {
  stack u8[N] result;
  result = __sha256_prf_internal(0x03, key, adrs_bytes);
  __store_n(out, result);   // copy stack array to output pointer
}
```

---

## Project file layout

```
src/
  address.jinc       ADRS type and inline setters
  utils.jinc         ull_to_bytes, bytes_to_ull, ct_memcmp, memzero
  hash/
    sha256_n32.jinc  SHA-256 compression + XMSS hash wrappers (N=32)
  wots.jinc          WOTS+ chain, sign, pkFromSig
  ltree.jinc         L-tree hash
  treehash.jinc      treehash and stack
  bds.jinc           BDS state and update functions
  xmss.jinc          XMSS keygen, sign, verify
  xmssmt.jinc        XMSS-MT keygen, sign, verify
test/
  test_*.jazz        export fn wrappers for testing
  test_*.c           C harnesses that link against generated .s files
```

---

## Building

```bash
# Compile a .jazz file to x86-64 assembly
jasminc -arch x86-64 test/test_foo.jazz -o test/test_foo.s

# Link with C test harness
gcc -o test/test_foo test/test_foo.c test/test_foo.s -no-pie

# Run
./test/test_foo
```

---

## Resources

- Full language docs: https://jasmin-lang.readthedocs.io
- libjade (canonical Jasmin crypto implementations): https://github.com/formosa-crypto/libjade
  - Use the **`release/2023.05` branch** — `main` is mid-restructure and has no `.jazz` source files.
  - SHA-256 reference: `src/crypto_hash/sha256/amd64/ref/`
  - SHAKE-256 reference: `src/crypto_xof/shake256/amd64/ref/`
  - Keccak-f[1600] reference: `src/common/keccak/keccak1600/amd64/ref/`
- formosa-crypto organisation: https://github.com/formosa-crypto
- EasyCrypt (formal verification): installed via opam, pinned to dev version
  - Check pin before upgrading: `opam pin list | grep easycrypt`
