# Jasmin bug: ICE "linearization: check_rexpr" with widening cast of reg ptr element

**Jasmin version**: 2025.06.3
**Related issue**: https://github.com/jasmin-lang/jasmin/issues/1126 (same error, different trigger)
**Status**: Unconfirmed whether this is the same root cause as #1126 or a distinct path.

---

## Summary

An internal compiler error `linearization: check_rexpr` is triggered when a
`reg ptr u8[N]` array element at a **non-zero compile-time index** is read with
a **widening cast** (`(32u)` or `(64u)`) as an **operand in a compound expression**
(e.g. `v += (64u) p[1]`).

---

## Minimal reproducer

```jasmin
fn bug(reg ptr u8[2] p) -> reg u64 {
  reg u64 v;
  v  = (64u) p[0];
  v += (64u) p[1];   /* ICE here */
  return v;
}
export fn entry(reg u64 inp) -> reg u64 {
  stack u8[2] buf; reg ptr u8[2] p; reg u64 r;
  buf[0] = 1; buf[1] = 2; p = buf;
  _ = #init_msf();
  r = bug(p); return r;
}
```

**Compile command**:
```
jasminc -arch x86-64 bug.jazz
```

**Output**:
```
bug.jazz, line 4 (2-18):
internal compilation error in function bug:
  linearization: check_rexpr
Please report at https://github.com/jasmin-lang/jasmin/issues
```

---

## Conditions required to trigger

All of the following must be true:

| Condition | Detail |
|-----------|--------|
| Function type | Non-inline `fn` (or inlined into an export fn — same error at call site) |
| Array type | `reg ptr u8[N]` |
| Index | Non-zero compile-time constant (e.g. `p[1]`, `p[2]`, `p[28]`) |
| Cast | Widening cast: `(32u)` or `(64u)` |
| Expression form | Compound: used as operand in `+=`, not as a standalone assignment |

---

## Does NOT trigger

```jasmin
// (a) u8-level read with compound expression — OK (no widening cast)
v += p[1];

// (b) Widening cast as simple assignment — OK
v = (64u) p[1];

// (c) Non-zero index read, no widening cast — OK
b = p[28];
```

---

## Workaround

Assign to a temporary register variable before using in a compound expression:

```jasmin
fn workaround(reg ptr u8[2] p) -> reg u64 {
  reg u64 v tmp;
  v   = (64u) p[0];
  tmp = (64u) p[1];   /* assign to temp first */
  v  += tmp;          /* then use temp in compound expr */
  return v;
}
```

---

## Isolation experiments

| Code | Compiles? |
|------|-----------|
| `v = (64u) p[1];` (simple assign, non-zero index) | ✓ |
| `v += (64u) p[0];` (compound, zero index) | ✓ |
| `v += p[1];` (compound, non-zero, no cast) | ✓ |
| `v += (64u) p[1];` (compound, non-zero, `(64u)` cast) | **ICE** |
| `v += (32u) p[1];` (compound, non-zero, `(32u)` cast) | **ICE** |
| `tmp = (64u) p[1]; v += tmp;` (temp var workaround) | ✓ |
| inline fn with `v += (64u) p[1];` | **ICE** (at inlined call site) |

---

## Context

Discovered while implementing the WOTS+ algorithm layer for an XMSS Jasmin port.
The algorithm layer needs to read multiple bytes from a `reg ptr u8[32]` ADRS buffer
and zero-extend them into u32/u64 registers for computation. The workaround (always
assign to a temp register before use in a compound expression) is effective.
