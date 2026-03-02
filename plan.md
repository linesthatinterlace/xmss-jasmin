# Testing & CI Upgrade Plan

## Diagnosis: What went wrong and why

The root CLAUDE.md is admirably honest: "wide but shallow." The test suite has
many parameter sets and many features, but almost every test signs 1–20
messages. The BDS algorithm's complexity is a *state machine* that transitions
over *hundreds* of signatures. A ceiling-vs-floor division bug in treehash
update budgets survived because no test ever drove (H=5, K=2) past index 16 —
the axes were tested in isolation but never together.

### Critical assessment of the current state

**What the current tests actually prove:**
- "The code can sign and verify a few messages" — true
- "The BDS state machine is correct across all transitions" — **false**
- "C and Jasmin produce identical state after N signatures" — **untested**
- "Treehash instances are always complete before consumption" — **unasserted**

**Concrete numbers that expose the shallowness:**

| Test | Signatures | Fraction of tree explored |
|------|-----------|--------------------------|
| test_xmss (C, h=10) | 20 | 20/1024 = 2% |
| test_bds (C, k=2, h=10) | 20 | 2% |
| test_bds (C, k=4, h=10) | 20 | 2% |
| test_xmss_kat (C, h=10) | 512 | 50% |
| Jasmin API h=10 | 5 | 0.5% |
| Jasmin API h=16 | 5 | 0.008% |
| Jasmin API h=20 | 5 | 0.0005% |
| Interop (C↔Jasmin) | 2 | 0.2% |

The only test that crosses a tree boundary is `test_xmss_mt` (1024+ sigs for
XMSS-MT 20/2, tree_height=10). The H=5 K=2 regression test was added *after*
the bug was found.

**The false confidence pattern:** The EBI nails it — "Be sceptical of 'X
passes' claims — verify the test covers the exact parameter combination and
depth." The suite *looks* comprehensive (12 C tests, 18 Jasmin tests), but
coverage is an illusion when every test barely scratches the state space.

**The invariant gap:** `bds_round()` reads `treehash[i].node` assuming
`completed == 1`. This assumption is **never checked**, in either
implementation. The algorithm's correctness depends on the update budget being
sufficient to complete all treehash instances before they're consumed. A budget
bug (like the floor/ceil bug) silently produces garbage auth paths that only
fail at verify time — and only if you happen to test the right index.

---

## The Plan

### Phase 1: Runtime invariant assertions (HIGHEST PRIORITY)

**Goal:** Make BDS bugs *impossible to hide* — fail at the point of corruption,
not at the downstream verify.

#### 1a. C: Add debug-mode treehash completion assertion

In `impl/c/src/bds.c`, `bds_round()`, before reading `treehash[i].node`:

```c
/* Before: memcpy(state->auth[i], state->treehash[i].node, p->n); */
#ifndef NDEBUG
    assert(state->treehash[i].completed &&
           "BDS invariant: treehash must be completed before node is consumed");
#endif
    memcpy(state->auth[i], state->treehash[i].node, p->n);
```

This uses the standard C `NDEBUG` convention — assertions are active in Debug
builds (which we already have via `make debug`) and stripped in Release. Zero
cost in production.

Also add a completion assertion in `bds_treehash_update()` at the point where
we select which treehash instance to update — assert that the lowest incomplete
instance is consistent with the update budget.

#### 1b. Jasmin: Add conditional invariant check

Jasmin doesn't have `assert()`, but we can add a debug-mode check function that
is compiled in for test builds but elided for production:

In `bds.jinc`, before reading `treehash[i].node` in `__bds_round()`:
- Read `completed` flag via `__th_completed_get_rt()`
- In test builds, call an exported check function or set a return code
- In production API builds, this is a no-op (controlled by a `param int
  BDS_DEBUG` flag)

Alternative (simpler): Add the check in the C test harness after each sign
call, by deserializing the BDS state and checking all treehash completion flags
directly. This avoids modifying the Jasmin algorithm code and is arguably
better — it tests the real production code path.

#### 1c. C: Add post-sign BDS state validation helper

Create a `bds_validate_state()` function (test-only, not in `src/`) that:
1. Checks `treehash[i].completed == 1` for all i where auth[i] was just
   consumed
2. Checks `stack_offset` is within bounds
3. Checks `next_leaf` is consistent with the current index
4. Verifies retain node indices are in valid range

This function gets called after every `xmss_sign()` in debug tests.

---

### Phase 2: Full tree boundary tests for all (H, K) combinations

**Goal:** Every parameter combination that could exhibit the floor/ceil bug is
tested through a full tree.

#### 2a. C: Exhaustive (H, K) matrix test

New test binary: `test_bds_exhaustive` (or extend `test_bds`).

For each feasible (H, K) combination:
- H=5, K=0: sign all 32 messages, verify each
- H=5, K=2: sign all 32 messages, verify each (the exact combo that was buggy)
- H=5, K=4: sign all 32 messages, verify each
- H=10, K=0: sign all 1024 messages, verify each
- H=10, K=2: sign all 1024 messages, verify each
- H=10, K=4: sign all 1024 messages, verify each

H=5 tests are fast (32 sigs each). H=10 tests take ~2–4 minutes each.

**Why not H=16 or H=20?** H=16 would require 65,536 signatures (~hours). The
BDS state machine's edge cases are determined by (H-K) and tree structure, not
absolute H. H=5 and H=10 cover all interesting cases:
- (H-K) odd: H=5 K=2 (= 3, odd), H=5 K=4 (= 1, odd), H=10 K=0 is even but tests k=0
- (H-K) even: H=10 K=2 (= 8, even), H=10 K=4 (= 6, even)

For XMSS-MT, the relevant (H, K) is at the per-layer `tree_height` level:
- XMSSMT 20/4 → tree_height=5, K=2: already tested (regression test)
- XMSSMT 20/2 → tree_height=10, K=2: already tested (boundary crossing)
- XMSSMT 20/4 → tree_height=5, K=0: add test

#### 2b. Jasmin: Full tree boundary test for H=5 K=2

The XMSSMT-SHA2_20/4_256 API test already signs 33 messages (32 + 1 boundary).
But we should also verify the XMSS single-tree case.

Add a Jasmin test that:
- Uses a small-H parameter set (need to create a test-only `.jazz` with H=5 or
  use the XMSSMT 20/4 path which has tree_height=5)
- Signs all 32 messages
- Verifies each one

**Practical constraint:** Jasmin has no runtime-parameterized H — each `.jazz`
file bakes in one (H, K). This is actually an *advantage* for testing: there's
no way to accidentally test the wrong params. But it means we need a test-only
`.jazz` file for H=5 if we want a single-tree XMSS test.

The XMSSMT 20/4 path exercises tree_height=5 K=2 naturally. The existing
boundary test signs 33 messages. **Extend it to verify at every index**, not
just boundary indices.

#### 2c. Label and CI placement

- H=5 tests: label "fast" (< 5 seconds)
- H=10 full-tree tests: label "slow" (2-4 minutes)
- Run all in CI

---

### Phase 3: Cross-implementation BDS state comparison

**Goal:** Detect state divergence between C and Jasmin after every signature,
not just at signature verification time.

#### 3a. BDS state serialisation alignment

Both implementations must use the same BDS state byte layout. The C
implementation has `xmss_bds_serialize()` / `xmss_bds_deserialize()` in
`test_bds_serial.c` (or is it in `bds.c`?). The Jasmin implementation uses a
flat byte buffer that IS the state.

The key question: is the Jasmin flat buffer byte-compatible with the C
serialized form? The SPEC.md BDS layout (§7) suggests yes, but this needs
verification.

#### 3b. Deep interop test

New test: `test_interop_bds_state` (in Jasmin test dir, links both C and Jasmin)

```
for idx in 0..N:
    c_sign(msg[idx], c_sk, c_state)
    jasmin_sign(msg[idx], j_sk, j_state)
    assert(c_state == j_state byte-for-byte)
    assert(c_sig == j_sig byte-for-byte)
```

Start with N=32 (for H=5 parameter set via XMSSMT 20/4) and N=1024 (for H=10
via XMSS-SHA2_10_256).

This is the **single most powerful test** we can add. If C and Jasmin diverge
at index 17, we know immediately — unlike today where we'd only notice if a
downstream verify happened to fail.

#### 3c. For XMSS-MT: multi-layer state comparison

XMSS-MT has D BDS states. The deep interop test should compare ALL D states
after each sign, not just the layer-0 state. State divergence in upper layers
would only manifest at tree boundary crossings — which are rare enough to miss
in shallow tests.

---

### Phase 4: BDS exhaustion edge cases

**Goal:** Test the last few signatures in a tree where treehash re-init is
impossible.

#### 4a. C test for near-exhaustion signing

For H=5, K=0 (or K=2):
- Sign messages at indices 28, 29, 30, 31 (the last 4)
- At these indices, `startidx = leaf_idx + 1 + 3*(1 << i)` exceeds 2^H for
  some treehash levels
- The `if (startidx < (1 << h))` guard fires
- Verify that signing still produces valid signatures
- Verify that the treehash instances that can't be re-initialized are handled
  correctly

This is already partially covered by the full-tree tests (Phase 2), but it's
worth having an explicit test that *names* the exhaustion case for
documentation.

#### 4b. Key exhaustion boundary

Sign the very last message (index 2^H - 1). Verify it succeeds.
Try to sign at index 2^H. Verify it fails with key-exhausted error.
This is partially tested in `test_utils_internal` but should be tested in the
full BDS context, not just as a utility check.

---

### Phase 5: CI improvements

**Goal:** The CI should catch regressions from Phases 1–4, and be structured to
fail fast and informatively.

#### 5a. Split C tests into three tiers

Current: "fast" (6 tests) and "slow" (7 tests), run sequentially in one job.

Proposed:
- **Tier 1 — Compile + fast** (< 30s): params, address, hash, wots, utils.
  Fail fast — if these fail, nothing else matters.
- **Tier 2 — Core correctness** (< 5 min): test_xmss, test_bds, test_bds_serial,
  test_bds_exhaustive (H=5 tests), test_xmss_mt (including boundary).
  Run in parallel where possible.
- **Tier 3 — Deep validation** (< 15 min): test_xmss_kat (512 sigs),
  test_xmss_mt_kat, test_bds_exhaustive (H=10 tests), test_xmss_acvp_kat.

This gives faster feedback — a BDS bug in H=5 K=2 fails in Tier 2 within
seconds, not after waiting for KAT tests.

#### 5b. Add slow Jasmin API tests to CI

Currently `test_api_xmss_sha2_16_256` (~20s keygen) and
`test_api_xmss_sha2_20_256` (~4 min keygen) are NOT in CI. They should be.

Add them as a separate CI step (or a "slow" job that runs in parallel with the
fast tests). The h=16 test is cheap (~40s total). The h=20 test is expensive
(~8 min) — consider running it only on the default branch and PRs targeting it,
not on every push to a feature branch.

#### 5c. Add deep interop tests to CI

The Phase 3 interop tests (BDS state comparison, 32+ sigs) should run in CI.
They're the highest-value cross-implementation check.

#### 5d. Parallelise more aggressively

The current Jasmin CI job is sequential: compile → unit tests → API tests → KAT
→ interop → CT. The compile step already uses `-j$(nproc)`, good. But the test
steps could be parallelised (unit tests don't depend on API tests).

Consider splitting the Jasmin job into:
- **Build job**: compile all .jazz → .s, build C library for interop
- **Test jobs** (parallel, depend on build): unit, API-fast, API-slow, KAT,
  interop, CT

This would cut the 17-minute Jasmin job significantly.

#### 5e. Consider a nightly / weekly "deep" CI run

For tests that are too slow for every push (H=10 full tree = ~4 min per K
value, H=20 Jasmin API = ~8 min), run them on a schedule (nightly or weekly)
plus on PRs targeting main. This follows the existing `riscv.yml` pattern.

---

### Phase 6: Intermediate state assertions (hardening)

**Goal:** Don't just test final output — verify internal BDS state at critical
indices.

#### 6a. Golden state snapshots

For a reference (H, K) combination (e.g., H=5, K=2), compute and store the
expected BDS state at key indices:
- idx=0 (after keygen)
- idx=15 (just before high-tau event at idx=16)
- idx=16 (high-tau event: tau=4 for idx=16 with H=5)
- idx=31 (last signature)

Generate these from the C implementation (which is the reference), store as
binary blobs or hex arrays in test data, and verify both C and Jasmin match at
these indices.

This is expensive to maintain (any algorithm change invalidates the golden
data), so limit it to one or two parameter sets. The cross-implementation
comparison (Phase 3) is more maintainable and catches the same class of bugs.

#### 6b. treehash + retain + auth node spot-checks

Rather than full state comparison, add targeted checks at high-tau indices:
- After signing at idx=2^k - 1 (triggers tau=k), verify that auth[k] was
  correctly updated from treehash[k] or retain
- This is a lighter-weight version of 6a that doesn't require golden data

---

## Implementation priority and ordering

| Priority | Phase | Effort | Impact | CI cost |
|----------|-------|--------|--------|---------|
| **P0** | 1a: C assertion | Small | Prevents silent corruption | Zero (debug only) |
| **P0** | 2a: C exhaustive (H,K) matrix | Medium | Catches the *exact class* of bug that bit us | +2 min |
| **P1** | 3b: Deep interop state comparison | Medium | Strongest cross-impl check | +5 min |
| **P1** | 1c: Post-sign validation helper | Medium | Makes all future tests more powerful | Zero (test lib) |
| **P2** | 4a: Exhaustion edge cases | Small | Covers untested guard | Negligible |
| **P2** | 5a-5e: CI restructuring | Medium | Faster feedback, better coverage | Net neutral |
| **P2** | 2b: Jasmin full boundary | Small | Extends existing test | Negligible |
| **P3** | 6a-6b: Golden snapshots | Large | Diminishing returns if Phase 3 is done | Small |

**Recommended implementation order:**
1. Phase 1a + 1c (assertions — cheap, high impact, no test infrastructure needed)
2. Phase 2a (exhaustive H,K matrix — the direct bug prevention)
3. Phase 3b (deep interop — the strongest cross-implementation check)
4. Phase 4 (exhaustion — straightforward, fills known gap)
5. Phase 5 (CI — organizational, can be done incrementally)
6. Phase 2b + 6 (Jasmin boundary + golden snapshots — hardening)

---

## Sceptical notes on the existing approach

Things I'd push back on in the current design:

1. **"Prefer pushing and letting CI run the full test suite"** — This is
   reasonable advice for *existing* tests, but it created a culture where nobody
   noticed the tests were shallow. CI passing creates false confidence. The
   lesson: CI must test deeply enough that passing actually *means* something.

2. **The KAT test at idx=512 is a false friend.** It exercises BDS state
   heavily (512 signatures!) but only for bds_k=0 and h=10. The bug was in
   bds_k=2 with h=5. The KAT test's depth gives an illusion of thoroughness
   for a parameter combination that wasn't the vulnerable one.

3. **Interop tests at depth=1 are nearly useless for BDS correctness.** Signing
   one message exercises keygen + the very first BDS round. The interesting BDS
   behaviour doesn't start until treehash instances need to be re-initialized
   (around index 3-4) and doesn't hit edge cases until much later.

4. **The "fast API test" category is misleading.** test_api_xmss_sha2_10_256 is
   "fast" but only signs 5 messages. For BDS correctness, 5 signatures out of
   1024 is not a meaningful test. "Fast" should refer to test *execution time*,
   not test *depth*. An H=5 test that signs all 32 messages in <1 second is
   both fast AND deep.

5. **XMSS-MT tests hide single-tree bugs.** The XMSS-MT 20/4 boundary test
   (tree_height=5) was the one that caught the H=5 K=2 bug. But single-tree
   XMSS with H=5 doesn't exist as a standard parameter set, so it was never
   tested directly. The BDS code is shared — a bug in BDS affects both XMSS and
   XMSS-MT, but the test suite's parameter set coverage is driven by RFC OIDs,
   not by BDS state machine coverage. **Test BDS independently of the parameter
   set it's embedded in.**
