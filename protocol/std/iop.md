# Standard IOPs — Prover–Verifier Interactions

This document describes the three IOPs in `protocol/std`, illustrating each with the concrete scenario from its test. Each IOP registers constraints on `protocol.Protocol` and produces a proof that can be verified with `protocol.Verify`.

All three follow the same lifecycle:
1. The IOP calls `prot.SendMeAChallenge` to commit columns and derive a Fiat-Shamir challenge.
2. It registers one or more constraints in `prot.S.Constraints` (or `CachedConstraints` when `CacheMe()` is passed).
3. The caller folds all constraints into one (`prot.FoldConstraints`) and calls `prot.Finalize()`.

---

## `EqualityUpToPermutationIOP`

### What it proves

Given two lists of column names `ID1 = [P_0, …, P_k]` and `ID2 = [Q_0, …, Q_l]`, it proves that the multisets `{P_j[i]}` and `{Q_j[i]}` are equal, i.e. there exists a permutation σ such that `P_j[σ(i)] = Q_j[i]` for all i, j.

### Concrete example (`TestPermutation`, N = 16)

```
ID1 = ["P0"]
ID2 = ["P1"]
P0 : [ p₀  p₁  p₂  …  p₁₅ ]   (random)
P1 : [ p₁  p₂  p₃  …  p₀  ]   (cyclic shift: P1[i] = P0[(i+1) % 16])
```

P0 and P1 encode the same multiset, so the claim holds.

### Σ-protocol

```
|------------------------------------------------------------------|
| [prover]                      | [verifier]                      |
|------------------------------------------------------------------|
| Commit(P0, P1)      ------->  | [Com(P0), Com(P1)]              | ROUND 1
|------------------------------------------------------------------|
|                               <-----  γ = FS(Com(P0), Com(P1)) |
|------------------------------------------------------------------|
| Compute Z:                    |                                  |
|   Z[0]   = 1                  |                                  |
|   Z[i+1] = Z[i] · (P0[i]−γ) |                                  |
|              ──────────────── |                                  |
|              (P1[i]−γ)        |                                  |
|                               |                                  |
| Commit(Z, Z_shifted) ------>  | [Com(Z), Com(Z_shifted)]        | ROUND 2
|------------------------------------------------------------------|
| (done via FoldConstraints + Finalize + Verify)                   |
| Records two constraints:                                         |
|   C1: (P1−γ)·Z_shifted − (P0−γ)·Z = 0  mod X^N−1              |
|   C2: (Z−1)·LAGRANGE_0_16 = 0  mod X^N−1  (enforces Z[0]=1)   |
|------------------------------------------------------------------|
```

`LAGRANGE_0_16` is a computable column: the verifier evaluates `L₀(ζ) = (1/N)·(ζ^N−1)/(ζ−1)` directly, without a commitment from the prover.

### Trace evolution

```
                P0      P1      γ      Z      Z_shifted    LAGRANGE_0_16
         ┌──────────────────────────────────────────────────────────────┐
  row 0  │  p₀      p₁      γ      1      Z₁           1              │
  row 1  │  p₁      p₂      γ      Z₁     Z₂           0              │
  row 2  │  p₂      p₃      γ      Z₂     Z₃           0              │
   ⋮     │   ⋮       ⋮       ⋮      ⋮       ⋮            ⋮              │
  row 15 │  p₁₅    p₀      γ      Z₁₅    1            0              │
         └──────────────────────────────────────────────────────────────┘
```

Because P1 is a cyclic shift of P0, `∏ᵢ(P0[i]−γ) = ∏ᵢ(P1[i]−γ)`, so `Z[16] = Z[0] = 1`. C1 vanishes on the domain.

### After the IOP

```
prot.S.Constraints = [ C1, C2 ]   (two constraints, or two CachedConstraints with CacheMe())
```

The caller must fold them before `Finalize`:
```go
prot.FoldConstraints("alpha")   // or FoldCachedConstraints if CacheMe was used
proof, _ := prot.Finalize()
protocol.Verify(&proof)
```

---

## `MultiSetEqualityUpToPermutationIOP`

### What it proves

Given two lists of column groups `ID1 = [[P_s[0], P_s[1], …]]` and `ID2 = [[Q_s[0], Q_s[1], …]]`, it proves that for each subset index s the multiset of tuples `{(P_s[0][i], P_s[1][i], …)}` equals `{(Q_s[0][i], Q_s[1][i], …)}`.

Tuples are compressed into scalars with a random α before applying the grand product, so a single `EqualityUpToPermutationIOP` call suffices.

### Concrete example (`TestPermutationMultiSet`, N = 16)

```
ID1 = [["A0","A1"], ["B0","B1"]]
ID2 = [["C0","C1"], ["D0","D1"]]

A0, A1, B0, B1 : random columns
C0[i] = A0[(i+1)%16]   C1[i] = A1[(i+1)%16]
D0[i] = B0[(i+1)%16]   D1[i] = B1[(i+1)%16]
```

Claim: `{(A0[i], A1[i])} = {(C0[i], C1[i])}` AND `{(B0[i], B1[i])} = {(D0[i], D1[i])}`.

### Σ-protocol

```
|---------------------------------------------------------------------------|
| [prover]                       | [verifier]                              |
|---------------------------------------------------------------------------|
| Commit(A0,A1,B0,B1,            |                                         |
|        C0,C1,D0,D1)  ------->  | [Com(A0),Com(A1),…,Com(D1)]            | ROUND 1
|---------------------------------------------------------------------------|
|                                <-----  α = FS(all 8 commitments)         |
|---------------------------------------------------------------------------|
| Fold each subset into a scalar virtual column (symbolic, not committed):  |
|   F1_0[i] = A0[i] + α · A1[i]                                           |
|   F1_1[i] = B0[i] + α · B1[i]                                           |
|   F2_0[i] = C0[i] + α · C1[i]                                           |
|   F2_1[i] = D0[i] + α · D1[i]                                           |
|---------------------------------------------------------------------------|
|                                <-----  γ = FS(same 8 commitments)        | ROUND 2
| (no new commitments in this round — EqualityUpToPermutation              |
|  finds the physical IDs from the virtual column leaves)                   |
|---------------------------------------------------------------------------|
| Compute Z:                     |                                         |
|   Z[0]   = 1                   |                                         |
|   Z[i+1] = Z[i] ·             |                                         |
|       (F1_0[i]−γ)(F1_1[i]−γ)  |                                         |
|      ──────────────────────── |                                         |
|       (F2_0[i]−γ)(F2_1[i]−γ)  |                                         |
|                                |                                         |
| Commit(Z, Z_shifted) ------->  | [Com(Z), Com(Z_shifted)]               | ROUND 3
|---------------------------------------------------------------------------|
| Records two constraints:                                                  |
|   C1: ∏_s(F2_s−γ)·Z_shifted − ∏_s(F1_s−γ)·Z = 0  mod X^N−1            |
|   C2: (Z−1)·LAGRANGE_0_16 = 0  mod X^N−1                                |
|---------------------------------------------------------------------------|
```

### Trace evolution

Virtual columns (F1_0, F1_1, F2_0, F2_1) live only in `prot.S.VirtualColumns` as symbolic expressions — they are never materialised as trace columns and never committed to. Their definitions are inlined into C1 at constraint-recording time.

```
After SendMeAChallenge(alpha):   A0 A1 B0 B1 C0 C1 D0 D1 | alpha
After EqualityUpToPermutationIOP:                           |       | gamma  Z  Z_shifted  LAGRANGE_0_16
```

The eight physical columns are committed in Round 1. α and γ are constant columns added by `SendMeAChallenge`. Z and Z_shifted are committed in Round 3. LAGRANGE_0_16 is never committed.

### Why the virtual columns share the same commitment round as α

`EqualityUpToPermutationIOP` is called with `VID1 = ["F1_0","F1_1"]` and `VID2 = ["F2_0","F2_1"]`. It looks each VID up in `prot.S.VirtualColumns`, finds the symbolic expression, and calls `.Vars()` to extract the physical column leaves (A0, A1, B0, B1, C0, C1, D0, D1). These are already committed, so the FS call for γ just binds the same existing digests — no new polynomial is sent.

---

## `DegreeReductionIOP`

### What it proves

Given a high-degree constraint `C` and a target degree `d`, it proves `C(Trace) = 0 mod X^N−1` using only degree-d intermediate constraints, by introducing auxiliary polynomials for each sub-expression of degree ≤ d found during Flatten.

### Concrete example (`TestDegreeReduction`, N = 16)

```
P0 : random
P1[i] = P0[i]²   for all i

C = P0^4 − P1^2   (degree 4)
targetDegree = 2
```

C vanishes on every row because P0[i]^4 = (P0[i]²)² = P1[i]².

### Flatten decomposition

`system.Flatten` rewrites C in-place by repeatedly extracting a sub-expression of degree ≤ 2 and replacing it with a fresh `Var`:

```
Start:  C = (P0·P0)·(P0·P0) − P1^2

Step 1: extract P1^2  →  define Q1 := P1^2
        intermediate constraint: P1^2 − Q1 = 0
        C becomes: (P0·P0)·(P0·P0) − Q1

Step 2: extract P0·P0 (left child)  →  define Q2 := P0·P0
        intermediate constraint: P0·P0 − Q2 = 0
        C becomes: Q2·(P0·P0) − Q1

Step 3: extract P0·P0 (right child)  →  already defined as Q2, skip
        C becomes: Q2·Q2 − Q1   (degree 2, loop ends)
```

Three constraints come out of `Flatten`:

| idx | constraint       | degree |
|-----|-----------------|--------|
| 0   | P1^2 − Q1 = 0  | 2      |
| 1   | P0·P0 − Q2 = 0 | 2      |
| 2   | Q2·Q2 − Q1 = 0 | 2      |

### Σ-protocol

```
|------------------------------------------------------------------|
| [prover]                     | [verifier]                       |
|------------------------------------------------------------------|
| Flatten C into C0, C1, C2    |                                  |
| Compute Q1 = P1^2            |                                  |
|         Q2 = P0^2 = P0·P0   |                                  |
|                              |                                  |
| Commit(Q1, Q2)     ------->  | [Com(Q1), Com(Q2)]              | ROUND 1
|------------------------------------------------------------------|
|                              <-----  α = FS(Com(Q1), Com(Q2))  |
|------------------------------------------------------------------|
| Fold:                        |                                  |
|   C_f = C0 + α·C1 + α²·C2  |                                  |
|       = (P1^2 − Q1)         |                                  |
|       + α·(P0^2 − Q2)       |                                  |
|       + α²·(Q2^2 − Q1)      |                                  |
|                              |                                  |
| H = C_f(Trace) / (X^N−1)    |                                  |
| Commit(P0, P1, H)  ------->  | [Com(P0), Com(P1), Com(H)]      | ROUND 2
|------------------------------------------------------------------|
|                              <-----  ζ = FS(all commitments)   |
|------------------------------------------------------------------|
| Open P0, P1, Q1, Q2 at ζ    |                                  |
| Open H at ζ        ------->  | Verify C_f(evals) = H(ζ)·(ζ^N−1)| ROUND 3
|------------------------------------------------------------------|
```

Note: Q1 and Q2 were committed in Round 1, so they are not re-committed in Round 2. P0 and P1 are committed by `Finalize` when it discovers them as leaves of C_f.

### Trace evolution

```
                P0      P1      Q2=(P0·P0)    Q1=(P1^2)    alpha
         ┌──────────────────────────────────────────────────────────┐
  row 0  │  p₀      p₀²     p₀²           p₀⁴          α          │
  row 1  │  p₁      p₁²     p₁²           p₁⁴          α          │
   ⋮     │   ⋮        ⋮       ⋮               ⋮            ⋮         │
  row 15 │  p₁₅    p₁₅²   p₁₅²          p₁₅⁴         α          │
         └──────────────────────────────────────────────────────────┘
```

`Q2[i] = P0[i]^2` and `Q1[i] = P1[i]^2 = P0[i]^4`. All three degree-2 constraints vanish row-by-row:
- `P1[i]^2 − Q1[i] = P0[i]^4 − P0[i]^4 = 0` ✓
- `P0[i]^2 − Q2[i] = 0` ✓
- `Q2[i]^2 − Q1[i] = P0[i]^4 − P0[i]^4 = 0` ✓

### After the IOP

```
prot.S.Constraints = [ C_f ]   (exactly one folded constraint, ready for Finalize)
```

Unlike the permutation IOPs, `DegreeReductionIOP` folds its constraints internally — the caller does not need a separate `FoldConstraints` call:

```go
DegreeReductionIOP(&prot, C, 2, "alpha")
proof, _ := prot.Finalize()
protocol.Verify(&proof)
```

---

## Composing IOPs: `CacheMe` and `FoldCachedConstraints`

Each IOP accepts a `system.CacheMe()` option that routes its constraints to `prot.S.CachedConstraints` instead of `prot.S.Constraints`. This is useful when multiple IOPs contribute constraints that should be folded together with a single challenge:

```go
// Accumulate constraints from both IOPs in the cache
EqualityUpToPermutationIOP(&prot, ["P0"], ["P1"], "Z", "gamma", system.CacheMe())

// Fold everything cached into one active constraint, then finalise
prot.FoldCachedConstraints("alpha")   // derives alpha, folds, moves to Constraints
proof, _ := prot.Finalize()
protocol.Verify(&proof)
```

This is exactly how `TestPermutation` runs in its "with caching" variant.

---

## Constraint count summary

| IOP                              | Constraints registered | Needs explicit fold? |
|----------------------------------|----------------------|----------------------|
| `EqualityUpToPermutationIOP`    | 2 (C1 grand product, C2 Lagrange)   | Yes — caller calls `FoldConstraints` |
| `MultiSetEqualityUpToPermutationIOP` | 2 (same as above)  | Yes — caller calls `FoldConstraints` |
| `DegreeReductionIOP`            | 1 (already folded internally with α) | No                   |
