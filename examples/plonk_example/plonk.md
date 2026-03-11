# PLONK proof walkthrough

This document traces every step of `TestPlonk` in `plonk_test.go`, from the gnark circuit to the final
verification check.
Generated files referenced below: `plonk_dag.html`, `trace_0_known.csv` … `trace_3_after_quotient.csv`.

---

## 1. The circuit

```go
type Circuit struct{ A, B, C, D frontend.Variable }

func (c *Circuit) Define(api frontend.API) error {
    a := api.Mul(c.A, c.B)   // a  = A · B
    a  = api.Add(a,  c.C)    // a  = A·B + C
    for i := 0; i < 20; i++ {
        a = api.Mul(a, a)    // a  = a²  (×20)
    }
    api.AssertIsDifferent(a, c.D)
    return nil
}
```

Assignment: `A=3, B=4, C=5, D=6`.
Intermediate values: `a₀ = 12`, `a₁ = 17`, then `a₂ = 17² = 289`, …, `a₂₂ = a₂₁²`.

gnark compiles this to a **Sparse R1CS** (PLONK gate form). Each gate is one row with selector
columns QL, QR, QM, QO, QK and wire columns L (left), R (right), O (output):

```
QL·L + QR·R + QM·L·R + QO·O + QK = 0
```

| row | gate      | L   | R   | O    | QL | QR | QM | QO |
|-----|-----------|-----|-----|------|----|----|----|-----|
| 0   | L·R=O     | 3   | 4   | 12   | 0  | 0  | 1  | −1 |
| 1   | L+R=O     | 5   | 12  | 17   | 1  | 1  | 0  | −1 |
| 2   | L·L=O     | 17  | 17  | 289  | 0  | 0  | 1  | −1 |
| 3   | L·L=O     | 289 | 289 | 83521| 0  | 0  | 1  | −1 |
| … (20 squarings total) |

The domain size is `N = 32` (next power of two above `nbConstraints + nbPublicInputs`).

---

## 2. System setup

`GetPlonkTrace()` calls gnark's solver and converts the result to a `trace.Trace` with **14 known columns**:

| group      | columns                    | meaning                                   |
|------------|----------------------------|-------------------------------------------|
| selectors  | QL, QR, QM, QO, QK         | gate type (fixed, set by the circuit)     |
| wires      | L, R, O                    | wire values for this execution            |
| identity   | ID1, ID2, ID3              | `[ωⁱ]`, `[g·ωⁱ]`, `[g²·ωⁱ]` — canonical wire positions |
| sigma      | S1, S2, S3                 | permuted wire positions (copy constraints)|

`TestPlonk` then registers two IOPs on a fresh `cs.System`:

**IOP 1 — arithmetic constraint**

```go
C := QL·L + QR·R + QM·L·R + QO·O + QK   // must vanish on X³²−1
system.RegisterConstraint(C)
```

**IOP 2 — copy-constraint permutation check**

```go
std.MultiSetEqualityUpToPermutationIOP(&system,
    [][]string{{"L","ID1"}, {"R","ID2"}, {"O","ID3"}},   // multiset 1: wire · position
    [][]string{{"L","S1"},  {"R","S2"},  {"O","S3"}},    // multiset 2: wire · sigma(position)
    "PlonkGrandProduct", "beta", "gamma")
```

This asserts that the multiset of triples `{(L[i],ID1[i]), (R[i],ID2[i]), (O[i],ID3[i])}` equals
`{(L[i],S1[i]), (R[i],S2[i]), (O[i],S3[i])}` — i.e. every wire value appears at the right position
in both the identity and the permuted layout, encoding the wiring of the circuit.

---

## 3. Prover actions DAG

`cs.Compile(&system)` produces a `CompiledIOP` whose `ProverActions` form the following DAG.
Open **`plonk_dag.html`** for an interactive view.

```
[known columns: L, R, O, QL, QR, QM, QO, QK, ID1, ID2, ID3, S1, S2, S3]
       │                   │
       ▼                   ▼
 ┌──────────┐        ┌──────────┐
 │  → beta  │        │  → beta  │   (both depend on the same columns;
 └──────────┘        └──────────┘    beta derived first)
       │
       ▼
 ┌──────────┐
 │ → gamma  │   (depends on beta)
 └──────────┘
       │
       ▼
 ┌─────────────────────────────────┐
 │ → PlonkGrandProduct             │   Z[0]=1, Z[i+1] = Z[i]·∏ⱼ(Wⱼ[i]+β·IDⱼ[i]+γ)
 │   PlonkGrandProduct(w^1X)       │                        / ∏ⱼ(Wⱼ[i]+β·Sⱼ[i]+γ)
 └─────────────────────────────────┘
       │
       ▼
 ┌────────────────┐
 │ → LAGRANGE_0_32│   L₀[i] = 1 if i=0, else 0
 └────────────────┘
```

Legend (from the HTML viewer):
- **Blue rectangle** — known (initial) column
- **Green rectangle** — computed column
- **Orange rounded rect** — prover action
- **Dashed blue arrow** — input dependency
- **Solid orange arrow** — produced output

---

## 4. Step-by-step proof generation

### Step 0 — initial trace (`trace_0_known.csv`)

14 columns, N=32 rows. Example rows:

```
 row │  L    R    O    QL  QR  QM  QO  QK
─────┼────────────────────────────────────
  0  │  3    4    12    0   0   1  -1   0
  1  │  5   12    17    1   1   0  -1   0
  2  │ 17   17   289    0   0   1  -1   0
  3  │289  289  83521   0   0   1  -1   0
```

### Step 1 — `Solve` → `trace_1_after_solve.csv`

The Kahn-style scheduler executes prover actions in topological order:

1. **ComputeChallenge → beta** — Fiat-Shamir hash of `Com(L,R,O,ID1,ID2,ID3,S1,S2,S3)`
2. **ComputeChallenge → gamma** — Fiat-Shamir hash of `Com(beta)`
3. **ComputeGrandProduct → PlonkGrandProduct, PlonkGrandProduct(w¹X)**
   Each row: `Z[i+1] = Z[i] · ∏ⱼ(Wⱼ[i]+β·IDⱼ[i]+γ) / ∏ⱼ(Wⱼ[i]+β·Sⱼ[i]+γ)`
   `Z[0] = 1`; if copy constraints hold, `Z[N−1] = 1` too.
4. **ComputeLagrangeColumn → LAGRANGE_0_32**
   The spike at row 0: `[1, 0, 0, …, 0]`.

5 new columns are added. The trace now has **19 columns**:

```
new columns: beta, gamma (constants), PlonkGrandProduct, PlonkGrandProduct(w^1X), LAGRANGE_0_32
```

Example (rows 0–1):

```
 row │ beta       gamma      PlonkGP       PlonkGP(wX)   L0_32
─────┼────────────────────────────────────────────────────────
  0  │ 411656995  544958135      1          1172038751     1
  1  │ 411656995  544958135  1172038751      299829684     0
```

### Step 2 — `DeriveFinalFoldingChallenge` → `trace_2_after_folding.csv`

`alpha` (`github.com/consensys/giop@alpha`) is derived as a Fiat-Shamir hash of:
- all committed columns not yet committed (PlonkGrandProduct, PlonkGrandProduct(w¹X), LAGRANGE_0_32, Z shifted copies)
- the "leaf" challenges of the round DAG (gamma, which transitively depends on beta)

The `VanishingRelation` is set to the symbolic fold:

```
C_vanish = C_arithmetic + alpha · C_grandproduct + alpha² · C_lagrange
```

where `alpha` appears as a constant column in the trace. 1 new column → **20 columns**.

### Step 3 — `ComputeQuotient` → `trace_3_after_quotient.csv`

Computes `H = C_vanish(trace) / (X³²−1)` on a coset of size `4N`:
- `C_vanish` has degree `≤ 3N−1` (highest-degree term: `QM·L·R` degree 3, times `Z` degree 1 from grand product)
- Dividing by `X³²−1` reduces it to degree `≤ 2N−2`

`H` is stored as `github.com/consensys/giop@quotient` (LagrangeShifted basis). 1 new column → **21 columns**.

### Step 4 — `DeriveOpeningChallenge`

`zeta` (`github.com/consensys/giop@zeta`) is derived from `Com(H)`.
This is a random evaluation point outside the domain.

### Step 5 — `OpenCommitments`

Every committed polynomial is evaluated at `zeta`. For the dummy commitment scheme used here,
`Open(P, zeta)` converts `P` to canonical basis and evaluates it directly.

The proof now contains:
- **Commitments + openings** for all 21 columns
- **Proof rounds**: `[beta, gamma, alpha, zeta]` (Fiat-Shamir transcript)
- **VanishingRelation**: the symbolic expression `C_vanish`

---

## 5. Verification

`verifierRunTime.Verify(&proof)` replays the Fiat-Shamir transcript using
the same commitment digests, re-derives `beta`, `gamma`, `alpha`, `zeta`, then checks:

```
C_vanish(openings at zeta)  =  H(zeta) · (zeta³² − 1)
```

This single equation, holding with high probability over a random `zeta`, implies that
`C_vanish` vanishes on all 32 roots of unity — i.e. every gate constraint and every copy
constraint is satisfied.

---

## 6. Trace column summary

| column                       | added at    | type       | description                                   |
|------------------------------|-------------|------------|-----------------------------------------------|
| L, R, O                      | initial     | witness    | left / right / output wire values             |
| QL, QR, QM, QO, QK           | initial     | fixed      | gate selectors                                |
| ID1, ID2, ID3                | initial     | fixed      | canonical wire positions (`ωⁱ`, `g·ωⁱ`, `g²·ωⁱ`) |
| S1, S2, S3                   | initial     | fixed      | permuted wire positions (sigma)               |
| beta                         | Solve       | challenge  | randomness for tuple compression              |
| gamma                        | Solve       | challenge  | randomness for grand product denominator      |
| PlonkGrandProduct            | Solve       | computed   | Z[i]: running product of wire/sigma ratios    |
| PlonkGrandProduct(w¹X)       | Solve       | computed   | Z shifted by +1 (Z[i] = Z_{prev}[i+1])       |
| LAGRANGE_0_32                | Solve       | computable | spike at row 0, encodes Z[0]=1 constraint     |
| `giop@alpha`                 | Fold        | challenge  | folds the N+2 constraints into one            |
| `giop@quotient`              | Quotient    | computed   | H = C_vanish / (X³²−1)                        |
| `giop@zeta`                  | Opening     | challenge  | evaluation point for all openings             |
