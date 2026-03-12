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

`GetPlonkTrace()` calls gnark's solver and converts the result to a `trace.Trace` with **8 initial
columns**. `GetPublicPart` + `GetPrivatePartCopy(_, 0)` together provide the columns passed to
`loom.Prove`:

| group      | columns                    | meaning                                   |
|------------|----------------------------|-------------------------------------------|
| selectors  | QL, QR, QM, QO, QK         | gate type (fixed, set by the circuit)     |
| wires      | 0-L, 0-R, 0-O              | wire values for instance 0 (`ithInstance` prefix) |

`GetPlonkTrace` also returns `publicTrace.S []int64` — gnark's sigma permutation over the 3·N wire
positions — which encodes the circuit wiring.

`TestPlonk` then registers two IOPs on a fresh `constraint.Builder`:

**IOP 1 — arithmetic gate constraint**

```go
system := constraint.NewBuilder(N)

C := expr.Col("QL").Mul(expr.Col("0-L")).
    Add(expr.Col("QR").Mul(expr.Col("0-R"))).
    Add(expr.Col("QM").Mul(expr.Col("0-L")).Mul(expr.Col("0-R"))).
    Add(expr.Col("QO").Mul(expr.Col("0-O"))).
    Add(expr.Col("QK"))

system.AssertZero(C)
```

**IOP 2 — copy constraint (PLONK wiring check)**

```go
arguments.CopyPermutation(&system,
    []string{"0-L", "0-R", "0-O"},  // wire columns for instance 0
    S)                               // gnark's sigma permutation (len = 3·N)
```

`CopyPermutation` internally:
1. Calls `builder.AddPermutationColumns(S)` to register a `PERMUTATION_GEN` derivation step that
   will produce support columns `ID_0, ID_1, ID_2` (`[ω^i]`, `[g·ω^i]`, `[g²·ω^i]`) and permuted
   columns `S_0, S_1, S_2` (random names).
2. Calls `PermutationTuple` on the multisets
   `{(0-L, ID_0), (0-R, ID_1), (0-O, ID_2)}` and `{(0-L, S_0), (0-R, S_1), (0-O, S_2)}`,
   which registers an alpha round (tuple compression) followed by a grand-product argument.

This asserts that the multiset of triples `{(0-L[i], ID_0[i]), (0-R[i], ID_1[i]), (0-O[i], ID_2[i])}` equals
`{(0-L[i], S_0[i]), (0-R[i], S_1[i]), (0-O[i], S_2[i])}` — i.e. every wire value appears at the
right canonical and permuted position, encoding the circuit wiring.

Finally:

```go
cciop := system.Compile()

proof, err := loom.Prove(cciop, fulltrace, 1)
err         = loom.Verify(cciop, &proof, 1)
```

---

## 3. Prover actions DAG

`system.Compile()` produces a `constraint.Program` whose `DerivationPlan` forms the following DAG.
Open **`plonk_dag.html`** for an interactive view.

```
[known columns: 0-L, 0-R, 0-O, QL, QR, QM, QO, QK]
       │
       ▼
 ┌─────────────────────────────────┐
 │ PERMUTATION_GEN                 │   produces ID_0, ID_1, ID_2 (identity positions)
 │                                 │   and     S_0,  S_1,  S_2  (sigma positions)
 └─────────────────────────────────┘
       │
       ▼
 ┌─────────────────────────────────┐
 │ FIAT_SHAMIR → alpha             │   Fiat-Shamir(Com(0-L,ID_0,0-R,ID_1,0-O,ID_2,
 │                                 │               0-L,S_0,0-R,S_1,0-O,S_2))
 └─────────────────────────────────┘   (compresses 3-tuples into scalars)
       │
       ▼
 ┌─────────────────────────────────┐
 │ FIAT_SHAMIR → gamma             │   Fiat-Shamir(Com(F1_0,F2_0,...))
 │                                 │   where F1_i = Fold(wire_i || ID_i, alpha)
 └─────────────────────────────────┘   and    F2_i = Fold(wire_i || S_i,  alpha)
       │
       ▼
 ┌─────────────────────────────────┐
 │ GRAND_PRODUCT → Z               │   Z[0]=1
 │                                 │   Z[i+1] = Z[i] · ∏ᵢ(F1ᵢ[i]−γ) / ∏ᵢ(F2ᵢ[i]−γ)
 └─────────────────────────────────┘
       │
       ▼
 ┌────────────────┐
 │ LAGRANGE_0_32  │   L₀[i] = 1 if i=0, else 0
 └────────────────┘
```

Legend (from the HTML viewer):
- **Blue rectangle** — known (initial) column
- **Green rectangle** — computed column
- **Orange rounded rect** — derivation step
- **Dashed blue arrow** — input dependency
- **Solid orange arrow** — produced output

---

## 4. Step-by-step proof generation

### Step 0 — initial trace (`trace_0_known.csv`)

8 columns, N=32 rows. Example rows:

```
 row │  0-L   0-R    0-O    QL  QR  QM  QO  QK
─────┼─────────────────────────────────────────
  0  │  3      4      12     0   0   1  -1   0
  1  │  5     12      17     1   1   0  -1   0
  2  │  17    17     289     0   0   1  -1   0
  3  │ 289   289   83521     0   0   1  -1   0
```

### Step 1 — `Solve` → `trace_1_after_solve.csv`

The Kahn-style scheduler executes derivation steps in topological order:

1. **PERMUTATION_GEN** — generates identity support columns and sigma columns:
   - `ID_0[i] = ωⁱ`, `ID_1[i] = g·ωⁱ`, `ID_2[i] = g²·ωⁱ`  (canonical wire positions)
   - `S_0, S_1, S_2` — the permuted wire positions as encoded by gnark's sigma `S`
2. **FIAT_SHAMIR → alpha** — Fiat-Shamir hash of commitments to all 12 columns above;
   compresses each wire-position pair into a scalar for the tuple permutation check
3. **FIAT_SHAMIR → gamma** — Fiat-Shamir hash of the alpha-folded columns;
   used as the shift in the grand-product denominator/numerator
4. **GRAND_PRODUCT → Z** — running product:
   `Z[0] = 1`, `Z[i+1] = Z[i] · ∏ⱼ(F1ⱼ[i]−γ) / ∏ⱼ(F2ⱼ[i]−γ)`
   where `F1ⱼ = Fold([wireⱼ, IDⱼ], α)` and `F2ⱼ = Fold([wireⱼ, Sⱼ], α)`.
   If copy constraints hold, `Z[N−1] = 1`.
5. **LAGRANGE_0_32** — the spike at row 0: `[1, 0, 0, …, 0]`.

6 new columns are added (`ID_0..2`, `S_0..2` already counted above; plus `alpha`, `gamma`, `Z`,
`LAGRANGE_0_32`). The trace now has **14 columns**.

Example (rows 0–1, values illustrative):

```
 row │ alpha       gamma      Z              LAGRANGE_0_32
─────┼──────────────────────────────────────────────────
  0  │ <hash>      <hash>        1            1
  1  │ <hash>      <hash>   <product>         0
```

### Step 2 — `DeriveFinalFoldingChallenge` → `trace_2_after_folding.csv`

`alpha` (`github.com/consensys/giop@alpha`) is derived as a Fiat-Shamir hash of:
- all committed columns not yet committed (Z, LAGRANGE_0_32, and any unbound columns)
- the "leaf" challenges of the round DAG (gamma, which transitively depends on alpha)

The `VanishingRelation` is the symbolic fold:

```
C_vanish = C_arithmetic + giop@alpha · C_grandproduct + (giop@alpha)² · C_lagrange
```

where `giop@alpha` appears as a constant column in the trace. 1 new column → **15 columns**.

### Step 3 — `ComputeQuotient` → `trace_3_after_quotient.csv`

Computes `H = C_vanish(trace) / (X³²−1)` on a coset of size `4N`:
- `C_vanish` has degree ≤ 4 (highest-degree term: `∏ⱼ(F2ⱼ−γ)·Z_rot` — three degree-1 factors
  times a degree-1 `Z_rot` = degree 4)
- Dividing by `X³²−1` reduces it to degree ≤ 3N−2

`H` is stored as `github.com/consensys/giop@quotient` (LagrangeNormal basis after
`CosetLagrangeToLagrangeNormal`). 1 new column → **16 columns**.

### Step 4 — `DeriveOpeningChallenge`

`zeta` (`github.com/consensys/giop@zeta`) is derived from `Com(H)` and the folding challenge.
This is a random evaluation point outside the domain.

### Step 5 — `OpenCommitments`

Every committed polynomial is evaluated at `zeta`. For rotated columns (Z rotated by +1 in the
grand-product constraint), an additional opening at `ω·zeta` is computed.

The proof contains:
- **Commitments + openings** for all committed columns
- **TranscriptRounds**: `[alpha, gamma, giop@alpha, giop@zeta]`
- **VanishingRelation**: the symbolic `C_vanish` as a `dag.DAG`

---

## 5. Verification

`loom.Verify(cciop, &proof, 1)` calls `verifier.NewRunTime(cciop).Verify(&proof, 1)` which:
1. **`ComputeChallenges`** — replays FS transcript using the same commitment digests,
   re-derives `alpha`, `gamma`, `giop@alpha`, `giop@zeta`
2. **`EvaluateVirtualColumns`** — evaluates `LAGRANGE_0_32` at `zeta` via `GetComputationableColumn`
3. **`FillClaimedValues`** — copies prover-claimed opening values into `runtime.Vars`
4. **`CheckRelation`** — verifies:

```
C_vanish(openings at zeta)  =  H(zeta) · (zeta³² − 1)
```

5. **`VerifyOpeningProofs`** — checks commitment openings (including the shifted opening at `ω·zeta`)

This single equation, holding with high probability over a random `zeta`, implies that `C_vanish`
vanishes on all 32 roots of unity — i.e. every gate constraint and every copy constraint is satisfied.

---

## 6. Trace column summary

| column                        | added at    | type        | description                                              |
|-------------------------------|-------------|-------------|----------------------------------------------------------|
| 0-L, 0-R, 0-O                 | initial     | witness     | left / right / output wire values (instance 0)          |
| QL, QR, QM, QO, QK            | initial     | fixed       | gate selectors                                           |
| ID_0, ID_1, ID_2              | Solve       | computed    | canonical wire positions (`ωⁱ`, `g·ωⁱ`, `g²·ωⁱ`)       |
| S_0, S_1, S_2                 | Solve       | computed    | permuted wire positions (sigma), random column names     |
| alpha                         | Solve       | challenge   | tuple-compression randomness (folds wire+position pairs) |
| gamma                         | Solve       | challenge   | grand-product shift randomness                           |
| Z                             | Solve       | computed    | running product of wire/sigma ratios; Z[0]=Z[N-1]=1      |
| LAGRANGE_0_32                 | Solve       | virtual     | spike at row 0, encodes Z[0]=1 boundary constraint       |
| `giop@alpha`                  | Fold        | challenge   | folds all constraints into one vanishing polynomial      |
| `giop@quotient`               | Quotient    | computed    | H = C_vanish / (X³²−1)                                  |
| `giop@zeta`                   | Opening     | challenge   | evaluation point for all openings                        |
