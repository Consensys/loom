# PLONK Proof Generation — Step by Step

This document walks through `TestPlonk` in `plonk_test.go`, showing how the prover builds a proof that a circuit is satisfied and how the verifier checks it. Each section corresponds to one round of the interactive protocol, made non-interactive via Fiat-Shamir.

---

## The Circuit

```go
func (c *Circuit) Define(api frontend.API) error {
    a := api.Mul(c.A, c.B)   // a = A*B
    a = api.Add(a, c.C)      // a = A*B + C
    for i := 0; i < 20; i++ {
        a = api.Mul(a, a)    // a = a^(2^20)
    }
    api.AssertIsDifferent(a, c.D)
    return nil
}
```

The witness used in the test is `(A=3, B=4, C=5, D=6)`. gnark compiles this into a **SparseR1CS** (PLONK) constraint system with 24 constraints over a domain of size N=32 (next power of two).

---

## PLONK Wire Semantics

Each constraint row enforces:

```
QL·L + QR·R + QM·L·R + QO·O + QK = 0
```

- **L, R**: left and right inputs to the gate
- **O**: output of the gate
- **QL, QR, QM, QO, QK**: selector polynomials encoding the gate type (fixed, public):
  - Multiplication gate: QM=1, QO=−1, QL=QR=QK=0
  - Addition gate: QL=1, QR=1, QO=−1, QK=0
  - Constant gate: QL=−1, QK=constant value
- **S1, S2, S3**: permutation polynomials encoding copy constraints (wire equalities across gates)
- **ID1, ID2, ID3**: identity permutation — three cosets {ωⁱ}, {g·ωⁱ}, {g²·ωⁱ}

The permutation argument proves that the wire values are consistent: that every wire used as an output in one gate is the same field element when used as an input to another.

---

## Initial Trace After `BuildTrace`

`BuildTrace` converts gnark's compiled circuit and witness solution into a 14-column trace. Each column is a Lagrange polynomial of degree N−1, so row `i` holds the evaluation at `ωⁱ`.

```
prettyPrintTrace(T):

 QL     QR     QM     QO     QK     S1     S2     S3     ID1    ID2    ID3    L      R      O
 0      0      1      -1     0      ...    ...    ...    1      g      g²     3      4      12       ← row 0: L*R = O  (3*4=12)
 0      0      1      -1     0      ...    ...    ...    ω      g·ω    g²·ω   12     5      17       ← row 1: L*R = O  ((12)*? but actually L+R=O after add)
 ...
 0      0      1      -1     0      ...    ...    ...    ...    ...    ...    ...    ...    ...
 0      0      0      0      0      ...    ...    ...    ...    ...    ...    0      0      0        ← padding rows (rows 24..31)
```

*Note: row 0 is the first real constraint `A·B → O`, row 1 adds C. Rows 2–22 are the 20 squarings, row 23 encodes the `AssertIsDifferent`. Rows 24–31 are zero-padded.*

The trace at this point has **14 columns**: `QL QR QM QO QK S1 S2 S3 ID1 ID2 ID3 L R O`.

The selector columns (QL..QK, S1..S3, ID1..ID3) are **fixed** — they encode the circuit structure and are the same for any valid witness. The wire columns (L, R, O) are **witness-dependent**.

---

## Round 0 — Setup (no interaction)

The prover initialises the system with the arithmetic constraint cached:

```go
C := QL·L + QR·R + QM·L·R + QO·O + QK          // cached, will be folded later

S := cs.NewSystem(T,
    []cs.Constraint{},       // no active constraints yet
    []cs.Constraint{C},      // C is cached
    N,
)
protocol := cs.NewProtocol(S)
```

**`S.CachedConstraints`** = `[ QL·L + QR·R + QM·L·R + QO·O + QK ]`

---

## Round 1 — Sample β (Permutation Preparation)

**Purpose**: bind the challenge β to the wire and permutation columns before constructing the folded permutation polynomials.

```
Prover  ──── Com(L), Com(R), Com(O), Com(ID1), Com(ID2), Com(ID3),
             Com(S1), Com(S2), Com(S3)  ────────────────────────────→  Verifier

Prover  ←────────────────────────────────────────────────  β = FS(commitments above)
```

```go
_, err = protocol.SendMeAChallenge(
    []string{ID_L, ID_R, ID_O, ID_ID1, ID_ID2, ID_ID3, ID_S1, ID_S2, ID_S3},
    "beta",
)
```

`β` is derived by Fiat-Shamir from the nine commitments above. It is stored in the trace as a constant column named `"beta"`.

**Prover then computes the folded permutation columns** (no further interaction):

```go
f1[i] = L[i] + β · ID1[i]    // left wire + β × identity coset 1
f2[i] = R[i] + β · ID2[i]    // right wire + β × identity coset 2
f3[i] = O[i] + β · ID3[i]    // output wire + β × identity coset 3

g1[i] = L[i] + β · S1[i]     // left wire + β × permutation coset 1
g2[i] = R[i] + β · S2[i]     // right wire + β × permutation coset 2
g3[i] = O[i] + β · S3[i]     // output wire + β × permutation coset 3
```

These are computed with `NewSimpleIOP(..., WithCaching())`, which evaluates each expression pointwise and records the constraint `fi - (wi + β·IDi) = 0` in `CachedConstraints`.

```
prettyPrintTrace(T) after β-round: 20 columns

 ...original 14 columns...    beta   f1     f2     f3     g1     g2     g3
 ...                           β      L+β·1  R+β·g  O+β·g² L+β·S1 R+β·S2 O+β·S3
 ...                           β      ...    ...    ...    ...    ...    ...
```

**`S.CachedConstraints`** after this round = 7 constraints:
1. `QL·L + QR·R + QM·L·R + QO·O + QK`
2. `(L + beta·ID1) − f1`
3. `(R + beta·ID2) − f2`
4. `(O + beta·ID3) − f3`
5. `(L + beta·S1)  − g1`
6. `(R + beta·S2)  − g2`
7. `(O + beta·S3)  − g3`

---

## Round 2 — Sample γ (Grand Product)

**Purpose**: reduce the multiset equality claim `{f1·f2·f3} = {g1·g2·g3}` to a single recurrence on a grand product polynomial `Z`.

```
Prover  ──── Com(f1), Com(f2), Com(f3), Com(g1), Com(g2), Com(g3)  ────→  Verifier

Prover  ←──────────────────────────────────────────────  γ = FS(commitments above)
```

```go
err = protocol.NewHintedIOP(
    cs.NewGrandProductIOP,
    []string{"f1", "f2", "f3", "g1", "g2", "g3"},
    "GrandProduct",
    "gamma",
    cs.WithCaching(),
)
```

**Prover computes the grand product polynomial `Z`**:

```
Z[0]   = 1
Z[i+1] = Z[i] · (f1[i]−γ)(f2[i]−γ)(f3[i]−γ)
               ─────────────────────────────────
               (g1[i]−γ)(g2[i]−γ)(g3[i]−γ)
```

`Z` is added to the trace as `"GrandProduct"`. An explicit cyclic-shift copy is also stored as `"GrandProduct_shifted"` (where `ZS[i] = Z[i+1 mod N]`), so that the recurrence can be expressed as a single polynomial equation vanishing on the domain without needing shift arithmetic in `ComputeQuotient`.

The recorded constraint is:

```
E2 · GrandProduct_shifted  −  E1 · GrandProduct  =  0  mod X^N − 1

where  E1 = (f1−γ)(f2−γ)(f3−γ)
       E2 = (g1−γ)(g2−γ)(g3−γ)
```

This vanishes on the domain iff `Z[N] = Z[0]`, which — combined with the boundary condition below — forces `Z[0] = Z[N] = 1`, proving multiset equality.

**Boundary condition**: the verifier must also check `Z[0] = 1`. This is enforced by a Lagrange constraint:

```go
err = protocol.NewLagrangeConstraint("GrandProduct", 0, one, cs.WithCaching())
```

`NewLagrangeConstraint` auto-inserts the Lagrange basis column `LAGRANGE_0` (all zeros except a 1 at row 0) and records:

```
(GrandProduct − 1) · LAGRANGE_0  =  0  mod X^N − 1
```

```
prettyPrintTrace(T) after γ-round: 23 columns

 ...22 columns from before...    gamma   GrandProduct   GrandProduct_shifted   LAGRANGE_0
 ...                              γ       1              Z[1]                   1
 ...                              γ       Z[1]           Z[2]                   0
 ...                              γ       ...            ...                    0
 ...                              γ       Z[N-1]         1                      0
```

**`S.CachedConstraints`** after this round = 9 constraints:
1–7. (same as before)
8. `E2·GrandProduct_shifted − E1·GrandProduct`
9. `(GrandProduct − 1)·LAGRANGE_0`

---

## Round 3 — Sample α (Constraint Folding)

**Purpose**: combine all 9 cached constraints into a single polynomial identity using a random linear combination.

```
Prover  ──── Com(all polynomials appearing in the 9 constraints)  ────→  Verifier

Prover  ←──────────────────────────────────────────────  α = FS(commitments above)
```

```go
err = protocol.FoldCachedConstraints("alpha")
```

The 9 cached constraints `C1, …, C9` are combined into:

```
C_folded = C1 + α·C2 + α²·C3 + α³·C4 + α⁴·C5 + α⁵·C6 + α⁶·C7 + α⁷·C8 + α⁸·C9
```

`α` is stored as a constant column `"alpha"` in the trace (needed for evaluation during quotient computation).

After folding, `S.CachedConstraints` is empty and `S.Constraints` holds exactly one constraint: `C_folded`.

---

## Round 4 — Finalize and Verify

**Purpose**: compute the quotient, open everything at a random evaluation point, and let the verifier check the polynomial identity.

### 4a — Prover computes and commits to the quotient H

```
H = C_folded(T) / (X^N − 1)
```

This quotient exists (has no remainder) because `C_folded` vanishes on every `ωⁱ` — that is the claim being proven. `H` is computed on a larger domain (of size `degree(C_folded) · N`) to avoid aliasing.

```
Prover  ──── Com(H)  ────────────────────────────────────────────────→  Verifier
```

### 4b — Verifier samples the evaluation point ζ

```
Prover  ←──────────────────────────────────  ζ = FS(all commitments so far, Com(H))
```

### 4c — Prover opens all polynomials at ζ

The prover evaluates every column appearing in `C_folded` (roughly 20+ columns) and `H` at the single point ζ, and sends opening proofs.

```
Prover  ──── { P(ζ) for every P in C_folded } ∪ { H(ζ) }  ──────────→  Verifier
```

### 4d — Verifier checks the identity

The verifier re-derives all challenges (β, γ, α, ζ) from the commitments using the same Fiat-Shamir hash, then checks:

```
C_folded( L(ζ), R(ζ), O(ζ), QL(ζ), …, Z(ζ), β, γ, α )  =  H(ζ) · (ζ^N − 1)
```

If this holds, the verifier is convinced (with overwhelming probability) that all 9 constraints vanish simultaneously on the entire domain.

```go
cs.Verify(&proof)
```

---

## Summary of Trace Evolution

| After stage          | Columns in trace                                                                            | `CachedConstraints` |
|----------------------|---------------------------------------------------------------------------------------------|---------------------|
| `BuildTrace`         | QL QR QM QO QK S1 S2 S3 ID1 ID2 ID3 L R O                                                 | 0 (added by NewSystem below) |
| `NewSystem`          | same                                                                                         | 1 (arithmetic)      |
| `SendMeAChallenge β` | + **beta**                                                                                   | 1                   |
| `generateFoldings`   | + **f1 f2 f3 g1 g2 g3**                                                                     | 7                   |
| `NewHintedIOP γ`     | + **gamma GrandProduct GrandProduct_shifted**                                               | 8                   |
| `NewLagrangeConstraint` | + **LAGRANGE_0**                                                                         | 9                   |
| `FoldCachedConstraints α` | + **alpha**                                                                           | 0 → 1 active        |
| `Finalize`           | + **H** (quotient, on big domain)                                                           | —                   |

The final proof (`Proof`) contains:
- One commitment digest per column (stored as the first coefficient in `dummycommitment`)
- One opening proof per column at ζ (claimed value + proof)
- The folded constraint expression `C_folded` (so the verifier can re-evaluate it)
- The ordered list of `Rounds` (for FS replay)
- The domain size N
