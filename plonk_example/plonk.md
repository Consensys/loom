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
 QL     QR     QM     QO     QK     S1     S2     S3     ID1    ID2    ID3    L      R      O
 0      0      1      -1     0      ...    ...    ...    1      g      g²     3      4      12       ← row 0: L*R = O  (3*4=12)
 0      0      1      -1     0      ...    ...    ...    ω      g·ω    g²·ω   12     5      17       ← row 1: L+R = O  (12+5=17)
 ...
 0      0      0      0      0      ...    ...    ...    ...    ...    ...    0      0      0        ← padding rows (rows 24..31)
```

*Note: row 0 is the first real constraint `A·B → O`, row 1 adds C. Rows 2–22 are the 20 squarings, row 23 encodes the `AssertIsDifferent`. Rows 24–31 are zero-padded.*

---

## Setup — Arithmetic Constraint

The arithmetic constraint is registered directly as an active constraint on the system:

```go
C := QL·L + QR·R + QM·L·R + QO·O + QK
system.AddConstraint(&S, C)
prot := protocol.NewProtocol(S)
```

**`S.Constraints`** = `[ QL·L + QR·R + QM·L·R + QO·O + QK ]`

There are no cached constraints. All constraints will be folded together in Round 3.

---

## Round 1 — Sample β (Permutation Preparation)

**Purpose**: commit to the wire and permutation columns, then derive β for folding the copy-constraint tuples into scalars.

This round happens inside `std.MultiSetEqualityUpToPermutation`.

```
Prover  ──── Com(L), Com(R), Com(O), Com(ID1), Com(ID2), Com(ID3),
             Com(S1), Com(S2), Com(S3)  ────────────────────────────→  Verifier

Prover  ←────────────────────────────────────────────────  β = FS(commitments above)
```

```go
std.MultiSetEqualityUpToPermutation(
    &prot,
    [][]string{{"L","ID1"}, {"R","ID2"}, {"O","ID3"}},
    [][]string{{"L","S1"},  {"R","S2"},  {"O","S3"}},
    "PlonkGrandProduct", "beta", "gamma",
)
```

β is derived by Fiat-Shamir from the nine commitments. It is stored in the trace as a constant column `"beta"`.

**Folded virtual columns** (symbolic, not materialised in the trace):

```
F1_0 = L + β·ID1,   F1_1 = R + β·ID2,   F1_2 = O + β·ID3
F2_0 = L + β·S1,    F2_1 = R + β·S2,    F2_2 = O + β·S3
```

These expressions are registered as **virtual columns** — they are kept in symbolic form and inlined directly into the grand product constraint. No new trace columns are created for them.

```
Trace after β-round: 15 columns

 ...original 14 columns...    beta
 ...                           β
```

---

## Round 2 — Sample γ (Grand Product)

**Purpose**: reduce the multiset equality claim `{F1_s} = {F2_s}` to a single recurrence on a grand product polynomial `Z`.

This round happens inside `EqualityUpToPermutation`, called by `MultiSetEqualityUpToPermutation`.

```
(no new commitments — physical columns were already committed in Round 1)

Prover  ←──────────────────────────────────────────────  γ = FS(same commitments as Round 1)
```

**Prover computes the grand product polynomial `Z`** (`"PlonkGrandProduct"`):

```
Z[0]   = 1
Z[i+1] = Z[i] · (F1_0[i]−γ)(F1_1[i]−γ)(F1_2[i]−γ)
               ─────────────────────────────────────
               (F2_0[i]−γ)(F2_1[i]−γ)(F2_2[i]−γ)
```

With F1/F2 inlined, this is:

```
Z[i+1] = Z[i] · (L[i]+β·ID1[i]−γ)(R[i]+β·ID2[i]−γ)(O[i]+β·ID3[i]−γ)
               ────────────────────────────────────────────────────────
               (L[i]+β·S1[i]−γ)(R[i]+β·S2[i]−γ)(O[i]+β·S3[i]−γ)
```

`Z` is added to the trace as `"PlonkGrandProduct"`. Its cyclic shift `ZS[i] = Z[(i+1) mod N]` is stored explicitly as `"PlonkGrandProduct_shifted"`.

Two active constraints are recorded:

```
C2: ∏_s(F2_s−γ) · PlonkGrandProduct_shifted  −  ∏_s(F1_s−γ) · PlonkGrandProduct  =  0  mod X^N − 1

C3: (PlonkGrandProduct − 1) · LAGRANGE_0  =  0  mod X^N − 1   (enforces Z[0]=1)
```

where `F1_s` and `F2_s` are the inlined symbolic expressions (no separate trace columns).

```
Trace after γ-round: 19 columns

 ...15 columns...    gamma   PlonkGrandProduct   PlonkGrandProduct_shifted   LAGRANGE_0
 ...                  γ       1                   Z[1]                        1
 ...                  γ       Z[1]                Z[2]                        0
 ...                  γ       ...                 ...                         0
 ...                  γ       Z[N-1]              1                           0
```

**`S.Constraints`** after this round = 3 active constraints:
1. `QL·L + QR·R + QM·L·R + QO·O + QK`
2. `∏_s(F2_s−γ)·PlonkGrandProduct_shifted − ∏_s(F1_s−γ)·PlonkGrandProduct`
3. `(PlonkGrandProduct − 1)·LAGRANGE_0`

---

## Round 3 — Sample α (Constraint Folding)

**Purpose**: combine all 3 active constraints into a single polynomial identity using a random linear combination.

```
Prover  ──── Com(all polynomials appearing in the 3 constraints)  ────→  Verifier

Prover  ←──────────────────────────────────────────────  α = FS(commitments above)
```

```go
prot.FoldConstraints("alpha")
```

The 3 active constraints `C1, C2, C3` are combined into:

```
C_folded = C1 + α·C2 + α²·C3
```

`α` is stored as a constant column `"alpha"` in the trace. After folding, `S.Constraints` holds exactly one constraint: `C_folded`.

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

The prover evaluates every column appearing in `C_folded` and `H` at the single point ζ, and sends opening proofs.

```
Prover  ──── { P(ζ) for every P in C_folded } ∪ { H(ζ) }  ──────────→  Verifier
```

### 4d — Verifier checks the identity

The verifier re-derives all challenges (β, γ, α, ζ) from the commitments using the same Fiat-Shamir hash, then checks:

```
C_folded( L(ζ), R(ζ), O(ζ), QL(ζ), …, Z(ζ), β, γ, α )  =  H(ζ) · (ζ^N − 1)
```

If this holds, the verifier is convinced (with overwhelming probability) that all 3 constraints vanish simultaneously on the entire domain.

```go
protocol.Verify(&proof)
```

---

## Summary of Trace Evolution

| After stage                        | Columns in trace                                                                                       | Active `Constraints` |
|------------------------------------|--------------------------------------------------------------------------------------------------------|----------------------|
| `BuildTrace`                       | QL QR QM QO QK S1 S2 S3 ID1 ID2 ID3 L R O                                                            | 0                    |
| `AddConstraint`                    | same                                                                                                    | 1 (arithmetic)       |
| `NewProtocol`                      | same                                                                                                    | 1                    |
| `MultiSetEqualityUpToPermutation` β | + **beta** (virtual: F1_0 F1_1 F1_2 F2_0 F2_1 F2_2)                                                 | 1                    |
| `EqualityUpToPermutation` γ        | + **gamma**, **PlonkGrandProduct**, **PlonkGrandProduct_shifted**, **LAGRANGE_0**                      | 3                    |
| `FoldConstraints` α                | + **alpha**                                                                                             | 1 (folded)           |
| `Finalize`                         | + **H** (quotient, on big domain)                                                                      | —                    |

The final proof (`Proof`) contains:
- One commitment digest per column (stored as the first coefficient in `dummycommitment`)
- One opening proof per column at ζ (claimed value + proof)
- The folded constraint expression `C_folded` (so the verifier can re-evaluate it)
- The ordered list of `Rounds` (for FS replay)
- The domain size N
