# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`github.com/consensys/iop` is a Go library for Interactive Oracle Proofs (IOP) and polynomial-based constraint systems over the Koalabear finite field. It depends on `gnark-crypto` for field arithmetic and FFT, and `gnark` for PLONK circuit compilation in `plonk_example/`.

## Building and Testing

```bash
# Build all packages
go build ./...

# Run all tests
go test ./...

# Run tests for a specific package
go test ./cs/...
go test ./pas/univariate/...
go test ./pas/sym/...
go test ./plonk_example/...

# Run a specific test
go test ./cs/... -run TestGrandProductIOP -v
go test ./plonk_example/... -run TestPlonk -v
```

## Package Architecture

### `cs/` — Constraint System and IOP Protocol

**Core types (`data.go`):**
```go
type Trace = map[string]*univariate.Polynomial   // columns indexed by name
type Constraint = sym.Expr                        // symbolic polynomial expression

type System struct {
    Trace             Trace
    Constraints       []Constraint  // active constraints (must be folded to 1 before Finalize)
    CachedConstraints []Constraint  // accumulated constraints to be folded later
    N                 int           // domain size (power of two)
}

func NewSystem(T Trace, C, CC []Constraint, N int) System

type Proof struct {
    OpeningProofs map[string]dummycommitment.PackedProof
    Constraint    Constraint
    Rounds        []Round   // ordered Fiat-Shamir rounds
    N             int
}

type Round struct {
    ChallengeName string
    Dependencies  []string  // IDs whose commitments feed this challenge
}

type Challenge struct {
    Name  string
    Value koalabear.Element
}
```

**IOP building blocks** — lower-level functions that operate directly on `*System`:
- `AddConstraint(S, C, opts...)`: adds C to active or cached constraints
- `NewSimpleIOP(S, E, IDresult, challenge, opts...)`: evaluates E pointwise → stores result polynomial in trace as `IDresult`, records constraint `E - IDresult = 0`
- `NewGrandProductIOP(S, IDs, IDresult, challenge, opts...)`: grand product permutation argument; IDs must be even-length (first half = numerator, second half = denominator); adds `IDresult` and `IDresult_shifted` to trace
- `NewLagrangeConstraint(S, ID, entry, value, opts...)`: proves `Trace[ID][entry] = value`; auto-inserts the Lagrange basis column `LAGRANGE_<entry>` into the trace
- `FoldCachedConstraints(S, challenge)`: folds all `CachedConstraints` into one using `Σᵢ αⁱ·Cᵢ`, appends it to `Constraints`, clears the cache
- `Flatten(S, C, targetDegree)`: degree reduction — splits C into low-degree intermediate polynomials via repeated `NewSimpleIOP` calls, adds intermediate constraints to `S.Constraints`

**`IOPOption` / `WithCaching()`**: pass `WithCaching()` to any IOP builder to route its constraint to `CachedConstraints` instead of `Constraints`. Required when building up constraints that will be folded together before `Finalize`.

**`Protocol` struct (`protocol.go`)** — orchestrates Fiat-Shamir and combines the building blocks:
```go
type Protocol struct{ S System; P Proof; I Interactions }
func NewProtocol(S System) Protocol
```
Key methods:
- `protocol.SendMeAChallenge(IDs []string, name string) (Element, error)`: commits to polynomials in `IDs`, derives a Fiat-Shamir challenge, adds it as a constant column in `S.Trace` under `name`
- `protocol.NewIOP(F NewIOP, E sym.Expr, IDresult, challengeName string, opts...)`: if `challengeName != ""`, calls `SendMeAChallenge` first, then calls `F`
- `protocol.NewHintedIOP(F NewHintedIOP, IDs []string, IDresult, challengeName string, opts...)`: always calls `SendMeAChallenge`, then calls `F`
- `protocol.NewLagrangeConstraint(ID, entry, value, opts...)`: syntactic sugar over the standalone function
- `protocol.FoldCachedConstraints(challengeName string)`: derives challenge via FS, folds cached constraints
- `protocol.Finalize() (Proof, error)`: requires exactly one active constraint; computes quotient H, commits, derives zeta, opens all polynomials at zeta
- `Verify(P *Proof) error`: replays FS rounds, re-derives zeta, checks `C(openings) = H(ζ)·(ζⁿ−1)`

**Fiat-Shamir ordering is strict**: `FS.NewChallenge(name)` must always be followed by `FS.ComputeChallenge(name)` before any subsequent `NewChallenge`. If `SendMeAChallenge` fails mid-way (e.g., a referenced polynomial is missing), the FS transcript is left in a broken state. All IDs referenced in a `NewHintedIOP` call must already be in `S.Trace` at call time.

**Constraint lifecycle in `Protocol`:**
1. Pass active constraints as `CC` (third arg) in `NewSystem` with `WithCaching()` intent, or use `AddConstraint`
2. Use `WithCaching()` on every IOP builder that should contribute to the final folded constraint
3. Call `FoldCachedConstraints` to reduce to one constraint (ends up in `Constraints`)
4. Call `Finalize` — requires `len(S.Constraints) == 1`

**Checkers (`test_utils.go`)** — for debugging:
- `BruteForceChecker(S System) error`: evaluates each constraint row-by-row at ωⁱ; requires Lagrange-basis polynomials in trace
- `QuotientChecker(S System) error`: verifies C(T) = H·(Xⁿ−1) at a random point; converts H from LagrangeShifted to Canonical internally

**`ensureChallengeInTrace`**: called automatically inside `NewSimpleIOP`, `NewGrandProductIOP`, and `FoldCachedConstraints`. When these functions are called directly (not through `Protocol`), they add the challenge as a constant column so `BruteForceChecker` and `EvalPointWise` can resolve it.

### `pas/univariate/` — Univariate Polynomial Operations

Two-layer representation:
- `EPolynomial`: coefficients, basis (`Canonical`/`Lagrange`/`LagrangeShifted`), layout (`Normal`/`BitReversed`), degree, `IsConstant` flag
- `Polynomial`: wraps `*EPolynomial` with an integer `Shift` for P(ωˢ·X)

Constructors:
- `NewPolynomial(coeffs, opts...)`: use `WithBasis`, `WithLayout`, `WithID`
- `NewInterpolatedPolynomial(evals, id, opts...)`: Lagrange basis, Normal layout
- `NewConstantPolynomial(value, opts...)`: `IsConstant=true`; `GetCoefficient(i)` always returns the same value

Key operations:
- `GetCoefficient(i)`: returns the i-th evaluation for Lagrange/LagrangeShifted; **panics** for non-constant Canonical
- `ToBasis(domain, targetBasis)` / `ToLayout(layout)`: in-place conversions
- `Evaluate(x)`: evaluates at a field element; **requires Canonical basis** (panics otherwise)
- `EvalPointWise(Pi map[string]*Polynomial, E sym.Expr, targetSize, opts...)`: Q(P₁[i],...,Pₙ[i]) pointwise over all i; inputs must be Lagrange or LagrangeShifted (use `WithInputBasis`, `WithOutputBasis`)
- `ComputeQuotient(Pi map[string]*Polynomial, E sym.Expr, N int, opts...)`: computes E(Pi)/(Xⁿ−1) on a big domain; returns LagrangeShifted by default — convert to Canonical before calling `Evaluate`
- `BuildGrandProduct(P1/P2, E1/E2, N, opts...)`: R[0]=1, R[i+1]=R[i]·E1(P1[i])/E2(P2[i])
- `NextPowerOfTwo(n int) int`: utility

**`CopyE` does not preserve `IsConstant`** — copies of constant polynomials lose the flag and behave as 1-coefficient Canonical polynomials (which FFT to all-constant Lagrange on `ToBasis`). This is intentional and used by `BuildGrandProduct`.

**FFT layout convention**: DIF produces BitReversed output from Normal input; DIT produces Normal output from BitReversed input. `ToBasis` chooses FFT mode to minimize redundant bit-reversals.

### `pas/sym/` — Symbolic Multivariate Expressions

- `Expr` interface: `Add()`, `Sub()`, `Mul()`, `Pow(uint32)`, `Degree()`, `Leaves()`, `LeavesWOPlaceholders()`
- Leaf types: `Var` (trace column reference), `Const` (field constant), `Placeholder` (challenge reference — same as `Var` for evaluation but excluded from `LeavesWOPlaceholders()`)
- `Convert(expr, varindex, nvars) Polynomial`: converts to dense multivariate polynomial
- `ToHorner(p Polynomial) *Horner`: efficient evaluation form; `h.Eval([]Element)`
- `RemoveDuplicates([]string) []string`: deduplicates while preserving order

### `plonk_example/` — PLONK Integration Example

Bridges gnark's PLONK circuit compilation to the IOP library:
- `BuildTrace(plonkTrace *gnark_plonk.Trace, solution *gnark_cs.SparseR1CSSolution, nbPublicInputs int) (cs.Trace, error)`: produces a 16-column trace (QL, QR, QM, QO, QK, S1, S2, S3, L, R, O, ID1, ID2, ID3 + Z/ZS slots)
  - Completes `Qk[i] = L[i]` for `i < nbPublicInputs` (gnark's `NewTrace` leaves these zero)
  - Domain size must be `NextPowerOfTwo(nbConstraints + nbPublicInputs)` to match `gnark`'s `evaluateLROSmallDomain`
  - **Use distinct named variables** for each polynomial local — reusing a single `p` variable and taking `&p` makes all map entries alias the same address

### `crypto/dummycommitment/`

Toy commitment scheme for testing:
- `Commit(p)`: returns `Coefficients[0]` as digest — works in any basis
- `Open(p, point)`: evaluates at point; requires Canonical basis
- `Verify(...)`: always returns nil

## Important Gotchas

**`Trace` is a `map[string]*Polynomial`**, not a slice. All column lookups are by name string.

**`Finalize` requires exactly one active constraint** (`len(S.Constraints) == 1`). Every constraint added outside `WithCaching()` bypasses the fold and counts separately. When using `Protocol`, use `WithCaching()` on all IOP builders and `NewLagrangeConstraint`, then call `FoldCachedConstraints` once before `Finalize`.

**Lagrange polynomial degree**: `NewPolynomial` strips trailing zeros when computing degree, which is wrong for Lagrange basis (each evaluation point is real data). After constructing a Lagrange polynomial from a slice, set `p.EP.Degree = len(p.EP.Coefficients) - 1`.

**`ComputeQuotient` returns `LagrangeShifted`** by default. Call `H.ToBasis(hDomain, Canonical)` before `H.Evaluate(zeta)`.

**FS challenge ordering**: every `SendMeAChallenge` call registers a new challenge name in the gnark-crypto FS transcript. Challenges must be derived strictly in order. A failed `SendMeAChallenge` (mid-loop, before `ComputeChallenge`) leaves the transcript broken for all subsequent challenges.

## Import Paths

```go
import (
    "github.com/consensys/iop/cs"
    "github.com/consensys/iop/pas/univariate"
    "github.com/consensys/iop/pas/sym"
    "github.com/consensys/iop/plonk_example"
    "github.com/consensys/iop/crypto/dummycommitment"
)
```
