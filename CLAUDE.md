# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`github.com/consensys/iop` is a Go library for Interactive Oracle Proofs (IOP) and polynomial-based constraint systems. It depends on `gnark-crypto` for the Koalabear finite field and FFT operations, and on `gnark` for PLONK integration.

## Building and Testing

```bash
# Build all packages
go build ./...

# Run all tests
go test ./...

# Run tests for a specific package
go test ./cs
go test ./pas/univariate
go test ./pas/sym
go test ./plonk

# Run a specific test
go test ./cs -run TestVanishing
go test ./pas/univariate -run TestBuildLinComb

# Run tests with verbose output
go test -v ./cs
```

## Package Architecture

### cs - Constraint Systems and IOP Protocols

The `cs` package contains both constraint system definitions and the IOP protocol logic (previously split into a separate `sigma` package).

**Core Types (`data.go`):**
```go
type Trace = []univariate.Polynomial  // Column polynomials
type Constraint = sym.Expr            // Alias for symbolic expressions

type System struct {
    Trace      Trace
    Constraint Constraint
    N          int           // Domain size
}

// Transcript holds a complete IOP proof (commitments + opening proofs)
type Transcript struct {
    OpeningProofs []dummycommitment.PackedProof
    Quotient      dummycommitment.PackedProof
    Constraint    Constraint
    Bindings      []Binding  // Ordered challenge derivation rounds
    N             int
}

// Binding describes one round: which commitments feed into which challenge
type Binding struct {
    ChallengeName   string
    CommitmentsName []string
}

// IopOption allows forcing challenge names/values (e.g. for testing)
type IopConfig struct {
    ChallengeNames  []string
    ChallengeValues []koalabear.Element
}
```

**Protocol Builders** — each returns a `System` (satisfiability check) and a `Transcript` (proof structure):
- `NewVanishingProtocol(S System, opts ...IopOption) (Transcript, error)`: proves C(P)=0 mod X^n-1; automatically commits to trace + quotient and derives `zeta` via Fiat-Shamir
- `NewFoldingProtocol(P []Polynomial, alpha Element) (System, Transcript, error)`: proves Σᵢ αⁱ·P[i] = R
- `NewPermutationProtocol(P1, P2 []Polynomial, challenge Element) (System, System, error)`: returns two systems; both satisfied iff P1 = P2 as multisets (grand product argument); challenge is represented as a `NewConstantPolynomial`
- `NewLagrangeProtocol(P Polynomial, entry int, value Element) (System, Transcript, error)`: proves P[entry] = value

**Shared Verifier (`verifier.go`):**
- `Verify(T *Transcript, opts ...IopOption) error`: replays the Fiat-Shamir transcript to rederive all challenges, checks opening proofs, and checks C(evaluations) = Q(ζ)·(ζⁿ−1). The last challenge in `T.Bindings` is always the evaluation point ζ; all earlier challenges appear as variables in `T.Constraint` and are passed to `ComputeEvaluationWithClaimedValues`.

**Constraint Checkers (`constraint_checker.go`):**
- `CheckConstraintSystem(S System) error`: quotient method — checks at one random point; **modifies** `S.Trace` in-place (converts to Canonical basis)
- `BruteForceChecker(S System) error`: evaluates constraint at every ω^j; requires Lagrange/constant polynomials in the trace

**Σ-Protocol Flow (vanishing example):**
1. Prover: commits to trace columns → commits to quotient H → binds all to FS transcript → derives ζ → opens everything at ζ
2. Verifier: re-derives ζ from same commitments → verifies openings → checks C(cols(ζ), challenges) = H(ζ)·(ζⁿ−1)

### pas/univariate - Univariate Polynomial Operations

**Polynomial Representations:**
- **Basis**: `Canonical` (coefficients), `Lagrange` (evaluations at ω^i), `LagrangeShifted` (evaluations at w·ω^i — avoids roots of X^n-1)
- **Layout**: `Normal`, `BitReversed` (FFT-friendly)
- **Shift**: integer field on `Polynomial` wrapper, represents P(ω^shift · X)
- **IsConstant**: flag on `EPolynomial`; when true, `GetCoefficient(i)` always returns `Coefficients[0]` regardless of index; `ToBasis` is a no-op; `BuildRatio` skips degree checks

**Key Operations:**
- `NewInterpolatedPolynomial(evals []Element, id, opts...)`: Lagrange basis
- `NewConstantPolynomial(value Element, opts...)`: single-coefficient constant; `GetCoefficient` returns the constant at any index
- `NewPolynomial(coeffs []Element, opts...)`: use `WithBasis`, `WithLayout`, `WithID` options
- `ToBasis(domain, targetBasis)` / `ToLayout(targetLayout)`: basis and layout conversions
- `GetCoefficient(i)`: returns P(ω^i) for Lagrange/LagrangeShifted basis; **panics** for Canonical (non-constant) basis
- `BuildLinComb(P []Polynomial, alpha Element)`: Σᵢ αⁱ·P[i]
- `BuildRatio(C1, C2 Expr, P1, P2 []Polynomial)`: R[0]=1, R[i+1] = R[i]·C1(P1[i])/C2(P2[i])
- `ComputeQuotient(Pi []Polynomial, C Expr, opts...)`: C(Pi) / (X^n-1); builds its own varindex from polynomial IDs
- `ComputeSym(Pi []Polynomial, Q *Horner, varindex VarIndex, opts...)`: Q(P1,...,Pn) pointwise; makes copies internally

**`CopyE` does not copy `IsConstant`** — copies of constant polynomials lose the flag and behave as regular 1-coefficient Canonical polynomials (they get FFT'd to all-constant Lagrange on `ToBasis`).

### pas/sym - Symbolic Expression System

- `Expr` interface: `Add()`, `Sub()`, `Mul()`, `Pow()`; leaf types are `Var` and `Const`
- `VarIndex`: `map[string]int` — maps variable name → position in value slice for evaluation
- `Convert(expr Expr, varindex VarIndex, nvars int) Polynomial`: converts `Expr` to multivariate polynomial
- `ToHorner(p Polynomial) *Horner`: Horner form for efficient evaluation via `h.Eval(values []Element)`

### plonk - PLONK IOP Integration

- `BuildTrace(plonkTrace, plonkSolution) (cs.Trace, error)`: converts gnark PLONK trace to 14-column `cs.Trace` (T[0-4]=QL/QR/QM/QO/QK, T[5-7]=S1/S2/S3, T[8-10]=L/R/O, T[11-13]=ID1/ID2/ID3 coset columns)
- `PlonkProver(T cs.Trace) ([]cs.System, []cs.Transcript, error)`: constructs 9 systems (3 fi-folding, 3 gi-folding, permutation recursive, permutation Lagrange, arithmetic)

### crypto/dummycommitment and crypto/dummyhash

Toy implementations used in tests:
- `dummycommitment.Commit(p)`: returns `Digest{p.EP.Coefficients[0]}` — works in any basis
- `dummycommitment.Open(p, point)`: evaluates p at point (requires Canonical basis)
- `dummycommitment.Verify(...)`: always returns nil
- `dummyhash.Hash{}`: always returns the same fixed bytes from `Sum()`; used with `fiatshamir.NewTranscript` from gnark-crypto

## Important Behaviors

**`CheckConstraintSystem` modifies the trace in-place** (converts all columns to Canonical basis). Call it before `NewVanishingProtocol`, or the dummy `Commit` and `BruteForceChecker` (which use Lagrange coefficients) may receive Canonical-basis polynomials.

**Constant polynomials in the trace**: `NewConstantPolynomial` is used to represent challenge values (e.g., `"gamma"` in permutation). `BruteForceChecker` handles them correctly (returns the constant at every index). `BuildRatio` also handles them correctly because `CopyE` loses `IsConstant`, causing the copy to go through FFT → all-constant Lagrange evaluations.

**Shift operations**: `ShallowCopy` + `SetShift` creates a metadata-only shift; coefficients are not rearranged. This is valid for `BruteForceChecker` (which uses `GetCoefficient` with shift arithmetic) but not for direct coefficient access.

## Import Paths

```go
import (
    "github.com/consensys/iop/cs"
    "github.com/consensys/iop/pas/univariate"
    "github.com/consensys/iop/pas/sym"
    "github.com/consensys/iop/plonk"
    "github.com/consensys/iop/crypto/dummycommitment"
    "github.com/consensys/iop/crypto/dummyhash"
)
```

## Testing Conventions

- Use `WithChallengeValues(...)` option on `NewVanishingProtocol` / `Verify` to force deterministic challenges in tests
- For permutation tests: use element-level cross-column permutation (flat-array rotation), not row-level swaps
- Test both valid and invalid inputs (e.g., `BruteForceChecker` should fail for non-permutations)
- `GetTrivialVanishingConstraint(t)` and `GetNonTrivialVanishingConstraint(t)` in `cs/test_utils.go` provide ready-made test systems
