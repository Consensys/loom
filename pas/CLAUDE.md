# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PAS (Polynomial Algebra System) is a Go library providing efficient polynomial operations over finite fields, with a focus on zero-knowledge proof systems. The library uses the Koalabear finite field from `github.com/consensys/gnark-crypto`.

## Architecture

### Package Structure

**`sym/`** - Symbolic Expression System
- Defines an AST for multivariate polynomials with algebraic operations
- Core types: `Expr` interface, `Var`, `Const`, `Add`, `Sub`, `Mul`, `Pow`
- `Polynomial` represents multivariate polynomials with coefficients stored as `map[string]koalabear.Element` where keys encode monomial exponents
- `Horner` form optimizes polynomial evaluation using Horner's method
- `Convert()` transforms symbolic expressions into multivariate polynomials
- `ToHorner()` converts multivariate polynomials to Horner form for efficient evaluation

**`univariate/`** - Univariate Polynomial Operations
- `EPolynomial`: Core univariate polynomial representation with coefficients, basis, layout, and degree
- `Polynomial`: Wrapper around `EPolynomial` that adds shift metadata for working with shifted domains
- Three basis representations:
  - `Canonical`: Standard coefficient form (1, x, x², ...)
  - `Lagrange`: Evaluations at FFT domain points
  - `LagrangeShifted`: Evaluations at shifted domain points (avoids vanishing sets X^n-1)
- Two memory layouts:
  - `Normal`: Standard ordering
  - `BitReversed`: Bit-reversed ordering for FFT efficiency
- Key operations:
  - `ComputeSym()`: Evaluates Q(P₁, ..., Pₙ) where Q is a multivariate polynomial and Pᵢ are univariate polynomials
  - `ComputeQuotient()`: Computes Q(P₁, ..., Pₙ) / (X^m-1) when the numerator is zero mod X^m-1
  - Basis conversions using FFT operations with careful layout management to minimize bit-reversals
  - Polynomial evaluation via Horner's method (canonical basis only)

**`cs/`** - Constraint System Tools
- `Constraint`: Type alias for `sym.Expr` representing polynomial constraints that must equal zero on traces
- `Trace`: Represents execution traces with columns (univariate polynomials) and variable index mapping
- `CheckTrace()`: Verifies constraint satisfiability by computing quotient h = C(T)/(X^n-1) and checking at random point
- `BuildRatio()`: Constructs ratio polynomial R where R[i+1] = R[i] × Q1(P1[i])/Q2(P2[i])
- `Fold()`: Combines multiple constraints using powers of challenge z: ∑ᵢ zⁱ×C[i]

### Key Design Patterns

**Polynomial Composition**: The core operation `Q(P₁, ..., Pₙ)` is computed by:
1. Converting all input polynomials to LagrangeShifted basis on the same domain
2. Pointwise evaluation: Result[i] = Q(P₁[i], ..., Pₙ[i])
3. Converting result back to desired basis/layout

**FFT Layout Management**: To minimize expensive bit-reversal operations:
- DIF (Decimation In Frequency): Normal input → BitReversed output
- DIT (Decimation In Time): BitReversed input → Normal output
- Conversions choose FFT mode based on current layout to avoid unnecessary bit-reversals

**Shifted Domains**: LagrangeShifted basis evaluates at w×ωⁱ instead of ωⁱ (where w is multiplicative generator), avoiding zeros of X^n-1 which is critical for quotient computation.

## Common Commands

### Testing
```bash
# Run all tests
go test ./...

# Run all tests with verbose output
go test -v ./...

# Run tests for a specific package
go test ./sym -v
go test ./univariate -v
go test ./cs -v

# Run a specific test
go test ./cs -run TestTraceTrivialQuotient -v

# Run tests with race detector
go test -race ./...
```

### Building
```bash
# Build all packages
go build ./...

# Check for compilation errors without producing binaries
go build -o /dev/null ./...
```

### Code Quality
```bash
# Format code
go fmt ./...

# Run static analysis
go vet ./...

# Tidy dependencies (removes unused)
go mod tidy

# Verify dependencies
go mod verify
```

## Development Notes

- All polynomial operations work over the Koalabear finite field
- When working with univariate polynomials, be mindful of basis and layout - conversions have computational cost
- The `Shift` field in `Polynomial` represents circular shifts in the coefficient domain (used for shifted evaluations)
- Polynomial IDs must be unique and non-empty when used in symbolic operations
- Domain sizes must be powers of two for FFT operations
- When computing quotients, inputs should use LagrangeShifted basis to avoid division-by-zero at roots of unity
