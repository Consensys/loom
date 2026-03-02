# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build / check compilation
go build ./...

# Run all tests
go test ./...

# Run a single package
go test ./cs/...
go test ./std/...
go test ./viewer/...

# Run a single test
go test ./std/... -run TestPermutationMultiSet -v

# Format and vet
go fmt ./...
go vet ./...
```

## Architecture

`github.com/consensys/giop` is a Go library for Interactive Oracle Proofs (IOPs) over the **Koalabear** finite field (`github.com/consensys/gnark-crypto/field/koalabear`). It proves that a **Trace** (a map of named polynomial columns) satisfies a set of algebraic constraints that vanish on `X^N - 1`.

### Layer overview (bottom → top)

| Package | Role |
|---|---|
| `pas/sym/` | Symbolic AST for multivariate polynomial expressions |
| `pas/univariate/` | Univariate polynomial arithmetic, FFT, basis conversion |
| `trace/` | `Trace = map[string]*univariate.Polynomial` |
| `cs/` | Constraint system: types, Fiat-Shamir, grand product, Lagrange |
| `std/` | Standard IOP gadgets (permutation, multiset equality) |
| `prover/` | Prover pipeline: solve → fold → quotient → open |
| `verifier/` | Verifier pipeline: replay FS → check algebraic relation |
| `crypto/dummycommitment/` | Toy commitment (digest = first coefficient) |
| `viewer/` | HTML DAG visualisers, CSV trace viewer |
| `plonk_example/` | Bridge from gnark PLONK traces to this IOP library |

### `pas/sym` — symbolic expressions

`Expr` is an AST interface supporting `Add/Sub/Mul/Pow`. Three leaf types encode column status:
- `CommittedColumn` — a trace column the prover commits to
- `Challenge` — a Fiat-Shamir challenge (degree 0, treated as a constant during evaluation)
- `ComputableColumn` — recomputable by the verifier (e.g., Lagrange basis columns)

`Leaves(config)` traverses the AST and returns column IDs, filtered by `WithoutCommittedColumns()` / `WithoutChallenges()` / `WithoutComputableColumns()`.

`Convert(expr, varindex, nvars)` → dense multivariate `Polynomial`; `ToHorner(p)` → efficient `*Horner` for evaluation via `h.Eval([]Element)`.

### `pas/univariate` — univariate polynomials

`Polynomial` wraps `*EPolynomial` (coefficients + basis + layout + degree) with an integer `Shift` for `P(ω^shift · X)`.

Three bases: `Canonical`, `Lagrange`, `LagrangeShifted`. Two layouts: `Normal`, `BitReversed`.

Critical operations:
- `GetCoefficient(i)` — works in Lagrange/LagrangeShifted and for constant polynomials; **panics** in Canonical (non-constant)
- `Evaluate(x)` — Horner evaluation; **requires Canonical basis**
- `ToBasis(domain, targetBasis)` — in-place basis conversion via FFT
- `EvalPointWise(trace, E, N)` — computes `E(trace)` row-by-row in Lagrange basis
- `ComputeQuotient(trace, E, N)` — computes `E(trace) / (X^N - 1)`; returns **LagrangeShifted** by default — call `ToBasis(domain, Canonical)` before `Evaluate`
- `BuildGrandProduct(trace, E1, E2, N)` — constructs `R` with `R[0]=1, R[i+1]=R[i]·E1[i]/E2[i]`

### `cs` — constraint system

**Core types** (`cs.go`, `compile.go`):
```go
type Trace = map[string]*univariate.Polynomial  // trace/trace.go
type Constraint = sym.Expr

type ProverAction struct {
    Inputs  []sym.Expr  // symbolic inputs; leaves give the required column IDs
    Outputs []string    // column IDs produced
    Exec    Action      // func(Trace, *Proof, []sym.Expr, []string) error
}

type System struct {
    Constraints   []Constraint
    ProverActions []ProverAction
    N             int
}

type Round struct {
    ChallengeName                string
    DependenciesCommittedColumns []string
    DependenciesChallenges       []string
}

type Proof struct {
    OpeningProofs     map[string]dummycommitment.PackedProof
    VanishingRelation Constraint
    Rounds            []Round
    N                 int
}

type CompiledIOP struct {
    ProverActions     []ProverAction
    VanishingRelation Constraint  // Fold(system.Constraints, alpha)
    N                 int
}
```

`cs.Compile(&system)` folds all constraints symbolically with `constants.FINAL_FOLDING_CHALLENGE` (the actual challenge value is derived at prove-time).

**Key functions** in `cs/`:
- `SendMeAChallenge(trace, proof, E, outputs)` — commits to columns in `E`, derives FS challenge, appends a `Round` to `proof.Rounds`, stores challenge as constant column in trace
- `GrandProduct(trace, proof, E, outputs)` — builds grand product column `R` and shifted version `R(w^1X)`, registers both in trace
- `GetColumnsId(E, opts...)` — extracts leaf column IDs from `[]sym.Expr`, with optional filtering
- `GetLagrangeID(i, N)` — canonical ID for the i-th Lagrange basis column

**Constants** (`constants/const.go`): `FINAL_FOLDING_CHALLENGE`, `FINAL_EVALUATION_POINT`, `FINAL_QUOTIENT` — prefixed with `github.com/consensys/giop@` to avoid namespace collisions.

### `std` — standard gadgets

- `EqualityUpToPermutationIOP(system, ID1, ID2, IDGrandProduct, gamma)` — proves `{ID1[i]}` = `{ID2[i]}` as multisets via a grand product argument
- `MultiSetEqualityUpToPermutationIOP(system, ID1, ID2, IDGrandProduct, alpha, gamma)` — same for tuples; uses `alpha` to compress tuples into scalars first, then `gamma` for the grand product
- `LocalConstraint(system, ID, i, value)` — constrains `Trace[ID][i] == value` using the Lagrange basis column `L_i`

### Prover pipeline (`prover/prove.go`)

`Runtime.Prove(knownColumns, nbWorkers)` runs:
1. **`Solve`** — Kahn's scheduler executes `ProverActions` in topological order; `knownColumns` seeds the initial ready set
2. **`DeriveFinalFoldingChallenge`** — commits all not-yet-committed trace columns, binds them to FS, derives `alpha`, registers it in trace and proof
3. **`ComputeQuotient`** — computes `H = VanishingRelation(trace) / (X^N - 1)`, commits to `H`, stores in trace
4. **`DeriveOpeningChallenge`** — derives `zeta` from commitment to `H`, registers in trace
5. **`OpenCommitments`** — evaluates all entries in `proof.OpeningProofs` at `zeta`

### Verifier pipeline (`verifier/verify.go`)

`NewRunTime(cciop)` builds a `Runtime` with `Varindex` populated from `cciop.VanishingRelation.Leaves()`.

`Runtime.Verify(&proof)` runs:
1. **`ComputeChallenges`** — Kahn's scheduler replays FS rounds to re-derive all challenges into `runtime.Vars`
2. **`ComputeOpeningPoint`** — re-derives `zeta` from commitment to quotient
3. **`EvaluateComputableColumns`** — evaluates Lagrange-type columns at `zeta`
4. **`FillClaimedValues`** — copies prover-claimed opening values into `runtime.Vars`
5. **`CheckRelation`** — verifies `VanishingRelation(openings) = H(zeta) · (zeta^N - 1)` using `sym.ToHorner` + `Eval`
6. **`VerifyOpeningProofs`** — calls `dummycommitment.Verify` for each opening (currently a no-op)

### `viewer` — HTML visualisers

- `WriteProofRoundsDagToHTML(rounds []cs.Round, filename)` — DAG of verifier FS rounds: committed-column leaf nodes → challenge nodes
- `WriteProverActionsDagToHTML(cciop cs.CompiledIOP, filename)` — bipartite DAG: known columns → action nodes → computed columns
- `WriteTraceToCSV(filename, trace, N)` — dumps all trace columns as CSV

## Key gotchas

**Polynomial basis discipline**: `Evaluate(x)` requires `Canonical` basis. `GetCoefficient(i)` requires `Lagrange`/`LagrangeShifted` or a constant polynomial. `dummycommitment.Open` converts to Canonical automatically. `ComputeQuotient` returns `LagrangeShifted` — call `ToBasis(domain, Canonical)` before evaluating at a point.

**`squareAndMultiply` builds trees, not DAGs**: `Expr.Pow(n)` uses binary exponentiation with `Clone` on every step to ensure no shared nodes. Shared nodes break `Prune` (which rewrites in-place).

**Fiat-Shamir transcript**: challenges must be derived in the exact order they were registered. A failed `SendMeAChallenge` mid-loop leaves the transcript in a broken state.

**`ProverActions` are in topological order**: `Solve` relies on this. The Kahn scheduler merely parallelises execution; the ordering must be correct at registration time.

**Lagrange column IDs**: `GetLagrangeID(i, N)` generates a canonical ID. The same Lagrange column registered from different gadgets is idempotent (`AddComputableColumn` is a no-op if the column already exists).

**`VarIndex` scope**: `verifier.Runtime.Varindex` is built from `cciop.VanishingRelation.Leaves()`. `FINAL_EVALUATION_POINT` (zeta) is stored in `runtime.Zeta` and is NOT in `Varindex`.
