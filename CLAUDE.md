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
| `pas/dag/` | DAG representation of `sym.Expr` with shared sub-expression nodes |
| `pas/univariate/` | Univariate polynomial arithmetic, FFT, pointwise evaluation |
| `trace/` | `Trace = map[string]univariate.Polynomial` |
| `prover_actions.go/` | `ProverAction`, `Proof`, `Round`, and all built-in action functions |
| `cs/` | Constraint system: types, constraint builders, compilation |
| `std/` | Standard IOP gadgets (permutation, inclusion, multiset equality) |
| `prover/` | Prover pipeline: solve → fold → quotient → open |
| `verifier/` | Verifier pipeline: replay FS → check algebraic relation |
| `crypto/dummycommitment/` | Toy commitment (digest = first coefficient) |
| `viewer/` | HTML DAG visualisers, CSV trace viewer |
| `plonk_example/` | Bridge from gnark PLONK traces to this IOP library |

### `pas/sym` — symbolic expressions

`Expr` is an AST interface supporting `Add/Sub/Mul/Pow`. Leaf types:
- `CommittedColumn` — a trace column the prover commits to
- `Challenge` — a Fiat-Shamir challenge (treated as a constant during evaluation)
- `ComputableColumn` — recomputable by the verifier (e.g. Lagrange columns)
- `ShiftedColumn` — a committed column evaluated at `ω^shift · X`

`Leaves(config)` filters by `WithoutCommittedColumns()` / `WithoutChallenges()` / `WithoutComputableColumns()` / `WithoutShiftedColumns()`. Shorthand filter slices: `sym.OnlyCommittedColumns`, `sym.OnlyChallenges`.

`NewShiftedColumn(id, shift)` creates `P(ω^shift · X)`.

### `pas/dag` — expression DAG

`DAG` is the shared-subexpression form of an `Expr`. Structurally identical sub-trees (including commutativity for Add/Mul) share a single `*DAGNode`.

- `ExprToDAG(e sym.Expr) *DAG` — converts a tree to a DAG
- `dag.Flatten()` — returns a flattened/optimised DAG
- `dag.Eval(vars map[string]koalabear.Element)` — evaluates the DAG at scalar assignments
- `dag.Leaves(config)` — enumerates leaf names (same options as `sym.Leaves`)

`VanishingRelation` in `CompiledIOP` and `verifier.Runtime` is a `dag.DAG`, not a `sym.Expr`.

### `pas/univariate` — univariate polynomials

`Polynomial = []koalabear.Element`. All polynomials are in **Lagrange Normal** form (evaluation at `ω^0, ω^1, …`). No basis/layout metadata.

- `len(p) == 1` signals a constant polynomial.
- `ComputeQuotient` returns **coset-Lagrange** form — call `CosetLagrangeToLagrangeNormal(H)` before storing in the trace or committing.
- `dummycommitment.Open` does IFFT + BitReverse + Horner to evaluate a Lagrange Normal polynomial.

Key functions in `iop_utils.go`:
- `BuildPointwiseEvaluation(trace, E, N, mu)` — computes `E(trace)` row-by-row
- `BuildGrandProduct(trace, E1, E2, N, mu)` — `R[0]=1, R[i+1]=R[i]·E1[i]/E2[i]`
- `BuildGrandSum(trace, E, M, N, mu)` — `R[i] = Σ_{j≤i} M[j]/E[j]`
- `BuildMultiplicityPolynomial(trace, S, T, N, mu)` — `M[i] = #{j | S[j]=T[i]}`
- `BuildFilteredAccPolynomial(trace, E, F, alpha, N, mu)` — accumulator filtered by binary column `F`

### `prover_actions.go/` — prover actions and proof types

**Note**: the package is in a directory named `prover_actions.go` (with `.go` suffix) and imported as `proveractions "github.com/consensys/giop/prover_actions.go"`.

**Core types**:
```go
type Action = func(trace.Trace, *Proof, *sync.Mutex, []sym.Expr, []string) error

type ProverAction struct {
    Inputs  []sym.Expr
    Outputs []string
    Exec    Action
}

type Round struct {
    ChallengeName                string
    DependenciesCommittedColumns []string
    DependenciesChallenges       []string
}

type Proof struct {
    OpeningProofs map[string]dummycommitment.PackedProof
    Rounds        []Round
    N             int
    // unexported: cacheChallengeDependencies map[string][]string
}
```

**Built-in action functions** (pass directly as `ProverAction.Exec`):
- `ComputeChallenge` — commits to columns in `E`, derives FS challenge, appends a `Round` to `proof.Rounds`, stores the challenge as a constant column in the trace
- `ComputeGrandProduct` — builds grand product column `R` from `E[0]/E[1]`
- `ComputeGrandSum` — builds grand sum column from `E[0]/E[1]`
- `ComputeColumn` — evaluates `E[0]` pointwise, stores result
- `ComputeMultiplicity` — computes multiplicity of `E[0]` in `E[1]`
- `ComputeLagrangeColumn` — generates the i-th Lagrange column (idempotent if already present)

**Utilities**:
- `GetColumnsId(E, opts...)` — extracts leaf column IDs from `[]sym.Expr`
- `GetLagrangeID(i, N)` — canonical ID `LAGRANGE_i_N` for the i-th Lagrange column
- `GetComputationableColumn(id)` — returns a `ComputableColumn` with `.F` (evaluator at a point) and `.Gen()` (generates the full column)
- `RegisterColumn(trace, id, poly, mu)` — thread-safe column registration; errors if already present

### `cs` — constraint system

**Core types** (`system.go`, `compile.go`):
```go
type Constraint = sym.Expr

type System struct {
    Constraints   []Constraint
    ProverActions []proveractions.ProverAction
    N             int
}

type CompiledIOP struct {
    ProverActions     []proveractions.ProverAction
    VanishingRelation dag.DAG   // Fold(system.Constraints, alpha) as a DAG
    N                 int
}
```

`cs.Compile(&system, opts...)` folds all constraints with `constants.FINAL_FOLDING_CHALLENGE`, converts to a `dag.DAG`, and flattens it. Option: `WithTargetDegree(d)` triggers degree reduction before folding.

**Constraint builders** (`common_constraints.go`):
- `BuildGrandProductConstraint(E1, E2, IDGrandProduct, N)` — `R(ωX)·E2 - R·E1 = 0`
- `BuildGrandSumConstraints(M, E, grandSum, N)` — two constraints encoding the recurrence relation
- `BuildLocalConstraint(E, M, i, N)` — `L_i·(E - M) = 0`
- `BuildCorrectConstructionConstraint(E, IdRes)` — `IdRes - E = 0`

**System methods**:
- `system.RegisterProverAction(inputs, outputs, exec)`
- `system.RegisterConstraint(C)` / `system.RegisterConstraints([]C)`
- `system.RegisterithLagrangeColumn(i)` — registers the Lagrange column prover action

**Constants** (`constants/const.go`): `FINAL_FOLDING_CHALLENGE`, `FINAL_EVALUATION_POINT`, `FINAL_QUOTIENT` — prefixed with `github.com/consensys/giop@`. Also `GetShiftedName(id, shift)` / `SplitShiftedName(id)` for shifted column naming.

### `std` — standard gadgets

- `EqualityUpToPermutationIOP(system, ID1, ID2 []string)` — proves `{ID1[i]}` = `{ID2[i]}` as multisets; gamma and grand product ID are generated internally
- `MultiSetEqualityUpToPermutationIOP(system, ID1, ID2 [][]string)` — same for tuples; alpha and gamma generated internally
- `InclusionCheckIOP(system, S, T string)` — proves every value in `S` appears in `T` (lookup argument using grand sums + multiplicity)
- `InclusionCheckMultiSetIOP(system, S, T []string)` — same for row-tuples; folds with a FS challenge before scalar inclusion check

All gadgets allocate fresh random IDs for intermediate columns/challenges via `RandomString`.

### Prover pipeline (`prover/prove.go`)

`Runtime.Prove(knownColumns, nbWorkers)` runs:
1. **`Solve`** — Kahn's scheduler executes `ProverActions` in topological order (parallel with `nbWorkers` goroutines); `knownColumns` seeds the initial ready set
2. **`DeriveFinalFoldingChallenge`** — commits all not-yet-committed trace columns, binds them and all final challenges to FS, derives `alpha`, registers in trace and proof
3. **`ComputeQuotient`** — computes `H = VanishingRelation(trace) / (X^N - 1)`, calls `CosetLagrangeToLagrangeNormal(H)`, commits to `H`
4. **`DeriveOpeningChallenge`** — derives `zeta` from quotient commitment + folding challenge, registers in trace; returns `zeta`
5. **`OpenCommitments`** — `OpenNonShiftedCommitments` (all at `zeta`) + `OpenShiftedCommitments` (at `ω^shift · zeta` for each shifted leaf)

### Verifier pipeline (`verifier/verify.go`)

`NewRunTime(cciop)` builds a `Runtime` with `VanishingRelation` = `cciop.VanishingRelation`.

`Runtime.Verify(&proof, nbWorkers)` runs:
1. **`ComputeChallenges`** — Kahn's scheduler replays FS rounds into `runtime.Vars`
2. **`EvaluateComputableColumns`** — evaluates Lagrange columns at `zeta` via `ComputableColumn.F`
3. **`FillClaimedValues`** — copies prover-claimed opening values into `runtime.Vars` (non-shifted and shifted)
4. **`CheckRelation`** — verifies `VanishingRelation.Eval(vars) = H(zeta) · (zeta^N - 1)`
5. **`VerifyOpeningProofs`** — calls `dummycommitment.Verify` for each opening

### `viewer` — HTML visualisers

- `WriteProofRoundsDagToHTML(rounds []proveractions.Round, filename)`
- `WriteProverActionsDagToHTML(cciop cs.CompiledIOP, filename)`
- `WriteTraceToCSV(filename, trace, N)`

## Key gotchas

**Polynomial representation**: `Polynomial = []koalabear.Element`, always in Lagrange Normal form. `len(p) == 1` means constant. `ComputeQuotient` is the only function that returns coset-Lagrange — always call `CosetLagrangeToLagrangeNormal` on its result.

**`prover_actions.go/` package name**: the directory is literally named `prover_actions.go`; import with the alias `proveractions "github.com/consensys/giop/prover_actions.go"`.

**Action mutex**: `Action` signature includes `*sync.Mutex`. Actions that write to the trace must use `RegisterColumn` (which locks internally). Actions that read from the trace or the proof must lock manually.

**Shifted columns**: use `sym.NewShiftedColumn(id, shift)` for `P(ω^shift · X)`. Shifted openings are handled by `OpenShiftedCommitments` / `VerifyOpeningProofs`. Filter with `sym.WithoutShiftedColumns()` or `sym.WithoutCommittedColumns()` as needed.

**Fiat-Shamir transcript**: challenges must be derived in the exact order they were registered. `ComputeChallenge` uses `cacheChallengeDependencies` to avoid double-counting committed columns that are already covered by a prior challenge.

**`ProverActions` registration order matters**: `Solve` is a Kahn scheduler — it only parallelises actions whose dependencies are satisfied. The ordering must reflect the data-flow DAG at registration time.

**`VanishingRelation` is a `dag.DAG`**: not a `sym.Expr`. Use `.Eval(vars)` for evaluation and `.Leaves(config)` for leaf enumeration.

**Lagrange column IDs**: `GetLagrangeID(i, N)` → `LAGRANGE_i_N`. `ComputeLagrangeColumn` is idempotent: if the column is already in the trace it returns `nil` without error.
