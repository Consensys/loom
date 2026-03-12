# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build / check compilation
go build ./...

# Run all tests
go test ./...

# Run a single package
go test ./constraint/...
go test ./arguments/...
go test ./examples/fibonacci/...
go test ./examples/plonk_example/...

# Run a single test
go test ./arguments/... -run TestPermutationMultiSet -v

# Format and vet
go fmt ./...
go vet ./...
```

## Architecture

`github.com/consensys/giop` is a Go library for Interactive Oracle Proofs (IOPs) over the **Koalabear** finite field (`github.com/consensys/gnark-crypto/field/koalabear`). It proves that a **Trace** (a map of named polynomial columns) satisfies a set of algebraic constraints that vanish on `X^N - 1`.

### Top-level API (`api.go`, package `giop`)

```go
func Prove(cciop constraint.Program, trace trace.Trace, nbWorkers int) (proof.Proof, error)
func Verify(cciop constraint.Program, p *proof.Proof, nbWorkers int) error
```

### Layer overview (bottom → top)

| Package | Role |
|---|---|
| `expr/` | Symbolic AST for multivariate polynomial expressions |
| `internal/dag/` | DAG representation of `expr.Expr` with shared sub-expression nodes |
| `internal/poly/` | Univariate polynomial arithmetic, FFT, pointwise evaluation |
| `trace/` | `Trace = map[string][]koalabear.Element` |
| `proof/` | `Proof` and `TranscriptRound` types |
| `internal/derive/` | `DerivationStep`, step functions, and re-exports from `proof/` |
| `constraint/` | Constraint system: `Builder`, `Program`, constraint builders, compilation |
| `arguments/` | Standard IOP arguments (permutation, lookup, copy, projection) |
| `internal/prover/` | Prover pipeline: solve → fold → quotient → open |
| `internal/verifier/` | Verifier pipeline: replay FS → check algebraic relation |
| `internal/commitment/` | Toy commitment (digest = first coefficient) |
| `viz/` | HTML DAG visualisers, CSV trace viewer |
| `internal/utils/` | `RandomString(n int) (string, error)` — crypto-random alphanumeric IDs |
| `examples/fibonacci/` | Simple Fibonacci IOP example |
| `examples/plonk_example/` | Bridge from gnark PLONK traces to this IOP library |

### `expr/` — symbolic expressions

`Expr` is an AST interface supporting `Add/Sub/Mul/Pow`. The single concrete leaf type is `*Leaf` with a `LeafType` field:
- `CommittedColumn` — a trace column the prover commits to
- `ChallengeColumn` — a Fiat-Shamir challenge (treated as degree-0 constant)
- `VirtualColumn` — recomputable by the verifier (e.g. Lagrange columns)
- `RotatedColumn` — a column evaluated at `ω^shift · X`
- `ConstantColumn` — a literal field element

Constructors: `expr.Col(name)`, `expr.NewChallenge(name)`, `expr.Virtual(name)`, `expr.Rot(name, shift)`, `expr.Const(value)`.

`Leaves(config Config)` and `LeavesFull(config Config)` filter by leaf type using options: `WithoutCommittedColumns()`, `WithoutChallenges()`, `WithoutVirtualumns()`, `WithoutRotatedColumns()`. Shorthand slices: `expr.OnlyCommittedColumns`, `expr.OnlyChallenges`, `expr.OnlyRotatedColumns`.

Key utilities: `expr.RemoveDuplicates`, `expr.Clone`, `expr.Sum(...Expr)`, `expr.Prod(...Expr)`.

`Expr.Prune(deg int)` — extracts a sub-expression of degree ≤ deg, replacing it in-place with a `Col` leaf; used by degree reduction.

`Expr.EvaluateOnIthEntry(_Pi [][]koalabear.Element, i int)` — fast row-level evaluation; caller must set `Leaf.Idx` first via `LeavesFull`.

### `internal/dag/` — expression DAG

`DAG` is the shared-subexpression form of an `Expr`. Structurally identical sub-trees (including commutativity for Add/Mul) share a single `*DAGNode`.

- `dag.ExprToDAG(e expr.Expr) *DAG` — converts a tree to a DAG
- `dag.Flatten()` — returns a flattened/optimised DAG
- `dag.Eval(vars map[string]koalabear.Element)` — evaluates the DAG at scalar assignments
- `dag.Leaves(config)` — enumerates leaf names (same options as `expr.Leaves`)

`VanishingRelation` in `constraint.Program` and `verifier.Verifier` is a `dag.DAG`.

### `internal/poly/` — univariate polynomials

`Polynomial = []koalabear.Element`. All polynomials are in **Lagrange Normal** form (evaluations at `ω^0, ω^1, …`). `len(p) == 1` signals a constant polynomial.

`ComputeQuotient` returns **coset-Lagrange** form — always call `CosetLagrangeToLagrangeNormal(H)` before storing in the trace or committing.

Key functions in `iop_utils.go`:
- `BuildPointwiseEvaluation(trace, E, N, mu)` — computes `E(trace)` row-by-row
- `BuildGrandProduct(trace, E1, E2, N, mu)` — `R[0]=1, R[i+1]=R[i]·E1[i]/E2[i]`
- `BuildGrandSum(trace, E, M, N, mu)` — `R[i] = Σ_{j≤i} M[j]/E[j]`
- `BuildMultiplicityPolynomial(trace, S, T, N, mu)` — `M[i] = #{j | S[j]=T[i]}`
- `BuildFilteredAccPolynomial(trace, E, F, alpha, N, mu)` — accumulator filtered by binary column `F`

### `proof/` — proof types

```go
type TranscriptRound struct {
    ChallengeName                string
    DependenciesCommittedColumns []string
    DependenciesChallenges       []string
}

type Proof struct {
    OpeningProofs    map[string]commitment.PackedProof
    TranscriptRounds []TranscriptRound
    N                int
    // unexported: cacheChallengeDependencies map[string][]string
}
```

`proof.NewProof(N int) Proof` — constructor. `internal/derive/` re-exports these as `derive.Proof` and `derive.TranscriptRound` for use within `internal/`.

### `internal/derive/` — derivation steps and step functions

**Core types**:
```go
type StepKind int
type Step = func(trace.Trace, *Proof, *sync.Mutex, []expr.Expr, []string, StepContext) error
type StepContext interface { String() string; GetID() StepKind; Key() string }

type DerivationStep struct {
    Inputs      []expr.Expr
    Outputs     []string
    StepContext StepContext
}
type DerivationPlan = []DerivationStep
```

**`StepKind` constants**: `GRAND_SUM`, `GRAND_PRODUCT`, `LAGRANGE`, `COMPUTE_COL`, `MULTIPLICITY`, `FITLERED_ACC_POLY` (note typo), `FIAT_SHAMIR`, `PERMUTATION_GEN`, `REGISTER_COL`.

**Context constructors**:
- `NewIDStepContext(id StepKind) IDStepContext` — stateless, `Key()` returns `""`
- `NewLagrangeContext(i, N int) LagrangeContext` — idempotent via FNV-keyed cache
- `NewPermutationContext(S []int64) PermutationContext` — idempotent via FNV-keyed cache

**Utilities**:
- `GetLagrangeID(i, N)` → `LAGRANGE_i_N`
- `GetPermutationSupportID(i int) string` → `ID_i`
- `GetComputationableColumn(id)` — returns a `VirtualColumn` descriptor with `.F` (point evaluator) and `.Gen()` (full column generator)
- `NewColumn(trace, id, poly, mu)` — thread-safe column registration; errors if already present
- `GetColumnsBaseId(exprs)` — extracts committed column names from `[]expr.Expr`

### `constraint/` — constraint system

**Core types**:
```go
type Relation = expr.Expr

type Builder struct {
    Relations      []Relation
    DerivationPlan []derive.DerivationStep
    Cache          map[string]int  // key -> index in DerivationPlan (for deduplication)
    N              int
}

type Program struct {
    DerivationPlan    []derive.DerivationStep
    VanishingRelation dag.DAG   // Fold(relations, alpha) as a flattened DAG
    N                 int
}
```

`constraint.NewBuilder(N int) Builder` — constructor.

`builder.Compile(opts...) Program` — folds all relations with `constants.FINAL_FOLDING_CHALLENGE`, converts to `dag.DAG`, flattens. Option: `WithTargetDegree(d)` triggers degree reduction before folding.

`constraint.Fold(E []expr.Expr, alpha expr.Expr) expr.Expr` — Horner evaluation `Σ_i αⁱ·E[i]`; used by gadgets to compress multi-column row-tuples into a single scalar.

**Builder methods**:
- `builder.AssertZero(C Relation)` / `builder.AssertAllZero([]Relation)`
- `builder.RegisterDerivationStep(inputs []expr.Expr, outputs []string, ctx derive.StepContext)`
- `builder.AddLagrangeColumn(i int)` — idempotent via `Cache`
- `builder.AddPermutationColumns(S []int64) ([]string, error)` — idempotent via `Cache`; returns `allOutputs` where `allOutputs[:nbChunks]` are support IDs (`ID_i`) and `allOutputs[nbChunks:]` are permuted column IDs

**Constraint builders** (`common_constraints.go`):
- `BuildGrandProductRelation(E1, E2 expr.Expr, GP string, N int) []Relation` — recurrence + boundary
- `BuildGrandSumRelations(M, E expr.Expr, grandSum string, N int) []Relation`
- `BuildLocalRelation(E, M expr.Expr, i, N int) Relation` — `L_i·(E - M) = 0`
- `BuildCorrectConstructionRelation(E expr.Expr, IdRes string) Relation`
- `BuildFilteredAccPolynomialRelation(E, F, alpha expr.Expr, R string, N int) []Relation`

**Constants** (`internal/constants/const.go`): `FINAL_FOLDING_CHALLENGE`, `FINAL_EVALUATION_POINT`, `FINAL_QUOTIENT` — prefixed `github.com/consensys/giop@`. Also `GetShiftedName(id, shift)` / `SplitShiftedName(id)`.

### `arguments/` — standard IOP arguments

- `Permutation(system, ID1, ID2 []string) error` — proves `{ID1[i]}` = `{ID2[i]}` as multisets; gamma and grand product ID are generated internally
- `PermutationTuple(system, ID1, ID2 [][]string) error` — same for row-tuples; alpha and gamma generated internally
- `Lookup(system, S, T string) error` — proves every value in `S` appears in `T` (lookup argument using grand sums + multiplicity)
- `LookupTuple(system, S, T []string) error` — same for row-tuples; folds with a FS challenge before scalar lookup
- `Projection(system, A, F1, B, F2 string) error` — proves the ordered sub-sequence of `A` selected by binary column `F1` equals the ordered sub-sequence of `B` selected by `F2`; uses filtered accumulator (Horner) + boundary constraint
- `ProjectionTuple(system, A []string, F1 string, B []string, F2 string) error` — same for row-tuples; row-tuples compressed via FS challenge γ, then delegates to `Projection`
- `CopyPermutation(system, wires []string, S []int64) error` — PLONK-style copy constraint
- `CopyPermtutationTuple(system, wires [][]string, S []int64) error` — same for multiple wire columns

All arguments allocate fresh random IDs for intermediate columns/challenges via `utils.RandomString`.

### Prover pipeline (`internal/prover/prove.go`)

`Prover.Prove(knownColumns map[string]bool, nbWorkers int) (proof.Proof, error)` runs:
1. **`Solve`** — Kahn's scheduler executes `DerivationPlan` in topological order (parallel with `nbWorkers` goroutines); `knownColumns` seeds the initial ready set
2. **`DeriveFinalFoldingChallenge`** — commits all not-yet-committed trace columns, derives `alpha`, appends a `TranscriptRound` to the proof
3. **`ComputeQuotient`** — computes `H = VanishingRelation(trace) / (X^N - 1)`, calls `CosetLagrangeToLagrangeNormal(H)`, commits to `H`
4. **`DeriveOpeningChallenge`** — derives `zeta` from quotient commitment + folding challenge; returns `zeta`
5. **`OpenCommitments`** — `OpenNonShiftedCommitments` (all at `zeta`) + `OpenShiftedCommitments` (at `ω^shift · zeta`)

### Verifier pipeline (`internal/verifier/verify.go`)

`verifier.NewRunTime(cciop constraint.Program) Verifier` builds a `Verifier` with `VanishingRelation` = `cciop.VanishingRelation`.

`Verifier.Verify(proof *derive.Proof, nbWorkers int) error` runs:
1. **`ComputeChallenges`** — Kahn's scheduler replays FS rounds into `runtime.Vars`
2. **`EvaluateVirtualColumns`** — evaluates Lagrange columns at `zeta` via `ComputableColumn.F`
3. **`FillClaimedValues`** — copies prover-claimed opening values into `runtime.Vars`
4. **`CheckRelation`** — verifies `VanishingRelation.Eval(vars) = H(zeta) · (zeta^N - 1)`
5. **`VerifyOpeningProofs`** — calls `commitment.Verify` for each opening

### `viz/` — HTML visualisers

- `WriteProofRoundsDagToHTML(rounds []derive.TranscriptRound, filename)`
- `WriteProverActionsDagToHTML(cciop constraint.Program, filename)`
- `WriteTraceToCSV(filename, trace, N)`

## Key gotchas

**Polynomial representation**: always Lagrange Normal form. `len(p) == 1` means constant. `ComputeQuotient` is the only function returning coset-Lagrange — always call `CosetLagrangeToLagrangeNormal` on its result.

**Rotated columns**: use `expr.Rot(id, shift)` for `P(ω^shift · X)`. Shifted openings handled by `OpenShiftedCommitments` / `VerifyOpeningProofs`. Named `id_shift_N` in the trace/proof.

**`VanishingRelation` is a `dag.DAG`**: not an `expr.Expr`. Use `.Eval(vars)` for scalar evaluation and `.Leaves(config)` for leaf enumeration.

**Lagrange IDs**: `derive.GetLagrangeID(i, N)` → `LAGRANGE_i_N`. `VirtualColumn` leaves with this ID are evaluated by the verifier via `GetComputationableColumn`.

**Fiat-Shamir ordering**: challenges must be derived in the order they were registered. `cacheChallengeDependencies` in `Proof` avoids double-counting committed columns covered by a prior challenge.

**`DerivationPlan` ordering matters**: `Solve` is a Kahn scheduler — registration order must reflect the data-flow DAG.

**`derive.Proof` = `proof.Proof`**: `internal/derive/proof.go` re-exports `proof.Proof` as `derive.Proof` so internal packages can use the short name. External callers use `proof.Proof`.

**Thread safety**: `DerivationStep.Execute` must use `derive.NewColumn` (locks internally) for writes. Direct trace reads must lock manually with the shared `*sync.Mutex`.
