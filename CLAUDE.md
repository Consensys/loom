# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build / check compilation
go build ./...

# Run all tests
go test ./...

# Run a single package
go test ./prover/...
go test ./verifier/...
go test ./board/...
go test ./arguments/...
go test ./internal/poly/...

# Run a single test
go test ./prover/... -run TestProver -v

# Run integration tests (go-corset bridge)
go test ./integration_test/... -run TestIntegration -v

# Run a single integration subtest
go test ./integration_test/... -run TestIntegration/permute_04 -v

# Format and vet
go fmt ./...
go vet ./...
```

## Architecture

`github.com/consensys/loom` is a Go library for Interactive Oracle Proofs (IOPs) over the **Koalabear** finite field (`github.com/consensys/gnark-crypto/field/koalabear`). It proves that a **Trace** (a map of named polynomial columns) satisfies a set of algebraic constraints that vanish on `X^N - 1`.

### Layer overview (bottom → top)

| Package | Role |
|---|---|
| `expr/` | Symbolic AST for multivariate polynomial expressions |
| `internal/dag/` | DAG representation of `expr.Expr` with shared sub-expression nodes |
| `internal/poly/` | Univariate polynomial arithmetic, FFT, pointwise evaluation |
| `internal/reedsolomon/` | Reed-Solomon encoding for commitments |
| `internal/merkle/` | Merkle tree for commitment roots |
| `internal/commitment/` | RS-based polynomial commitment scheme |
| `trace/` | `Trace = map[string][]koalabear.Element` |
| `proof/` | `Proof`, `PublicInput`, `LogupBus` types |
| `board/` | **Core**: modular constraint system — `Builder`, `Module`, `Compile`, `Program`, `ProverStep` |
| `arguments/` | Standard IOP arguments (permutation, lookup, copy, projection) |
| `prover/` | Prover pipeline: execute steps → quotient → evaluate at zeta |
| `verifier/` | Verifier pipeline: replay FS → check relations |
| `integration_test/` | go-corset → loom bridge + integration test suite |
| `viz/` | HTML DAG visualisers, CSV trace viewer |

### `expr/` — symbolic expressions

`Expr` is an AST interface supporting `Add/Sub/Mul/Pow`. Concrete leaf types via `*Leaf`:
- `CommittedColumn` — prover-committed trace column
- `ChallengeColumn` — Fiat-Shamir challenge (degree-0 constant)
- `VirtualColumn` — recomputable by verifier (e.g. Lagrange columns)
- `RotatedColumn` — column evaluated at `ω^shift · X`
- `ConstantColumn` — literal field element

Constructors: `expr.Col(name)`, `expr.NewChallenge(name)`, `expr.Virtual(name)`, `expr.Rot(name, shift)`, `expr.Const(value)`.

Key utilities: `expr.RemoveDuplicates`, `expr.Clone`, `expr.Sum(...Expr)`, `expr.Prod(...Expr)`.

`Leaves(config)` / `LeavesFull(config)` filter by leaf type. Shorthand: `expr.OnlyCommittedColumns`, `expr.OnlyChallenges`, `expr.OnlyRotatedColumns`.

### `internal/dag/` — expression DAG

`DAG` is the shared-subexpression form of an `Expr`. `VanishingRelation` in `CompiledModule` is a `*dag.DAG`.

- `dag.ExprToDAG(e) *DAG` — convert tree to DAG; `dag.Flatten()` — optimise
- `dag.Eval(vars map[string]koalabear.Element)` — scalar evaluation
- `dag.Leaves(config)` — enumerate leaf names

### `internal/poly/` — univariate polynomials

`Polynomial = []koalabear.Element`. All polynomials are in **Lagrange Normal** form (evaluations at `ω^0, ω^1, …`). `len(p) == 1` signals a constant polynomial.

`ComputeQuotient` returns **coset-Lagrange** form — always call `CosetLagrangeToLagrangeNormal(H)` before storing or committing.

Key functions in `iop_utils.go`:
- `BuildPointwiseEvaluation(Pi, E, mu)` — `E(trace)` row-by-row
- `BuildGrandProduct(Pi, E1, E2, mu)` — `R[0]=1, R[i+1]=R[i]·E1[i]/E2[i]`
- `BuildLogup(Pi, E, M, mu)` — `R[i] = Σ_{j≤i} M[j]/E[j]`
- `BuildMultiplicityPolynomial(Pi, S, T, mu)` — `M[i] = #{j | S[j]=T[i]}`

### `proof/` — proof types

```go
type Proof struct {
    ValuesAtZeta           map[string]koalabear.Element // column/challenge evals at zeta
    PublicColumns          map[string]PublicInput        // extracted public values per column
    FSInputs               [][]byte                      // Merkle roots per FS round
    AIRQuotientsCommitment []byte                        // commitment to all H chunks
}

type PublicEntry struct { Idx int; Value koalabear.Element }
type PublicInput struct { N int; Entries []PublicEntry }

type LogupBus struct {
    Positive []string  // last entry is the running sum
    Negative []string  // last entry is the running sum
}
```

`proof.NewProof()` — constructor.

### `board/` — modular constraint system

This is the central package. A `Builder` accumulates modules, logup buses, public columns, and computation steps; `Compile(b)` produces a `Program` with a level-ordered step schedule.

**`Module`** (builder) holds relations and column generators for one constraint domain of size N. Methods:
- `AssertZero(relation)` / `AssertEqualAt(A, B, i)` / `AssertZeroAt(relation, i...)` / `AssertZeroExceptAt(relation, i...)`
- `AssertZeroRelativeAt(relation, i...)` — fires at row `N-1-i` (relative from end)
- `LagrangeCol(i) expr.Expr` — absolute Lagrange basis; registers a `LagrangeGen` and returns the leaf expression
- `LagrangeColRelative(i) expr.Expr` — relative Lagrange basis; fires at row `N-1-i`

**`board.Column`** and **`board.Table`** — the two helper types used by `arguments/`:
```go
type Column struct { Module string; In expr.Expr }
type Table  struct { Module string; In []expr.Expr }
func NewTable(module string, size int) Table
```

**`Builder`** orchestrates all modules:
- `AddModule(name, m)` / `AddPublicColumn(name)` / `AddLogupBus(cm)`
- `AddFiatShamirStep(E, out)` — explicit FS challenge registration
- `AddMakeEntriesPublicStep(module, E, sel, out, idx)` — extract values into `proof.PublicColumns`
- `AddMakeRelativeIthValuePublicStep(module, E, out, pos)` — single value extraction at row `N-1-pos`
- `AddMakeIthValuePublicStep(module, E, out, pos)` — single value extraction at absolute row `pos`
- `AddCountMultiplicityStep(S, T []expr.Expr, output)` — `M[i] = #{j|S[j]=T[i]}`
- `AddCountWeightedMultiplicityStep(selS, S, T []expr.Expr, output)` — weighted variant
- `AddLogupStep(module, E, M, out)` — running logup sum
- `AddGrandProductStep(module, N, D, out)` — running grand product

**`ProverStep`** — unit of execution:
```go
type ProverStep struct {
    Ctx  StepContext
    Ins  []expr.Expr
    Outs []string   // note: plural — a step can produce multiple output columns
    Step Step       // func([]expr.Expr, []string, trace.Trace, *Program, *proof.Proof, *sync.Mutex, StepContext) error
}
```

**`Compile(b *Builder) (Program, error)`** — scheduling algorithm:
1. Compute data-flow levels via fixed-point iteration
2. Assign FS steps to rounds (grouped by challenge dependencies)
3. Sync FS steps in same round to max level in that round
4. **Enforce strictly increasing levels across rounds** — if round r is bumped, rounds r+1, r+2, … are also bumped. Without this, two FS steps from different rounds can land on the same level and get merged into one canonical challenge (breaking arguments that need distinct randomness per round).
5. Re-propagate non-FS levels, bumping them over FS barriers
6. Group steps by level
7. Add final FS step (folding challenge `challenge@loom_final`)
8. Collapse per-round FS steps into canonical challenges (`challenge@loom_i`)
9. Extend final FS with all module-relation columns not yet committed
10. Compile modules: fold relations with final challenge, build `*dag.DAG`, create `fft.Domain`

**`Program`** (output of `Compile`):
```go
type Program struct {
    Modules               map[string]CompiledModule
    PublicColumns         []string
    FScolumnsDependencies [][]string  // columns committed per FS round
    LogupBus              []LogupBus
    Steps                 [][]ProverStep  // step schedule grouped by level
}

type CompiledModule struct {
    GenCol            []Gen      // column generators (Lagrange, selector, permutation)
    N                 int
    VanishingRelation *dag.DAG   // folded constraint DAG
    D                 *fft.Domain
}
```

### `arguments/` — standard IOP arguments

All functions take a `*board.Builder`. Multi-source variants (Union) allow multiple source/target column groups sharing the same randomness for efficiency.

```go
// Permutation
PermutationWithinModule(builder, module string, A, B []expr.Expr) error
PermutationTupleWithinModule(builder, module string, A, B [][]expr.Expr) error
PermutationCrossModules(builder *board.Builder, A, B board.Column) error
FixedPermutationWithinModule(builder, module string, A, B [][]expr.Expr, S board.PermutationGen) error
CopyConstraint(builder, module string, A []expr.Expr, S board.PermutationGen) error

// Lookup (subset argument: every value in S appears in T)
Lookup(builder, S, T board.Column) error
LookupTuple(builder, S, T board.Table) error
LookupUnion(builder, S, T []board.Column) error        // multiple S/T pairs sharing one challenge
LookupUnionTuple(builder, S, T []board.Table) error

// Conditional lookup (with per-row selectors)
CLookup(builder, S, T board.Column, selS, selT expr.Expr) error
CLookupTuple(builder, S, T board.Table, selS, selT expr.Expr) error
CLookupUnion(builder, selS, selT []expr.Expr, S, T []board.Column) error
CLookupUnionTuple(builder, selS, selT []expr.Expr, S, T []board.Table) error

// Range: every value in S is in [0, bound)
Range(builder *board.Builder, S board.Column, bound uint64) error
```

### Prover pipeline (`prover/prover.go`)

`prover.Prove(t trace.Trace, setup *PublicKey, publicInputs proof.PublicInputs, program board.Program, opts...) (proof.Proof, error)` runs:

1. **`ExecuteSteps()`** — for each level in `program.Steps`:
   - Run `GenCol` functions from all modules (Lagrange, selectors, permutations)
   - For `FSStep`: commit dependencies → bind Merkle root to FS → derive challenge → store in trace
   - For all other steps: call `step.Execute()`
2. **`ComputeAIRQuotients()`** — for each module:
   - Compute `H = VanishingRelation / (X^N - 1)` in coset-Lagrange form
   - `CosetLagrangeToLagrangeNormal` → IFFT to coefficients → split into N-sized chunks → FFT each chunk
   - Commit to all chunks; bind to FS; derive `zeta`
3. **`ComputeEvaluationsAtZeta()`** — for each module's `VanishingRelation` leaves:
   - `CommittedColumn`: evaluate at `zeta`; `RotatedColumn`: evaluate at `ω^shift · zeta`
   - Store in `proof.ValuesAtZeta`

`prover.Setup(t trace.Trace, program board.Program) (*PublicKey, error)` — commits to all `PublicColumns` using `RSCommit`, returns Merkle tree root as `PublicKey`.

### Verifier pipeline (`verifier/verifier.go`)

`verifier.Verify(publicInputs map[string]proof.PublicInput, setup *PublicKey, program board.Program, p proof.Proof) error` runs:

1. **`deriveChallenges()`** — for each FS round: bind `FSInputs[i]` to FS transcript, compute `challenge@loom_i`, store in `ValuesAtZeta`; then derive `zeta`
2. **`computePublicColumns()`** — interpolate: `ValuesAtZeta[col] = Σ_j L_{idx_j}(zeta) · value_j`
3. **`computeLagrange()`** — for each Lagrange leaf in any module: compute `L_i(zeta)`, store in `ValuesAtZeta`
4. **`checkLogupBus()`** — for each `LogupBus`: verify `sum(Positive last entries) = sum(Negative last entries)`
5. **`checkAIRRelations()`** — for each module: reconstruct `Q(zeta)` from quotient chunks, evaluate `VanishingRelation.Eval(ValuesAtZeta)`, check `V(zeta) = (zeta^N - 1) · Q(zeta)`

### `integration_test/` — go-corset bridge

`zkc_utils.go` translates a compiled `go-corset` AIR schema into a loom `board.Builder`, then loads `.lt` trace files for end-to-end prove+verify testing.

**`CorsetBridge`** — the central translator:
- `NewCorsetBridge(builder, airSchema)` — constructor
- `SetupModules()` — creates one loom `Module` per go-corset module (skips width-0 root modules)
- `ScanConstraints(bridge)` — iterates all constraints in lexicographic order and calls `AddConstraintInLoom`
- `AddConstraintInLoom(name, constraint)` — dispatches on constraint type:
  - `VanishingConstraint`: global (multiplied by `IS_REAL` selector + bounds masking) or local (domain `{K}` for specific rows)
  - `PermutationConstraint` → `arguments.PermutationWithinModule` / `PermutationTupleWithinModule`
  - `LookupConstraint` → `arguments.LookupUnion` / `CLookupUnion` (with/without selectors)
  - `RangeConstraint` → `arguments.Range`

**IS_REAL column**: each module gets a synthetic `__is_real__` (or `modname.__is_real__`) column = 1 for real rows, 0 for zero-padded rows. All global vanishing constraints are multiplied by this selector.

**Trace loading** (`TracesFromLT`):
- Reads `.lt` (JSONL) trace files via go-corset's `TraceBuilder`
- Records original heights before go-corset adds spillage rows
- Zero-pads all columns to `nextPow2(H)` (IS_REAL handles row exclusion; last-value padding is not used)
- Injects `IS_REAL` column per module

**Constraint translation subtleties**:
- `(:domain {0})` — trivially zero (spillage row in go-corset, skipped in loom)
- `(:domain {-K})` — fires at the K-th row from the last **real** row (`H-K`). Implemented via selector `IS_REAL * Rot(IS_REAL,1) * … * Rot(IS_REAL,K-1) * ((1-Rot(IS_REAL,K)) + LagrangeColRelative(K-1))` to correctly handle both padded (H < N) and unpadded (H = N) traces
- Forward-shift boundary: for global constraints with `bounds.End=k`, last k real rows are excluded by multiplying `Rot(IS_REAL,j) * (1-LagrangeColRelative(j-1))` for j=1..k
- Backward-shift boundary: shifts of depth j ≤ `bounds.Start` are wrapped with `(1-L_0)*…*(1-L_{j-1})` to match go-corset's spillage-row zero semantics

## Key gotchas

**Polynomial representation**: always Lagrange Normal form. `len(p) == 1` means constant. `ComputeQuotient` is the only function that returns coset-Lagrange — always call `CosetLagrangeToLagrangeNormal` on its result.

**Multi-module**: each module has its own domain size N and its own `fft.Domain`. Never mix columns from different modules in the same `VanishingRelation`.

**FS challenge naming**: canonical challenge names are `challenge@loom_0`, `challenge@loom_1`, …, `challenge@loom_final`. These are stored in `proof.ValuesAtZeta` and used as `ChallengeColumn` leaves.

**FS round distinctness**: two FS steps that depend on the same challenge set will be assigned the same round and merged into one canonical challenge. If an argument needs two independent random challenges (e.g. a folding gamma and a grand-product gamma), register them in separate `AddFiatShamirStep` calls with a data dependency ordering them. `Compile` enforces strictly increasing levels across rounds to prevent collapse.

**Logup bus invariant**: both positive and negative sides must have the same final running sum. The verifier checks `Positive[last] = Negative[last]` (not the full polynomial identity).

**`VanishingRelation` is a `*dag.DAG`**: not an `expr.Expr`. Use `.Eval(vars)` for scalar evaluation and `.Leaves(config)` for leaf enumeration.

**Rotated columns**: use `expr.Rot(id, shift)` for `P(ω^shift · X)`. Evaluated at `ω^shift · zeta` in `ComputeEvaluationsAtZeta`. Named `id_shift_N` in the proof.

**`ProverStep.Outs` is `[]string`**: a step can produce multiple output columns. The `Step` function signature is `func([]expr.Expr, []string, trace.Trace, *Program, *proof.Proof, *sync.Mutex, StepContext) error`.

**`Compile` phase ordering matters**: steps must encode the correct data-flow DAG before calling `Compile`. The scheduling algorithm propagates levels via fixed-point — a missing dependency edge will produce a wrong schedule silently.

**Thread safety in steps**: `ProverStep.Step` receives a `*sync.Mutex`; use it for any write to the shared `trace.Trace`. Reads from already-computed columns are safe without the lock.
