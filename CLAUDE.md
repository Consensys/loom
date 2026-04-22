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
- `LagrangeCol(i) expr.Expr` — idempotent; registers a `LagrangeGen` and returns the leaf expression

**`Builder`** orchestrates all modules:
- `AddModule(name, m)` / `AddPublicColumn(name)` / `AddLogupBus(cm)`
- `AddFiatShamirStep(E, out)` — explicit FS challenge registration
- `AddMakeEntriesPublicStep(module, E, sel, out, idx)` — extract values into `proof.PublicColumns`
- `AddMakeIthValuePublicStep(module, E, out, pos)` — single value extraction
- `AddCountMultiplicityStep(S, T, out)` — `M[i] = #{j|S[j]=T[i]}`
- `AddLogupStep(module, E, M, out)` — running logup sum
- `AddGrandProductStep(module, N, D, out)` — running grand product

**`ProverStep`** — unit of execution:
```go
type ProverStep struct {
    Ctx  StepContext
    Ins  []expr.Expr
    Out  string
    Step Step  // func([]expr.Expr, string, trace.Trace, *Program, *proof.Proof, *sync.Mutex, StepContext) error
}
```

**`Compile(b *Builder) Program`** — 9-phase scheduling algorithm:
1. Compute data-flow levels via fixed-point iteration
2. Assign FS steps to rounds (grouped by challenge dependencies)
3. Sync FS steps in same round to max level in that round
4. Re-propagate non-FS levels, bumping them over FS barriers
5. Group steps by level
6. Add final FS step (folding challenge `challenge@loom_final`)
7. Collapse per-round FS steps into canonical challenges (`challenge@loom_i`)
8. Extend final FS with all module-relation columns not yet committed
9. Compile modules: fold relations with final challenge, build `*dag.DAG`, create `fft.Domain`

**`Program`** (output of `Compile`):
```go
type Program struct {
    Modules              map[string]CompiledModule
    PublicColumns        []string
    FScolumnsDependencies [][]string  // columns committed per FS round
    LogupBus             []LogupBus
    Steps                [][]ProverStep  // step schedule grouped by level
}

type CompiledModule struct {
    GenCol           []Gen       // column generators (Lagrange, selector, permutation)
    N                int
    VanishingRelation *dag.DAG   // folded constraint DAG
    D                *fft.Domain
}
```

### `arguments/` — standard IOP arguments

These work on a `board.Builder` directly:
- `Permutation(system, ID1, ID2 []string) error` — multiset equality via grand product
- `PermutationTuple(system, ID1, ID2 [][]string) error` — row-tuple variant
- `Lookup(system, S, T string) error` — subset argument via logup + multiplicity
- `LookupTuple(system, S, T []string) error` — row-tuple variant
- `Projection(system, A, F1, B, F2 string) error` — filtered subsequence equality
- `ProjectionTuple(system, A []string, F1 string, B []string, F2 string) error`
- `CopyPermutation(system, wires []string, S []int64) error` — PLONK-style copy

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

## Key gotchas

**Polynomial representation**: always Lagrange Normal form. `len(p) == 1` means constant. `ComputeQuotient` is the only function that returns coset-Lagrange — always call `CosetLagrangeToLagrangeNormal` on its result.

**Multi-module**: each module has its own domain size N and its own `fft.Domain`. Never mix columns from different modules in the same `VanishingRelation`.

**FS challenge naming**: canonical challenge names are `challenge@loom_0`, `challenge@loom_1`, …, `challenge@loom_final`. These are stored in `proof.ValuesAtZeta` and used as `ChallengeColumn` leaves.

**Logup bus invariant**: both positive and negative sides must have the same final running sum. The verifier checks `Positive[last] = Negative[last]` (not the full polynomial identity).

**`VanishingRelation` is a `*dag.DAG`**: not an `expr.Expr`. Use `.Eval(vars)` for scalar evaluation and `.Leaves(config)` for leaf enumeration.

**Rotated columns**: use `expr.Rot(id, shift)` for `P(ω^shift · X)`. Evaluated at `ω^shift · zeta` in `ComputeEvaluationsAtZeta`. Named `id_shift_N` in the proof.

**`Compile` phase ordering matters**: steps must encode the correct data-flow DAG before calling `Compile`. The 9-phase algorithm propagates levels via fixed-point — a missing dependency edge will produce a wrong schedule silently.

**Thread safety in steps**: `ProverStep.Step` receives a `*sync.Mutex`; use it for any write to the shared `trace.Trace`. Reads from already-computed columns are safe without the lock.
