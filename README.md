# loom

> **WARNING: This code has not been audited and is not ready for production use. It is provided for research and experimentation purposes only. Do not use it to secure real assets or in any security-critical context.**

`loom` is a Go library for building and verifying **Interactive Oracle Proofs (IOPs)** over the [Koalabear](https://github.com/consensys/gnark-crypto) finite field.

It lets you describe a computation as a set of polynomial constraints over a **trace** (a collection of named columns), compile it into a proof system, and produce a succinct proof that all constraints vanish on the evaluation domain.

Fiat-Shamir challenges, including lookup/permutation challenges, canonical trace-round challenges, `__zeta`, `alpha_DEEP`, and FRI fold challenges, are sampled in the Koalabear E4 extension field. The `alpha_DEEP` challenge binds the claimed evaluations folded into the DEEP quotient. Base trace columns remain base-valued and are lifted only when evaluated at extension points. The resulting soundness error is approximately `N/2^124`.

## Core concepts

| Concept | Type | Description |
|---|---|---|
| Trace | `trace.Trace` (`Base` and `Ext` column maps) | Named base or extension columns. Columns in the same module share the module size N; a program may contain several sizes |
| Relation | `expr.Expr` | A multivariate polynomial that must vanish row-wise |
| Builder | `board.Builder` | Accumulates modules, relations, and derivation steps before compilation |
| Module | `board.Module` | A named constraint domain; all columns within it share the same N |
| Program | `board.Program` | Compiled IOP: level-ordered step schedule + folded vanishing relations |
| Public openings | `proof.Proof.PublicColumns` / `proof.PublicInput` | Values exposed by board steps such as `AddExposeIthEntryStep` and checked through sparse public columns |

## Workflow

```
1. Create a board.Builder and add one board.Module per constraint domain
2. Describe polynomial constraints on each module (AssertZero, …)
3. Attach standard arguments (permutation, lookup, …) from the arguments/ package
4. board.Compile(&builder) → Program
5. setup.Setup(trace, program) → setup.PublicKey, if the program has precommitted public columns
6. prover.Prove(trace, publicKey, publicInputs, program) → Proof
7. verifier.Verify(publicInputs, setup.Roots(publicKey), program, proof)
```

## Example: PLONK gate + copy constraint

Prove that PLONK arithmetic gates are satisfied and that wires are consistently connected.

```go
builder := board.NewBuilder()
mod := board.NewModule("plonk")

// Arithmetic gate: QL·L + QR·R + QM·L·R + QO·O + QK = 0
gate := expr.Col("QL").Mul(expr.Col("L")).
    Add(expr.Col("QR").Mul(expr.Col("R"))).
    Add(expr.Col("QM").Mul(expr.Col("L")).Mul(expr.Col("R"))).
    Add(expr.Col("QO").Mul(expr.Col("O"))).
    Add(expr.Col("QK"))
mod.AssertZero(gate)
builder.AddModule(mod)

// Copy constraint: wires L, R, O are consistently permuted by S
arguments.CopyConstraint(&builder, "plonk", []expr.Expr{
    expr.Col("L"), expr.Col("R"), expr.Col("O"),
}, S)  // S is a board.PermutationGen

pg, err := board.Compile(&builder)
prf, err := prover.Prove(trace, nil, nil, pg)
err = verifier.Verify(nil, nil, pg, prf)
```

## Standard arguments (`arguments/`)

| Function | What it proves |
|---|---|
| `PermutationWithinModule(builder, module, A, B []expr.Expr)` | `{A[i]}` = `{B[i]}` as multisets (same module) |
| `PermutationTupleWithinModule(builder, module, A, B [][]expr.Expr)` | Same for row-tuples |
| `PermutationCrossModules(builder, A, B board.Column)` | Multiset equality across two modules |
| `CopyConstraint(builder, module, A []expr.Expr, S PermutationGen)` | PLONK-style copy constraint |
| `FixedPermutationWithinModule(builder, module, A, B [][]expr.Expr, S PermutationGen)` | Fixed permutation check |
| `Lookup(builder, S, T board.Column)` | Every value in `S` appears in `T` |
| `LookupTuple(builder, S, T board.Table)` | Same for row-tuples |
| `LookupUnion(builder, S, T []board.Column)` | Multiple S/T pairs sharing one challenge |
| `LookupUnionTuple(builder, S, T []board.Table)` | Same for row-tuples |
| `CLookup(builder, S, T board.Column, selS, selT expr.Expr)` | Conditional lookup with per-row selectors |
| `CLookupTuple(builder, S, T board.Table, selS, selT expr.Expr)` | Conditional lookup for row-tuples |
| `CLookupUnion(builder, selS, selT []expr.Expr, S, T []board.Column)` | Conditional lookup, multi-pair |
| `CLookupUnionTuple(builder, selS, selT []expr.Expr, S, T []board.Table)` | Conditional tuple lookup, multi-pair |
| `Range(builder, S board.Column, bound uint64)` | Every value in `S` is in `[0, bound)` |

`board.Column{Module: "name", In: expr}` and `board.Table{Module: "name", In: []expr}` are the two helper types used across all argument functions.

## Public values

Values exposed with `board.AddExposeIthEntryStep`, `board.AddExposeRelativeIthEntryStep`, `board.AddExposeLastEntryStep`, and `board.AddMakeEntriesPublicStep` are stored in `proof.Proof.PublicColumns`. The verifier reconstructs their sparse public columns at `__zeta` and checks the constraints that bind them to the private trace.

```go
publicColumn := proof.PublicInput{
    N: 16,
    Entries: []proof.PublicEntry{
        {Idx: 0, Value: zeroElement},
        {Idx: 5, Value: someElement},
    },
}
```

The `publicInputs` parameters on `prover.Prove` and `verifier.Verify` are still part of the API, but the current prover/verifier path uses the public values carried in `Proof.PublicColumns`.

For columns that require a setup commitment (e.g. PLONK selector columns), mark them with `builder.MakeColumnPublic` and use `setup.Setup` to pre-commit them:

```go
pk, err  := setup.Setup(trace, pg)
prf, err := prover.Prove(trace, pk, nil, pg)
err       = verifier.Verify(nil, setup.Roots(pk), pg, prf)
```

## Development

```sh
go mod download
go test ./integration_test/go_corset/zkc   # current Go-Corset/zkc integration path
go test ./...                              # full suite, including older Lisp fixtures
```

Go-Corset integration tests are split by frontend. Current zkc fixtures live in `integration_test/go_corset/zkc/testdata`; the older Lisp fixtures live under `integration_test/go_corset/lisp`.

## Visualisation (`viz/`)

```go
viz.ViewDag(pg, "plan.html")         // interactive step-DAG in the browser
viz.WriteRawTraceToCSV("trace.csv", trace)  // column dump
```
