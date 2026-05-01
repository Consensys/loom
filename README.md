# loom

> **WARNING: This code has not been audited and is not ready for production use. It is provided for research and experimentation purposes only. Do not use it to secure real assets or in any security-critical context.**

`loom` is a Go library for building and verifying **Interactive Oracle Proofs (IOPs)** over the [Koalabear](https://github.com/consensys/gnark-crypto) finite field.

It lets you describe a computation as a set of polynomial constraints over a **trace** (a collection of named columns), compile it into a proof system, and produce a succinct proof that all constraints vanish on the evaluation domain.

## Core concepts

| Concept | Type | Description |
|---|---|---|
| Trace | `trace.Trace` (`map[string][]koalabear.Element`) | Named columns of field elements, all of length N |
| Relation | `expr.Expr` | A multivariate polynomial that must vanish row-wise |
| Builder | `board.Builder` | Accumulates modules, relations, and derivation steps before compilation |
| Module | `board.Module` | A named constraint domain; all columns within it share the same N |
| Program | `board.Program` | Compiled IOP: level-ordered step schedule + folded vanishing relations |
| Public inputs | `proof.PublicInputs` | Claimed values at specific row indices, checked by both prover and verifier |

## Workflow

```
1. Create a board.Builder and add one board.Module per constraint domain
2. Describe polynomial constraints on each module (AssertZero, …)
3. Attach standard arguments (permutation, lookup, …) from the arguments/ package
4. board.Compile(builder) → Program
5. prover.Prove(trace, setup, publicInputs, program) → Proof
6. verifier.Verify(publicInputs, setup, program, proof)
```

## Example: Fibonacci sequence

Prove that columns `A`, `B`, `C` satisfy `A[i] + B[i] = C[i]` on every row and that consecutive rows shift correctly (`A[i+1] = B[i]`, `B[i+1] = C[i]`).

```go
import (
    "github.com/consensys/loom/arguments"
    "github.com/consensys/loom/board"
    "github.com/consensys/loom/expr"
    "github.com/consensys/loom/prover"
    "github.com/consensys/loom/verifier"
)

// --- 1. Build constraint system ---
builder := board.NewBuilder()
mod := board.NewModule("")   // single unnamed module
builder.AddModule("", mod)

// A + B - C = 0 on every row
mod.AssertZero(expr.Col("A").Add(expr.Col("B")).Sub(expr.Col("C")))

// A[i+1] = B[i]  ↔  multiset {A[1..N-1]} = {B[0..N-2]}
// Use a permutation argument restricted to the shifted rows.
arguments.PermutationWithinModule(&builder, "", []expr.Expr{expr.Rot("A", 1)}, []expr.Expr{expr.Col("B")})
arguments.PermutationWithinModule(&builder, "", []expr.Expr{expr.Rot("B", 1)}, []expr.Expr{expr.Col("C")})

// --- 2. Compile ---
pg, err := board.Compile(&builder)

// --- 3. Prove ---
prf, err := prover.Prove(trace, nil, nil, pg)

// --- 4. Verify ---
err = verifier.Verify(nil, nil, pg, prf)
```

## Example: PLONK gate + copy constraint

Prove that PLONK arithmetic gates are satisfied and that wires are consistently connected.

```go
// Arithmetic gate: QL·L + QR·R + QM·L·R + QO·O + QK = 0
gate := expr.Col("QL").Mul(expr.Col("L")).
    Add(expr.Col("QR").Mul(expr.Col("R"))).
    Add(expr.Col("QM").Mul(expr.Col("L")).Mul(expr.Col("R"))).
    Add(expr.Col("QO").Mul(expr.Col("O"))).
    Add(expr.Col("QK"))
mod.AssertZero(gate)

// Copy constraint: wires L, R, O are consistently permuted by S
arguments.CopyConstraint(&builder, "", []expr.Expr{
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
| `CLookupUnion(builder, selS, selT []expr.Expr, S, T []board.Column)` | Conditional lookup, multi-pair |
| `Range(builder, S board.Column, bound uint64)` | Every value in `S` is in `[0, bound)` |

`board.Column{Module: "name", In: expr}` and `board.Table{Module: "name", In: []expr}` are the two helper types used across all argument functions.

## Public inputs

`proof.PublicInputs` is a `map[string]PublicInput` that binds specific row indices of named columns to claimed field values. Pass it to both `prover.Prove` and `verifier.Verify`.

```go
publicInputs := proof.PublicInputs{
    "A": {N: 16, Entries: []proof.PublicEntry{
        {Idx: 0, Value: zeroElement},
        {Idx: 5, Value: someElement},
    }},
}
```

For columns that require a setup commitment (e.g. PLONK selector columns), use `prover.Setup` to pre-commit them:

```go
setup, err := prover.Setup(trace, pg)
prf, err  := prover.Prove(trace, setup, publicInputs, pg)
err        = verifier.Verify(publicInputs, setup, pg, prf)
```

## Visualisation (`viz/`)

```go
viz.ViewDag(pg, "plan.html")         // interactive step-DAG in the browser
viz.WriteRawTraceToCSV("trace.csv", trace)  // column dump
```
