# loom

> **WARNING: This code has not been audited and is not ready for production use. It is provided for research and experimentation purposes only. Do not use it to secure real assets or in any security-critical context.**

`loom` is a Go library for building and verifying **Interactive Oracle Proofs (IOPs)** over the [Koalabear](https://github.com/consensys/gnark-crypto) finite field.

It lets you describe a computation as a set of polynomial constraints over a **trace** (a collection of named columns), compile it into a proof system, and produce a succinct proof that all constraints vanish on the evaluation domain.

## Core concepts

| Concept | Type | Description |
|---|---|---|
| Trace | `trace.Trace` (`map[string][]koalabear.Element`) | Named columns of field elements, all of length N |
| Relation | `constraint.Relation` (= `expr.Expr`) | A multivariate polynomial that must vanish row-wise |
| Builder | `constraint.Builder` | Accumulates relations and derivation steps before compilation |
| Program | `constraint.Program` | Compiled IOP: derivation plan + folded vanishing relation |
| Public inputs | `proof.PublicInputs` | Claimed values at specific row indices, verified by both parties |

## Workflow

```
1. Build a trace (your witness columns)
2. Describe constraints on a Builder
3. Attach standard arguments (permutation, lookup, projection, …)
4. Compile → Program
5. Prove(Program, trace, publicInputs) → Proof
6. Verify(Program, proof, publicInputs)
```

## Example: Fibonacci sequence

Prove that three columns `A`, `B`, `C` form a Fibonacci sequence: `A[i] + B[i] = C[i]` for all `i`, and that each row correctly shifts into the next (`A[i+1] = B[i]`, `B[i+1] = C[i]`).

```go
import (
    "github.com/consensys/loom"
    "github.com/consensys/loom/arguments"
    "github.com/consensys/loom/constraint"
    "github.com/consensys/loom/expr"
    "github.com/consensys/loom/proof"
    "github.com/consensys/gnark-crypto/field/koalabear"
)

N := 16

// --- 1. Declare public inputs: A[0]=0, B[0]=1 ---
publicInputs := proof.PublicInputs{
    "A": {Idx: []int{0}, Vals: []koalabear.Element{{}}},         // A[0] = 0
    "B": {Idx: []int{0}, Vals: []koalabear.Element{koalabear.One()}}, // B[0] = 1
}

// --- 2. Describe constraints ---
system := constraint.NewBuilder(N, publicInputs)

colA := expr.Col("A")
colB := expr.Col("B")
colC := expr.Col("C")

// A + B - C = 0  (Fibonacci recurrence, row-wise)
system.AssertZero(colA.Add(colB).Sub(colC))

// Shift constraints: A[i]=B[i-1] and B[i]=C[i-1]
// expressed via a filter: rows 1..N-1 of A equal rows 0..N-2 of B, etc.
filter := make([]koalabear.Element, N)
for i := 1; i < N; i++ {
    filter[i].SetOne()
}
system.AddColumn("F", filter)
F := expr.Col("F")
Fshift := expr.Rot("F", 1) // F shifted by +1: selects rows 0..N-2
arguments.Projection(&system, colA, F, colB, Fshift)
arguments.Projection(&system, colB, F, colC, Fshift)

// --- 3. Compile ---
cp := system.Compile()

// --- 4. Build the trace ---
trace := GetFibonacciTrace(N, "A", "B", "C")

// --- 5. Prove ---
prf, err := loom.Prove(cp, trace, publicInputs, 1 /*nbWorkers*/)

// --- 6. Verify ---
err = loom.Verify(cp, &prf, publicInputs, 1)
```

Full source: [`examples/fibonacci/`](examples/fibonacci/)

## Example: PLONK gate + copy constraint

Prove that PLONK arithmetic gates are satisfied and that wires are correctly connected via a permutation argument.

```go
// Arithmetic gate: QL·L + QR·R + QM·L·R + QO·O + QK = 0
C := expr.Col("QL").Mul(expr.Col("L")).
    Add(expr.Col("QR").Mul(expr.Col("R"))).
    Add(expr.Col("QM").Mul(expr.Col("L")).Mul(expr.Col("R"))).
    Add(expr.Col("QO").Mul(expr.Col("O"))).
    Add(expr.Col("QK"))
system.AssertZero(C)

// Copy constraint: wire columns L, R, O are consistently permuted by S
arguments.CopyPermutation(&system, []string{"L", "R", "O"}, S)

cp := system.Compile()
prf, err := loom.Prove(cp, trace, nil, 1)
err = loom.Verify(cp, &prf, nil, 1)
```

Full source: [`examples/plonk_example/`](examples/plonk_example/)

## Standard arguments (`arguments/`)

| Function | What it proves |
|---|---|
| `Permutation(system, E1, E2 []expr.Expr)` | `{E1[i]}` = `{E2[i]}` as multisets |
| `PermutationTuple(system, E1, E2 [][]expr.Expr)` | Same for row-tuples |
| `Lookup(system, S, T expr.Expr)` | Every value in `S` appears in `T` |
| `LookupTuple(system, S, T []expr.Expr)` | Same for row-tuples |
| `Projection(system, A, B, F1, F2 expr.Expr)` | The `F1`-selected sub-sequence of `A` equals the `F2`-selected sub-sequence of `B` |
| `ProjectionTuple(system, A []expr.Expr, F1, B []expr.Expr, F2)` | Same for row-tuples |
| `CopyPermutation(system, wires []string, S []int64)` | PLONK-style copy constraint |

## Public inputs

`proof.PublicInputs` is a `map[string]PublicColumnInfo` that binds specific row indices of named columns to claimed field values. Both prover and verifier receive it; the verifier checks the claims before accepting the proof.

```go
publicInputs := proof.PublicInputs{
    "A": {Idx: []int{0, 5}, Vals: []koalabear.Element{v0, v5}},
}
```

## Visualisation (`viz/`)

```go
viz.WriteDerivationPlanDagToHTML(cp, "plan.html")           // interactive derivation DAG
viz.WriteProofTranscriptRoundsDagToHTML(proof.TranscriptRounds, "rounds.html") // FS transcript
viz.WriteTraceToCSV("trace.csv", trace, N)                  // column dump
```
