package verifier

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/arguments"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/prover"
	"github.com/consensys/loom/trace"
)

// buildFibLookupProgram constructs the standard fibonacci+range+lookup
// program used across the verifier integration tests.
func buildFibLookupProgram(t *testing.T) board.Program {
	t.Helper()

	builder := board.NewBuilder()

	fibonacciModule := board.NewModule()
	rangeModule := board.NewModule()

	N := 4
	fibonacciModule.N = N
	rangeModule.N = 2 * N

	C := expr.Rot("A", 1).Sub(expr.Col("B"))
	fibonacciModule.AssertZeroExceptAt(C, N-1)
	C = expr.Rot("B", 1).Sub(expr.Col("C"))
	fibonacciModule.AssertZeroExceptAt(C, N-1)
	C = expr.Col("C").Sub(expr.Col("A")).Sub(expr.Col("B"))
	fibonacciModule.AssertZero(C)

	builder.AddModule("fibonacci", fibonacciModule)
	builder.AddModule("range", rangeModule)

	T := board.Input{Module: "range", In: expr.Col("Lookup")}
	for _, c := range []string{"A", "B", "C"} {
		S := board.Input{Module: "fibonacci", In: expr.Col(c)}
		if err := arguments.Lookup(&builder, S, T); err != nil {
			t.Fatal(err)
		}
	}

	program, err := board.Compile(&builder)
	if err != nil {
		t.Fatal(err)
	}
	return program
}

func buildFibTrace(t *testing.T) (board.Program, trace.Trace) {
	t.Helper()
	program := buildFibLookupProgram(t)
	N := 4
	var a, b koalabear.Element
	b.SetOne()
	traceFrob := prover.TraceFibonacci(N, a, b)
	traceRange := prover.TraceRange(N)
	tr := prover.MergeTrace(traceFrob, traceRange)
	return program, tr
}

func TestVerifier(t *testing.T) {
	program, tr := buildFibTrace(t)

	proof, err := prover.Prove(tr, nil, program)
	if err != nil {
		t.Fatal(err)
	}

	if err := Verify(nil, program, proof); err != nil {
		t.Fatal(err)
	}
}

// TestVerifierWithGrinding runs the full prove/verify loop with a small
// proof-of-work bit count plumbed through both sides.
func TestVerifierWithGrinding(t *testing.T) {
	program, tr := buildFibTrace(t)

	const grindingBits = 8

	proof, err := prover.Prove(tr, nil, program, prover.WithFRIGrindingBits(grindingBits))
	if err != nil {
		t.Fatal(err)
	}

	if err := Verify(nil, program, proof, WithFRIGrindingBits(grindingBits)); err != nil {
		t.Fatal(err)
	}
}

// TestVerifierGrindingMismatch — prover used grinding, verifier didn't
// configure it. The resulting Fiat-Shamir state diverges and verification
// fails.
func TestVerifierGrindingMismatch(t *testing.T) {
	program, tr := buildFibTrace(t)

	proof, err := prover.Prove(tr, nil, program, prover.WithFRIGrindingBits(8))
	if err != nil {
		t.Fatal(err)
	}

	if err := Verify(nil, program, proof); err == nil {
		t.Fatal("Verify: expected rejection when verifier ignores prover grinding")
	}
}
