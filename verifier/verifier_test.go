package verifier

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/arguments"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/prover"
)

func TestVerifier(t *testing.T) {

	// build the modules
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

	T := board.Input{
		Module: "range",
		In:     expr.Col("Lookup"),
	}
	columnsFibonacci := []string{"A", "B", "C"}
	for _, c := range columnsFibonacci {
		S := board.Input{
			Module: "fibonacci",
			In:     expr.Col(c),
		}
		err := arguments.Lookup(&builder, S, T)
		if err != nil {
			t.Fatal(err)
		}
	}

	program, err := board.Compile(&builder)
	if err != nil {
		t.Fatal(err)
	}

	// load the traces
	var a, b koalabear.Element
	b.SetOne()
	traceFrob := prover.TraceFibonacci(N, a, b)
	traceRange := prover.TraceRange(N)
	tr := prover.MergeTrace(traceFrob, traceRange)

	proof, err := prover.Prove(tr, nil, program)
	if err != nil {
		t.Fatal(err)
	}

	err = Verify(nil, program, proof)
	if err != nil {
		t.Fatal(err)
	}
}

// func TestPlonk(t *testing.T) {

// 	// build the plonk module

// 	plonkModule := board.NewModule()

// 	N := 2024
// 	plonkModule.N = N

// 	qll := expr.Col(ID_Ql).Mul(expr.Col(ID_L))
// 	qrr := expr.Col(ID_Qr).Mul(expr.Col(ID_R))
// 	qmlr := expr.Col(ID_Qm).Mul(expr.Col(ID_L)).Mul(expr.Col(ID_R))
// 	qoo := expr.Col(ID_Qo).Mul(expr.Col(ID_O))
// 	qk := expr.Col(ID_Qk)
// 	vanishingRelation := qll.Add(qrr).Add(qmlr).Add(qoo).Add(qk)

// 	sigmaName := "S"

// }
