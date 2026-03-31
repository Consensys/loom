package prover

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/arguments"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/trace"
	"github.com/consensys/loom/viz"
)

func checkVanishingRelation(t *testing.T, tr trace.Trace, md board.CompiledModule) {
	ev, err := poly.Eval(tr, md.VanishingRelation, md.N)
	if err != nil {
		t.Fatal(err)
	}
	for i, v := range ev {
		if !v.IsZero() {
			t.Errorf("vanishing relation doesn hold at %d, got %s", i, v.String())
		}
	}
}

func TestProver(t *testing.T) {

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
	traceFrob := TraceFibonacci(N, a, b)
	traceRange := TraceRange(N)
	tr := mergeTrace(traceFrob, traceRange)

	// one the trace is loaded, we know the actual size of the modules

	proof := Prove(tr, program)

	for _, m := range program.Modules {
		checkVanishingRelation(t, tr, m)
	}

	// check the values of the bus
	for _, bus := range proof.CrossModulesLogupBus {
		var cumPos, cumNeg koalabear.Element
		for _, logup := range bus.Positive {
			cumPos.Add(&cumPos, &logup.Value)
		}
		for _, logup := range bus.Negative {
			cumNeg.Add(&cumNeg, &logup.Value)
		}
		if !cumPos.Equal(&cumNeg) {
			t.Fatal("logup values are not equal")
		}
	}

	viz.WriteRawTraceToCSV("trace.csv", tr)
}
