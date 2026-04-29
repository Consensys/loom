package prover

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/arguments"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/viz"
)

func TestVanishingRelationsAndLogupBus(t *testing.T) {

	builder := board.NewBuilder()

	fibonacciModule := board.NewModule("fibo")
	rangeModule := board.NewModule("range")

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

	viz.ViewDag(program, "dag.html")

	// load the traces
	var a, b koalabear.Element
	b.SetOne()
	traceFrob := TraceFibonacci(N, a, b)
	traceRange := TraceRange(N)
	tr := MergeTrace(traceFrob, traceRange)

	proof, err := Prove(tr, nil, nil, program, EmulateFS())
	if err != nil {
		t.Fatal(err)
	}

	for _, m := range program.Modules {
		if err := CheckVanishingRelation(tr, m); err != nil {
			t.Fatal(err)
		}
	}

	// check the values of the bus
	for _, bus := range program.LogupBus {
		var cumNegative, cumPositive koalabear.Element
		for _, pos := range bus.Positive {
			if len(proof.PublicColumns[pos].Entries) > 1 {
				t.Fatal("an extracted value from a logup column should have exactly one entry")
			}
			pe := proof.PublicColumns[pos].Entries[0]
			cumPositive.Add(&cumPositive, &pe.Value)
		}
		for _, neg := range bus.Negative {
			if len(proof.PublicColumns[neg].Entries) > 1 {
				t.Fatal("an extracted value from a logup column should have exactly one entry")
			}
			pe := proof.PublicColumns[neg].Entries[0]
			cumNegative.Add(&cumNegative, &pe.Value)
		}
		cumPositive.Sub(&cumPositive, &cumNegative)
		if !cumPositive.IsZero() {
			t.Fatal("the cumulative sums of the bus are not equal")
		}
	}

	viz.WriteRawTraceToCSV("trace.csv", tr)

}
