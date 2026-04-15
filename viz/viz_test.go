package viz

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/loom/arguments"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
)

func TestViz(t *testing.T) {

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

	// arguments.RawLogup(&builder, board.Input{
	// 	Module: "fibonacci",
	// 	In:     expr.Col("A"),
	// })

	program, err := board.Compile(&builder)
	if err != nil {
		t.Fatal(err)
	}

	ViewDag(program, "dag.html")

	out := filepath.Join(t.TempDir(), "dag.html")
	ViewDag(program, out)

	info, err := os.Stat(out)
	if err != nil {
		t.Fatalf("output file not created: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("output file is empty")
	}
	t.Logf("dag written to %s (open in browser to inspect)", out)
}
