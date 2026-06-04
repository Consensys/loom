// Copyright Consensys Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

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

	fibonacciModule := board.NewModule("fibonacci")
	rangeModule := board.NewModule("range")

	N := 4
	fibonacciModule.N = N
	rangeModule.N = 2 * N

	C := expr.Col("A", expr.WithShift(1)).Sub(expr.Col("B"))
	fibonacciModule.AssertZeroExceptAt(C, N-1)
	C = expr.Col("B", expr.WithShift(1)).Sub(expr.Col("C"))
	fibonacciModule.AssertZeroExceptAt(C, N-1)
	C = expr.Col("C").Sub(expr.Col("A")).Sub(expr.Col("B"))
	fibonacciModule.AssertZero(C)

	builder.AddModule(fibonacciModule)
	builder.AddModule(rangeModule)

	T := board.Column{
		Module: "range",
		In:     expr.Col("Lookup"),
	}
	columnsFibonacci := []string{"A", "B", "C"}
	for _, c := range columnsFibonacci {
		S := board.Column{
			Module: "fibonacci",
			In:     expr.Col(c),
		}
		err := arguments.Lookup(&builder, S, T)
		if err != nil {
			t.Fatal(err)
		}
	}

	// arguments.RawLogup(&builder, board.Column{
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
