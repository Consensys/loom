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

package prover

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/arguments"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/trace"
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

func TestFRICommitPhaseRecordsExpandedOracleMetadata(t *testing.T) {
	builder := board.NewBuilder()

	module := board.NewModule("main")
	module.N = 4
	// Keep the module trivial so the proof only exercises the commitment flow.
	module.AssertZero(expr.Col("A").Sub(expr.Col("A")))
	builder.AddModule("main", module)
	// Add one FS round so we get a trace-oracle commitment before zeta is sampled.
	builder.AddFiatShamirStep([]expr.Expr{expr.Col("A")}, "alpha")

	program, err := board.Compile(&builder)
	if err != nil {
		t.Fatal(err)
	}

	var zero koalabear.Element
	tr := trace.Trace{
		"A": []koalabear.Element{zero, zero, zero, zero},
	}

	prf, err := Prove(tr, nil, nil, program, EmulateFS())
	if err != nil {
		t.Fatal(err)
	}
	if len(prf.CommitmentOpenings.Commitments) < 2 {
		t.Fatalf("got %d commitments, want at least 2", len(prf.CommitmentOpenings.Commitments))
	}
	got := prf.CommitmentOpenings.Commitments[0]
	// The committed codeword should live on the enlarged FRI domain, not the
	// original trace domain.
	if got.BaseDomainSize != 4 {
		t.Fatalf("got base domain size %d, want 4", got.BaseDomainSize)
	}
	if got.CodewordDomainSize != 8 {
		t.Fatalf("got codeword domain size %d, want 8", got.CodewordDomainSize)
	}
	if len(got.PolynomialNames) != 1 {
		t.Fatalf("got %d committed polynomials, want 1", len(got.PolynomialNames))
	}
	last := prf.CommitmentOpenings.Commitments[len(prf.CommitmentOpenings.Commitments)-1]
	if len(last.PolynomialNames) == 0 {
		t.Fatal("expected the AIR quotient commitment to contain committed polynomials")
	}
}
