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

package verifier

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/arguments"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/prover"
	"github.com/consensys/loom/trace"
	"github.com/consensys/loom/viz"
)

func prepareFibonacciModule(N int) board.Module {
	fibonacciModule := board.NewModule("fibo")
	fibonacciModule.N = N
	C := expr.Rot("A", 1).Sub(expr.Col("B"))
	fibonacciModule.AssertZeroExceptAt(C, N-1)
	C = expr.Rot("B", 1).Sub(expr.Col("C"))
	fibonacciModule.AssertZeroExceptAt(C, N-1)
	C = expr.Col("C").Sub(expr.Col("A")).Sub(expr.Col("B"))
	fibonacciModule.AssertZero(C)
	return fibonacciModule
}

func preparePlonkModule(N int) board.Module {
	plonkModule := board.NewModule("plonk")
	plonkModule.N = N

	qll := expr.Col(ID_Ql).Mul(expr.Col(ID_L))
	qrr := expr.Col(ID_Qr).Mul(expr.Col(ID_R))
	qmlr := expr.Col(ID_Qm).Mul(expr.Col(ID_L)).Mul(expr.Col(ID_R))
	qoo := expr.Col(ID_Qo).Mul(expr.Col(ID_O))
	qk := expr.Col(ID_Qk)
	vanishingRelation := qll.Add(qrr).Add(qmlr).Add(qoo).Add(qk)
	plonkModule.AssertZero(vanishingRelation)
	return plonkModule
}

func buildFibLookupProgram(t *testing.T) board.Program {
	t.Helper()

	builder := board.NewBuilder()

	rangeModule := board.NewModule("lookup")
	N := 4
	rangeModule.N = 2 * N

	fibonacciModule := prepareFibonacciModule(N)
	builder.AddModule("fibonacci", fibonacciModule)
	builder.AddModule("range", rangeModule)

	T := board.Column{
		Module: "range",
		In:     expr.Col("Lookup"),
	}
	for _, c := range []string{"A", "B", "C"} {
		S := board.Column{
			Module: "fibonacci",
			In:     expr.Col(c),
		}
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

func TestVerifierFibo(t *testing.T) {
	program, tr := buildFibTrace(t)

	proof, err := prover.Prove(tr, nil, nil, program)
	if err != nil {
		t.Fatal(err)
	}

	if err := Verify(nil, nil, program, proof); err != nil {
		t.Fatal(err)
	}
}

func TestVerifierWithGrinding(t *testing.T) {
	program, tr := buildFibTrace(t)

	const grindingBits = 8

	proof, err := prover.Prove(tr, nil, nil, program, prover.WithFRIGrindingBits(grindingBits))
	if err != nil {
		t.Fatal(err)
	}

	if err := Verify(nil, nil, program, proof, WithFRIGrindingBits(grindingBits)); err != nil {
		t.Fatal(err)
	}
}

func TestVerifierTamperedClaimedValue(t *testing.T) {
	program, tr := buildFibTrace(t)

	prf, err := prover.Prove(tr, nil, nil, program)
	if err != nil {
		t.Fatal(err)
	}

	cv := prf.CommitmentOpenings.OpenedValues
	if len(cv) == 0 {
		t.Fatal("proof has no claimed values")
	}
	var junk koalabear.Element
	junk.SetOne()
	cv[len(cv)-1].Add(&cv[len(cv)-1], &junk)

	if err := Verify(nil, nil, program, prf); err == nil {
		t.Fatal("Verify: expected rejection after claimed value tamper")
	}
}

func TestVerifierGrindingMismatch(t *testing.T) {
	program, tr := buildFibTrace(t)

	proof, err := prover.Prove(tr, nil, nil, program, prover.WithFRIGrindingBits(8))
	if err != nil {
		t.Fatal(err)
	}

	if err := Verify(nil, nil, program, proof); err == nil {
		t.Fatal("Verify: expected rejection when verifier ignores prover grinding")
	}
}

func TestVerifierPlonk(t *testing.T) {
	builder := board.NewBuilder()

	N := 16
	tr, sigma, size, err := getPlonkTrace(N)
	if err != nil {
		t.Fatal(err)
	}

	plonkModule := preparePlonkModule(size)
	builder.AddModule("plonk", plonkModule)

	lro := []expr.Expr{expr.Col(ID_L), expr.Col(ID_R), expr.Col(ID_O)}
	sigmaGen := board.NewPermutationGen(sigma, "plonk.S")
	if err := arguments.CopyConstraint(&builder, "plonk", lro, sigmaGen); err != nil {
		t.Fatal(err)
	}

	program, err := board.Compile(&builder)
	if err != nil {
		t.Fatal(err)
	}

	proof, err := prover.Prove(tr, nil, nil, program)
	if err != nil {
		t.Fatal(err)
	}
	viz.ViewDag(program, "dag_plonk.html")

	if err := Verify(nil, nil, program, proof); err != nil {
		t.Fatal(err)
	}
}

func TestFiboPlonk(t *testing.T) {
	NPlonk := 16
	tr, sigma, size, err := getPlonkTrace(NPlonk)
	if err != nil {
		t.Fatal(err)
	}

	plonkModule := preparePlonkModule(size)
	NFibo := 4
	fibonacciModule := prepareFibonacciModule(NFibo)
	rangeModule := board.NewModule("range")
	rangeModule.N = 2 * NFibo

	builder := board.NewBuilder()
	builder.AddModule("plonk", plonkModule)
	builder.AddModule("fibonacci", fibonacciModule)
	builder.AddModule("range", rangeModule)

	T := board.Column{
		Module: "range",
		In:     expr.Col("Lookup"),
	}
	for _, c := range []string{"A", "B", "C"} {
		S := board.Column{
			Module: "fibonacci",
			In:     expr.Col(c),
		}
		if err := arguments.Lookup(&builder, S, T); err != nil {
			t.Fatal(err)
		}
	}

	lro := []expr.Expr{expr.Col(ID_L), expr.Col(ID_R), expr.Col(ID_O)}
	sigmaGen := board.NewPermutationGen(sigma, "plonk.S")
	if err := arguments.CopyConstraint(&builder, "plonk", lro, sigmaGen); err != nil {
		t.Fatal(err)
	}

	program, err := board.Compile(&builder)
	if err != nil {
		t.Fatal(err)
	}
	viz.ViewDag(program, "mixed_dag.html")

	var a, b koalabear.Element
	b.SetOne()
	traceFrob := prover.TraceFibonacci(NFibo, a, b)
	traceRange := prover.TraceRange(NFibo)
	fullTrace := prover.MergeTrace(traceFrob, traceRange, tr)

	proof, err := prover.Prove(fullTrace, nil, nil, program)
	if err != nil {
		t.Fatal(err)
	}

	viz.WriteRawTraceToCSV("trace.csv", fullTrace)

	if err := Verify(nil, nil, program, proof); err != nil {
		t.Fatal(err)
	}
}
