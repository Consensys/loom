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

package recursion

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/prover"
	"github.com/consensys/loom/setup"
	"github.com/consensys/loom/trace"
	"github.com/consensys/loom/verifier"
)

// makeInnerForBench builds a Fibonacci-like inner board.Builder and the
// matching base-field witness columns. The Builder is returned uncompiled
// so the "build inner" benchmark measures board.Compile by itself.
func makeInnerForBench(n int) (board.Builder, map[string][]koalabear.Element) {
	builder := board.NewBuilder()
	mod := board.NewModule("inner")
	mod.N = n
	// A_{i+1} = B_i, B_{i+1} = A_i + B_i, C_i = A_i + B_i, at all rows
	// except the last.
	mod.AssertZeroExceptAt(expr.Rot("A", 1).Sub(expr.Col("B")), n-1)
	mod.AssertZeroExceptAt(expr.Rot("B", 1).Sub(expr.Col("A").Add(expr.Col("B"))), n-1)
	mod.AssertZero(expr.Col("C").Sub(expr.Col("A").Add(expr.Col("B"))))
	builder.AddModule(mod)

	a := make([]koalabear.Element, n)
	b := make([]koalabear.Element, n)
	c := make([]koalabear.Element, n)
	a[0].SetZero()
	b[0].SetOne()
	for i := 0; i < n; i++ {
		c[i].Add(&a[i], &b[i])
		if i+1 < n {
			a[i+1].Set(&b[i])
			b[i+1].Set(&c[i])
		}
	}
	cols := map[string][]koalabear.Element{"A": a, "B": b, "C": c}
	return builder, cols
}

// compileInner is a helper used by every benchmark in this file to
// obtain a fresh inner program. Errors are converted to b.Fatal.
func compileInner(b *testing.B, n int) (board.Program, trace.Trace) {
	b.Helper()
	builder, cols := makeInnerForBench(n)
	program, err := board.Compile(&builder)
	if err != nil {
		b.Fatalf("inner Compile: %v", err)
	}
	tr := trace.New()
	for name, vals := range cols {
		tr.SetBase(name, vals)
	}
	return program, tr
}

const benchInnerN = 4

// BenchmarkInnerBuild measures the cost of compiling the inner
// (subject) program — board.Compile applied to a fresh Builder.
func BenchmarkInnerBuild(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		builder, _ := makeInnerForBench(benchInnerN)
		if _, err := board.Compile(&builder); err != nil {
			b.Fatalf("Compile: %v", err)
		}
	}
}

// BenchmarkInnerProve measures the cost of producing a native Loom
// proof for the inner program. SkipFRI matches the cheapest path and
// keeps the focus on the AIR/quotient machinery; flip it off when
// FRI cost matters.
func BenchmarkInnerProve(b *testing.B) {
	program, tr := compileInner(b, benchInnerN)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := prover.Prove(tr, setup.ProvingKey{}, nil, program, prover.SkipFRI()); err != nil {
			b.Fatalf("inner prove: %v", err)
		}
	}
}

// BenchmarkRecursionBuild measures the cost of compiling the outer
// verifier program from an inner (program, proof) pair — this is
// BuildVerifierCore + its internal board.Compile.
func BenchmarkRecursionBuild(b *testing.B) {
	program, tr := compileInner(b, benchInnerN)
	innerProof, err := prover.Prove(tr, setup.ProvingKey{}, nil, program, prover.SkipFRI())
	if err != nil {
		b.Fatalf("inner prove: %v", err)
	}
	input := RecursionInput{Program: program, Proof: innerProof}
	cfg := DefaultConfig()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, err := BuildVerifierCore(input, cfg); err != nil {
			b.Fatalf("BuildVerifierCore: %v", err)
		}
	}
}

// BenchmarkRecursionProve measures the cost of generating the outer
// proof — prover.Prove on the recursion program built by
// BuildVerifierCore.
func BenchmarkRecursionProve(b *testing.B) {
	program, tr := compileInner(b, benchInnerN)
	innerProof, err := prover.Prove(tr, setup.ProvingKey{}, nil, program, prover.SkipFRI())
	if err != nil {
		b.Fatalf("inner prove: %v", err)
	}
	outerProgram, outerTrace, err := BuildVerifierCore(
		RecursionInput{Program: program, Proof: innerProof},
		DefaultConfig(),
	)
	if err != nil {
		b.Fatalf("BuildVerifierCore: %v", err)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := prover.Prove(outerTrace, setup.ProvingKey{}, nil, outerProgram, prover.SkipFRI()); err != nil {
			b.Fatalf("outer prove: %v", err)
		}
	}
}

// BenchmarkRecursionVerify measures the cost of verifying the outer
// proof.
func BenchmarkRecursionVerify(b *testing.B) {
	program, tr := compileInner(b, benchInnerN)
	innerProof, err := prover.Prove(tr, setup.ProvingKey{}, nil, program, prover.SkipFRI())
	if err != nil {
		b.Fatalf("inner prove: %v", err)
	}
	outerProgram, outerTrace, err := BuildVerifierCore(
		RecursionInput{Program: program, Proof: innerProof},
		DefaultConfig(),
	)
	if err != nil {
		b.Fatalf("BuildVerifierCore: %v", err)
	}
	outerProof, err := prover.Prove(outerTrace, setup.ProvingKey{}, nil, outerProgram, prover.SkipFRI())
	if err != nil {
		b.Fatalf("outer prove: %v", err)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := verifier.Verify(nil, setup.VerificationKey{}, outerProgram, outerProof, verifier.SkipFRI()); err != nil {
			b.Fatalf("outer verify: %v", err)
		}
	}
}
