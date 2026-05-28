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
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/prover"
	"github.com/consensys/loom/setup"
	"github.com/consensys/loom/trace"
	"github.com/consensys/loom/verifier"
)

// innerSpec describes the inner-proof workload: one Fibonacci-like module
// per entry, sized as specified. With multiple distinct sizes the FRI
// verifier exercises multi-level folding (level intro per distinct size).
type innerSpec struct {
	label    string
	sizes    []int
	skipFRI  bool
}

// allInnerSpecs are the benchmark workloads. Add an entry here to
// extend coverage; every Benchmark* function iterates this list.
var allInnerSpecs = []innerSpec{
	{label: "Small", sizes: []int{4}, skipFRI: true},
	{label: "Large", sizes: []int{64, 32, 16, 8}, skipFRI: false},
}

// buildInner constructs the inner builder + base-field trace columns for
// the given spec. Each module "fib_<N>" computes Fibonacci of size N with
// its own A/B/C columns.
func buildInner(spec innerSpec) (board.Builder, map[string][]koalabear.Element) {
	builder := board.NewBuilder()
	cols := make(map[string][]koalabear.Element)
	for _, n := range spec.sizes {
		modName := fmt.Sprintf("fib_%d", n)
		aName := modName + ".A"
		bName := modName + ".B"
		cName := modName + ".C"

		mod := board.NewModule(modName)
		mod.N = n
		mod.AssertZeroExceptAt(expr.Rot(aName, 1).Sub(expr.Col(bName)), n-1)
		mod.AssertZeroExceptAt(expr.Rot(bName, 1).Sub(expr.Col(aName).Add(expr.Col(bName))), n-1)
		mod.AssertZero(expr.Col(cName).Sub(expr.Col(aName).Add(expr.Col(bName))))
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
		cols[aName] = a
		cols[bName] = b
		cols[cName] = c
	}
	return builder, cols
}

func compileInner(b *testing.B, spec innerSpec) (board.Program, trace.Trace) {
	b.Helper()
	builder, cols := buildInner(spec)
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

func innerProveOpts(spec innerSpec) []prover.Option {
	if spec.skipFRI {
		return []prover.Option{prover.SkipFRI()}
	}
	return nil
}

func innerVerifyOpts(spec innerSpec) []verifier.Option {
	if spec.skipFRI {
		return []verifier.Option{verifier.SkipFRI()}
	}
	return nil
}

// BenchmarkInnerBuild measures board.Compile on the inner program.
func BenchmarkInnerBuild(b *testing.B) {
	for _, spec := range allInnerSpecs {
		b.Run(spec.label, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				builder, _ := buildInner(spec)
				if _, err := board.Compile(&builder); err != nil {
					b.Fatalf("Compile: %v", err)
				}
			}
		})
	}
}

// BenchmarkInnerProve measures prover.Prove on the inner program.
func BenchmarkInnerProve(b *testing.B) {
	for _, spec := range allInnerSpecs {
		b.Run(spec.label, func(b *testing.B) {
			program, tr := compileInner(b, spec)
			opts := innerProveOpts(spec)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := prover.Prove(tr, setup.ProvingKey{}, nil, program, opts...); err != nil {
					b.Fatalf("inner prove: %v", err)
				}
			}
		})
	}
}

// BenchmarkRecursionBuild measures BuildVerifierCore on each workload.
func BenchmarkRecursionBuild(b *testing.B) {
	for _, spec := range allInnerSpecs {
		b.Run(spec.label, func(b *testing.B) {
			program, tr := compileInner(b, spec)
			innerProof, err := prover.Prove(tr, setup.ProvingKey{}, nil, program, innerProveOpts(spec)...)
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
		})
	}
}

// BenchmarkRecursionProve measures prover.Prove on the outer program.
func BenchmarkRecursionProve(b *testing.B) {
	for _, spec := range allInnerSpecs {
		b.Run(spec.label, func(b *testing.B) {
			program, tr := compileInner(b, spec)
			innerProof, err := prover.Prove(tr, setup.ProvingKey{}, nil, program, innerProveOpts(spec)...)
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
		})
	}
}

// BenchmarkRecursionVerify measures verifier.Verify on the outer proof.
func BenchmarkRecursionVerify(b *testing.B) {
	for _, spec := range allInnerSpecs {
		b.Run(spec.label, func(b *testing.B) {
			program, tr := compileInner(b, spec)
			innerProof, err := prover.Prove(tr, setup.ProvingKey{}, nil, program, innerProveOpts(spec)...)
			if err != nil {
				b.Fatalf("inner prove: %v", err)
			}
			_ = innerVerifyOpts // referenced for symmetry; outer always SkipFRI
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
		})
	}
}
