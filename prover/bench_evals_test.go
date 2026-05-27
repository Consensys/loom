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
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/setup"
	"github.com/consensys/loom/trace"
)

// BenchmarkProveWide exercises the wide-trace shape (single module, modest N,
// many columns) where evaluations-at-zeta is a sizeable share of total prove
// wall time. The R parameter scales width = 3*R and so the number of per-column
// evaluations at zeta — making this a useful proxy for the ComputeEvaluationsAtZeta
// fan-out.
func BenchmarkProveWide(b *testing.B) {
	const (
		log2Rows    = 12
		repetitions = 256
	)
	rows := 1 << log2Rows

	col := func(i int) string { return fmt.Sprintf("synth.c_%d", i) }

	builder := board.NewBuilder()
	m := board.NewModule("synth")
	m.N = rows
	for k := 0; k < repetitions; k++ {
		a := expr.Col(col(3 * k))
		bb := expr.Col(col(3*k + 1))
		c := expr.Col(col(3*k + 2))
		m.AssertZero(a.Mul(bb).Sub(c))
	}
	builder.AddModule(m)
	program, err := board.Compile(&builder)
	if err != nil {
		b.Fatalf("Compile: %v", err)
	}

	t := trace.New(3 * repetitions)
	for k := 0; k < repetitions; k++ {
		a := make([]koalabear.Element, rows)
		bs := make([]koalabear.Element, rows)
		c := make([]koalabear.Element, rows)
		for i := 0; i < rows; i++ {
			a[i].SetUint64(uint64(i + 1 + k))
			bs[i].SetUint64(uint64(2*i + 3 + k))
			c[i].Mul(&a[i], &bs[i])
		}
		t.SetBase(col(3*k), a)
		t.SetBase(col(3*k+1), bs)
		t.SetBase(col(3*k+2), c)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Prove(t, setup.ProvingKey{}, nil, program)
		if err != nil {
			b.Fatalf("Prove: %v", err)
		}
	}
}
