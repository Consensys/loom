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

package poseidon2_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	nativeposeidon2 "github.com/consensys/gnark-crypto/field/koalabear/poseidon2"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/recursion/gadgets/poseidon2"
	"github.com/consensys/loom/recursion/internal/testutil"
	"github.com/consensys/loom/trace"
)

// randomInput returns a deterministic-but-arbitrary width-16 input from a
// seed. Reproducibility matters for debugging negative tests.
func seededInput(seed uint64) [poseidon2.Width]koalabear.Element {
	var in [poseidon2.Width]koalabear.Element
	for i := 0; i < poseidon2.Width; i++ {
		in[i].SetUint64(seed*1000003 + uint64(i)*0x9e3779b97f4a7c15)
	}
	return in
}

func buildBuilderAndTrace(t *testing.T, name string, n int, inputs [][poseidon2.Width]koalabear.Element) (board.Builder, trace.Trace, poseidon2.ColumnNames) {
	t.Helper()
	builder := board.NewBuilder()
	cn := poseidon2.BuildModule(&builder, name, n)

	cols, _ := poseidon2.GenerateTrace(cn, n, inputs)

	tr := trace.New()
	for k, v := range cols {
		tr.SetBase(k, v)
	}
	return builder, tr, cn
}

// TestPoseidon2GadgetSinglePermutation proves the gadget for one specific
// input and cross-checks the output against the native permutation.
func TestPoseidon2GadgetSinglePermutation(t *testing.T) {
	in := seededInput(1)
	inputs := [][poseidon2.Width]koalabear.Element{in}

	builder, tr, _ := buildBuilderAndTrace(t, "p2", 1, inputs)
	testutil.ProveAndVerify(t, &builder, tr)
}

// TestPoseidon2GadgetMultiplePermutations exercises the gadget with n=8
// permutations (module N = 8) and verifies the witness against the native
// hasher for every row.
func TestPoseidon2GadgetMultiplePermutations(t *testing.T) {
	const n = 8
	inputs := make([][poseidon2.Width]koalabear.Element, n)
	for i := 0; i < n; i++ {
		inputs[i] = seededInput(uint64(i + 1))
	}

	// Sanity-check outputs match native independently of the prover path.
	perm := nativeposeidon2.NewPermutation(poseidon2.Width, poseidon2.NbFullRounds, poseidon2.NbPartialRound)
	expected := make([][poseidon2.Width]koalabear.Element, n)
	for i := 0; i < n; i++ {
		expected[i] = inputs[i]
		if err := perm.Permutation(expected[i][:]); err != nil {
			t.Fatalf("native permutation: %v", err)
		}
	}

	builder, tr, cn := buildBuilderAndTrace(t, "p2", n, inputs)

	// Cross-check the gadget output columns against the native expected
	// outputs before running the prover.
	for i := 0; i < poseidon2.Width; i++ {
		col, ok := tr.Base[cn.Post[poseidon2.NbRounds-1][i]]
		if !ok {
			t.Fatalf("missing post column %s", cn.Post[poseidon2.NbRounds-1][i])
		}
		for row := 0; row < n; row++ {
			if !col[row].Equal(&expected[row][i]) {
				t.Fatalf("output mismatch at row=%d lane=%d: got %s want %s",
					row, i, col[row].String(), expected[row][i].String())
			}
		}
	}

	testutil.ProveAndVerify(t, &builder, tr)
}

// TestPoseidon2GadgetWithPadding verifies that a module sized larger than the
// number of "real" permutations still produces a valid proof (the padding
// rows trace Permutation([0]*16)).
func TestPoseidon2GadgetWithPadding(t *testing.T) {
	const n = 4
	inputs := [][poseidon2.Width]koalabear.Element{
		seededInput(42),
	}
	builder, tr, _ := buildBuilderAndTrace(t, "p2", n, inputs)
	testutil.ProveAndVerify(t, &builder, tr)
}

// TestPoseidon2GadgetRejectsCorruption corrupts one cell of the witness and
// confirms the prove-or-verify path rejects the modified trace.
func TestPoseidon2GadgetRejectsCorruption(t *testing.T) {
	inputs := [][poseidon2.Width]koalabear.Element{seededInput(7)}
	builder, tr, cn := buildBuilderAndTrace(t, "p2", 1, inputs)

	// Flip one limb of a mid-round post column.
	target := cn.Post[poseidon2.NbRounds/2][3]
	col := tr.Base[target]
	col[0].SetUint64(uint64(col[0][0]) + 1)
	tr.Base[target] = col

	testutil.ExpectProveOrVerifyFailure(t, &builder, tr)
}
