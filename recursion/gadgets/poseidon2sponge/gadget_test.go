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

package poseidon2sponge_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	nativeposeidon2 "github.com/consensys/gnark-crypto/field/koalabear/poseidon2"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/recursion/gadgets/poseidon2sponge"
	"github.com/consensys/loom/recursion/internal/testutil"
	"github.com/consensys/loom/trace"
)

func seededInput(seed uint64) [poseidon2sponge.Width]koalabear.Element {
	var in [poseidon2sponge.Width]koalabear.Element
	for i := 0; i < poseidon2sponge.Width; i++ {
		in[i].SetUint64(seed*1000003 + uint64(i)*0x9e3779b97f4a7c15)
	}
	return in
}

func buildBuilderAndTrace(t *testing.T, name string, n int, inputs [][poseidon2sponge.Width]koalabear.Element) (board.Builder, trace.Trace, poseidon2sponge.ColumnNames) {
	t.Helper()
	builder := board.NewBuilder()
	cn := poseidon2sponge.BuildModule(&builder, name, n)
	cols, _ := poseidon2sponge.GenerateTrace(cn, n, inputs)

	tr := trace.New()
	for k, v := range cols {
		tr.SetBase(k, v)
	}
	return builder, tr, cn
}

// TestPoseidon2SpongeSinglePermutation proves the gadget for one input.
func TestPoseidon2SpongeSinglePermutation(t *testing.T) {
	in := seededInput(1)
	inputs := [][poseidon2sponge.Width]koalabear.Element{in}

	builder, tr, _ := buildBuilderAndTrace(t, "p2s", 1, inputs)
	testutil.ProveAndVerify(t, &builder, tr)
}

// TestPoseidon2SpongeMultiplePermutations exercises n=4 permutations and
// cross-checks every output lane against the native width-24 permutation.
func TestPoseidon2SpongeMultiplePermutations(t *testing.T) {
	const n = 4
	inputs := make([][poseidon2sponge.Width]koalabear.Element, n)
	for i := 0; i < n; i++ {
		inputs[i] = seededInput(uint64(i + 1))
	}

	perm := nativeposeidon2.NewPermutation(
		poseidon2sponge.Width,
		poseidon2sponge.NbFullRounds,
		poseidon2sponge.NbPartialRound,
	)
	expected := make([][poseidon2sponge.Width]koalabear.Element, n)
	for i := 0; i < n; i++ {
		expected[i] = inputs[i]
		if err := perm.Permutation(expected[i][:]); err != nil {
			t.Fatalf("native permutation: %v", err)
		}
	}

	builder, tr, cn := buildBuilderAndTrace(t, "p2s_multi", n, inputs)

	for i := 0; i < poseidon2sponge.Width; i++ {
		col, ok := tr.Base[cn.Post[poseidon2sponge.NbRounds-1][i]]
		if !ok {
			t.Fatalf("missing post column %s", cn.Post[poseidon2sponge.NbRounds-1][i])
		}
		for row := 0; row < n; row++ {
			if !col[row].Equal(&expected[row][i]) {
				t.Fatalf("row=%d lane=%d: got %s want %s", row, i, col[row].String(), expected[row][i].String())
			}
		}
	}

	testutil.ProveAndVerify(t, &builder, tr)
}

// TestPoseidon2SpongeWithPadding checks padding rows (all-zero input)
// pass the constraints.
func TestPoseidon2SpongeWithPadding(t *testing.T) {
	const n = 2
	inputs := [][poseidon2sponge.Width]koalabear.Element{
		seededInput(42),
	}
	builder, tr, _ := buildBuilderAndTrace(t, "p2s_pad", n, inputs)
	testutil.ProveAndVerify(t, &builder, tr)
}

// TestPoseidon2SpongeRejectsCorruption flips one mid-round witness cell
// and confirms verification fails.
func TestPoseidon2SpongeRejectsCorruption(t *testing.T) {
	inputs := [][poseidon2sponge.Width]koalabear.Element{seededInput(7)}
	builder, tr, cn := buildBuilderAndTrace(t, "p2s_corrupt", 1, inputs)

	target := cn.Post[poseidon2sponge.NbRounds/2][5]
	col := tr.Base[target]
	col[0].SetUint64(uint64(col[0][0]) + 1)
	tr.Base[target] = col

	testutil.ExpectProveOrVerifyFailure(t, &builder, tr)
}
