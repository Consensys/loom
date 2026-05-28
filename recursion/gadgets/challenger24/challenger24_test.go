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

package challenger24_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/hash"
	"github.com/consensys/loom/recursion/gadgets/challenger24"
	"github.com/consensys/loom/recursion/internal/testutil"
	"github.com/consensys/loom/trace"
)

// nativeSpongeDigest returns the Poseidon2SpongeHasher digest of inputs
// — the same hash Loom's fiat-shamir transcript uses.
func nativeSpongeDigest(inputs []koalabear.Element) hash.Digest {
	h := hash.NewPoseidon2SpongeHasher()
	h.WriteElements(inputs...)
	return h.Sum()
}

func TestChallenger24SinglePermutation(t *testing.T) {
	// 12 inputs fit in one rate block (Rate=16); single permutation.
	inputs := make([]koalabear.Element, 12)
	for i := range inputs {
		inputs[i].SetUint64(uint64(i*37 + 1))
	}

	want := nativeSpongeDigest(inputs)

	builder := board.NewBuilder()
	inputExprs := make([]expr.Expr, len(inputs))
	for i, v := range inputs {
		inputExprs[i] = expr.Const(v)
	}
	cn := challenger24.BuildModule(&builder, "ch_one", inputExprs)
	if cn.NPermutations != 1 {
		t.Fatalf("expected 1 permutation, got %d", cn.NPermutations)
	}

	cols, gotDigest := challenger24.GenerateTrace(cn, inputs)
	for i := 0; i < challenger24.DigestLen; i++ {
		if !gotDigest[i].Equal(&want[i]) {
			t.Fatalf("digest limb %d: got %s want %s", i, gotDigest[i].String(), want[i].String())
		}
	}

	tr := trace.New()
	for k, v := range cols {
		tr.SetBase(k, v)
	}
	testutil.ProveAndVerify(t, &builder, tr)
}

func TestChallenger24TwoPermutations(t *testing.T) {
	// 20 inputs: 1 full rate block + 4-element partial block = 2 perms.
	inputs := make([]koalabear.Element, 20)
	for i := range inputs {
		inputs[i].SetUint64(uint64(i*101 + 7))
	}

	want := nativeSpongeDigest(inputs)

	builder := board.NewBuilder()
	inputExprs := make([]expr.Expr, len(inputs))
	for i, v := range inputs {
		inputExprs[i] = expr.Const(v)
	}
	cn := challenger24.BuildModule(&builder, "ch_two", inputExprs)
	if cn.NPermutations != 2 {
		t.Fatalf("expected 2 permutations, got %d", cn.NPermutations)
	}

	cols, gotDigest := challenger24.GenerateTrace(cn, inputs)
	for i := 0; i < challenger24.DigestLen; i++ {
		if !gotDigest[i].Equal(&want[i]) {
			t.Fatalf("digest limb %d: got %s want %s", i, gotDigest[i].String(), want[i].String())
		}
	}

	tr := trace.New()
	for k, v := range cols {
		tr.SetBase(k, v)
	}
	testutil.ProveAndVerify(t, &builder, tr)
}

func TestChallenger24ExactlyRate(t *testing.T) {
	// Exactly Rate=16 inputs — full block, no partial, single permutation.
	inputs := make([]koalabear.Element, challenger24.Rate)
	for i := range inputs {
		inputs[i].SetUint64(uint64(i*13 + 3))
	}

	want := nativeSpongeDigest(inputs)

	builder := board.NewBuilder()
	inputExprs := make([]expr.Expr, len(inputs))
	for i, v := range inputs {
		inputExprs[i] = expr.Const(v)
	}
	cn := challenger24.BuildModule(&builder, "ch_exact", inputExprs)
	cols, gotDigest := challenger24.GenerateTrace(cn, inputs)
	for i := 0; i < challenger24.DigestLen; i++ {
		if !gotDigest[i].Equal(&want[i]) {
			t.Fatalf("digest limb %d: got %s want %s", i, gotDigest[i].String(), want[i].String())
		}
	}

	tr := trace.New()
	for k, v := range cols {
		tr.SetBase(k, v)
	}
	testutil.ProveAndVerify(t, &builder, tr)
}

// TestChallenger24RejectsBadDigest tampers with a digest limb in the
// trace and confirms the proof fails.
func TestChallenger24RejectsBadDigest(t *testing.T) {
	inputs := make([]koalabear.Element, 8)
	for i := range inputs {
		inputs[i].SetUint64(uint64(i + 1))
	}

	builder := board.NewBuilder()
	inputExprs := make([]expr.Expr, len(inputs))
	for i, v := range inputs {
		inputExprs[i] = expr.Const(v)
	}
	cn := challenger24.BuildModule(&builder, "ch_bad", inputExprs)
	cols, _ := challenger24.GenerateTrace(cn, inputs)

	// Corrupt the digest at the digest row.
	col := cols[cn.Digest[0]]
	var one koalabear.Element
	one.SetOne()
	col[cn.DigestRow].Add(&col[cn.DigestRow], &one)

	tr := trace.New()
	for k, v := range cols {
		tr.SetBase(k, v)
	}
	testutil.ExpectProveOrVerifyFailure(t, &builder, tr)
}
