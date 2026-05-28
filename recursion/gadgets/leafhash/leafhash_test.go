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

package leafhash_test

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/internal/commitment"
	"github.com/consensys/loom/recursion/extfield"
	"github.com/consensys/loom/recursion/gadgets/leafhash"
	"github.com/consensys/loom/recursion/gadgets/poseidon2sponge"
	"github.com/consensys/loom/recursion/internal/testutil"
	"github.com/consensys/loom/trace"
)

func randExt(t *testing.T) ext.E4 {
	t.Helper()
	var v ext.E4
	if _, err := v.B0.A0.SetRandom(); err != nil {
		t.Fatal(err)
	}
	if _, err := v.B0.A1.SetRandom(); err != nil {
		t.Fatal(err)
	}
	if _, err := v.B1.A0.SetRandom(); err != nil {
		t.Fatal(err)
	}
	if _, err := v.B1.A1.SetRandom(); err != nil {
		t.Fatal(err)
	}
	return v
}

// nativeLeafDigest computes the expected leaf digest using Loom's native
// Poseidon2LeafHasher for a single ext pair.
func nativeLeafDigest(P, Q ext.E4) [leafhash.DigestLen]koalabear.Element {
	h := commitment.Poseidon2LeafHasher{}
	digest := h.HashLeaf(nil, []commitment.PairExt{{P, Q}})
	return digest
}

// buildOneLeafHashModule wires a small module with leafP/leafQ committed
// columns + the leafhash gadget. Returns builder, trace, leafhash CN, and
// the column names allocated for leafP/leafQ.
func buildOneLeafHashModule(t *testing.T, name string, n int, leaves []leafhash.ExtLeaf) (board.Builder, trace.Trace, leafhash.ColumnNames) {
	t.Helper()

	mod := board.NewModule(name)
	mod.N = n

	// Allocate column names for leafP/leafQ; these are caller-managed
	// witnesses that the leafhash gadget references by name.
	var leafPCols, leafQCols [extfield.Limbs]string
	for i := 0; i < extfield.Limbs; i++ {
		leafPCols[i] = name + ".leafP_" + string('0'+rune(i))
		leafQCols[i] = name + ".leafQ_" + string('0'+rune(i))
	}

	cn := leafhash.RegisterExtLeafHash(&mod, name+".lh", leafPCols, leafQCols)

	builder := board.NewBuilder()
	builder.AddModule(mod)

	// Fill trace.
	tr := trace.New()

	// Sponge input columns: use BuildSpongeInputs.
	spongeInputs := leafhash.BuildSpongeInputs(leaves)
	for len(spongeInputs) < n {
		// Pad with all-zero state (which corresponds to the trivial
		// degenerate "leaf" — but our constraints force state[0]=tag, [2]=1
		// so an all-zero pad would violate the constraints. Instead, repeat
		// the first real leaf so all rows have identical valid input.)
		spongeInputs = append(spongeInputs, spongeInputs[0])
	}
	spongeCols, _ := poseidon2sponge.GenerateTrace(cn.Sponge, n, spongeInputs)
	for k, v := range spongeCols {
		tr.SetBase(k, v)
	}

	// leafP / leafQ columns. Pad rows mirror the first real leaf so the
	// equality constraints are satisfied at every row.
	leafCols := make(map[string][]koalabear.Element, 2*extfield.Limbs)
	for i := 0; i < extfield.Limbs; i++ {
		leafCols[leafPCols[i]] = make([]koalabear.Element, n)
		leafCols[leafQCols[i]] = make([]koalabear.Element, n)
	}
	for row := 0; row < n; row++ {
		idx := row
		if idx >= len(leaves) {
			idx = 0
		}
		for i := 0; i < extfield.Limbs; i++ {
			leafCols[leafPCols[i]][row].Set(&leaves[idx].P[i])
			leafCols[leafQCols[i]][row].Set(&leaves[idx].Q[i])
		}
	}
	for k, v := range leafCols {
		tr.SetBase(k, v)
	}

	return builder, tr, cn
}

// TestLeafHashGadgetSingle proves one ext-rail leaf hash and confirms the
// gadget's digest columns match the native commitment.Poseidon2LeafHasher
// digest.
// TestFlexibleLeafHashMultiBlock exercises a leaf whose total input
// length (3 header + 2 ext pairs = 19 elements) exceeds one sponge
// rate (16) — forcing two-block absorption.
func TestFlexibleLeafHashMultiBlock(t *testing.T) {
	ext1P, ext1Q := randExt(t), randExt(t)
	ext2P, ext2Q := randExt(t), randExt(t)
	leaf := leafhash.FlexibleLeaf{
		ExtPairsP: [][extfield.Limbs]koalabear.Element{extfield.FromE4(ext1P), extfield.FromE4(ext2P)},
		ExtPairsQ: [][extfield.Limbs]koalabear.Element{extfield.FromE4(ext1Q), extfield.FromE4(ext2Q)},
	}

	if leafhash.NumBlocksForFlexible(0, 2) != 2 {
		t.Fatalf("expected 2 blocks for (0 base, 2 ext)")
	}

	mod := board.NewModule("flexlh_multi")
	mod.N = 2
	var extPCols, extQCols [][extfield.Limbs]string
	for j := 0; j < 2; j++ {
		var pc, qc [extfield.Limbs]string
		for i := 0; i < extfield.Limbs; i++ {
			pc[i] = fmt.Sprintf("ext%d.P_%d", j, i)
			qc[i] = fmt.Sprintf("ext%d.Q_%d", j, i)
		}
		extPCols = append(extPCols, pc)
		extQCols = append(extQCols, qc)
	}
	cn := leafhash.RegisterFlexibleLeafHash(&mod, "flh", nil, nil, extPCols, extQCols)
	if cn.NumBlocks != 2 {
		t.Fatalf("expected 2 sponge blocks, got %d", cn.NumBlocks)
	}

	builder := board.NewBuilder()
	builder.AddModule(mod)

	tr := trace.New()
	// Fill ext column witnesses (constant across rows).
	for j := 0; j < 2; j++ {
		var p, q [extfield.Limbs]koalabear.Element
		if j == 0 {
			p, q = extfield.FromE4(ext1P), extfield.FromE4(ext1Q)
		} else {
			p, q = extfield.FromE4(ext2P), extfield.FromE4(ext2Q)
		}
		for i := 0; i < extfield.Limbs; i++ {
			pc := make([]koalabear.Element, mod.N)
			qc := make([]koalabear.Element, mod.N)
			for r := range pc {
				pc[r].Set(&p[i])
				qc[r].Set(&q[i])
			}
			tr.SetBase(extPCols[j][i], pc)
			tr.SetBase(extQCols[j][i], qc)
		}
	}
	// Fill per-block sponge sub-traces.
	states := leafhash.FlexibleLeafSpongeStates(leaf)
	for b, st := range states {
		inputs := make([][24]koalabear.Element, mod.N)
		for r := range inputs {
			inputs[r] = st
		}
		cols, _ := poseidon2sponge.GenerateTrace(cn.Sponges[b], mod.N, inputs)
		for k, v := range cols {
			tr.SetBase(k, v)
		}
	}

	testutil.ProveAndVerify(t, &builder, tr)

	// Cross-check the gadget digest against the native HashLeaf output.
	nativeDigest := commitment.Poseidon2LeafHasher{}.HashLeaf(nil, []commitment.PairExt{{ext1P, ext1Q}, {ext2P, ext2Q}})
	for i := 0; i < leafhash.DigestLen; i++ {
		got := tr.Base[cn.Digest[i]][0]
		if !got.Equal(&nativeDigest[i]) {
			t.Fatalf("digest[%d]: in-circuit %s, native %s", i, got.String(), nativeDigest[i].String())
		}
	}
}

func TestLeafHashGadgetSingle(t *testing.T) {
	P := randExt(t)
	Q := randExt(t)
	leaf := leafhash.ExtLeaf{
		P: extfield.FromE4(P),
		Q: extfield.FromE4(Q),
	}

	builder, tr, cn := buildOneLeafHashModule(t, "lh_one", 1, []leafhash.ExtLeaf{leaf})

	// Cross-check digest against native.
	want := nativeLeafDigest(P, Q)
	for i := 0; i < leafhash.DigestLen; i++ {
		got := tr.Base[cn.Digest[i]][0]
		if !got.Equal(&want[i]) {
			t.Fatalf("digest limb %d: got %s want %s", i, got.String(), want[i].String())
		}
	}

	testutil.ProveAndVerify(t, &builder, tr)
}

// TestLeafHashGadgetBatch exercises 4 different leaves in one module and
// verifies each row's digest matches the native hasher.
func TestLeafHashGadgetBatch(t *testing.T) {
	const n = 4
	pairs := make([][2]ext.E4, n)
	leaves := make([]leafhash.ExtLeaf, n)
	for i := 0; i < n; i++ {
		pairs[i] = [2]ext.E4{randExt(t), randExt(t)}
		leaves[i] = leafhash.ExtLeaf{
			P: extfield.FromE4(pairs[i][0]),
			Q: extfield.FromE4(pairs[i][1]),
		}
	}

	builder, tr, cn := buildOneLeafHashModule(t, "lh_batch", n, leaves)

	for row := 0; row < n; row++ {
		want := nativeLeafDigest(pairs[row][0], pairs[row][1])
		for i := 0; i < leafhash.DigestLen; i++ {
			got := tr.Base[cn.Digest[i]][row]
			if !got.Equal(&want[i]) {
				t.Fatalf("row %d digest limb %d: got %s want %s", row, i, got.String(), want[i].String())
			}
		}
	}

	testutil.ProveAndVerify(t, &builder, tr)
}

// TestLeafHashGadgetRejectsBadLeaf tampers with one limb of LeafP and
// confirms the leaf-hash constraints catch the inconsistency between the
// (Sponge.In) absorbed value and the leafP witness.
func TestLeafHashGadgetRejectsBadLeaf(t *testing.T) {
	P := randExt(t)
	Q := randExt(t)
	leaf := leafhash.ExtLeaf{
		P: extfield.FromE4(P),
		Q: extfield.FromE4(Q),
	}

	builder, tr, _ := buildOneLeafHashModule(t, "lh_bad", 1, []leafhash.ExtLeaf{leaf})

	// Corrupt leafP limb 0 — leaves the sponge trace consistent with the
	// honest P, but the equality constraint linking sponge.In[3] to
	// leafP[0] now fails.
	col := tr.Base["lh_bad.leafP_0"]
	var one koalabear.Element
	one.SetOne()
	col[0].Add(&col[0], &one)

	testutil.ExpectProveOrVerifyFailure(t, &builder, tr)
}

// TestLeafHashGadgetRejectsBadDigest tampers with the sponge output
// (which feeds the Digest view); the Poseidon2 constraints catch this.
func TestLeafHashGadgetRejectsBadDigest(t *testing.T) {
	P := randExt(t)
	Q := randExt(t)
	leaf := leafhash.ExtLeaf{
		P: extfield.FromE4(P),
		Q: extfield.FromE4(Q),
	}

	builder, tr, cn := buildOneLeafHashModule(t, "lh_dig", 1, []leafhash.ExtLeaf{leaf})

	col := tr.Base[cn.Digest[0]]
	var one koalabear.Element
	one.SetOne()
	col[0].Add(&col[0], &one)

	testutil.ExpectProveOrVerifyFailure(t, &builder, tr)
}
