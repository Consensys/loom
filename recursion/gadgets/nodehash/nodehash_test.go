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

package nodehash_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/internal/commitment"
	"github.com/consensys/loom/internal/hash"
	"github.com/consensys/loom/recursion/gadgets/nodehash"
	"github.com/consensys/loom/recursion/gadgets/poseidon2sponge"
	"github.com/consensys/loom/recursion/internal/testutil"
	"github.com/consensys/loom/trace"
)

func randDigest(t *testing.T) [nodehash.DigestLen]koalabear.Element {
	t.Helper()
	var d [nodehash.DigestLen]koalabear.Element
	for i := range d {
		if _, err := d[i].SetRandom(); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

// nativeNodeHash uses Loom's Poseidon2NodeHasher to compute the expected
// HashNode for the given left/right digests.
func nativeNodeHash(left, right [nodehash.DigestLen]koalabear.Element) [nodehash.DigestLen]koalabear.Element {
	var l, r hash.Digest
	for i := 0; i < nodehash.DigestLen; i++ {
		l[i].Set(&left[i])
		r[i].Set(&right[i])
	}
	h := commitment.Poseidon2NodeHasher{}
	out := h.HashNode(l, r)
	var ret [nodehash.DigestLen]koalabear.Element
	for i := 0; i < nodehash.DigestLen; i++ {
		ret[i].Set(&out[i])
	}
	return ret
}

func buildOneNodeHash(t *testing.T, name string, n int, nodes []nodehash.Node) (board.Builder, trace.Trace, nodehash.ColumnNames, [nodehash.DigestLen]string, [nodehash.DigestLen]string) {
	t.Helper()

	mod := board.NewModule(name)
	mod.N = n

	// Allocate left/right column names; they're caller-managed witnesses.
	var leftCols, rightCols [nodehash.DigestLen]string
	for i := 0; i < nodehash.DigestLen; i++ {
		leftCols[i] = name + ".left_" + string('0'+rune(i))
		rightCols[i] = name + ".right_" + string('0'+rune(i))
	}

	cn := nodehash.Register(&mod, name+".nh", leftCols, rightCols)

	builder := board.NewBuilder()
	builder.AddModule(mod)

	spongeInputs := nodehash.BuildSpongeInputs(nodes)
	// Pad up to n by repeating the first node so all rows are valid.
	for len(spongeInputs) < n {
		spongeInputs = append(spongeInputs, spongeInputs[0])
	}

	tr := trace.New()

	spCols, _ := poseidon2sponge.GenerateTrace(cn.Sponge, n, spongeInputs)
	for k, v := range spCols {
		tr.SetBase(k, v)
	}

	// left / right witness columns.
	leftRightCols := make(map[string][]koalabear.Element, 2*nodehash.DigestLen)
	for i := 0; i < nodehash.DigestLen; i++ {
		leftRightCols[leftCols[i]] = make([]koalabear.Element, n)
		leftRightCols[rightCols[i]] = make([]koalabear.Element, n)
	}
	for row := 0; row < n; row++ {
		idx := row
		if idx >= len(nodes) {
			idx = 0
		}
		for i := 0; i < nodehash.DigestLen; i++ {
			leftRightCols[leftCols[i]][row].Set(&nodes[idx].Left[i])
			leftRightCols[rightCols[i]][row].Set(&nodes[idx].Right[i])
		}
	}
	for k, v := range leftRightCols {
		tr.SetBase(k, v)
	}

	// Digest columns.
	digestCols := make(map[string][]koalabear.Element, nodehash.DigestLen)
	for i := 0; i < nodehash.DigestLen; i++ {
		digestCols[cn.Digest[i]] = make([]koalabear.Element, n)
	}
	for row := 0; row < n; row++ {
		idx := row
		if idx >= len(nodes) {
			idx = 0
		}
		d := nodehash.DigestOf(nodes[idx])
		for i := 0; i < nodehash.DigestLen; i++ {
			digestCols[cn.Digest[i]][row].Set(&d[i])
		}
	}
	for k, v := range digestCols {
		tr.SetBase(k, v)
	}

	return builder, tr, cn, leftCols, rightCols
}

// TestNodeHashGadgetSingle proves one node hash and confirms the digest
// matches the native Poseidon2NodeHasher.HashNode.
func TestNodeHashGadgetSingle(t *testing.T) {
	left := randDigest(t)
	right := randDigest(t)
	node := nodehash.Node{Left: left, Right: right}

	builder, tr, cn, _, _ := buildOneNodeHash(t, "nh_one", 1, []nodehash.Node{node})

	want := nativeNodeHash(left, right)
	for i := 0; i < nodehash.DigestLen; i++ {
		got := tr.Base[cn.Digest[i]][0]
		if !got.Equal(&want[i]) {
			t.Fatalf("digest limb %d: got %s want %s", i, got.String(), want[i].String())
		}
	}

	testutil.ProveAndVerify(t, &builder, tr)
}

// TestNodeHashGadgetBatch exercises 4 different nodes and cross-checks
// every row's digest against the native hasher.
func TestNodeHashGadgetBatch(t *testing.T) {
	const n = 4
	nodes := make([]nodehash.Node, n)
	for i := 0; i < n; i++ {
		nodes[i] = nodehash.Node{Left: randDigest(t), Right: randDigest(t)}
	}

	builder, tr, cn, _, _ := buildOneNodeHash(t, "nh_batch", n, nodes)

	for row := 0; row < n; row++ {
		want := nativeNodeHash(nodes[row].Left, nodes[row].Right)
		for i := 0; i < nodehash.DigestLen; i++ {
			got := tr.Base[cn.Digest[i]][row]
			if !got.Equal(&want[i]) {
				t.Fatalf("row %d limb %d: got %s want %s", row, i, got.String(), want[i].String())
			}
		}
	}

	testutil.ProveAndVerify(t, &builder, tr)
}

// TestNodeHashGadgetRejectsBadLeft tampers with left[0] in the witness;
// the input-equality constraint between leftCols and compress1.In[1]
// catches the inconsistency.
func TestNodeHashGadgetRejectsBadLeft(t *testing.T) {
	left := randDigest(t)
	right := randDigest(t)
	node := nodehash.Node{Left: left, Right: right}

	builder, tr, _, leftCols, _ := buildOneNodeHash(t, "nh_bad_l", 1, []nodehash.Node{node})

	col := tr.Base[leftCols[0]]
	var one koalabear.Element
	one.SetOne()
	col[0].Add(&col[0], &one)

	testutil.ExpectProveOrVerifyFailure(t, &builder, tr)
}

// TestNodeHashGadgetRejectsBadDigest flips one digest limb; the digest =
// In[8+i] + Out[8+i] constraint catches it.
func TestNodeHashGadgetRejectsBadDigest(t *testing.T) {
	left := randDigest(t)
	right := randDigest(t)
	node := nodehash.Node{Left: left, Right: right}

	builder, tr, cn, _, _ := buildOneNodeHash(t, "nh_bad_d", 1, []nodehash.Node{node})

	col := tr.Base[cn.Digest[0]]
	var one koalabear.Element
	one.SetOne()
	col[0].Add(&col[0], &one)

	testutil.ExpectProveOrVerifyFailure(t, &builder, tr)
}
