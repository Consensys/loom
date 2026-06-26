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

package merkle

import (
	"testing"

	"github.com/consensys/loom/internal/hash"
)

type testNodeHasher struct{}

func (testNodeHasher) HashNode(left, right hash.Digest) hash.Digest {
	var out hash.Digest
	l := left[0].Uint64()
	r := right[0].Uint64()
	out[0].SetUint64(1_000_003 + 131*l + 17*r)
	return out
}

func TestPreInjectionSiblingSingleInjection(t *testing.T) {
	nh := testNodeHasher{}
	injection := LevelInjection{
		LevelWidth: 4,
		LeafHashes: testDigests(4, 1_000),
	}
	tree, err := NewWithInjections(8, nh, []LevelInjection{injection})
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.Build(testDigests(8, 10)); err != nil {
		t.Fatal(err)
	}

	const leafIdx = 3
	proof, err := tree.OpenProof(leafIdx)
	if err != nil {
		t.Fatal(err)
	}

	depth := log2(tree.nLeaves / injection.LevelWidth)
	pathRow := leafIdx >> depth
	siblingRow := pathRow ^ 1
	runningSibling, err := tree.PreInjectionSibling(injection.LevelWidth, pathRow)
	if err != nil {
		t.Fatal(err)
	}

	gotPostSibling := proof.Siblings[depth]
	wantPostSibling := nh.HashNode(runningSibling, injection.LeafHashes[siblingRow])
	if gotPostSibling != wantPostSibling {
		t.Fatalf("post-injection sibling mismatch: got %v, want %v", gotPostSibling, wantPostSibling)
	}
	if proof.InjectionLeaves[0] != injection.LeafHashes[pathRow] {
		t.Fatalf("path injection leaf mismatch: got %v, want %v", proof.InjectionLeaves[0], injection.LeafHashes[pathRow])
	}
}

func TestPreInjectionSiblingMultipleInjectionsIncludesLowerInjections(t *testing.T) {
	nh := testNodeHasher{}
	injections := []LevelInjection{
		{
			LevelWidth: 4,
			LeafHashes: testDigests(4, 1_000),
		},
		{
			LevelWidth: 2,
			LeafHashes: testDigests(2, 2_000),
		},
	}
	tree, err := NewWithInjections(8, nh, injections)
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.Build(testDigests(8, 10)); err != nil {
		t.Fatal(err)
	}

	const leafIdx = 6
	proof, err := tree.OpenProof(leafIdx)
	if err != nil {
		t.Fatal(err)
	}

	depth := log2(tree.nLeaves / injections[1].LevelWidth)
	pathRow := leafIdx >> depth
	siblingRow := pathRow ^ 1
	runningSibling, err := tree.PreInjectionSibling(injections[1].LevelWidth, pathRow)
	if err != nil {
		t.Fatal(err)
	}

	gotPostSibling := proof.Siblings[depth]
	wantPostSibling := nh.HashNode(runningSibling, injections[1].LeafHashes[siblingRow])
	if gotPostSibling != wantPostSibling {
		t.Fatalf("post-injection sibling mismatch: got %v, want %v", gotPostSibling, wantPostSibling)
	}

	// The width-2 pre-injection node is computed from width-4 nodes after
	// the width-4 injection has already been folded in.
	width2Node := injections[1].LevelWidth + siblingRow
	wantRunningSibling := nh.HashNode(tree.nodes[2*width2Node], tree.nodes[2*width2Node+1])
	if runningSibling != wantRunningSibling {
		t.Fatalf("pre-injection sibling did not include lower injection: got %v, want %v", runningSibling, wantRunningSibling)
	}
}

func TestPreInjectionSiblingRejectsMissingLevel(t *testing.T) {
	nh := testNodeHasher{}
	tree, err := New(4, nh)
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.Build(testDigests(4, 10)); err != nil {
		t.Fatal(err)
	}
	if _, err := tree.PreInjectionSibling(2, 0); err == nil {
		t.Fatal("expected missing pre-injection level error")
	}
}

func testDigests(n int, offset uint64) []hash.Digest {
	res := make([]hash.Digest, n)
	for i := range res {
		res[i][0].SetUint64(offset + uint64(i))
	}
	return res
}
