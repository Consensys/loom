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

func TestVerifyWithInjectionsSingleInjection(t *testing.T) {
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

	pathRow := leafIdx >> log2(tree.nLeaves/injection.LevelWidth)
	if proof.InjectionLeaves[0] != injection.LeafHashes[pathRow] {
		t.Fatalf("path injection leaf mismatch: got %v, want %v", proof.InjectionLeaves[0], injection.LeafHashes[pathRow])
	}
	if !VerifyWithInjections(tree.Root(), proof, testDigests(8, 10)[leafIdx], []int{injection.LevelWidth}, nh) {
		t.Fatal("VerifyWithInjections rejected a valid proof")
	}

	badProof := proof
	badProof.InjectionLeaves = append([]hash.Digest{}, proof.InjectionLeaves...)
	badProof.InjectionLeaves[0][0].SetUint64(0xdeadbeef)
	if VerifyWithInjections(tree.Root(), badProof, testDigests(8, 10)[leafIdx], []int{injection.LevelWidth}, nh) {
		t.Fatal("VerifyWithInjections accepted a tampered injection leaf")
	}
}

func TestVerifyWithInjectionsMultipleInjections(t *testing.T) {
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

	if len(proof.InjectionLeaves) != len(injections) {
		t.Fatalf("InjectionLeaves length = %d, want %d", len(proof.InjectionLeaves), len(injections))
	}
	for k, injection := range injections {
		pathRow := leafIdx >> log2(tree.nLeaves/injection.LevelWidth)
		if proof.InjectionLeaves[k] != injection.LeafHashes[pathRow] {
			t.Fatalf("injection %d leaf mismatch: got %v, want %v", k, proof.InjectionLeaves[k], injection.LeafHashes[pathRow])
		}
	}
	if !VerifyWithInjections(tree.Root(), proof, testDigests(8, 10)[leafIdx], []int{4, 2}, nh) {
		t.Fatal("VerifyWithInjections rejected a valid multi-injection proof")
	}
}

func testDigests(n int, offset uint64) []hash.Digest {
	res := make([]hash.Digest, n)
	for i := range res {
		res[i][0].SetUint64(offset + uint64(i))
	}
	return res
}
