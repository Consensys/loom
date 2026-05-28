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

package recursion_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/internal/commitment"
	internalmerkle "github.com/consensys/loom/internal/merkle"
	"github.com/consensys/loom/recursion/extfield"
	"github.com/consensys/loom/recursion/gadgets/frichain"
	"github.com/consensys/loom/recursion/gadgets/friround"
	"github.com/consensys/loom/recursion/gadgets/idxselect"
	"github.com/consensys/loom/recursion/gadgets/merkle"
	"github.com/consensys/loom/recursion/internal/testutil"
	"github.com/consensys/loom/trace"

	"github.com/consensys/loom/expr"
)

// foldLayer reproduces native fri.foldLayerExt for an ext-rail layer.
func foldLayer(layer []ext.E4, alpha ext.E4, domain *fft.Domain) []ext.E4 {
	half := len(layer) / 2
	out := make([]ext.E4, half)

	var two, invTwo koalabear.Element
	two.SetUint64(2)
	invTwo.Inverse(&two)

	var xInv koalabear.Element
	xInv.SetOne()

	for i := 0; i < half; i++ {
		p, q := layer[i], layer[i+half]
		var sum, diff ext.E4
		sum.Add(&p, &q)
		sum.MulByElement(&sum, &invTwo)
		diff.Sub(&p, &q)
		diff.MulByElement(&diff, &invTwo)
		diff.MulByElement(&diff, &xInv)
		diff.Mul(&diff, &alpha)
		out[i].Add(&sum, &diff)
		xInv.Mul(&xInv, &domain.GeneratorInv)
	}
	return out
}

func log2(n int) int {
	k := 0
	for n > 1 {
		n >>= 1
		k++
	}
	return k
}

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

// makeLayerMerkleTree builds a Merkle tree over the paired-leaf encoding
// of one FRI layer. Each leaf at position i pairs (layer[i], layer[i +
// N/2]) and is hashed via Poseidon2LeafHasher.
func makeLayerMerkleTree(t *testing.T, layer []ext.E4) (*internalmerkle.Tree, []internalmerkle.Proof, []commitment.PairExt) {
	t.Helper()
	half := len(layer) / 2

	lh := commitment.Poseidon2LeafHasher{}
	nh := commitment.Poseidon2NodeHasher{}

	pairs := make([]commitment.PairExt, half)
	digests := make([]internalmerkle.LeafHash, half)
	for i := 0; i < half; i++ {
		pairs[i] = commitment.PairExt{layer[i], layer[i+half]}
		digests[i] = lh.HashLeaf(nil, []commitment.PairExt{pairs[i]})
	}

	tree, err := internalmerkle.New(half, nh)
	if err != nil {
		t.Fatalf("merkle.New: %v", err)
	}
	if err := tree.Build(digests); err != nil {
		t.Fatalf("tree.Build: %v", err)
	}

	proofs := make([]internalmerkle.Proof, half)
	for i := 0; i < half; i++ {
		p, err := tree.OpenProof(i)
		if err != nil {
			t.Fatalf("tree.OpenProof: %v", err)
		}
		proofs[i] = p
	}

	return tree, proofs, pairs
}

// TestEndToEndFRIVerifierWithMerkleBinding integrates friround + frichain
// + merkle + idxselect in one verifier program to check an entire
// single-query FRI traversal: fold equations, cross-round chaining,
// final-poly match, per-layer Merkle path verification of the
// (LeafP, LeafQ) openings against committed roots, AND a cross-module
// binding via exposed values that links friround's row-0 (P, Q) to the
// matching merkle module's row-0 (LeafP, LeafQ).
//
// Setup: N = 16, D = 4, numRounds = 2, NumQueries = 4 (chosen so all
// modules share the same N: fri_verify = 4, layer-0 merkle = 4
// (depth 3 padded to 4), layer-1 merkle = 4 (depth 2 padded to 4)).
// Same N is required because Loom's exposed values reconstruct their
// value at zeta using each consuming module's N — sharing only works
// when all consumers agree.
func TestEndToEndFRIVerifierWithMerkleBinding(t *testing.T) {
	const N = 16
	const numRounds = 2
	queries := []int{5, 2, 3, 6}
	const universalN = 4 // shared by fri_verify and every merkle layer

	initialLayer := make([]ext.E4, N)
	for i := range initialLayer {
		initialLayer[i] = randExt(t)
	}
	alphas := []ext.E4{randExt(t), randExt(t)}

	// Native FRI commit phase: fold layer_0 -> layer_1 -> layer_2.
	layers := [][]ext.E4{initialLayer}
	domains := []*fft.Domain{fft.NewDomain(uint64(N))}
	for j := 0; j < numRounds; j++ {
		nextLayer := foldLayer(layers[j], alphas[j], domains[j])
		layers = append(layers, nextLayer)
		domains = append(domains, fft.NewDomain(uint64(len(nextLayer))))
	}
	finalPoly := layers[numRounds] // size N/D = 4

	omegasInv := []koalabear.Element{domains[0].GeneratorInv, domains[1].GeneratorInv}
	kBits := []int{log2(N / 2), log2(N / 4)} // {3, 2}

	// Build per-layer Merkle trees for the FRI openings.
	trees := make([]*internalmerkle.Tree, numRounds)
	pairs := make([][]commitment.PairExt, numRounds)
	proofs := make([][]internalmerkle.Proof, numRounds)
	for j := 0; j < numRounds; j++ {
		trees[j], proofs[j], pairs[j] = makeLayerMerkleTree(t, layers[j])
	}
	_ = trees // roots would feed into public inputs in a real verifier

	// ── Build the in-circuit verifier ────────────────────────────────
	builder := board.NewBuilder()

	// (1) FRI verifier module: friround for each layer + frichain.Link +
	// idxselect for the final-poly check.
	capacity := len(queries)
	friMod := board.NewModule("fri_verify")
	friMod.N = capacity

	friGroups := make([]friround.ColumnNames, numRounds)
	for j := 0; j < numRounds; j++ {
		friGroups[j] = friround.Register(&friMod, friRoundPrefix(j), omegasInv[j], kBits[j])
	}
	for j := 0; j+1 < numRounds; j++ {
		frichain.Link(&friMod, friGroups[j], friGroups[j+1])
	}

	// Final-poly check at the last round.
	lastGroup := friGroups[numRounds-1]
	selCN := idxselect.Register(&friMod, "final.sel", finalPoly, lastGroup.Bits)
	for i := 0; i < extfield.Limbs; i++ {
		rel := expr.Col(lastGroup.Expected[i]).Sub(expr.Col(selCN.Out[i]))
		friMod.AssertZero(rel)
	}

	builder.AddModule(friMod)

	// (2) Cross-module binding: expose friround[j]'s query-0 (P, Q) so
	// the matching merkle module's row-0 (LeafP, LeafQ) can be
	// constrained against them. Without this binding the trace generator
	// is trusted to fill the two modules consistently; with it, a
	// malicious prover that diverges between friround and merkle is
	// caught either inside friround (its own AssertEqualAt against the
	// exposed value), or inside merkle (its AssertEqualAt against the
	// same exposed value).
	for j := 0; j < numRounds; j++ {
		for i := 0; i < extfield.Limbs; i++ {
			builder.AddExposeIthValueStep("fri_verify", expr.Col(friGroups[j].P[i]), exposeName("P", j, i), 0)
			builder.AddExposeIthValueStep("fri_verify", expr.Col(friGroups[j].Q[i]), exposeName("Q", j, i), 0)
		}
	}

	// (3) Per-layer Merkle modules — one per FRI round. All modules use
	// the same N (universalN) so the cross-module exposed values
	// reconstruct identically at zeta.
	merkleCNs := make([]merkle.ColumnNames, numRounds)
	for j := 0; j < numRounds; j++ {
		merkleCNs[j] = merkle.BuildModule(&builder, merkleModName(j), universalN)

		merkleMod := builder.Modules[merkleModName(j)]
		for i := 0; i < extfield.Limbs; i++ {
			merkleMod.AssertEqualAt(expr.Col(merkleCNs[j].LeafP[i]), expr.Exposed(exposeName("P", j, i)), 0)
			merkleMod.AssertEqualAt(expr.Col(merkleCNs[j].LeafQ[i]), expr.Exposed(exposeName("Q", j, i)), 0)
		}
	}

	// ── Fill the trace ───────────────────────────────────────────────
	tr := trace.New()

	// FRI verifier trace.
	for j := 0; j < numRounds; j++ {
		Nj := N >> uint(j)
		roundQueries := make([]friround.Query, len(queries))
		for qi, s := range queries {
			base := s % (Nj / 2)
			roundQueries[qi] = friround.Query{
				P:     layers[j][base],
				Q:     layers[j][base+Nj/2],
				Alpha: alphas[j],
				Base:  uint64(base),
			}
		}
		for k, v := range friround.GenerateTrace(friGroups[j], capacity, roundQueries) {
			tr.SetBase(k, v)
		}
	}

	idxs := make([]uint64, len(queries))
	for qi, s := range queries {
		idxs[qi] = uint64(s % len(finalPoly))
	}
	for k, v := range idxselect.GenerateTrace(selCN, capacity, finalPoly, idxs) {
		tr.SetBase(k, v)
	}

	// Per-layer Merkle trace — one path per layer for query[0]. We pass
	// universalN as the capacity so the trace generator pads short paths
	// (layer 1, real depth 2) up to N=4.
	for j := 0; j < numRounds; j++ {
		Nj := N >> uint(j)
		base := queries[0] % (Nj / 2)
		path := merkle.Path{
			LeafP:    pairs[j][base][0],
			LeafQ:    pairs[j][base][1],
			LeafIdx:  base,
			Siblings: proofs[j][base].Siblings,
		}
		for k, v := range merkle.GenerateTrace(merkleCNs[j], universalN, path) {
			tr.SetBase(k, v)
		}
	}

	testutil.ProveAndVerify(t, &builder, tr)

	// Confirm that each merkle module's last REAL step (= row siblingsLen-1)
	// holds the layer's committed root. In a real verifier the
	// VerificationKey holds these roots as public inputs, and the merkle
	// gadget's last-step parent would be constrained against them.
	for j := 0; j < numRounds; j++ {
		root := trees[j].Root()
		Nj := N >> uint(j)
		base := queries[0] % (Nj / 2)
		siblingsLen := len(proofs[j][base].Siblings)
		lastRealRow := siblingsLen - 1
		for i := 0; i < merkle.DigestWidth; i++ {
			col := tr.Base[merkleCNs[j].Parent[i]]
			got := col[lastRealRow]
			if !got.Equal(&root[i]) {
				t.Fatalf("layer %d parent[%d] at row %d = %s, want %s",
					j, i, lastRealRow, got.String(), root[i].String())
			}
		}
	}
}

func friRoundPrefix(j int) string { return "r_" + string('0'+rune(j)) }
func merkleModName(j int) string  { return "merkle_layer_" + string('0'+rune(j)) }

// exposeName forms the exposed-value identifier shared between friround
// (row-0 P/Q at layer j) and merkle layer j (row-0 LeafP/LeafQ).
func exposeName(which string, layer, limb int) string {
	return "fri_layer_" + string('0'+rune(layer)) + "_q0_" + which + "_" + string('0'+rune(limb))
}

// TestEndToEndFRIVerifierRejectsCrossModuleMismatch confirms the cross-
// module binding is sound: tampering with merkle's LeafP[0] at row 0
// breaks the AssertEqualAt constraint against the exposed value (which
// the prover step seeded from friround's row-0 P_0).
func TestEndToEndFRIVerifierRejectsCrossModuleMismatch(t *testing.T) {
	const N = 16
	const numRounds = 2
	queries := []int{5, 2, 3, 6}
	const universalN = 4

	initialLayer := make([]ext.E4, N)
	for i := range initialLayer {
		initialLayer[i] = randExt(t)
	}
	alphas := []ext.E4{randExt(t), randExt(t)}

	layers := [][]ext.E4{initialLayer}
	domains := []*fft.Domain{fft.NewDomain(uint64(N))}
	for j := 0; j < numRounds; j++ {
		nextLayer := foldLayer(layers[j], alphas[j], domains[j])
		layers = append(layers, nextLayer)
		domains = append(domains, fft.NewDomain(uint64(len(nextLayer))))
	}
	finalPoly := layers[numRounds]

	omegasInv := []koalabear.Element{domains[0].GeneratorInv, domains[1].GeneratorInv}
	kBits := []int{log2(N / 2), log2(N / 4)}

	trees := make([]*internalmerkle.Tree, numRounds)
	pairs := make([][]commitment.PairExt, numRounds)
	proofs := make([][]internalmerkle.Proof, numRounds)
	for j := 0; j < numRounds; j++ {
		trees[j], proofs[j], pairs[j] = makeLayerMerkleTree(t, layers[j])
	}
	_ = trees

	builder := board.NewBuilder()

	friMod := board.NewModule("fri_verify")
	friMod.N = universalN
	friGroups := make([]friround.ColumnNames, numRounds)
	for j := 0; j < numRounds; j++ {
		friGroups[j] = friround.Register(&friMod, friRoundPrefix(j), omegasInv[j], kBits[j])
	}
	for j := 0; j+1 < numRounds; j++ {
		frichain.Link(&friMod, friGroups[j], friGroups[j+1])
	}
	lastGroup := friGroups[numRounds-1]
	selCN := idxselect.Register(&friMod, "final.sel", finalPoly, lastGroup.Bits)
	for i := 0; i < extfield.Limbs; i++ {
		rel := expr.Col(lastGroup.Expected[i]).Sub(expr.Col(selCN.Out[i]))
		friMod.AssertZero(rel)
	}
	builder.AddModule(friMod)

	for j := 0; j < numRounds; j++ {
		for i := 0; i < extfield.Limbs; i++ {
			builder.AddExposeIthValueStep("fri_verify", expr.Col(friGroups[j].P[i]), exposeName("P", j, i), 0)
			builder.AddExposeIthValueStep("fri_verify", expr.Col(friGroups[j].Q[i]), exposeName("Q", j, i), 0)
		}
	}

	merkleCNs := make([]merkle.ColumnNames, numRounds)
	for j := 0; j < numRounds; j++ {
		merkleCNs[j] = merkle.BuildModule(&builder, merkleModName(j), universalN)

		merkleMod := builder.Modules[merkleModName(j)]
		for i := 0; i < extfield.Limbs; i++ {
			merkleMod.AssertEqualAt(expr.Col(merkleCNs[j].LeafP[i]), expr.Exposed(exposeName("P", j, i)), 0)
			merkleMod.AssertEqualAt(expr.Col(merkleCNs[j].LeafQ[i]), expr.Exposed(exposeName("Q", j, i)), 0)
		}
	}

	tr := trace.New()
	for j := 0; j < numRounds; j++ {
		Nj := N >> uint(j)
		roundQueries := make([]friround.Query, len(queries))
		for qi, s := range queries {
			base := s % (Nj / 2)
			roundQueries[qi] = friround.Query{
				P:     layers[j][base],
				Q:     layers[j][base+Nj/2],
				Alpha: alphas[j],
				Base:  uint64(base),
			}
		}
		for k, v := range friround.GenerateTrace(friGroups[j], universalN, roundQueries) {
			tr.SetBase(k, v)
		}
	}
	idxs := make([]uint64, len(queries))
	for qi, s := range queries {
		idxs[qi] = uint64(s % len(finalPoly))
	}
	for k, v := range idxselect.GenerateTrace(selCN, universalN, finalPoly, idxs) {
		tr.SetBase(k, v)
	}
	for j := 0; j < numRounds; j++ {
		Nj := N >> uint(j)
		base := queries[0] % (Nj / 2)
		path := merkle.Path{
			LeafP:    pairs[j][base][0],
			LeafQ:    pairs[j][base][1],
			LeafIdx:  base,
			Siblings: proofs[j][base].Siblings,
		}
		for k, v := range merkle.GenerateTrace(merkleCNs[j], universalN, path) {
			tr.SetBase(k, v)
		}
	}

	// Tamper merkle layer 0's LeafP[0] at row 0. friround's P_0 at row 0
	// is still honest (= the original opening), so the exposed value
	// (seeded by the prover step from friround) is honest. The merkle
	// gadget's AssertEqualAt(LeafP[0], Exposed(...), 0) now fails because
	// the in-circuit LeafP[0] differs from the exposed value.
	col := tr.Base[merkleCNs[0].LeafP[0]]
	var one koalabear.Element
	one.SetOne()
	col[0].Add(&col[0], &one)

	testutil.ExpectProveOrVerifyFailure(t, &builder, tr)
}
