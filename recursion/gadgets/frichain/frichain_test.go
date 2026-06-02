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

package frichain_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/recursion/extfield"
	"github.com/consensys/loom/recursion/gadgets/frichain"
	"github.com/consensys/loom/recursion/gadgets/friround"
	"github.com/consensys/loom/recursion/gadgets/idxselect"
	"github.com/consensys/loom/recursion/internal/testutil"
	"github.com/consensys/loom/trace"
)

func randExt(t *testing.T) ext.E6 {
	t.Helper()
	var v ext.E6
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

// foldLayer reproduces native fri.foldLayerExt verbatim.
func foldLayer(layer []ext.E6, alpha ext.E6, domain *fft.Domain) []ext.E6 {
	half := len(layer) / 2
	out := make([]ext.E6, half)

	var two, invTwo koalabear.Element
	two.SetUint64(2)
	invTwo.Inverse(&two)

	var xInv koalabear.Element
	xInv.SetOne()

	for i := 0; i < half; i++ {
		p, q := layer[i], layer[i+half]
		var sum, diff ext.E6
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

// simulateFRI returns:
//   - layers: layers[j] is the round-j FRI layer (layer[0] = initial)
//   - omegasInv: omegasInv[j] = round-j domain generator inverse
//   - kBits: kBits[j] = bit count of base_j = log2(N_j/2)
func simulateFRI(initialLayer []ext.E6, alphas []ext.E6) (layers [][]ext.E6, omegasInv []koalabear.Element, kBits []int) {
	N := len(initialLayer)
	numRounds := len(alphas)

	layers = make([][]ext.E6, numRounds+1)
	omegasInv = make([]koalabear.Element, numRounds)
	kBits = make([]int, numRounds)

	layers[0] = initialLayer
	for j := 0; j < numRounds; j++ {
		Nj := N >> uint(j)
		domain := fft.NewDomain(uint64(Nj))
		omegasInv[j] = domain.GeneratorInv
		kBits[j] = log2(Nj / 2)
		layers[j+1] = foldLayer(layers[j], alphas[j], domain)
	}
	return
}

func log2(n int) int {
	k := 0
	for n > 1 {
		n >>= 1
		k++
	}
	return k
}

// TestEndToEndFRIQueryWithChain composes friround instances + frichain in a
// SINGLE module to verify a complete FRI traversal (commit phase replayed
// natively, fold equations + cross-round chaining checked in-circuit).
//
// Setup: N = 16, D = 4, numRounds = 2. Two queries in one module — alpha
// is now pinned constant across rows, so we need at least two real queries
// (padding rows with alpha=0 would break the pinning constraint).
func TestEndToEndFRIQueryWithChain(t *testing.T) {
	const N = 16
	const numRounds = 2
	queries := []int{5, 2}

	initialLayer := make([]ext.E6, N)
	for i := range initialLayer {
		initialLayer[i] = randExt(t)
	}
	alphas := make([]ext.E6, numRounds)
	for i := range alphas {
		alphas[i] = randExt(t)
	}
	layers, omegasInv, kBits := simulateFRI(initialLayer, alphas)

	capacity := len(queries)
	mod := board.NewModule("fri_query")
	mod.N = capacity

	groups := make([]friround.ColumnNames, numRounds)
	for j := 0; j < numRounds; j++ {
		prefix := nameForRound("r", j)
		groups[j] = friround.Register(&mod, prefix, omegasInv[j], kBits[j])
	}
	for j := 0; j+1 < numRounds; j++ {
		frichain.Link(&mod, groups[j], groups[j+1])
	}

	builder := board.NewBuilder()
	builder.AddModule(mod)

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
		cols := friround.GenerateTrace(groups[j], capacity, roundQueries)
		for k, v := range cols {
			tr.SetBase(k, v)
		}
	}

	testutil.ProveAndVerify(t, &builder, tr)
}

// TestEndToEndFRIQueryRejectsCorruptedRound tampers with round 1's P and Q
// limbs and confirms the chain catches the mismatch with round 0's
// expected.
func TestEndToEndFRIQueryRejectsCorruptedRound(t *testing.T) {
	const N = 16
	const numRounds = 2
	queries := []int{5, 2}

	initialLayer := make([]ext.E6, N)
	for i := range initialLayer {
		initialLayer[i] = randExt(t)
	}
	alphas := []ext.E6{randExt(t), randExt(t)}
	layers, omegasInv, kBits := simulateFRI(initialLayer, alphas)

	capacity := len(queries)
	mod := board.NewModule("fri_chain_corrupt")
	mod.N = capacity

	groups := make([]friround.ColumnNames, numRounds)
	for j := 0; j < numRounds; j++ {
		groups[j] = friround.Register(&mod, nameForRound("r", j), omegasInv[j], kBits[j])
	}
	for j := 0; j+1 < numRounds; j++ {
		frichain.Link(&mod, groups[j], groups[j+1])
	}
	builder := board.NewBuilder()
	builder.AddModule(mod)

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
		cols := friround.GenerateTrace(groups[j], capacity, roundQueries)
		for k, v := range cols {
			tr.SetBase(k, v)
		}
	}

	// Tamper round 1's P[0] and Q[0] at query 0 so the chain check fails
	// on whichever branch top_bit selects.
	var one koalabear.Element
	one.SetOne()
	pCol := tr.Base[groups[1].P[0]]
	pCol[0].Add(&pCol[0], &one)
	qCol := tr.Base[groups[1].Q[0]]
	qCol[0].Add(&qCol[0], &one)

	testutil.ExpectProveOrVerifyFailure(t, &builder, tr)
}

// TestEndToEndFRIQueryWithFinalPoly extends the previous test by also
// asserting that round-last's expected equals finalPoly[base_last] via the
// idxselect gadget. This closes the FRI verifier's final-round gap. Uses
// two real queries (no padding) so every row satisfies the chain.
func TestEndToEndFRIQueryWithFinalPoly(t *testing.T) {
	const N = 16
	const numRounds = 2
	queries := []int{5, 2} // two queries in [0, N/2 = 8)

	initialLayer := make([]ext.E6, N)
	for i := range initialLayer {
		initialLayer[i] = randExt(t)
	}
	alphas := []ext.E6{randExt(t), randExt(t)}
	layers, omegasInv, kBits := simulateFRI(initialLayer, alphas)

	finalPoly := layers[numRounds] // length = N / 2^numRounds = N/D = 4

	capacity := len(queries) // already a power of two

	mod := board.NewModule("fri_final")
	mod.N = capacity

	groups := make([]friround.ColumnNames, numRounds)
	for j := 0; j < numRounds; j++ {
		groups[j] = friround.Register(&mod, nameForRound("r", j), omegasInv[j], kBits[j])
	}
	for j := 0; j+1 < numRounds; j++ {
		frichain.Link(&mod, groups[j], groups[j+1])
	}

	// idxselect on finalPoly indexed by bits of base_{numRounds-1}.
	// kBits[numRounds-1] = log2(N/4) = 2, exactly log2(len(finalPoly)).
	lastGroup := groups[numRounds-1]
	selCN := idxselect.Register(&mod, "final.sel", finalPoly, lastGroup.Bits)

	// Constrain expected_{last} = idxselect.out
	for i := 0; i < extfield.Limbs; i++ {
		rel := expr.Col(lastGroup.Expected[i]).Sub(expr.Col(selCN.Out[i]))
		mod.AssertZero(rel)
	}

	builder := board.NewBuilder()
	builder.AddModule(mod)

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
		cols := friround.GenerateTrace(groups[j], capacity, roundQueries)
		for k, v := range cols {
			tr.SetBase(k, v)
		}
	}

	// idxselect trace: per-row index = s mod len(finalPoly).
	idxs := make([]uint64, len(queries))
	for qi, s := range queries {
		idxs[qi] = uint64(s % len(finalPoly))
	}
	idxCols := idxselect.GenerateTrace(selCN, capacity, finalPoly, idxs)
	for k, v := range idxCols {
		tr.SetBase(k, v)
	}

	testutil.ProveAndVerify(t, &builder, tr)
}

// nameForRound builds a column-prefix for the j-th round of a per-query
// module.
func nameForRound(base string, j int) string {
	return base + "_" + string('0'+rune(j))
}

// TestEndToEndMultiDegreeFRI exercises level-batching: a second-level
// polynomial of smaller degree is introduced at round 1 via the gamma-mix
// step. The chain constraint at round-0 -> round-1 uses LinkWithLevel
// instead of Link.
//
// Setup: N = 16, level_0 has D_0 = 4 (full degree, so layer_0 size = N),
// level_1 has D_1 = 2 (smaller; layer at round 1 size = N/2 = 8). Level 1
// enters at round j_1 = log2(D_0 / D_1) = 1.
//
// The verifier flow:
//
//	Round 0: fold layer_0 -> layer_1_unmixed
//	Level 1 enters: layer_1_mixed = layer_1_unmixed + gamma_1 * level_1
//	Round 1: fold layer_1_mixed -> layer_2 (= finalPoly, size 4)
func TestEndToEndMultiDegreeFRI(t *testing.T) {
	const N = 16
	const numRounds = 2
	queries := []int{5, 2}

	// Initial layer (level_0.evals) and level_1.evals.
	layer0 := make([]ext.E6, N)
	for i := range layer0 {
		layer0[i] = randExt(t)
	}
	level1Evals := make([]ext.E6, N/2)
	for i := range level1Evals {
		level1Evals[i] = randExt(t)
	}

	alphas := []ext.E6{randExt(t), randExt(t)}
	gamma1 := randExt(t)

	// Native commit phase:
	domain0 := fft.NewDomain(uint64(N))
	layer1Unmixed := foldLayer(layer0, alphas[0], domain0)
	// Mix: layer1 += gamma_1 * level_1.evals (pointwise).
	layer1Mixed := make([]ext.E6, len(layer1Unmixed))
	for i := range layer1Mixed {
		var term ext.E6
		term.Mul(&gamma1, &level1Evals[i])
		layer1Mixed[i].Add(&layer1Unmixed[i], &term)
	}
	domain1 := fft.NewDomain(uint64(N / 2))
	layer2 := foldLayer(layer1Mixed, alphas[1], domain1)
	finalPoly := layer2 // size N/D = 4

	omegasInv := []koalabear.Element{domain0.GeneratorInv, domain1.GeneratorInv}
	kBits := []int{log2(N / 2), log2(N / 4)} // {3, 2}

	// Build the verifier circuit.
	capacity := len(queries)
	mod := board.NewModule("fri_multi")
	mod.N = capacity

	groups := make([]friround.ColumnNames, numRounds)
	for j := 0; j < numRounds; j++ {
		groups[j] = friround.Register(&mod, nameForRound("r", j), omegasInv[j], kBits[j])
	}

	// Level 1 enters at round 1: use LinkWithLevel.
	ld := frichain.RegisterLevel(&mod, "level1")
	frichain.LinkWithLevel(&mod, groups[0], groups[1], ld)

	// Final-poly check at the last round.
	lastGroup := groups[numRounds-1]
	selCN := idxselect.Register(&mod, "final.sel", finalPoly, lastGroup.Bits)
	for i := 0; i < extfield.Limbs; i++ {
		rel := expr.Col(lastGroup.Expected[i]).Sub(expr.Col(selCN.Out[i]))
		mod.AssertZero(rel)
	}

	builder := board.NewBuilder()
	builder.AddModule(mod)

	// Fill the trace.
	tr := trace.New()

	// Round 0 trace: P, Q from layer_0; alpha_0; base = s mod (N/2) = s.
	r0Queries := make([]friround.Query, len(queries))
	for qi, s := range queries {
		base := s
		r0Queries[qi] = friround.Query{
			P:     layer0[base],
			Q:     layer0[base+N/2],
			Alpha: alphas[0],
			Base:  uint64(base),
		}
	}
	for k, v := range friround.GenerateTrace(groups[0], capacity, r0Queries) {
		tr.SetBase(k, v)
	}

	// Round 1 trace: P, Q from layer_1_MIXED; alpha_1; base = s mod (N/4).
	r1Queries := make([]friround.Query, len(queries))
	for qi, s := range queries {
		base := s % (N / 4)
		r1Queries[qi] = friround.Query{
			P:     layer1Mixed[base],
			Q:     layer1Mixed[base+N/4],
			Alpha: alphas[1],
			Base:  uint64(base),
		}
	}
	for k, v := range friround.GenerateTrace(groups[1], capacity, r1Queries) {
		tr.SetBase(k, v)
	}

	// Level 1 trace: gamma, leafP, leafQ at base_1 and base_1 + 4 of
	// level_1.evals (length 8).
	levelCols := make(map[string][]koalabear.Element, 3*extfield.Limbs)
	allocLevelCol := func(name string) []koalabear.Element {
		c := make([]koalabear.Element, capacity)
		levelCols[name] = c
		return c
	}
	gammaCols := [extfield.Limbs][]koalabear.Element{}
	leafPCols := [extfield.Limbs][]koalabear.Element{}
	leafQCols := [extfield.Limbs][]koalabear.Element{}
	for i := 0; i < extfield.Limbs; i++ {
		gammaCols[i] = allocLevelCol(ld.Gamma[i])
		leafPCols[i] = allocLevelCol(ld.LeafP[i])
		leafQCols[i] = allocLevelCol(ld.LeafQ[i])
	}
	gammaLimbs := extfield.FromE6(gamma1)
	for qi, s := range queries {
		base1 := s % (N / 4)
		leafP := extfield.FromE6(level1Evals[base1])
		leafQ := extfield.FromE6(level1Evals[base1+N/4])
		for i := 0; i < extfield.Limbs; i++ {
			gammaCols[i][qi].Set(&gammaLimbs[i])
			leafPCols[i][qi].Set(&leafP[i])
			leafQCols[i][qi].Set(&leafQ[i])
		}
	}
	for k, v := range levelCols {
		tr.SetBase(k, v)
	}

	// idxselect trace: index = s mod len(finalPoly) = s mod 4.
	idxs := make([]uint64, len(queries))
	for qi, s := range queries {
		idxs[qi] = uint64(s % len(finalPoly))
	}
	for k, v := range idxselect.GenerateTrace(selCN, capacity, finalPoly, idxs) {
		tr.SetBase(k, v)
	}

	testutil.ProveAndVerify(t, &builder, tr)
}

// TestEndToEndMultiDegreeFRIRejectsBadLevel tampers with the level-1 leaf
// value and confirms the gamma-mix chain catches the inconsistency.
func TestEndToEndMultiDegreeFRIRejectsBadLevel(t *testing.T) {
	const N = 16
	const numRounds = 2
	queries := []int{5, 2}

	layer0 := make([]ext.E6, N)
	for i := range layer0 {
		layer0[i] = randExt(t)
	}
	level1Evals := make([]ext.E6, N/2)
	for i := range level1Evals {
		level1Evals[i] = randExt(t)
	}
	alphas := []ext.E6{randExt(t), randExt(t)}
	gamma1 := randExt(t)

	domain0 := fft.NewDomain(uint64(N))
	layer1Unmixed := foldLayer(layer0, alphas[0], domain0)
	layer1Mixed := make([]ext.E6, len(layer1Unmixed))
	for i := range layer1Mixed {
		var term ext.E6
		term.Mul(&gamma1, &level1Evals[i])
		layer1Mixed[i].Add(&layer1Unmixed[i], &term)
	}
	domain1 := fft.NewDomain(uint64(N / 2))
	layer2 := foldLayer(layer1Mixed, alphas[1], domain1)
	finalPoly := layer2

	omegasInv := []koalabear.Element{domain0.GeneratorInv, domain1.GeneratorInv}
	kBits := []int{log2(N / 2), log2(N / 4)}

	capacity := len(queries)
	mod := board.NewModule("fri_multi_bad")
	mod.N = capacity

	groups := make([]friround.ColumnNames, numRounds)
	for j := 0; j < numRounds; j++ {
		groups[j] = friround.Register(&mod, nameForRound("r", j), omegasInv[j], kBits[j])
	}
	ld := frichain.RegisterLevel(&mod, "level1")
	frichain.LinkWithLevel(&mod, groups[0], groups[1], ld)

	lastGroup := groups[numRounds-1]
	selCN := idxselect.Register(&mod, "final.sel", finalPoly, lastGroup.Bits)
	for i := 0; i < extfield.Limbs; i++ {
		rel := expr.Col(lastGroup.Expected[i]).Sub(expr.Col(selCN.Out[i]))
		mod.AssertZero(rel)
	}

	builder := board.NewBuilder()
	builder.AddModule(mod)

	tr := trace.New()
	for j := 0; j < numRounds; j++ {
		Nj := N >> uint(j)
		roundQueries := make([]friround.Query, len(queries))
		for qi, s := range queries {
			base := s % (Nj / 2)
			var P, Q ext.E6
			if j == 0 {
				P = layer0[base]
				Q = layer0[base+Nj/2]
			} else {
				P = layer1Mixed[base]
				Q = layer1Mixed[base+Nj/2]
			}
			roundQueries[qi] = friround.Query{P: P, Q: Q, Alpha: alphas[j], Base: uint64(base)}
		}
		for k, v := range friround.GenerateTrace(groups[j], capacity, roundQueries) {
			tr.SetBase(k, v)
		}
	}

	// Level 1 trace.
	levelCols := make(map[string][]koalabear.Element, 3*extfield.Limbs)
	gammaLimbs := extfield.FromE6(gamma1)
	for i := 0; i < extfield.Limbs; i++ {
		levelCols[ld.Gamma[i]] = make([]koalabear.Element, capacity)
		levelCols[ld.LeafP[i]] = make([]koalabear.Element, capacity)
		levelCols[ld.LeafQ[i]] = make([]koalabear.Element, capacity)
	}
	for qi, s := range queries {
		base1 := s % (N / 4)
		leafP := extfield.FromE6(level1Evals[base1])
		leafQ := extfield.FromE6(level1Evals[base1+N/4])
		for i := 0; i < extfield.Limbs; i++ {
			levelCols[ld.Gamma[i]][qi].Set(&gammaLimbs[i])
			levelCols[ld.LeafP[i]][qi].Set(&leafP[i])
			levelCols[ld.LeafQ[i]][qi].Set(&leafQ[i])
		}
	}

	// Corrupt gamma_0 at query 0. gamma multiplies the leaf in BOTH
	// branches of the selector, so corruption breaks the chain regardless
	// of which branch top_bit selects.
	var one koalabear.Element
	one.SetOne()
	levelCols[ld.Gamma[0]][0].Add(&levelCols[ld.Gamma[0]][0], &one)

	for k, v := range levelCols {
		tr.SetBase(k, v)
	}

	idxs := make([]uint64, len(queries))
	for qi, s := range queries {
		idxs[qi] = uint64(s % len(finalPoly))
	}
	for k, v := range idxselect.GenerateTrace(selCN, capacity, finalPoly, idxs) {
		tr.SetBase(k, v)
	}

	testutil.ExpectProveOrVerifyFailure(t, &builder, tr)
}

