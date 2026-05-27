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

// foldLayer reproduces native fri.foldLayerExt verbatim.
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

// simulateFRI returns:
//   - layers: layers[j] is the round-j FRI layer (layer[0] = initial)
//   - omegasInv: omegasInv[j] = round-j domain generator inverse
//   - kBits: kBits[j] = bit count of base_j = log2(N_j/2)
func simulateFRI(initialLayer []ext.E4, alphas []ext.E4) (layers [][]ext.E4, omegasInv []koalabear.Element, kBits []int) {
	N := len(initialLayer)
	numRounds := len(alphas)

	layers = make([][]ext.E4, numRounds+1)
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
// Setup: N = 16, D = 4, numRounds = 2. One query at position s.
func TestEndToEndFRIQueryWithChain(t *testing.T) {
	const N = 16
	const numRounds = 2
	const s = 5 // query position in [0, N/2 = 8)

	// 1. Build a native FRI traversal so we know each round's (P, Q, alpha)
	// at the query position.
	initialLayer := make([]ext.E4, N)
	for i := range initialLayer {
		initialLayer[i] = randExt(t)
	}
	alphas := make([]ext.E4, numRounds)
	for i := range alphas {
		alphas[i] = randExt(t)
	}
	layers, omegasInv, kBits := simulateFRI(initialLayer, alphas)

	// 2. Build the verifier circuit: one module with numRounds friround
	// groups + frichain links between them.
	const capacity = 2 // 1 query padded to N=2
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

	// 3. Fill the trace.
	tr := trace.New()

	for j := 0; j < numRounds; j++ {
		Nj := N >> uint(j)
		base := s % (Nj / 2)

		query := friround.Query{
			P:     layers[j][base],
			Q:     layers[j][base+Nj/2],
			Alpha: alphas[j],
			Base:  uint64(base),
		}
		// Pad row uses base=0 / zero values.
		queries := []friround.Query{query}
		cols := friround.GenerateTrace(groups[j], capacity, queries)
		for k, v := range cols {
			tr.SetBase(k, v)
		}
	}

	testutil.ProveAndVerify(t, &builder, tr)
}

// TestEndToEndFRIQueryRejectsCorruptedRound tampers with round 0's expected
// limb and confirms the chain catches the mismatch with round 1's P/Q.
func TestEndToEndFRIQueryRejectsCorruptedRound(t *testing.T) {
	const N = 16
	const numRounds = 2
	const s = 5

	initialLayer := make([]ext.E4, N)
	for i := range initialLayer {
		initialLayer[i] = randExt(t)
	}
	alphas := []ext.E4{randExt(t), randExt(t)}
	layers, omegasInv, kBits := simulateFRI(initialLayer, alphas)

	const capacity = 2
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
		base := s % (Nj / 2)
		queries := []friround.Query{{
			P:     layers[j][base],
			Q:     layers[j][base+Nj/2],
			Alpha: alphas[j],
			Base:  uint64(base),
		}}
		cols := friround.GenerateTrace(groups[j], capacity, queries)
		for k, v := range cols {
			tr.SetBase(k, v)
		}
	}

	// Tamper round 1's P[0] limb so the chain check from round 0's expected
	// to round 1's selected fails.
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

	initialLayer := make([]ext.E4, N)
	for i := range initialLayer {
		initialLayer[i] = randExt(t)
	}
	alphas := []ext.E4{randExt(t), randExt(t)}
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

