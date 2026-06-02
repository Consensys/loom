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

package friquery_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/recursion/gadgets/friquery"
	"github.com/consensys/loom/recursion/internal/testutil"
	"github.com/consensys/loom/trace"
)

func randomExt(t *testing.T) ext.E6 {
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

// foldLayer reproduces the native fri.foldLayerExt verbatim so the test is
// self-contained (no dependency on internal/fri).
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

// buildRounds simulates a FRI fold pipeline of numRounds rounds starting
// from initialLayer of size N, picks query position s in [0, N/2), and
// returns a friquery.Round slice that the gadget can consume directly.
func buildRounds(initialLayer []ext.E6, alphas []ext.E6, s int) []friquery.Round {
	N := len(initialLayer)
	numRounds := len(alphas)
	if N <= 0 || N&(N-1) != 0 {
		panic("buildRounds: N must be a power of two")
	}

	layer := initialLayer
	domain := fft.NewDomain(uint64(N))

	rounds := make([]friquery.Round, 0, numRounds)
	for j := 0; j < numRounds; j++ {
		nj := len(layer)
		base := s % (nj / 2)

		// Round-j data.
		var xInv koalabear.Element
		xInv.Exp(domain.GeneratorInv, big.NewInt(int64(base)))

		// Determine "bit" for THIS round — meaningful for rounds j >= 1 only.
		// bit_j = 1 iff (s mod N_j) >= N_j/2.
		bit := uint64(0)
		if (s%nj) >= nj/2 {
			bit = 1
		}

		rounds = append(rounds, friquery.Round{
			P:     layer[base],
			Q:     layer[base+nj/2],
			Alpha: alphas[j],
			XInv:  xInv,
			Bit:   bit,
		})

		// Fold to next layer.
		layer = foldLayer(layer, alphas[j], domain)
		// Half the domain for the next round.
		domain = fft.NewDomain(uint64(nj / 2))
	}

	return rounds
}

// TestFriQueryGadget runs a complete 2-round FRI traversal (N=16, D=4) and
// confirms the per-query gadget accepts it.
func TestFriQueryGadget(t *testing.T) {
	const N = 16
	const numRounds = 2
	const s = 5 // query position in [0, N/2)

	layer := make([]ext.E6, N)
	for i := range layer {
		layer[i] = randomExt(t)
	}
	alphas := []ext.E6{randomExt(t), randomExt(t)}

	rounds := buildRounds(layer, alphas, s)
	if len(rounds) != numRounds {
		t.Fatalf("expected %d rounds, got %d", numRounds, len(rounds))
	}

	builder := board.NewBuilder()
	cn := friquery.BuildModule(&builder, "fq", numRounds)
	cols := friquery.GenerateTrace(cn, numRounds, rounds)

	tr := trace.New()
	for k, v := range cols {
		tr.SetBase(k, v)
	}
	testutil.ProveAndVerify(t, &builder, tr)
}

// TestFriQueryGadgetDeepRecursion exercises a 4-round traversal (N=64, D=4).
func TestFriQueryGadgetDeepRecursion(t *testing.T) {
	const N = 64
	const numRounds = 4
	const s = 13

	layer := make([]ext.E6, N)
	for i := range layer {
		layer[i] = randomExt(t)
	}
	alphas := make([]ext.E6, numRounds)
	for i := range alphas {
		alphas[i] = randomExt(t)
	}

	rounds := buildRounds(layer, alphas, s)

	builder := board.NewBuilder()
	cn := friquery.BuildModule(&builder, "fq_deep", numRounds)
	cols := friquery.GenerateTrace(cn, numRounds, rounds)

	tr := trace.New()
	for k, v := range cols {
		tr.SetBase(k, v)
	}
	testutil.ProveAndVerify(t, &builder, tr)
}

// TestFriQueryGadgetRejectsBrokenChain corrupts the next-round's P (or Q,
// depending on the bit) and confirms the chain constraint catches it.
func TestFriQueryGadgetRejectsBrokenChain(t *testing.T) {
	const N = 16
	const numRounds = 2
	const s = 5

	layer := make([]ext.E6, N)
	for i := range layer {
		layer[i] = randomExt(t)
	}
	alphas := []ext.E6{randomExt(t), randomExt(t)}
	rounds := buildRounds(layer, alphas, s)

	builder := board.NewBuilder()
	cn := friquery.BuildModule(&builder, "fq_chain", numRounds)
	cols := friquery.GenerateTrace(cn, numRounds, rounds)

	// Corrupt the next-round's selected column. rounds[1].Bit determines
	// whether P or Q is the chain target.
	var target string
	if rounds[1].Bit == 0 {
		target = cn.P[0]
	} else {
		target = cn.Q[0]
	}
	col := cols[target]
	var one koalabear.Element
	one.SetOne()
	col[1].Add(&col[1], &one)

	tr := trace.New()
	for k, v := range cols {
		tr.SetBase(k, v)
	}
	testutil.ExpectProveOrVerifyFailure(t, &builder, tr)
}

// TestFriQueryGadgetRejectsNonBinaryBit checks the binary-bit constraint.
func TestFriQueryGadgetRejectsNonBinaryBit(t *testing.T) {
	const N = 16
	const numRounds = 2
	const s = 3

	layer := make([]ext.E6, N)
	for i := range layer {
		layer[i] = randomExt(t)
	}
	alphas := []ext.E6{randomExt(t), randomExt(t)}
	rounds := buildRounds(layer, alphas, s)

	builder := board.NewBuilder()
	cn := friquery.BuildModule(&builder, "fq_bit", numRounds)
	cols := friquery.GenerateTrace(cn, numRounds, rounds)

	cols[cn.Bit][1].SetUint64(7)

	tr := trace.New()
	for k, v := range cols {
		tr.SetBase(k, v)
	}
	testutil.ExpectProveOrVerifyFailure(t, &builder, tr)
}
