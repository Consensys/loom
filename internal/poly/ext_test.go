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

package poly

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/dag"
)

func e4FromU64(a0, a1, b0, b1 uint64) ext.E4 {
	var z ext.E4
	z.B0.A0.SetUint64(a0)
	z.B0.A1.SetUint64(a1)
	z.B1.A0.SetUint64(b0)
	z.B1.A1.SetUint64(b1)
	return z
}

func liftE4(v koalabear.Element) ext.E4 {
	var z ext.E4
	z.Lift(&v)
	return z
}

func canonicalEvalExt(coeffs []ext.E4, z ext.E4) ext.E4 {
	if len(coeffs) == 0 {
		return ext.E4{}
	}
	y := coeffs[len(coeffs)-1]
	for i := len(coeffs) - 2; i >= 0; i-- {
		y.Mul(&y, &z)
		y.Add(&y, &coeffs[i])
	}
	return y
}

func canonicalEvalBaseAtExt(coeffs []koalabear.Element, z ext.E4) ext.E4 {
	if len(coeffs) == 0 {
		return ext.E4{}
	}
	y := liftE4(coeffs[len(coeffs)-1])
	for i := len(coeffs) - 2; i >= 0; i-- {
		coeff := liftE4(coeffs[i])
		y.Mul(&y, &z)
		y.Add(&y, &coeff)
	}
	return y
}

func extCanonicalToLagrangeNormal(coeffs ExtPolynomial) ExtPolynomial {
	p := make(ExtPolynomial, len(coeffs))
	copy(p, coeffs)
	d := fft.NewDomain(uint64(len(p)))
	d.FFTExt(p, fft.DIF)
	fft.BitReverse(p)
	return p
}

func TestExtPointwiseArithmetic(t *testing.T) {
	p1 := ExtPolynomial{
		e4FromU64(1, 2, 3, 4),
		e4FromU64(5, 6, 7, 8),
	}
	p2 := ExtPolynomial{
		e4FromU64(9, 10, 11, 12),
		e4FromU64(13, 14, 15, 16),
	}

	sum, err := AddExt(p1, p2)
	if err != nil {
		t.Fatalf("AddExt failed: %v", err)
	}
	diff, err := SubExt(p1, p2)
	if err != nil {
		t.Fatalf("SubExt failed: %v", err)
	}
	product, err := MulExt(p1, p2)
	if err != nil {
		t.Fatalf("MulExt failed: %v", err)
	}

	for i := range p1 {
		var want ext.E4
		want.Add(&p1[i], &p2[i])
		if !sum[i].Equal(&want) {
			t.Fatalf("AddExt[%d] = %s, want %s", i, sum[i].String(), want.String())
		}
		want.Sub(&p1[i], &p2[i])
		if !diff[i].Equal(&want) {
			t.Fatalf("SubExt[%d] = %s, want %s", i, diff[i].String(), want.String())
		}
		want.Mul(&p1[i], &p2[i])
		if !product[i].Equal(&want) {
			t.Fatalf("MulExt[%d] = %s, want %s", i, product[i].String(), want.String())
		}
	}

	if _, err := AddExt(p1, p2[:1]); err == nil {
		t.Fatal("expected AddExt length mismatch error")
	}
}

func TestEvaluateAtExt(t *testing.T) {
	p := makeLagrangePoly(3, 5, 7, 11)
	d := fft.NewDomain(uint64(len(p)))
	zeta := e4FromU64(2, 3, 5, 7)

	got := EvaluateAtExt(p, d, zeta)

	coeffs := make(Polynomial, len(p))
	copy(coeffs, p)
	lagrangeNormalToCanonical(coeffs)
	want := canonicalEvalBaseAtExt(coeffs, zeta)
	if !got.Equal(&want) {
		t.Fatalf("EvaluateAtExt = %s, want %s", got.String(), want.String())
	}
}

func TestExtEvaluateAtExt(t *testing.T) {
	coeffs := ExtPolynomial{
		e4FromU64(1, 2, 3, 4),
		e4FromU64(5, 6, 7, 8),
		e4FromU64(9, 10, 11, 12),
		e4FromU64(13, 14, 15, 16),
	}
	p := extCanonicalToLagrangeNormal(coeffs)
	d := fft.NewDomain(uint64(len(p)))
	zeta := e4FromU64(2, 3, 5, 7)

	got := ExtEvaluateAtExt(p, d, zeta)
	want := canonicalEvalExt(coeffs, zeta)
	if !got.Equal(&want) {
		t.Fatalf("ExtEvaluateAtExt = %s, want %s", got.String(), want.String())
	}
}

func TestDeepQuotientExt(t *testing.T) {
	coeffs := ExtPolynomial{
		e4FromU64(1, 2, 3, 4),
		e4FromU64(5, 6, 7, 8),
		e4FromU64(9, 10, 11, 12),
		e4FromU64(13, 14, 15, 16),
	}
	p := extCanonicalToLagrangeNormal(coeffs)
	d := fft.NewDomain(uint64(len(p)))
	zeta := e4FromU64(2, 3, 5, 7)
	v := ExtEvaluateAtExt(p, d, zeta)

	q := DeepQuotientExt(p, v, zeta, d)

	omega := d.Generator
	var omegaJ koalabear.Element
	omegaJ.SetOne()
	for j := range p {
		omegaJExt := liftE4(omegaJ)
		var den, lhs ext.E4
		den.Sub(&zeta, &omegaJExt)
		lhs.Mul(&q[j], &den)
		lhs.Add(&lhs, &p[j])
		if !lhs.Equal(&v) {
			t.Fatalf("row %d: quotient identity gives %s, want %s", j, lhs.String(), v.String())
		}
		omegaJ.Mul(&omegaJ, &omega)
	}
}

func TestComputeQuotientMixed(t *testing.T) {
	const size = 4

	f := makeLagrangePoly(2, 4, 6, 8)
	eta := e4FromU64(3, 1, 4, 1)
	h := make(ExtPolynomial, size)
	for i := range size {
		h[i] = liftE4(f[i])
		if i%2 == 1 {
			h[i].Add(&h[i], &eta)
		}
	}

	diff := expr.ExtCol("h").Sub(expr.Col("f"))
	relation := diff.Mul(diff.Sub(expr.Challenge("eta")))
	relationDAG := dag.ExprToDAG(relation)

	PiBase := map[string]Polynomial{"f": f}
	PiExt := map[string]ExtPolynomial{
		"h":   h,
		"eta": {eta},
	}
	Q, err := ComputeQuotientMixed(PiBase, PiExt, *relationDAG, size)
	if err != nil {
		t.Fatal(err)
	}

	x := e4FromU64(5, 7, 11, 13)
	domain := fft.NewDomain(size)
	valuesAtX := map[string]ext.E4{
		"f":   EvaluateAtExt(f, domain, x),
		"h":   ExtEvaluateAtExt(h, domain, x),
		"eta": eta,
	}
	numeratorAtX := relationDAG.EvalMixed(nil, valuesAtX)

	qCopy := make(ExtPolynomial, len(Q))
	copy(qCopy, Q)
	CosetExtLagrangeToLagrangeNormal(qCopy)
	qAtX := ExtEvaluateAtExt(qCopy, fft.NewDomain(uint64(len(qCopy))), x)

	var xN, one, xNMinusOne, rhs ext.E4
	one.SetOne()
	xN.Exp(x, big.NewInt(size))
	xNMinusOne.Sub(&xN, &one)
	rhs.Mul(&qAtX, &xNMinusOne)

	if !numeratorAtX.Equal(&rhs) {
		t.Fatalf("quotient identity failed: E(Pi(x)) = %s, Q(x)*(x^N-1) = %s", numeratorAtX.String(), rhs.String())
	}
}
