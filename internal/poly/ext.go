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
	"fmt"
	"math/bits"
	"sync"

	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/loom/internal/parallel"
)

// ExtPolynomial is a polynomial whose coefficients/evaluations live in the
// Koalabear E4 extension field.
type ExtPolynomial = []ext.E4

var extEvalBufPool sync.Pool

func getExtBuf(n int) []ext.E4 {
	if v := extEvalBufPool.Get(); v != nil {
		if b := v.([]ext.E4); cap(b) >= n {
			return b[:n]
		}
	}
	return make([]ext.E4, n)
}

func putExtBuf(b []ext.E4) {
	extEvalBufPool.Put(b[:cap(b)])
}

// AddExt returns the pointwise sum P1 + P2.
func AddExt(P1, P2 ExtPolynomial) (ExtPolynomial, error) {
	if len(P1) != len(P2) {
		return nil, fmt.Errorf("AddExt: length mismatch %d != %d", len(P1), len(P2))
	}
	res := make(ExtPolynomial, len(P1))
	for i := range P1 {
		res[i].Add(&P1[i], &P2[i])
	}
	return res, nil
}

// SubExt returns the pointwise difference P1 - P2.
func SubExt(P1, P2 ExtPolynomial) (ExtPolynomial, error) {
	if len(P1) != len(P2) {
		return nil, fmt.Errorf("SubExt: length mismatch %d != %d", len(P1), len(P2))
	}
	res := make(ExtPolynomial, len(P1))
	for i := range P1 {
		res[i].Sub(&P1[i], &P2[i])
	}
	return res, nil
}

// MulExt returns the pointwise product P1 * P2.
func MulExt(P1, P2 ExtPolynomial) (ExtPolynomial, error) {
	if len(P1) != len(P2) {
		return nil, fmt.Errorf("MulExt: length mismatch %d != %d", len(P1), len(P2))
	}
	res := make(ExtPolynomial, len(P1))
	for i := range P1 {
		res[i].Mul(&P1[i], &P2[i])
	}
	return res, nil
}

// EvaluateAtExt evaluates a base-field polynomial p, stored in Lagrange normal
// form over d, at the extension-field point zeta. Base coefficients are lifted
// during Horner evaluation.
// EvaluateAtExt assumes len(p) is a power of two; behaviour is undefined otherwise.
// Optional fftOpts are forwarded to the internal FFT (e.g. fft.WithNbTasks(1)
// when EvaluateAtExt is itself called from inside a parallel.Execute loop).
func EvaluateAtExt(p Polynomial, d *fft.Domain, zeta ext.E4, fftOpts ...fft.Option) ext.E4 {
	n := len(p)
	if n == 1 {
		return liftBaseToExt(p[0])
	}
	_p := getBuf(n)
	copy(_p, p)
	nn := uint64(64 - bits.TrailingZeros64(uint64(n)))
	d.FFTInverse(_p, fft.DIF, fftOpts...)

	var res ext.E4
	for i := n - 1; i >= 0; i-- {
		iRev := bits.Reverse64(uint64(i)) >> nn
		coeff := liftBaseToExt(_p[iRev])
		res.Mul(&res, &zeta)
		// TODO(perf) use only the B0.A0 coord
		res.Add(&res, &coeff)
	}
	putBuf(_p)
	return res
}

// ExtEvaluateAtExt evaluates an extension-field polynomial p, stored in
// Lagrange normal form over d, at the extension-field point zeta.
func ExtEvaluateAtExt(p ExtPolynomial, d *fft.Domain, zeta ext.E4, fftOpts ...fft.Option) ext.E4 {
	n := len(p)
	if n == 1 {
		return p[0]
	}
	_p := getExtBuf(n)
	copy(_p, p)
	nn := uint64(64 - bits.TrailingZeros64(uint64(n)))
	d.FFTInverseExt(_p, fft.DIF, fftOpts...)

	var res ext.E4
	for i := n - 1; i >= 0; i-- {
		iRev := bits.Reverse64(uint64(i)) >> nn
		coeff := _p[iRev]
		res.Mul(&res, &zeta)
		res.Add(&res, &coeff)
	}
	putExtBuf(_p)
	return res
}

// BuildZPowBitReversed precomputes (zeta^bitRev(0), zeta^bitRev(1), …,
// zeta^bitRev(n-1)) so that the SIMD InnerProduct[ByElement] can replace
// the Horner loop in {Ext,}EvaluateAtExtWithZPow. The result is in
// bit-reversed-canonical order to match the post-DIF FFTInverse layout
// used by those functions.
//
// n must be a power of two. The work scales as O(n) ext-muls and is
// chunked across goroutines using PowUint64 to seed each chunk
// independently, so build cost amortises well when shared across tasks
// that evaluate at the same zeta.
func BuildZPowBitReversed(zeta ext.E4, n int) []ext.E4 {
	if n <= 0 {
		return nil
	}
	out := make([]ext.E4, n)
	if n == 1 {
		out[0].SetOne()
		return out
	}
	nn := uint64(64 - bits.TrailingZeros64(uint64(n)))

	// First sweep produces zeta^i in normal order using parallel chunks
	// seeded with PowUint64Ext (binary exponentiation for ext.E4).
	normal := make([]ext.E4, n)
	parallel.ExecuteWithThreshold(n, zetaPowParallelThreshold, func(start, end int) {
		acc := powUint64Ext(zeta, uint64(start))
		for i := start; i < end; i++ {
			normal[i].Set(&acc)
			acc.Mul(&acc, &zeta)
		}
	})

	// Permute into bit-reversed order.
	parallel.ExecuteWithThreshold(n, zetaPowParallelThreshold, func(start, end int) {
		for i := start; i < end; i++ {
			iRev := bits.Reverse64(uint64(i)) >> nn
			out[iRev] = normal[i]
		}
	})
	return out
}

const zetaPowParallelThreshold = 1 << 12

// powUint64Ext returns base^exp via binary exponentiation.
func powUint64Ext(base ext.E4, exp uint64) ext.E4 {
	var res ext.E4
	res.SetOne()
	b := base
	for exp != 0 {
		if exp&1 == 1 {
			res.Mul(&res, &b)
		}
		b.Mul(&b, &b)
		exp >>= 1
	}
	return res
}

// EvaluateAtExtWithZPow is EvaluateAtExt where the bit-reversed powers of
// zeta have been precomputed by the caller (typically once per (n, zeta)
// across many polynomials). Replaces the per-Horner ext-mul chain with a
// single SIMD InnerProductByElement on the FFTInverse output.
func EvaluateAtExtWithZPow(p Polynomial, d *fft.Domain, zPowBitRev []ext.E4, fftOpts ...fft.Option) ext.E4 {
	n := len(p)
	if n == 1 {
		return liftBaseToExt(p[0])
	}
	if len(zPowBitRev) != n {
		panic("EvaluateAtExtWithZPow: zPow length must equal len(p)")
	}
	_p := getBuf(n)
	copy(_p, p)
	d.FFTInverse(_p, fft.DIF, fftOpts...)
	res := ext.Vector(zPowBitRev).InnerProductByElement(koalabear.Vector(_p))
	putBuf(_p)
	return res
}

// ExtEvaluateAtExtWithZPow is the ext-rail counterpart of EvaluateAtExtWithZPow.
func ExtEvaluateAtExtWithZPow(p ExtPolynomial, d *fft.Domain, zPowBitRev []ext.E4, fftOpts ...fft.Option) ext.E4 {
	n := len(p)
	if n == 1 {
		return p[0]
	}
	if len(zPowBitRev) != n {
		panic("ExtEvaluateAtExtWithZPow: zPow length must equal len(p)")
	}
	_p := getExtBuf(n)
	copy(_p, p)
	d.FFTInverseExt(_p, fft.DIF, fftOpts...)
	res := ext.Vector(zPowBitRev).InnerProduct(ext.Vector(_p))
	putExtBuf(_p)
	return res
}

// DeepQuotientExt computes q(X) = (v - p(X)) / (z - X) for an extension-field
// polynomial p in Lagrange normal form over d. The domain points remain
// base-field roots of unity and are lifted into E4 for the denominator.
func DeepQuotientExt(p ExtPolynomial, v, z ext.E4, d *fft.Domain) ExtPolynomial {
	N := len(p)
	q := make(ExtPolynomial, N)
	var omegaJ koalabear.Element
	omegaJ.SetOne()
	omega := d.Generator
	for j := 0; j < N; j++ {
		var num, den ext.E4
		omegaJExt := liftBaseToExt(omegaJ)
		num.Sub(&v, &p[j])
		den.Sub(&z, &omegaJExt)
		den.Inverse(&den)
		q[j].Mul(&num, &den)
		omegaJ.Mul(&omegaJ, &omega)
	}
	return q
}

func liftBaseToExt(v koalabear.Element) ext.E4 {
	var res ext.E4
	res.Lift(&v)
	return res
}
