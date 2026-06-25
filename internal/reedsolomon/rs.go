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

package reedsolomon

import (
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/gnark-crypto/utils"
	"github.com/consensys/loom/internal/poly"
)

type Config struct {
	Cache *poly.DomainCache
}

type EncoderOption func(c *Config)

func WithCache(cache *poly.DomainCache) EncoderOption {
	return func(c *Config) {
		c.Cache = cache
	}
}

func NewEncoder(N uint64, opts ...EncoderOption) Encoder {
	var config Config
	for _, opt := range opts {
		opt(&config)
	}
	return Encoder{Domain: config.Cache.Get(N)}
}

type Encoder struct {
	Domain *fft.Domain
}

// RSEncode evaluates p on the N-th roots of unity (N must be > len(p)).
// p is in Lagrange form
// it returns a copy of p in bit-reversed evaluation order.
// Optional fftOpts are forwarded to both internal FFTs (e.g. to cap inner
// parallelism with fft.WithNbTasks when Encode is itself called inside a
// parallel.Execute loop).
func (encoder *Encoder) Encode(p poly.Polynomial, d *fft.Domain, fftOpts ...fft.Option) poly.Polynomial {

	// get the size of p
	n := len(p)

	// create _p, a copy of p of size N (zero-padded)
	N := encoder.Domain.Cardinality
	_p := make(poly.Polynomial, N)
	copy(_p, p)

	// Lagrange normal to canonical normal, then canonical normal to
	// bit-reversed evaluations on the larger domain.
	d.FFTInverse(_p[:n], fft.DIF, fftOpts...)
	utils.BitReverse(_p[:n])
	encoder.Domain.FFT(_p, fft.DIF, fftOpts...)

	// return _p
	return _p
}

// EncodeExt evaluates an extension-field polynomial on the encoder domain.
// The input p is in Lagrange normal form over d; the output is a fresh
// extension polynomial in bit-reversed Lagrange form over encoder.Domain.
func (encoder *Encoder) EncodeExt(p poly.ExtPolynomial, d *fft.Domain, fftOpts ...fft.Option) poly.ExtPolynomial {
	n := len(p)

	N := encoder.Domain.Cardinality
	_p := make(poly.ExtPolynomial, N)
	copy(_p, p)

	d.FFTInverseExt6(_p[:n], fft.DIF, fftOpts...)
	utils.BitReverse(_p[:n])
	encoder.Domain.FFTExt6(_p, fft.DIF, fftOpts...)

	return _p
}
