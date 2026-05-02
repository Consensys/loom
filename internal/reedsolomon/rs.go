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

func NewEncoder(N uint64) Encoder {
	domain := fft.NewDomain(N)
	return Encoder{
		Domain: domain,
	}
}

type Encoder struct {
	Domain *fft.Domain
}

// RSEncode evalutes p on the N-th roots of unity (N must be > len(p))
// p is in Lagrange form
// it returns a copy of p
func (encoder *Encoder) Encode(p poly.Polynomial, d *fft.Domain) poly.Polynomial {

	// get the size of p
	n := len(p)

	// create _p, a copy of p of size N (zero-padded)
	N := encoder.Domain.Cardinality
	_p := make(poly.Polynomial, N)
	copy(_p, p)

	// compute fftinv(_p[:n]) using d (d must be of the size of p)
	// Lagrange normal → canonical bit-reversed (w.r.t. n); then un-reverse to canonical normal
	d.FFTInverse(_p[:n], fft.DIF)
	utils.BitReverse(_p[:n])

	// compute fft(_p) using the Encoder domain
	// canonical normal (zero-padded to N) → Lagrange bit-reversed (w.r.t. N) → Lagrange normal
	encoder.Domain.FFT(_p, fft.DIF)
	utils.BitReverse(_p)

	// return _p
	return _p
}
