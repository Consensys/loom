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

	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
)

// isPowerOfTwo checks if n is a power of two
func isPowerOfTwo(n int) bool {
	return n > 0 && (n&(n-1)) == 0
}

// NextPowerOfTwo returns the next power of two greater than or equal to n
func NextPowerOfTwo(n int) int {
	if n <= 0 {
		return 1
	}
	if isPowerOfTwo(n) {
		return n
	}
	n--
	n |= n >> 1
	n |= n >> 2
	n |= n >> 4
	n |= n >> 8
	n |= n >> 16
	n |= n >> 32
	return n + 1
}

func LagrangeAtZeta(zeta koalabear.Element, N, i int) koalabear.Element {
	var zetan, omegai, one, Nk koalabear.Element
	Nk.SetUint64(uint64(N))
	omegai, err := koalabear.Generator(uint64(N))
	if err != nil {
		panic(err)
	}
	omegai.Exp(omegai, big.NewInt(int64(i)))
	zetan.Exp(zeta, big.NewInt(int64(N)))
	one.SetOne()
	zetan.Sub(&zetan, &one)
	zeta.Sub(&zeta, &omegai)
	omegai.Mul(&omegai, &zetan)
	zeta.Mul(&zeta, &Nk)
	omegai.Div(&omegai, &zeta)
	return omegai
}

func LagrangeAtZetaExt(zeta ext.E4, N, i int) ext.E4 {
	var zetaN, numerator, denominator, one ext.E4
	zetaN.Exp(zeta, big.NewInt(int64(N)))
	one.SetOne()
	zetaN.Sub(&zetaN, &one)

	omegaI, err := koalabear.Generator(uint64(N))
	if err != nil {
		panic(err)
	}
	omegaI.Exp(omegaI, big.NewInt(int64(i)))
	numerator.MulByElement(&zetaN, &omegaI)

	var omegaIExt ext.E4
	omegaIExt.Lift(&omegaI)
	denominator.Sub(&zeta, &omegaIExt)

	var Nk koalabear.Element
	Nk.SetUint64(uint64(N))
	denominator.MulByElement(&denominator, &Nk)
	denominator.Inverse(&denominator)

	numerator.Mul(&numerator, &denominator)
	return numerator
}

// nextPowerOfTwo is an alias for NextPowerOfTwo for internal use
func nextPowerOfTwo(n int) int {
	return NextPowerOfTwo(n)
}
