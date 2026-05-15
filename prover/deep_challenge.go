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

package prover

import (
	"fmt"

	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/loom/internal/constants"
	"github.com/consensys/loom/proof"
)

// BindDeepEvaluationClaims binds the claimed evaluations batched by the DEEP
// quotient to the alpha_DEEP transcript challenge. The order must match
// ComputeDeepQuotient and verifier.checkFRIBridge.
func BindDeepEvaluationClaims(fs *fiatshamir.Transcript, prf proof.Proof, layout DEEPquotientLayout) error {
	for i := range layout.Sizes {
		for _, keysAtShift := range layout.Keys[i] {
			for _, key := range keysAtShift {
				if err := bindValueAtZeta(fs, prf, key); err != nil {
					return err
				}
			}
		}
		for _, chunkName := range layout.AIRChunks[i] {
			if err := bindValueAtZeta(fs, prf, chunkName); err != nil {
				return err
			}
		}
	}
	return nil
}

func (pr *proverRuntime) deriveDeepAlpha(layout DEEPquotientLayout) error {
	if err := BindDeepEvaluationClaims(pr.fs, pr.Proof, layout); err != nil {
		return err
	}
	if pr.config.EmulateFS {
		pr.alpha.MustSetRandom()
		if _, err := pr.fs.ComputeChallenge(constants.DEEP_ALPHA); err != nil {
			return fmt.Errorf("deriveDeepAlpha: compute emulated alpha: %w", err)
		}
		return nil
	}
	alphaBytes, err := pr.fs.ComputeChallenge(constants.DEEP_ALPHA)
	if err != nil {
		return err
	}
	return setExtFromBytes(&pr.alpha, alphaBytes)
}

func bindValueAtZeta(fs *fiatshamir.Transcript, prf proof.Proof, key string) error {
	v, ok := prf.ValueAtZetaExt(key)
	if !ok {
		return fmt.Errorf("BindDeepEvaluationClaims: %q not found in ValuesAtZeta", key)
	}
	return fs.Bind(constants.DEEP_ALPHA, serializeE4(v))
}

func serializeE4(v ext.E4) []byte {
	res := make([]byte, 0, 4*koalabear.Bytes)
	b0a0 := v.B0.A0.Bytes()
	b0a1 := v.B0.A1.Bytes()
	b1a0 := v.B1.A0.Bytes()
	b1a1 := v.B1.A1.Bytes()
	res = append(res, b0a0[:]...)
	res = append(res, b0a1[:]...)
	res = append(res, b1a0[:]...)
	res = append(res, b1a1[:]...)
	return res
}
