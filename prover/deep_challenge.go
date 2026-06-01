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

	"github.com/consensys/loom/internal/constants"
	fiatshamir "github.com/consensys/loom/internal/fiat-shamir"
	"github.com/consensys/loom/internal/hash"
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
	alpha, err := pr.fs.ComputeChallenge(constants.DEEP_ALPHA)
	if err != nil {
		return err
	}
	pr.alpha = hash.OutputToExt(alpha)
	return nil
}

func bindValueAtZeta(fs *fiatshamir.Transcript, prf proof.Proof, key string) error {
	v, ok := prf.ValueAtZetaExt(key)
	if !ok {
		return fmt.Errorf("BindDeepEvaluationClaims: %q not found in ValuesAtZeta", key)
	}
	return fs.Bind(constants.DEEP_ALPHA, hash.ExtToElements(v))
}
