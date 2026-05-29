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

package recursion

import (
	"fmt"

	"github.com/consensys/loom/internal/commitment"
	"github.com/consensys/loom/proof"
)

// Config carries optional knobs for verifier-circuit construction. Defaults
// are exposed via DefaultConfig.
type Config struct {
	// HashBackendID identifies the algebraic hash the inner proof was produced
	// with. Only Poseidon2 is supported for recursion.
	HashBackendID string

	// ModulePrefix is prepended to every module / column name BuildVerifierCore
	// emits. Use it when composing multiple verifier circuits into the same
	// outer builder (e.g. BuildAggregationCore wires two inner proofs by
	// instantiating BuildVerifierCore twice with distinct prefixes). The empty
	// prefix is the default and matches the historical single-proof layout.
	ModulePrefix string
}

// DefaultConfig returns a Config preset for Poseidon2 recursion, which is the
// only mode currently supported.
func DefaultConfig() Config {
	return Config{HashBackendID: commitment.HashBackendPoseidon2}
}

// validateInnerProof ensures the inner proof is recursion-compatible. SHA-256
// proofs cannot be recursed because their hash chain has no efficient
// in-circuit encoding.
func validateInnerProof(p proof.Proof, cfg Config) error {
	id := commitment.NormalizeHashBackendID(p.HashBackendID)
	want := commitment.NormalizeHashBackendID(cfg.HashBackendID)
	if id != commitment.HashBackendPoseidon2 {
		return fmt.Errorf("recursion: inner proof uses hash backend %q; only %q is supported", id, commitment.HashBackendPoseidon2)
	}
	if want != commitment.HashBackendPoseidon2 {
		return fmt.Errorf("recursion: config hash backend %q is not supported (only %q)", want, commitment.HashBackendPoseidon2)
	}
	if id != want {
		return fmt.Errorf("recursion: inner proof hash backend %q does not match config %q", id, want)
	}
	return nil
}
