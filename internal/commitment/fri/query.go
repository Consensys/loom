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

package fri

import (
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/internal/merkle"
)

// buildQueryProofs constructs the Merkle openings and coset data for every
// query position. For each query j (leaf index in [0, N/k)):
//
//   - Opens each committed oracle's tree at leaf j.
//   - Opens each FRI layer tree at the appropriate leaf (j_ℓ = j mod (N_ℓ/(k·k^ℓ))).
func buildQueryProofs(
	queryIndices []uint64,
	oracles []committedOracle,
	layerTrees []*merkle.Tree,
	layerCodewords [][]koalabear.Element,
	k int,
) (
	oracleOpenings [][]merkle.Proof,
	oracleCosetData [][][]koalabear.Element,
	layerOpenings [][]merkle.Proof,
	layerCosetData [][][]koalabear.Element,
	err error,
) {
	numQueries := len(queryIndices)
	numOracles := len(oracles)
	numLayers := len(layerTrees)

	oracleOpenings = make([][]merkle.Proof, numQueries)
	oracleCosetData = make([][][]koalabear.Element, numQueries)
	layerOpenings = make([][]merkle.Proof, numQueries)
	layerCosetData = make([][][]koalabear.Element, numQueries)

	for qi, j64 := range queryIndices {
		j := int(j64)

		// --- Oracle openings ---
		oracleOpenings[qi] = make([]merkle.Proof, numOracles)
		oracleCosetData[qi] = make([][]koalabear.Element, numOracles)

		for oi, oracle := range oracles {
			N := int(oracle.CodewordDomainSize)
			nLeaves := N / k // leaves of oracle tree

			// Map query j (which is in [0, N/k)) to oracle's leaf index.
			// Since all oracles share the same N (enforced in Prove), j is directly valid.
			if j >= nLeaves {
				err = fmt.Errorf("fri: query index %d out of range for oracle %d (nLeaves=%d)", j, oi, nLeaves)
				return
			}

			pf, pfErr := oracle.Tree.OpenProof(j)
			if pfErr != nil {
				err = pfErr
				return
			}
			oracleOpenings[qi][oi] = pf

			// Coset data: K·k elements, poly_polyIdx at coset offset t.
			K := oracle.NumPolynomials
			data := make([]koalabear.Element, K*k)
			for polyIdx, name := range oracle.PolynomialNames {
				codeword := oracle.Codewords[name]
				for t := range k {
					pos := j + t*nLeaves
					data[polyIdx*k+t] = codeword[pos]
				}
			}
			oracleCosetData[qi][oi] = data
		}

		// --- Layer openings ---
		layerOpenings[qi] = make([]merkle.Proof, numLayers)
		layerCosetData[qi] = make([][]koalabear.Element, numLayers)

		jEll := j // tracks the leaf index at each layer
		for li := range numLayers {
			Nell := len(layerCodewords[li])
			nLeavesEll := Nell / k

			// At layer 0, jEll == j (the query leaf index).
			// At layer ℓ > 0, jEll = j mod (N_ℓ/k) computed from the previous round.
			if jEll >= nLeavesEll {
				err = fmt.Errorf("fri: layer %d leaf index %d out of range (nLeaves=%d)", li, jEll, nLeavesEll)
				return
			}

			pf, pfErr := layerTrees[li].OpenProof(jEll)
			if pfErr != nil {
				err = pfErr
				return
			}
			layerOpenings[qi][li] = pf

			// Coset data: k values at positions {jEll, jEll+nLeavesEll, …, jEll+(k-1)·nLeavesEll}.
			coset := make([]koalabear.Element, k)
			for t := range k {
				pos := jEll + t*nLeavesEll
				coset[t] = layerCodewords[li][pos]
			}
			layerCosetData[qi][li] = coset

			// Advance to the next layer's leaf index.
			if li < numLayers-1 {
				nLeavesNext := len(layerCodewords[li+1]) / k
				jEll = jEll % nLeavesNext
			}
		}
	}
	return
}

// cosetLeafBytes serialises the coset data for a single leaf into bytes for
// Merkle proof verification. The layout must match buildCosetMerkleTree /
// buildLayerMerkleTree.
func cosetLeafBytes(cosetData []koalabear.Element) []byte {
	return marshalElements(cosetData)
}
