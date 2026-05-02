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
	"encoding/binary"
	"fmt"
	"math/big"

	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/loom/internal/merkle"
	"github.com/consensys/loom/internal/reedsolomon"
)

// Params holds the FRI configuration and precomputed per-level data.
// Build once with NewParams; reuse across many Prove/Verify calls.
type Params struct {
	N          int // 2^n: size of the evaluation domain
	D          int // 2^m: degree of the purported polynomial
	NumQueries int // number of independent queries (controls soundness error ≈ (1-δ)^Q)
	LeafHasher merkle.LeafHasher
	NodeHasher merkle.NodeHasher

	numRounds int // numRounds = m
	invTwo    koalabear.Element
	domains   []*fft.Domain // domains[j] has cardinality N/2^j, generator ωⱼ
}

// NewParams constructs and validates a Params, precomputing r+1 domains and inv(2).
func NewParams(N, D, numQueries int, lh merkle.LeafHasher, nh merkle.NodeHasher) (Params, error) {
	if N <= 0 || N&(N-1) != 0 {
		return Params{}, fmt.Errorf("fri: N must be a positive power of two, got %d", N)
	}
	if D <= 0 || D&(D-1) != 0 {
		return Params{}, fmt.Errorf("fri: D must be a positive power of two, got %d", D)
	}
	if D >= N {
		return Params{}, fmt.Errorf("fri: D must be < N, got D=%d N=%d", D, N)
	}
	if numQueries <= 0 {
		return Params{}, fmt.Errorf("fri: numQueries must be positive, got %d", numQueries)
	}

	numRounds := log2(D) // r = m = log₂(D)

	var two, invTwo koalabear.Element
	two.SetUint64(2)
	invTwo.Inverse(&two)

	domains := make([]*fft.Domain, numRounds+1)
	for j := 0; j <= numRounds; j++ {
		domains[j] = fft.NewDomain(uint64(N) >> j)
	}

	return Params{
		N:          N,
		D:          D,
		NumQueries: numQueries,
		LeafHasher: lh,
		NodeHasher: nh,
		numRounds:  numRounds,
		invTwo:     invTwo,
		domains:    domains,
	}, nil
}

// QueryLayer holds the two opened values and their Merkle proofs for one folding level.
type QueryLayer struct {
	LeafP  koalabear.Element // aⱼ[ s mod Nⱼ ]
	LeafQ  koalabear.Element // aⱼ[ (s mod Nⱼ + Nⱼ/2) mod Nⱼ ]
	ProofP merkle.Proof
	ProofQ merkle.Proof
}

// Query holds the opening data for one full query path across all r levels.
type Query struct {
	Layers []QueryLayer // len = numRounds
}

// Proof is the complete FRI proof sent from prover to verifier.
// The root of layer 0 (a₀) is not included here; it is passed separately to Verify.
type Proof struct {
	Roots     [][]byte            // Merkle roots for layers 1..r-1; len = numRounds-1
	FinalPoly []koalabear.Element // explicit evaluations of the final folded layer
	Queries   []Query             // len = NumQueries
}

// Encode converts a polynomial from Lagrange form (size D) to its evaluation
// on the full domain of size N. The result is a₀, ready to pass to Prove.
func (p Params) Encode(poly []koalabear.Element) ([]koalabear.Element, error) {
	if len(poly) != p.D {
		return nil, fmt.Errorf("fri: Encode: polynomial length %d != D=%d", len(poly), p.D)
	}
	enc := reedsolomon.NewEncoder(uint64(p.N))
	domainD := fft.NewDomain(uint64(p.D))
	return enc.Encode(poly, domainD), nil
}

// Prove runs the full FRI protocol (commit phase + query phase) and returns a Proof.
// evals must be the evaluations of f on the domain of size N (= a₀, output of Encode).
// ts must already have been initialised with any prior-round context.
func Prove(p Params, evals []koalabear.Element, ts *fiatshamir.Transcript) (Proof, error) {
	if len(evals) != p.N {
		return Proof{}, fmt.Errorf("fri: Prove: evals length %d != N=%d", len(evals), p.N)
	}

	// Register all challenge names up front.
	for j := 0; j < p.numRounds; j++ {
		ts.NewChallenge(foldName(j))
	}
	for k := 0; k < p.NumQueries; k++ {
		ts.NewChallenge(queryName(k))
	}

	// ── Commit phase ────────────────────────────────────────────────────────

	layers := make([][]koalabear.Element, p.numRounds+1)
	layers[0] = evals
	trees := make([]*merkle.Tree, p.numRounds)
	alphas := make([]koalabear.Element, p.numRounds)

	var prf Proof
	if p.numRounds > 1 {
		prf.Roots = make([][]byte, p.numRounds-1)
	}

	for j := 0; j < p.numRounds; j++ {
		tree, err := buildTree(layers[j], p.LeafHasher, p.NodeHasher)
		if err != nil {
			return Proof{}, fmt.Errorf("fri: build tree layer %d: %w", j, err)
		}
		trees[j] = tree
		root := tree.Root()

		name := foldName(j)
		if err := ts.Bind(name, root); err != nil {
			return Proof{}, fmt.Errorf("fri: bind fold %d: %w", j, err)
		}
		b, err := ts.ComputeChallenge(name)
		if err != nil {
			return Proof{}, fmt.Errorf("fri: compute fold challenge %d: %w", j, err)
		}
		alphas[j].SetBytes(b)

		// root₀ is passed separately to Verify; only roots 1..r-1 go in the proof.
		if j > 0 {
			prf.Roots[j-1] = root
		}

		layers[j+1] = foldLayer(layers[j], alphas[j], p.domains[j], p.invTwo)
	}

	prf.FinalPoly = layers[p.numRounds]

	// Bind FinalPoly to seed the first query challenge.
	if err := ts.Bind(queryName(0), serialise(prf.FinalPoly)); err != nil {
		return Proof{}, fmt.Errorf("fri: bind final poly: %w", err)
	}

	// ── Query phase ──────────────────────────────────────────────────────────

	prf.Queries = make([]Query, p.NumQueries)
	for k := 0; k < p.NumQueries; k++ {
		b, err := ts.ComputeChallenge(queryName(k))
		if err != nil {
			return Proof{}, fmt.Errorf("fri: compute query challenge %d: %w", k, err)
		}
		s := int(binary.BigEndian.Uint64(b[:8]) % uint64(p.N/2))

		if k < p.NumQueries-1 {
			if err := ts.Bind(queryName(k+1), b); err != nil {
				return Proof{}, fmt.Errorf("fri: bind query chain %d: %w", k+1, err)
			}
		}

		q, err := openQuery(s, layers, trees, p.numRounds)
		if err != nil {
			return Proof{}, fmt.Errorf("fri: open query %d: %w", k, err)
		}
		prf.Queries[k] = q
	}

	return prf, nil
}

// Verify checks a FRI proof.
// root0 is the Merkle root of a₀ (the commitment to the input evaluations).
// ts must be in the same state as when Prove was called (same prior-round context).
func Verify(p Params, root0 []byte, prf Proof, ts *fiatshamir.Transcript) error {
	wantRoots := p.numRounds - 1
	if p.numRounds == 1 {
		wantRoots = 0
	}
	if len(prf.Roots) != wantRoots {
		return fmt.Errorf("fri: proof has %d intermediate roots, want %d", len(prf.Roots), wantRoots)
	}
	if len(prf.Queries) != p.NumQueries {
		return fmt.Errorf("fri: proof has %d queries, want %d", len(prf.Queries), p.NumQueries)
	}

	// Register all challenge names.
	for j := 0; j < p.numRounds; j++ {
		ts.NewChallenge(foldName(j))
	}
	for k := 0; k < p.NumQueries; k++ {
		ts.NewChallenge(queryName(k))
	}

	// Assemble all roots: roots[0] = root0, roots[1..r-1] from proof.
	roots := make([][]byte, p.numRounds)
	roots[0] = root0
	for j := 1; j < p.numRounds; j++ {
		roots[j] = prf.Roots[j-1]
	}

	// Replay commit phase to recover alphas.
	alphas := make([]koalabear.Element, p.numRounds)
	for j := 0; j < p.numRounds; j++ {
		name := foldName(j)
		if err := ts.Bind(name, roots[j]); err != nil {
			return fmt.Errorf("fri: bind fold %d: %w", j, err)
		}
		b, err := ts.ComputeChallenge(name)
		if err != nil {
			return fmt.Errorf("fri: compute fold challenge %d: %w", j, err)
		}
		alphas[j].SetBytes(b)
	}

	// Replay the FinalPoly binding.
	if err := ts.Bind(queryName(0), serialise(prf.FinalPoly)); err != nil {
		return fmt.Errorf("fri: bind final poly: %w", err)
	}

	// Derive query indices and verify each query.
	for k := 0; k < p.NumQueries; k++ {
		b, err := ts.ComputeChallenge(queryName(k))
		if err != nil {
			return fmt.Errorf("fri: compute query challenge %d: %w", k, err)
		}
		s := int(binary.BigEndian.Uint64(b[:8]) % uint64(p.N/2))

		if k < p.NumQueries-1 {
			if err := ts.Bind(queryName(k+1), b); err != nil {
				return fmt.Errorf("fri: bind query chain %d: %w", k+1, err)
			}
		}

		if err := checkQuery(s, prf.Queries[k], roots, prf.FinalPoly, alphas, p); err != nil {
			return fmt.Errorf("fri: query %d failed: %w", k, err)
		}
	}

	return nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

func foldName(j int) string  { return fmt.Sprintf("fri_fold_%d", j) }
func queryName(k int) string { return fmt.Sprintf("fri_query_%d", k) }

func log2(n int) int {
	k := 0
	for n > 1 {
		n >>= 1
		k++
	}
	return k
}

// buildTree builds a Merkle tree where leaf i = LeafHasher(aⱼ[i].Marshal()).
func buildTree(layer []koalabear.Element, lh merkle.LeafHasher, nh merkle.NodeHasher) (*merkle.Tree, error) {
	n := len(layer)
	tree, err := merkle.New(n, lh, nh)
	if err != nil {
		return nil, err
	}
	leaves := make([][]byte, n)
	for i, e := range layer {
		leaves[i] = e.Marshal()
	}
	return tree, tree.Build(leaves)
}

// foldLayer folds a layer of size Nⱼ into a layer of size Nⱼ/2.
// domain must have cardinality Nⱼ and generator ωⱼ.
func foldLayer(layer []koalabear.Element, alpha koalabear.Element, domain *fft.Domain, invTwo koalabear.Element) []koalabear.Element {
	half := len(layer) / 2
	next := make([]koalabear.Element, half)

	// xInv = ωⱼ^{-i}, starting at i=0
	var xInv, sum, diff koalabear.Element
	xInv.SetOne()

	for i := 0; i < half; i++ {
		p, q := layer[i], layer[i+half]

		// (p+q) * invTwo
		sum.Add(&p, &q)
		sum.Mul(&sum, &invTwo)

		// alpha * (p-q) * invTwo * xInv
		diff.Sub(&p, &q)
		diff.Mul(&diff, &invTwo)
		diff.Mul(&diff, &xInv)
		diff.Mul(&diff, &alpha)

		next[i].Add(&sum, &diff)

		xInv.Mul(&xInv, &domain.GeneratorInv)
	}

	return next
}

// serialise encodes a slice of field elements to bytes (4 bytes each, Marshal form).
func serialise(poly []koalabear.Element) []byte {
	buf := make([]byte, len(poly)*koalabear.Bytes)
	for i, e := range poly {
		copy(buf[i*koalabear.Bytes:], e.Marshal())
	}
	return buf
}

// openQuery builds the Merkle opening data for query index s across all r levels.
func openQuery(s int, layers [][]koalabear.Element, trees []*merkle.Tree, numRounds int) (Query, error) {
	q := Query{Layers: make([]QueryLayer, numRounds)}
	for j := 0; j < numRounds; j++ {
		Nj := len(layers[j])
		idx := s % Nj // -> if idx >= Nj/2, the folding relation (p+q)/2 + alpha*(p-q)/2w^idx becomes (p+q)/2 - alpha*(p-q)/2w^[idx%(Nj%2)]=p+q)/2 + alpha*(q-p)/2w^[idx%(Nj%2)] so the arithmetic holds
		sibIdx := (idx + Nj/2) % Nj

		proofP, err := trees[j].OpenProof(idx)
		if err != nil {
			return Query{}, fmt.Errorf("layer %d OpenProof idx=%d: %w", j, idx, err)
		}
		proofQ, err := trees[j].OpenProof(sibIdx)
		if err != nil {
			return Query{}, fmt.Errorf("layer %d OpenProof sibIdx=%d: %w", j, sibIdx, err)
		}

		q.Layers[j] = QueryLayer{
			LeafP:  layers[j][idx],
			LeafQ:  layers[j][sibIdx],
			ProofP: proofP,
			ProofQ: proofQ,
		}
	}
	return q, nil
}

// checkQuery verifies one query: Merkle proofs at each level + folding consistency.
func checkQuery(s int, q Query, roots [][]byte, finalPoly []koalabear.Element,
	alphas []koalabear.Element, p Params) error {

	numRounds := p.numRounds

	for j := 0; j < numRounds; j++ {
		Nj := int(p.domains[j].Cardinality)
		idx := s % Nj
		sibIdx := (idx + Nj/2) % Nj
		layer := q.Layers[j]

		// Verify Merkle proofs.
		if !merkle.Verify(roots[j], layer.ProofP, layer.LeafP.Marshal(), p.LeafHasher, p.NodeHasher) {
			return fmt.Errorf("level %d: LeafP Merkle proof invalid (idx=%d)", j, idx)
		}
		if !merkle.Verify(roots[j], layer.ProofQ, layer.LeafQ.Marshal(), p.LeafHasher, p.NodeHasher) {
			return fmt.Errorf("level %d: LeafQ Merkle proof invalid (idx=%d)", j, sibIdx)
		}

		// Compute yⱼ = ωⱼ^idx and fold: expected = (LeafP+LeafQ)/2 + α*(LeafP-LeafQ)/(2·yⱼ).
		var yj, yjInv, sum, diff, expected koalabear.Element
		yj.Exp(p.domains[j].Generator, big.NewInt(int64(idx)))
		yjInv.Inverse(&yj)

		sum.Add(&layer.LeafP, &layer.LeafQ)
		sum.Mul(&sum, &p.invTwo)

		diff.Sub(&layer.LeafP, &layer.LeafQ)
		diff.Mul(&diff, &p.invTwo)
		diff.Mul(&diff, &yjInv)
		diff.Mul(&diff, &alphas[j])

		expected.Add(&sum, &diff)

		// Check consistency with the next level.
		if j < numRounds-1 {
			nextLeafP := q.Layers[j+1].LeafP
			if !expected.Equal(&nextLeafP) {
				return fmt.Errorf("level %d: folded value does not match layer %d LeafP", j, j+1)
			}
		} else {
			Nr := len(finalPoly)
			finalVal := finalPoly[s%Nr]
			if !expected.Equal(&finalVal) {
				return fmt.Errorf("level %d (final): folded value does not match FinalPoly", j)
			}
		}
	}

	return nil
}
