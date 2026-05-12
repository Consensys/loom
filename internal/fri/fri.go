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
	"sort"

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

	numRounds    int // numRounds = m
	invTwo       koalabear.Element
	domains      []*fft.Domain // domains[j] has cardinality N/2^j, generator ωⱼ
	domainsLight []domainLight // domainLight stores only the cardinality and the domain generator
}

type Config struct {
	LightMode bool
}

type Option func(c *Config) error

func LightMode() Option {
	return func(c *Config) error {
		c.LightMode = true
		return nil
	}
}

// NewParams constructs and validates a Params, precomputing r+1 domains and inv(2).
func NewParams(N, D, numQueries int, lh merkle.LeafHasher, nh merkle.NodeHasher, opts ...Option) (Params, error) {
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

	var config Config
	for _, opt := range opts {
		if err := opt(&config); err != nil {
			return Params{}, err
		}
	}

	numRounds := log2(D) // r = m = log₂(D)

	var two, invTwo koalabear.Element
	two.SetUint64(2)
	invTwo.Inverse(&two)

	res := Params{
		N:          N,
		D:          D,
		NumQueries: numQueries,
		LeafHasher: lh,
		NodeHasher: nh,
		numRounds:  numRounds,
		invTwo:     invTwo,
	}

	if !config.LightMode {
		res.domains = make([]*fft.Domain, numRounds+1)
		for j := 0; j <= numRounds; j++ {
			res.domains[j] = fft.NewDomain(uint64(N) >> j)
		}
	}
	res.domainsLight = make([]domainLight, numRounds+1)
	for j := 0; j <= numRounds; j++ {
		g, err := koalabear.Generator(uint64(N) >> j)
		if err != nil {
			return Params{}, err
		}
		res.domainsLight[j] = domainLight{cardinality: uint64(N) >> j, generator: g}

	}

	return res, nil
}

type domainLight struct {
	cardinality uint64
	generator   koalabear.Element
}

// QueryLayer holds the two opened values and a single Merkle proof for one folding level.
// LeafP = layer[base], LeafQ = layer[base + Nⱼ/2] where base = s % (Nⱼ/2).
// The pair is committed as a single leaf: hash(encode(LeafP) || encode(LeafQ)).
type QueryLayer struct {
	LeafP koalabear.Element // layer[base], lower-index element of the sibling pair
	LeafQ koalabear.Element // layer[base + Nⱼ/2], upper-index element
	Path  merkle.Proof      // authenticates the pair; depth = log₂(Nⱼ/2)
}

// Query holds the opening data for one full query path across all r levels.
type Query struct {
	Layers []QueryLayer // len = numRounds
}

// ────────────────────────────────────────────────────────────────────────────────
// Multi-degree FRI types (see multi_degree_fri.txt for the full protocol spec)
// ────────────────────────────────────────────────────────────────────────────────

// Level groups polynomials of the same degree, introduced at the folding round
// where the running polynomial's degree matches Level.D. Trees holds the
// pre-built paired-leaf Merkle trees, one per polynomial in Evals; build them
// with Params.BuildLevelTree so the leaf/node hashers match.
type Level struct {
	D     int
	Evals [][]koalabear.Element // evaluation vectors, each of size N * D / p.D
	Trees []*merkle.Tree        // pre-built paired-leaf Merkle trees, len matches Evals
}

// QueriesAtLevel holds one opening per polynomial in one Level for one outer
// query position (the opening at the level's own domain).
type QueriesAtLevel = []QueryLayer

// Proof is the complete multi-degree FRI proof. Level polynomial Merkle roots
// are NOT stored here — they are passed externally to Verify (the caller
// commits to those polynomials before invoking FRI).
type Proof struct {
	// LevelQueries[l-1][k][i] = opening for levels[l].Evals[i] at outer query k.
	LevelQueries [][]QueriesAtLevel

	// Running-polynomial FRI path
	FRIRoots   [][]byte            // Merkle roots for running poly T_1..T_{r-1}
	FinalPoly  []koalabear.Element // explicit final folded evaluations
	FRIQueries []Query             // len = NumQueries
}

// FullDomainGenerator returns the generator of the full evaluation domain (layer 0, size N).
func (p Params) FullDomainGenerator() koalabear.Element {
	return p.domains[0].Generator
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

// BuildLevelTree builds the paired-leaf Merkle tree expected by FRI for a
// level polynomial: tree of len(layer)/2 leaves where
// leaf k = LeafHasher(encode(layer[k]) || encode(layer[k + len(layer)/2])).
func (p Params) BuildLevelTree(layer []koalabear.Element) (*merkle.Tree, error) {
	return buildTree(layer, p.LeafHasher, p.NodeHasher)
}

// ────────────────────────────────────────────────────────────────────────────────
// Prove — multi-degree FRI prover
// ────────────────────────────────────────────────────────────────────────────────

// Prove runs multi-degree FRI (commit + query phase) and returns a Proof together
// with the query positions. levels[0].D must equal p.D and len(levels[0].Evals) must
// be 1. levels is sorted in-place in decreasing order of D.
// ts must already have been initialised with any prior-round context.
func Prove(p Params, levels []Level, ts *fiatshamir.Transcript) (Proof, []int, error) {
	sort.Slice(levels, func(i, j int) bool { return levels[i].D > levels[j].D })

	if len(levels) == 0 {
		return Proof{}, nil, fmt.Errorf("fri: Prove: at least one level required")
	}
	if levels[0].D != p.D {
		return Proof{}, nil, fmt.Errorf("fri: Prove: levels[0].D=%d must equal p.D=%d", levels[0].D, p.D)
	}
	if len(levels[0].Evals) != 1 {
		return Proof{}, nil, fmt.Errorf("fri: Prove: levels[0] must contain exactly one polynomial, got %d", len(levels[0].Evals))
	}
	if len(levels[0].Evals[0]) != p.N {
		return Proof{}, nil, fmt.Errorf("fri: Prove: levels[0].Evals[0] length %d != N=%d", len(levels[0].Evals[0]), p.N)
	}
	if len(levels[0].Trees) != 1 {
		return Proof{}, nil, fmt.Errorf("fri: Prove: levels[0] must have exactly one Tree, got %d", len(levels[0].Trees))
	}

	numLevels := len(levels)

	// Build levelAtRound: folding round j → level index l (1-based).
	levelAtRound := make(map[int]int, numLevels-1)
	for l := 1; l < numLevels; l++ {
		if levels[l].D <= 0 || levels[l].D&(levels[l].D-1) != 0 {
			return Proof{}, nil, fmt.Errorf("fri: Prove: levels[%d].D=%d is not a positive power of two", l, levels[l].D)
		}
		jl := log2(p.D / levels[l].D)
		if jl < 1 || jl >= p.numRounds {
			return Proof{}, nil, fmt.Errorf("fri: Prove: levels[%d].D=%d gives intro round %d, must be in 1..%d", l, levels[l].D, jl, p.numRounds-1)
		}
		if _, dup := levelAtRound[jl]; dup {
			return Proof{}, nil, fmt.Errorf("fri: Prove: two levels share intro round %d", jl)
		}
		levelAtRound[jl] = l
		Nl := p.N >> jl
		for i, evals := range levels[l].Evals {
			if len(evals) != Nl {
				return Proof{}, nil, fmt.Errorf("fri: Prove: levels[%d].Evals[%d] length %d != N_l=%d", l, i, len(evals), Nl)
			}
		}
		if len(levels[l].Trees) != len(levels[l].Evals) {
			return Proof{}, nil, fmt.Errorf("fri: Prove: levels[%d] has %d Trees, want %d (= len(Evals))", l, len(levels[l].Trees), len(levels[l].Evals))
		}
	}

	// ── Register all challenge names up front, in compute order ──────────────
	// At round j (j >= 1), if a level is introduced, we bind all its poly
	// roots to fri_level_j_gamma and compute that challenge before computing
	// fri_fold_j. Each level uses a single FS slot — multiple polynomials are
	// just multiple Bind calls to the same name.
	ts.NewChallenge(foldName(0))
	for j := 1; j < p.numRounds; j++ {
		if l, ok := levelAtRound[j]; ok {
			ts.NewChallenge(levelGammaName(l))
		}
		ts.NewChallenge(foldName(j))
	}
	for k := 0; k < p.NumQueries; k++ {
		ts.NewChallenge(queryName(k))
	}

	// ── Commit phase ─────────────────────────────────────────────────────────

	// running is the current evaluation vector; copy levels[0].Evals[0] so we own it.
	running := make([]koalabear.Element, p.N)
	copy(running, levels[0].Evals[0])

	layers := make([][]koalabear.Element, p.numRounds+1)
	friTrees := make([]*merkle.Tree, p.numRounds)
	alphas := make([]koalabear.Element, p.numRounds)

	var prf Proof
	if p.numRounds > 1 {
		prf.FRIRoots = make([][]byte, p.numRounds-1)
	}

	for j := 0; j < p.numRounds; j++ {
		// Level batching step (j > 0 only; j=0 reuses the caller-supplied levels[0].Trees[0]).
		if j > 0 {
			if l, ok := levelAtRound[j]; ok {
				gammaName := levelGammaName(l)
				for i := range levels[l].Evals {
					if err := ts.Bind(gammaName, levels[l].Trees[i].Root()); err != nil {
						return Proof{}, nil, fmt.Errorf("fri: Prove: bind level poly l=%d i=%d: %w", l, i, err)
					}
				}
				b, err := ts.ComputeChallenge(gammaName)
				if err != nil {
					return Proof{}, nil, fmt.Errorf("fri: Prove: compute level gamma l=%d: %w", l, err)
				}
				var gamma koalabear.Element
				gamma.SetBytes(b)

				// Batch γ^{i+1} * levels[l].Evals[i] into running (pointwise).
				var gammaPow koalabear.Element
				gammaPow.Set(&gamma)
				for _, evals := range levels[l].Evals {
					for k, v := range evals {
						var term koalabear.Element
						term.Mul(&v, &gammaPow)
						running[k].Add(&running[k], &term)
					}
					gammaPow.Mul(&gammaPow, &gamma)
				}
			}
		}

		// layers[j] = running after batching, before folding (= what T_j commits to).
		layers[j] = running

		var tree *merkle.Tree
		if j == 0 {
			tree = levels[0].Trees[0] // caller-supplied, root must match running pre-fold
		} else {
			var err error
			tree, err = buildTree(running, p.LeafHasher, p.NodeHasher)
			if err != nil {
				return Proof{}, nil, fmt.Errorf("fri: Prove: build tree layer %d: %w", j, err)
			}
		}
		friTrees[j] = tree
		root := tree.Root()

		name := foldName(j)
		if err := ts.Bind(name, root); err != nil {
			return Proof{}, nil, fmt.Errorf("fri: Prove: bind fold %d: %w", j, err)
		}
		b, err := ts.ComputeChallenge(name)
		if err != nil {
			return Proof{}, nil, fmt.Errorf("fri: Prove: compute fold challenge %d: %w", j, err)
		}
		alphas[j].SetBytes(b)

		// Root of T_0 is passed to Verify separately; only T_1..T_{r-1} go in the proof.
		if j > 0 {
			prf.FRIRoots[j-1] = root
		}

		// foldLayer returns a new slice, so running for round j+1 is independent.
		running = foldLayer(running, alphas[j], p.domains[j], p.invTwo)
	}
	layers[p.numRounds] = running
	prf.FinalPoly = running

	if err := ts.Bind(queryName(0), serialise(prf.FinalPoly)); err != nil {
		return Proof{}, nil, fmt.Errorf("fri: Prove: bind final poly: %w", err)
	}

	// ── Query phase ───────────────────────────────────────────────────────────

	prf.FRIQueries = make([]Query, p.NumQueries)
	if numLevels > 1 {
		prf.LevelQueries = make([][]QueriesAtLevel, numLevels-1)
		for l := range prf.LevelQueries {
			prf.LevelQueries[l] = make([]QueriesAtLevel, p.NumQueries)
		}
	}

	queryPositions := make([]int, p.NumQueries)
	for k := 0; k < p.NumQueries; k++ {
		b, err := ts.ComputeChallenge(queryName(k))
		if err != nil {
			return Proof{}, nil, fmt.Errorf("fri: Prove: compute query challenge %d: %w", k, err)
		}
		s := int(binary.BigEndian.Uint64(b[:8]) % uint64(p.N/2))
		queryPositions[k] = s

		if k < p.NumQueries-1 {
			if err := ts.Bind(queryName(k+1), b); err != nil {
				return Proof{}, nil, fmt.Errorf("fri: Prove: bind query chain %d: %w", k+1, err)
			}
		}

		q, err := openQuery(s, layers, friTrees, p.numRounds)
		if err != nil {
			return Proof{}, nil, fmt.Errorf("fri: Prove: open FRI query %d: %w", k, err)
		}
		prf.FRIQueries[k] = q

		for l := 1; l < numLevels; l++ {
			jl := log2(p.D / levels[l].D)
			Nl := p.N >> jl
			base := s % (Nl / 2)

			prf.LevelQueries[l-1][k] = make(QueriesAtLevel, len(levels[l].Evals))
			for i := range levels[l].Evals {
				path, err := levels[l].Trees[i].OpenProof(base)
				if err != nil {
					return Proof{}, nil, fmt.Errorf("fri: Prove: open level query l=%d i=%d k=%d: %w", l, i, k, err)
				}
				prf.LevelQueries[l-1][k][i] = QueryLayer{
					LeafP: levels[l].Evals[i][base],
					LeafQ: levels[l].Evals[i][base+Nl/2],
					Path:  path,
				}
			}
		}
	}

	return prf, queryPositions, nil
}

// ────────────────────────────────────────────────────────────────────────────────
// Verify — multi-degree FRI verifier
// ────────────────────────────────────────────────────────────────────────────────

// Verify checks a multi-degree FRI proof.
//
// levelRoots[l][i] is the Merkle root of levels[l].Evals[i] (committed by the
// caller before invoking FRI). levelRoots[0] must contain exactly one entry,
// which plays the role of "root0" in single-degree FRI.
//
// levelDs[l] is the polynomial-size parameter D for level l; levelDs[0] must
// equal p.D and the slice must be ordered consistently with how Prove was
// called (i.e. decreasing D).
//
// ts must be in the same state as when Prove was called.
func Verify(p Params, levelRoots [][][]byte, levelDs []int, prf Proof, ts *fiatshamir.Transcript) error {
	if len(levelDs) == 0 {
		return fmt.Errorf("fri: Verify: at least one level required")
	}
	if len(levelRoots) != len(levelDs) {
		return fmt.Errorf("fri: Verify: levelRoots has %d entries, levelDs has %d", len(levelRoots), len(levelDs))
	}
	if levelDs[0] != p.D {
		return fmt.Errorf("fri: Verify: levelDs[0]=%d must equal p.D=%d", levelDs[0], p.D)
	}
	if len(levelRoots[0]) != 1 {
		return fmt.Errorf("fri: Verify: levelRoots[0] must contain exactly one root, got %d", len(levelRoots[0]))
	}

	numLevels := len(levelDs)
	numExtraLevels := numLevels - 1

	wantFRIRoots := p.numRounds - 1
	if p.numRounds <= 1 {
		wantFRIRoots = 0
	}
	if len(prf.FRIRoots) != wantFRIRoots {
		return fmt.Errorf("fri: Verify: proof has %d FRI roots, want %d", len(prf.FRIRoots), wantFRIRoots)
	}
	if len(prf.FRIQueries) != p.NumQueries {
		return fmt.Errorf("fri: Verify: proof has %d FRI queries, want %d", len(prf.FRIQueries), p.NumQueries)
	}
	if numExtraLevels > 0 && len(prf.LevelQueries) != numExtraLevels {
		return fmt.Errorf("fri: Verify: proof has %d level query sets, want %d", len(prf.LevelQueries), numExtraLevels)
	}

	// levelAtRound: folding round j → level index l (1-based).
	levelAtRound := make(map[int]int, numExtraLevels)
	for l := 1; l < numLevels; l++ {
		jl := log2(p.D / levelDs[l])
		levelAtRound[jl] = l
	}

	// ── Register all challenge names up front, in compute order (same as Prove) ──
	ts.NewChallenge(foldName(0))
	for j := 1; j < p.numRounds; j++ {
		if l, ok := levelAtRound[j]; ok {
			ts.NewChallenge(levelGammaName(l))
		}
		ts.NewChallenge(foldName(j))
	}
	for k := 0; k < p.NumQueries; k++ {
		ts.NewChallenge(queryName(k))
	}

	// Assemble FRI running-polynomial roots: roots[0] is the level-0 root;
	// roots[1..r-1] come from prf.FRIRoots.
	roots := make([][]byte, p.numRounds)
	roots[0] = levelRoots[0][0]
	for j := 1; j < p.numRounds; j++ {
		roots[j] = prf.FRIRoots[j-1]
	}

	// ── Replay commit phase (interleaved, same order as Prove) ───────────────
	gammas := make([]koalabear.Element, numLevels) // gammas[l] for levels[l], l = 1..numLevels-1
	alphas := make([]koalabear.Element, p.numRounds)

	for j := 0; j < p.numRounds; j++ {
		if j > 0 {
			if l, ok := levelAtRound[j]; ok {
				gammaName := levelGammaName(l)
				for i, root := range levelRoots[l] {
					if err := ts.Bind(gammaName, root); err != nil {
						return fmt.Errorf("fri: Verify: bind level poly l=%d i=%d: %w", l, i, err)
					}
				}
				b, err := ts.ComputeChallenge(gammaName)
				if err != nil {
					return fmt.Errorf("fri: Verify: compute level gamma l=%d: %w", l, err)
				}
				gammas[l].SetBytes(b)
			}
		}

		name := foldName(j)
		if err := ts.Bind(name, roots[j]); err != nil {
			return fmt.Errorf("fri: Verify: bind fold %d: %w", j, err)
		}
		b, err := ts.ComputeChallenge(name)
		if err != nil {
			return fmt.Errorf("fri: Verify: compute fold challenge %d: %w", j, err)
		}
		alphas[j].SetBytes(b)
	}

	if err := ts.Bind(queryName(0), serialise(prf.FinalPoly)); err != nil {
		return fmt.Errorf("fri: Verify: bind final poly: %w", err)
	}

	// ── Query phase ───────────────────────────────────────────────────────────
	// levelRootsExtra[l-1] = roots for levels[l] (l >= 1), passed to checkQuery.
	var levelRootsExtra [][][]byte
	if numExtraLevels > 0 {
		levelRootsExtra = levelRoots[1:]
	}

	for k := 0; k < p.NumQueries; k++ {
		b, err := ts.ComputeChallenge(queryName(k))
		if err != nil {
			return fmt.Errorf("fri: Verify: compute query challenge %d: %w", k, err)
		}
		s := int(binary.BigEndian.Uint64(b[:8]) % uint64(p.N/2))

		if k < p.NumQueries-1 {
			if err := ts.Bind(queryName(k+1), b); err != nil {
				return fmt.Errorf("fri: Verify: bind query chain %d: %w", k+1, err)
			}
		}

		var levelQueriesForQuery []QueriesAtLevel
		if numExtraLevels > 0 {
			levelQueriesForQuery = make([]QueriesAtLevel, numExtraLevels)
			for l := 0; l < numExtraLevels; l++ {
				levelQueriesForQuery[l] = prf.LevelQueries[l][k]
			}
		}

		if err := checkQuery(s, prf.FRIQueries[k], levelQueriesForQuery, levelRootsExtra,
			levelAtRound, gammas, roots, prf.FinalPoly, alphas, p); err != nil {
			return fmt.Errorf("fri: Verify: query %d failed: %w", k, err)
		}
	}

	return nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

func levelGammaName(l int) string { return fmt.Sprintf("fri_level_%d_gamma", l) }
func foldName(j int) string       { return fmt.Sprintf("fri_fold_%d", j) }
func queryName(k int) string      { return fmt.Sprintf("fri_query_%d", k) }

func log2(n int) int {
	k := 0
	for n > 1 {
		n >>= 1
		k++
	}
	return k
}

// buildTree builds a Merkle tree of Nⱼ/2 leaves where
// leaf k = LeafHasher(encode(layer[k]) || encode(layer[k + Nⱼ/2])).
func buildTree(layer []koalabear.Element, lh merkle.LeafHasher, nh merkle.NodeHasher) (*merkle.Tree, error) {
	half := len(layer) / 2
	tree, err := merkle.New(half, lh, nh)
	if err != nil {
		return nil, err
	}
	leaves := make([][]byte, half)
	for k := 0; k < half; k++ {
		leaves[k] = append(layer[k].Marshal(), layer[k+half].Marshal()...)
	}
	return tree, tree.Build(leaves)
}

// foldLayer folds a layer of size Nⱼ into a layer of size Nⱼ/2.
func foldLayer(layer []koalabear.Element, alpha koalabear.Element, domain *fft.Domain, invTwo koalabear.Element) []koalabear.Element {
	half := len(layer) / 2
	next := make([]koalabear.Element, half)

	var xInv, sum, diff koalabear.Element
	xInv.SetOne()

	for i := 0; i < half; i++ {
		p, q := layer[i], layer[i+half]

		sum.Add(&p, &q)
		sum.Mul(&sum, &invTwo)

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

// openQuery builds the Merkle opening data for query index s across all r folding levels.
func openQuery(s int, layers [][]koalabear.Element, trees []*merkle.Tree, numRounds int) (Query, error) {
	q := Query{Layers: make([]QueryLayer, numRounds)}
	for j := 0; j < numRounds; j++ {
		Nj := len(layers[j])
		base := s % (Nj / 2)

		path, err := trees[j].OpenProof(base)
		if err != nil {
			return Query{}, fmt.Errorf("layer %d OpenProof base=%d: %w", j, base, err)
		}

		q.Layers[j] = QueryLayer{
			LeafP: layers[j][base],
			LeafQ: layers[j][base+Nj/2],
			Path:  path,
		}
	}
	return q, nil
}

// checkQuery verifies one multi-degree FRI query:
//   - Merkle proofs for all level polynomial openings
//   - Merkle proofs and fold consistency for the running-polynomial path
//   - Batching consistency at each level introduction round
//
// levelQueriesForQuery[l-1] holds openings for levels[l] (l 0-based index offset by 1).
// levelRoots[l-1][i] is the Merkle root of levels[l].Evals[i] (l 0-based offset by 1).
// gammas[l] is the batching challenge for levels[l] (1-based; gammas[0] unused).
func checkQuery(s int, fq Query,
	levelQueriesForQuery []QueriesAtLevel,
	levelRoots [][][]byte,
	levelAtRound map[int]int,
	gammas []koalabear.Element,
	roots [][]byte,
	finalPoly []koalabear.Element,
	alphas []koalabear.Element,
	p Params) error {

	// Verify Merkle proofs for all level polynomial openings.
	for lIdx, lqList := range levelQueriesForQuery {
		for i, ld := range lqList {
			leafData := append(ld.LeafP.Marshal(), ld.LeafQ.Marshal()...)
			if !merkle.Verify(levelRoots[lIdx][i], ld.Path, leafData, p.LeafHasher, p.NodeHasher) {
				return fmt.Errorf("level %d poly %d: Merkle proof invalid", lIdx+1, i)
			}
		}
	}

	// Verify running-polynomial fold path with batching consistency checks.
	for j := 0; j < p.numRounds; j++ {
		Nj := int(p.domainsLight[j].cardinality)
		base := s % (Nj / 2)
		layer := fq.Layers[j]

		leafData := append(layer.LeafP.Marshal(), layer.LeafQ.Marshal()...)
		if !merkle.Verify(roots[j], layer.Path, leafData, p.LeafHasher, p.NodeHasher) {
			return fmt.Errorf("round %d: Merkle proof invalid (base=%d)", j, base)
		}

		// Fold: expected = (LeafP+LeafQ)/2 + α*(LeafP-LeafQ)/(2·ωⱼ^base).
		var xInv, sum, diff, expected koalabear.Element
		xInv.Exp(p.domainsLight[j].generator, big.NewInt(int64(Nj-base)))
		sum.Add(&layer.LeafP, &layer.LeafQ)
		sum.Mul(&sum, &p.invTwo)
		diff.Sub(&layer.LeafP, &layer.LeafQ)
		diff.Mul(&diff, &p.invTwo)
		diff.Mul(&diff, &xInv)
		diff.Mul(&diff, &alphas[j])
		expected.Add(&sum, &diff)

		if j < p.numRounds-1 {
			Nj1 := Nj / 2
			nextLayer := fq.Layers[j+1]
			isLeafP := base < Nj1/2

			// expectedNext = fold output + level contributions at round j+1 (if any).
			var expectedNext koalabear.Element
			expectedNext.Set(&expected)

			if li, ok := levelAtRound[j+1]; ok {
				gamma := gammas[li]
				var gammaPow koalabear.Element
				gammaPow.Set(&gamma)
				for _, ld := range levelQueriesForQuery[li-1] {
					var leafVal koalabear.Element
					if isLeafP {
						leafVal.Set(&ld.LeafP)
					} else {
						leafVal.Set(&ld.LeafQ)
					}
					var term koalabear.Element
					term.Mul(&leafVal, &gammaPow)
					expectedNext.Add(&expectedNext, &term)
					gammaPow.Mul(&gammaPow, &gamma)
				}
			}

			if isLeafP {
				if !expectedNext.Equal(&nextLayer.LeafP) {
					return fmt.Errorf("round %d: folded value mismatch at round %d LeafP", j, j+1)
				}
			} else {
				if !expectedNext.Equal(&nextLayer.LeafQ) {
					return fmt.Errorf("round %d: folded value mismatch at round %d LeafQ", j, j+1)
				}
			}
		} else {
			finalVal := finalPoly[s%len(finalPoly)]
			if !expected.Equal(&finalVal) {
				return fmt.Errorf("round %d (final): folded value does not match FinalPoly", j)
			}
		}
	}

	return nil
}
