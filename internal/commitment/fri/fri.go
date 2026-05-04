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
	"errors"
	"fmt"
	"sort"

	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/gnark-crypto/utils"
	"github.com/consensys/loom/internal/merkle"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/internal/reedsolomon"
)

var ErrInvalidPolynomial = errors.New("fri commitment: invalid polynomial")

const DefaultFRIMinBlowupFactor = 2
const DefaultFRIFoldingFactor = 8
const DefaultFRIFinalPolynomialMaxLen = 16
const DefaultFRINumQueries = 20

// fiat-shamir challenge name strings for the FRI-internal protocol.
const (
	friCombineChallenge      = "fri@combine"
	friLayerChallengeFmt     = "fri@layer_%d"
	friFinalChallenge        = "fri@final"
	friQueryChallengeFmt     = "fri@query_%d"
	friGrindingSeedChallenge = "fri@grinding_seed"
	friGrindingNonceName     = "fri@grinding_nonce"
	friOpenChallengeFmt      = "fri@open_%d"
)

// Config collects parameters governing the FRI protocol.
type Config struct {
	// MinBlowupFactor is the minimum acceptable Reed-Solomon rate expansion
	// factor (ρ = 1/MinBlowupFactor). It is a sanity-check floor: every Commit
	// requires CodewordDomainSize ≥ MinBlowupFactor · max(n_i). When
	// CodewordDomainSize is left at zero, the first Commit also uses
	// MinBlowupFactor to derive the codeword domain size from the input
	// polynomial sizes. Default: 2.
	MinBlowupFactor int
	// FoldingFactor k: each FRI round reduces the domain size by k.
	// Must be a power of two. Default: 8.
	FoldingFactor int
	// FinalPolynomialMaxLen: stop folding when the codeword is at most this long.
	// The final codeword is transmitted in full. Default: 16.
	FinalPolynomialMaxLen int
	// NumQueries is the number of random spot-check positions. Default: 20.
	NumQueries int
	// CodewordDomainSize is the actual codeword domain size N every oracle is
	// encoded at. All oracles in a single Committer share this N (required for
	// the DEEP combiner to operate on a single joint domain). When zero, the
	// first Commit pins it to MinBlowupFactor · max(poly sizes in that Commit);
	// subsequent Commits reuse the same value. When set explicitly, it must
	// satisfy CodewordDomainSize ≥ MinBlowupFactor · max(n_i) for every Commit.
	CodewordDomainSize uint64
	// GrindingBits is the number of leading zero bits required from the
	// SHA256 hash of (transcript-derived seed ‖ nonce) before query indices
	// are drawn. Each bit halves the per-bit query soundness cost. Default 0
	// disables grinding.
	GrindingBits int
}

func (c *Config) applyDefaults() {
	if c.MinBlowupFactor == 0 {
		c.MinBlowupFactor = DefaultFRIMinBlowupFactor
	}
	if c.FoldingFactor == 0 {
		c.FoldingFactor = DefaultFRIFoldingFactor
	}
	if c.FinalPolynomialMaxLen == 0 {
		c.FinalPolynomialMaxLen = DefaultFRIFinalPolynomialMaxLen
	}
	if c.NumQueries == 0 {
		c.NumQueries = DefaultFRINumQueries
	}
}

// Commitment holds the metadata for one committed oracle (one Commit call).
type Commitment struct {
	// Root is the Merkle root of the Reed-Solomon codeword committed by the prover.
	Root []byte
	// BaseDomainSize is n where the prover's polynomial is initially given by its
	// values on a domain of size n.
	BaseDomainSize uint64
	// CodewordDomainSize is N = blowup · n, the size of the evaluation domain.
	CodewordDomainSize uint64
	// PolynomialNames records the committed polynomials in the deterministic
	// order used to build the batched codeword Merkle tree. The number of
	// polynomials is len(PolynomialNames).
	PolynomialNames []string
	// PolynomialSizes records each batched polynomial's base-domain size before
	// Reed-Solomon extension.
	PolynomialSizes []uint64
}

type committedOracle struct {
	Commitment
	// Codewords holds the RS codewords (Lagrange on codeword domain) for each poly.
	Codewords map[string]poly.Polynomial
	// Coefficients holds the canonical-form coefficient vector (length n_i) for
	// each polynomial, retained from RS encoding so that Open can evaluate at
	// arbitrary points via Horner in O(n) instead of O(N) barycentric on the
	// codeword.
	Coefficients map[string]poly.Polynomial
	Tree         *merkle.Tree
}

// openRequest records an opening claim. The y value is computed eagerly
// at Open time (Horner on the canonical coefficients) so that the claim
// can be transcript-bound immediately and returned to the caller.
type openRequest struct {
	oracleI int
	polyI   int // index into committedOracle.PolynomialNames
	name    string
	point   koalabear.Element
	y       koalabear.Element
}

// deepPoint is collected by Verifier.BindCommitment (auto-DEEP) and
// Verifier.Open (user opens) so Verify can reconstruct the same
// per-polynomial DEEP-quotient structure the prover built.
type deepPoint struct {
	oracleI int
	name    string
	point   koalabear.Element
}

// Verifier mirrors the prover's Fiat-Shamir transcript replaying and acts
// as a cursored reader over the proof's opened values. The caller drives it
// with BindCommitment + Open (in lockstep with the prover's Commit + Open
// calls); each Open binds the claim to the transcript and returns the
// (still-unverified) value the prover supplied. The final cryptographic
// check happens in Verify.
type Verifier struct {
	Transcript *fiatshamir.Transcript
	// Config holds the verifier's expected protocol parameters. Verify rejects
	// any proof whose self-described parameters fall below this floor.
	Config Config

	proof Proof

	// deepPoints accumulates BindCommitment-derived auto-DEEP claims and
	// user Open claims in registration order — exactly mirroring the
	// prover-side openRequests sequence.
	deepPoints []deepPoint
	// cursor is the next OpenedValues index a BindCommitment auto-DEEP
	// entry (during transcript replay) or a user Open call will consume.
	// It also doubles as the index used to derive the transcript challenge
	// name "fri@open_<cursor>" inside bindOpenClaim.
	cursor int
	// oracleByPoly maps a polynomial name to its oracle index, used by Open
	// to look up (oracleI, polyI) for index-form transcript binding.
	oracleByPoly map[string]int

	oracleCount int
}

// Committer is a FRI-backed commitment scheme.
type Committer struct {
	leafHasher       merkle.LeafHasher
	nodeHasher       merkle.NodeHasher
	transcript       *fiatshamir.Transcript
	config           Config
	committedOracles []committedOracle
	polynomials      map[string]int // polynomial name → oracle index
	openRequests     []openRequest
}

func NewCommitter(transcript *fiatshamir.Transcript, config Config, leafHasher merkle.LeafHasher, nodeHasher merkle.NodeHasher) Committer {
	config.applyDefaults()
	return Committer{
		leafHasher:       leafHasher,
		nodeHasher:       nodeHasher,
		transcript:       transcript,
		config:           config,
		committedOracles: make([]committedOracle, 0),
		polynomials:      make(map[string]int),
		openRequests:     make([]openRequest, 0),
	}
}

// NewVerifier constructs a fresh verifier bound to a transcript, the proof
// to be checked, and the verifier's expected Config. Open and BindCommitment
// read claimed values from the embedded proof; Verify cross-checks each
// against the FRI proximity argument.
//
// Each non-zero field of config acts as a floor: Verify rejects proofs whose
// self-described parameters fall below the configured value. A zero field
// means "no floor for this parameter". The verifier infers all protocol
// parameters (folding factor, final polynomial length, etc.) from the proof
// data itself and does not need config defaults for operational correctness.
func NewVerifier(transcript *fiatshamir.Transcript, config Config, proof Proof) Verifier {
	return Verifier{
		Transcript:   transcript,
		Config:       config,
		proof:        proof,
		oracleByPoly: make(map[string]int),
	}
}

// Commit encodes the named polynomials via Reed-Solomon and builds one Merkle
// tree over the coset-grouped codewords (k evaluations per leaf).
func (c *Committer) Commit(challengeName string, polys map[string]poly.Polynomial) error {
	if len(polys) == 0 {
		return nil
	}

	names := make([]string, 0, len(polys))
	for name := range polys {
		if name == "" {
			return fmt.Errorf("%w: empty polynomial name", ErrInvalidPolynomial)
		}
		names = append(names, name)
	}
	sort.Strings(names)

	// Polynomial names are globally unique across a Committer. Re-using a name
	// across Commit calls would alias the prover's name → oracle map and the
	// verifier's deepPoints lookup to different oracles — a soundness gap.
	for _, name := range names {
		if _, exists := c.polynomials[name]; exists {
			return fmt.Errorf("%w: polynomial name %q already committed in a prior Commit call",
				ErrInvalidPolynomial, name)
		}
	}

	orderedPolys := make([]poly.Polynomial, len(names))
	var maxBaseDomain uint64
	for i, name := range names {
		pol := polys[name]
		orderedPolys[i] = pol
		size := uint64(len(pol))
		if size == 0 {
			return fmt.Errorf("%w: zero-length polynomial", ErrInvalidPolynomial)
		}
		if size > maxBaseDomain {
			maxBaseDomain = size
		}
	}
	if c.config.CodewordDomainSize == 0 {
		c.config.CodewordDomainSize = uint64(c.config.MinBlowupFactor) * maxBaseDomain
	}
	if c.config.CodewordDomainSize < uint64(c.config.MinBlowupFactor)*maxBaseDomain {
		return fmt.Errorf("%w: codeword domain %d below MinBlowupFactor·n = %d",
			ErrInvalidPolynomial, c.config.CodewordDomainSize,
			uint64(c.config.MinBlowupFactor)*maxBaseDomain)
	}
	codewordDomainSize := c.config.CodewordDomainSize
	if codewordDomainSize == 0 {
		return fmt.Errorf("%w: zero codeword domain", ErrInvalidPolynomial)
	}
	if int(codewordDomainSize) < c.config.FoldingFactor {
		return fmt.Errorf("%w: codeword domain %d is smaller than folding factor %d",
			ErrInvalidPolynomial, codewordDomainSize, c.config.FoldingFactor)
	}
	encoder := reedsolomon.Encoder{Domain: fft.NewDomain(codewordDomainSize)}

	codewords, canonicals := c.encode(orderedPolys, &encoder)
	k := c.config.FoldingFactor
	tree, err := buildCosetMerkleTree(codewords, k, c.leafHasher, c.nodeHasher)
	if err != nil {
		return err
	}

	meta := Commitment{
		Root:               tree.Root(),
		CodewordDomainSize: codewordDomainSize,
		PolynomialNames:    append([]string(nil), names...),
		PolynomialSizes:    make([]uint64, len(orderedPolys)),
		BaseDomainSize:     maxBaseDomain,
	}
	for i, pol := range orderedPolys {
		meta.PolynomialSizes[i] = uint64(len(pol))
	}

	oracleI := len(c.committedOracles)
	codewordsByName := make(map[string]poly.Polynomial, len(names))
	coeffsByName := make(map[string]poly.Polynomial, len(names))
	for i, name := range names {
		codewordsByName[name] = codewords[i]
		coeffsByName[name] = canonicals[i]
	}
	c.committedOracles = append(c.committedOracles, committedOracle{
		Commitment:   meta,
		Codewords:    codewordsByName,
		Coefficients: coeffsByName,
		Tree:         tree,
	})
	for _, name := range names {
		c.polynomials[name] = oracleI
	}
	// Transcript registration order is strict (each ComputeChallenge requires
	// the immediately-preceding registered challenge to have been computed
	// first), so we register and compute every challenge in lockstep — no
	// upfront batch declaration. Order:
	//   for each polynomial p:
	//     NewChallenge(deepName(p))
	//     Bind(deepName(p), root); ComputeChallenge(deepName(p))
	//     Open(p, deepPt) registers + binds + computes fri@open_<i>
	//   NewChallenge(challengeName)
	//   Bind(challengeName, root); ComputeChallenge(challengeName)
	for _, name := range names {
		dcn := deepChallengeName(challengeName, name)
		if err := c.transcript.NewChallenge(dcn); err != nil {
			return err
		}
		if err := c.transcript.Bind(dcn, meta.Root); err != nil {
			return err
		}
		deepBytes, err := c.transcript.ComputeChallenge(dcn)
		if err != nil {
			return err
		}
		var deepPt koalabear.Element
		deepPt.SetBytes(deepBytes)
		if _, err := c.Open(name, deepPt); err != nil {
			return err
		}
	}
	if err := c.transcript.NewChallenge(challengeName); err != nil {
		return err
	}
	if err := c.transcript.Bind(challengeName, meta.Root); err != nil {
		return err
	}
	if _, err := c.transcript.ComputeChallenge(challengeName); err != nil {
		return err
	}
	return nil
}

// Open evaluates the named polynomial at point, binds the claim
// (oracleI, polyI, point, y) to the transcript under a sequential
// challenge name, registers the claim for the eventual FRI proximity
// proof, and returns y. The point must lie outside the codeword domain L
// (the rejection check is point^N == 1).
//
// Unlike Commit, Open is transcript-noisy: every open immediately enters
// the Fiat-Shamir state, so outer protocols may safely use the returned
// value to derive subsequent challenges. The final FRI proximity check
// in Prove cross-validates that y is consistent with the committed
// codeword.
func (c *Committer) Open(name string, point koalabear.Element) (koalabear.Element, error) {
	oracleI, ok := c.polynomials[name]
	if !ok {
		return koalabear.Element{}, errors.New("fri: invalid polynomial reference")
	}
	oracle := &c.committedOracles[oracleI]
	if isInDomain(point, oracle.CodewordDomainSize) {
		return koalabear.Element{}, fmt.Errorf("fri: Open: point lies in the codeword domain L")
	}
	polyI := -1
	for i, n := range oracle.PolynomialNames {
		if n == name {
			polyI = i
			break
		}
	}
	if polyI < 0 {
		// Unreachable: c.polynomials[name] === oracleI implies the name
		// is in oracle.PolynomialNames.
		return koalabear.Element{}, fmt.Errorf("fri: Open: %q not in oracle %d", name, oracleI)
	}

	// Eager Horner evaluation on the cached canonical coefficients.
	y := poly.EvaluateCanonical(oracle.Coefficients[name], point)

	// Bind the claim to the transcript: index-form (oracleI, polyI, point, y).
	if err := bindOpenClaim(c.transcript, len(c.openRequests), oracleI, polyI, point, y); err != nil {
		return koalabear.Element{}, err
	}

	c.openRequests = append(c.openRequests, openRequest{
		oracleI: oracleI,
		polyI:   polyI,
		name:    name,
		point:   point,
		y:       y,
	})
	return y, nil
}

// isInDomain reports whether x is a power of the primitive N-th root of
// unity that generates the codeword domain L (i.e., x^N == 1).
func isInDomain(x koalabear.Element, N uint64) bool {
	if N == 0 {
		return false
	}
	xN := elementPow(x, int(N))
	return xN.IsOne()
}

// bindOpenClaim is shared between prover-side Open and verifier-side Open
// to keep the transcript binding format identical. The challenge name is
// fri@open_<callIdx>; the bound bytes are
// [oracleI uint64 LE][polyI uint64 LE][point.Marshal()][y.Marshal()].
func bindOpenClaim(transcript *fiatshamir.Transcript, callIdx, oracleI, polyI int, point, y koalabear.Element) error {
	name := fmt.Sprintf(friOpenChallengeFmt, callIdx)
	if err := transcript.NewChallenge(name); err != nil {
		return err
	}
	buf := make([]byte, 16+2*koalabear.Bytes)
	binary.LittleEndian.PutUint64(buf[0:8], uint64(oracleI))
	binary.LittleEndian.PutUint64(buf[8:16], uint64(polyI))
	copy(buf[16:16+koalabear.Bytes], point.Marshal())
	copy(buf[16+koalabear.Bytes:], y.Marshal())
	if err := transcript.Bind(name, buf); err != nil {
		return err
	}
	if _, err := transcript.ComputeChallenge(name); err != nil {
		return err
	}
	return nil
}

// Prove produces a full Proof covering all registered Open requests.
// All committed oracles must have the same CodewordDomainSize.
func (c *Committer) Prove() (Proof, error) {
	commitments := make([]Commitment, len(c.committedOracles))
	for i, oracle := range c.committedOracles {
		commitments[i] = oracle.Commitment
	}

	if len(c.openRequests) == 0 {
		return Proof{Commitments: commitments}, nil
	}

	// All oracles must share the same codeword domain.
	N := int(c.committedOracles[0].CodewordDomainSize)
	for i, oracle := range c.committedOracles {
		if int(oracle.CodewordDomainSize) != N {
			return Proof{}, fmt.Errorf("fri: oracle %d has codeword domain %d, want %d",
				i, oracle.CodewordDomainSize, N)
		}
	}

	k := c.config.FoldingFactor

	// 1. Read claimed values directly from openRequests — they were computed
	// (and transcript-bound) at Open time.
	bigDomain := fft.NewDomain(uint64(N))
	openedValues := make([]koalabear.Element, len(c.openRequests))
	for r, req := range c.openRequests {
		openedValues[r] = req.y
	}

	// 2. Derive combiner challenge β from the transcript.
	if err := c.transcript.NewChallenge(friCombineChallenge); err != nil {
		return Proof{}, err
	}
	betaBytes, err := c.transcript.ComputeChallenge(friCombineChallenge)
	if err != nil {
		return Proof{}, err
	}
	var beta koalabear.Element
	beta.SetBytes(betaBytes)

	// 3. Build DEEP-combined codeword q.
	q, err := buildDEEPCombiner(c.openRequests, openedValues, c.committedOracles, beta, N)
	if err != nil {
		return Proof{}, err
	}

	// 4. FRI commit phase: fold q repeatedly, committing each layer.
	layerTrees, layerCodewords, layerRoots, finalCodeword, err :=
		runFRICommitPhase(q, c.transcript, c.config, bigDomain.Generator, c.leafHasher, c.nodeHasher)
	if err != nil {
		return Proof{}, err
	}

	// 5. Bind final polynomial to the transcript so query indices depend on it.
	if err := c.transcript.NewChallenge(friFinalChallenge); err != nil {
		return Proof{}, err
	}
	if err := c.transcript.Bind(friFinalChallenge, marshalElements(finalCodeword)); err != nil {
		return Proof{}, err
	}
	if _, err := c.transcript.ComputeChallenge(friFinalChallenge); err != nil {
		return Proof{}, err
	}

	// 6. Optional proof-of-work grinding. Find a nonce so SHA256(seed ‖ nonce)
	// has at least GrindingBits leading zeros, then bind it.
	var grindingNonce uint64
	if c.config.GrindingBits > 0 {
		grindingNonce, err = grindAndBind(c.transcript, c.config.GrindingBits)
		if err != nil {
			return Proof{}, err
		}
	}

	// 7. Derive query leaf indices in [0, N/k).
	nLeaves := N / k
	queryIndices, err := deriveQueryIndices(c.transcript, c.config.NumQueries, nLeaves)
	if err != nil {
		return Proof{}, err
	}

	// 7. Build query proofs (Merkle paths + coset data).
	oracleOpenings, oracleCosetData, layerOpenings, layerCosetData, err :=
		buildQueryProofs(queryIndices, c.committedOracles, layerTrees, layerCodewords, k)
	if err != nil {
		return Proof{}, err
	}

	// BlowupFactor is computed from the actual ratio of codeword to base
	// domain. This may exceed Config.MinBlowupFactor when small polynomials
	// were lifted to the FoldingFactor floor.
	var blowup int
	if base := c.committedOracles[0].BaseDomainSize; base > 0 {
		blowup = int(c.committedOracles[0].CodewordDomainSize / base)
	}

	return Proof{
		Commitments:           commitments,
		LayerCommitments:      layerRoots,
		FinalPolynomial:       finalCodeword,
		OpenedValues:          openedValues,
		QueryIndices:          queryIndices,
		OracleOpenings:        oracleOpenings,
		OracleCosetData:       oracleCosetData,
		LayerOpenings:         layerOpenings,
		LayerCosetData:        layerCosetData,
		GrindingNonce:         grindingNonce,
		NumQueries:            c.config.NumQueries,
		FoldingFactor:         c.config.FoldingFactor,
		FinalPolynomialMaxLen: c.config.FinalPolynomialMaxLen,
		BlowupFactor:          blowup,
		GrindingBits:          c.config.GrindingBits,
	}, nil
}

// runFRICommitPhase performs successive k-way FRI folds on q, committing each
// layer to the transcript. Returns the trees, raw codewords, Merkle roots, and
// the final (un-folded) codeword.
func runFRICommitPhase(
	q []koalabear.Element,
	transcript *fiatshamir.Transcript,
	config Config,
	domainGen koalabear.Element,
	lh merkle.LeafHasher,
	nh merkle.NodeHasher,
) (
	layerTrees []*merkle.Tree,
	layerCodewords [][]koalabear.Element,
	layerRoots [][]byte,
	finalCodeword []koalabear.Element,
	err error,
) {
	k := config.FoldingFactor
	g := q
	gen := domainGen

	for len(g) > config.FinalPolynomialMaxLen && len(g) >= k {
		var layerTree *merkle.Tree
		layerTree, err = buildLayerMerkleTree(g, k, lh, nh)
		if err != nil {
			return
		}
		root := layerTree.Root()
		layerTrees = append(layerTrees, layerTree)
		layerCodewords = append(layerCodewords, g)
		layerRoots = append(layerRoots, root)

		layerI := len(layerRoots) - 1
		challengeName := fmt.Sprintf(friLayerChallengeFmt, layerI)
		if err = transcript.NewChallenge(challengeName); err != nil {
			return
		}
		if err = transcript.Bind(challengeName, root); err != nil {
			return
		}
		var alphaBytes []byte
		alphaBytes, err = transcript.ComputeChallenge(challengeName)
		if err != nil {
			return
		}
		var alpha koalabear.Element
		alpha.SetBytes(alphaBytes)

		g = foldLayer(g, alpha, gen, k)
		gen = elementPow(gen, k)
	}
	finalCodeword = g
	return
}

// BindCommitment mirrors a prover-side Committer.Commit call: it advances the
// transcript past the next oracle's Merkle root and per-polynomial auto-DEEP
// challenges, derives each auto-DEEP point, and binds the corresponding
// claimed value (read from the embedded proof) to the transcript via the
// same index-form scheme used by Open. The oracle index is the order of
// BindCommitment calls (same as the order of prover-side Commit calls).
func (v *Verifier) BindCommitment(oracleName string) error {
	if v.oracleCount >= len(v.proof.Commitments) {
		return fmt.Errorf("fri: BindCommitment(%q): no more commitments in proof (have %d)", oracleName, len(v.proof.Commitments))
	}
	commitment := v.proof.Commitments[v.oracleCount]
	oracleI := v.oracleCount
	v.oracleCount++

	// Mirror the prover-side check: polynomial names must be globally unique
	// across all BindCommitment calls. Otherwise Open — which matches by
	// name — could silently target the wrong oracle.
	for _, name := range commitment.PolynomialNames {
		if _, dup := v.oracleByPoly[name]; dup {
			return fmt.Errorf("fri: BindCommitment: polynomial name %q already bound in a prior commitment", name)
		}
	}
	for _, name := range commitment.PolynomialNames {
		v.oracleByPoly[name] = oracleI
	}

	// Strict positional Fiat-Shamir order — see the matching comment in
	// Committer.Commit for the required registration sequence.
	for polyI, name := range commitment.PolynomialNames {
		dcn := deepChallengeName(oracleName, name)
		if err := v.Transcript.NewChallenge(dcn); err != nil {
			return err
		}
		if err := v.Transcript.Bind(dcn, commitment.Root); err != nil {
			return err
		}
		deepBytes, err := v.Transcript.ComputeChallenge(dcn)
		if err != nil {
			return err
		}
		var pt koalabear.Element
		pt.SetBytes(deepBytes)

		if v.cursor >= len(v.proof.OpenedValues) {
			return fmt.Errorf("fri: BindCommitment: proof.OpenedValues exhausted (cursor=%d, len=%d)",
				v.cursor, len(v.proof.OpenedValues))
		}
		y := v.proof.OpenedValues[v.cursor]
		if err := bindOpenClaim(v.Transcript, v.cursor, oracleI, polyI, pt, y); err != nil {
			return err
		}
		v.deepPoints = append(v.deepPoints, deepPoint{oracleI: oracleI, name: name, point: pt})
		v.cursor++
	}
	if err := v.Transcript.NewChallenge(oracleName); err != nil {
		return err
	}
	if err := v.Transcript.Bind(oracleName, commitment.Root); err != nil {
		return err
	}
	if _, err := v.Transcript.ComputeChallenge(oracleName); err != nil {
		return err
	}
	return nil
}

// Open consumes the next opened value from the proof's OpenedValues queue,
// binds the claim (oracleI, polyI, point, value) to the transcript, and
// returns the (still-unverified) value. Callers may safely use the returned
// value to derive subsequent Fiat-Shamir challenges in an outer protocol;
// the transcript binding ensures the prover cannot change a value after the
// fact, and the final Verify call rejects the proof if any opened value is
// inconsistent with the FRI commitment.
//
// Open calls must occur in the same (name, point) sequence as the prover's
// Committer.Open calls. Divergence is detected at the next ComputeChallenge
// boundary as a transcript mismatch.
func (v *Verifier) Open(name string, point koalabear.Element) (koalabear.Element, error) {
	oracleI, ok := v.oracleByPoly[name]
	if !ok {
		return koalabear.Element{}, fmt.Errorf("fri: Open: polynomial %q not bound to any oracle", name)
	}
	commitment := v.proof.Commitments[oracleI]
	if isInDomain(point, commitment.CodewordDomainSize) {
		return koalabear.Element{}, fmt.Errorf("fri: Open: point lies in the codeword domain L")
	}
	polyI := -1
	for i, n := range commitment.PolynomialNames {
		if n == name {
			polyI = i
			break
		}
	}
	if polyI < 0 {
		return koalabear.Element{}, fmt.Errorf("fri: Open: %q not in oracle %d", name, oracleI)
	}
	if v.cursor >= len(v.proof.OpenedValues) {
		return koalabear.Element{}, fmt.Errorf("fri: Open: proof.OpenedValues exhausted (cursor=%d, len=%d)",
			v.cursor, len(v.proof.OpenedValues))
	}
	y := v.proof.OpenedValues[v.cursor]
	if err := bindOpenClaim(v.Transcript, v.cursor, oracleI, polyI, point, y); err != nil {
		return koalabear.Element{}, err
	}
	v.deepPoints = append(v.deepPoints, deepPoint{oracleI: oracleI, name: name, point: point})
	v.cursor++
	return y, nil
}

func deepChallengeName(commitmentChallengeName, polynomialName string) string {
	return fmt.Sprintf("%s@deep_%s", commitmentChallengeName, polynomialName)
}

// encode RS-encodes each input polynomial and returns the codewords alongside
// their canonical-form coefficient vectors (length n_i, kept for fast Horner
// evaluation in Open). The Lagrange-form input → canonical[n] → zero-pad →
// Lagrange-form codeword pipeline already computes the canonical form
// transiently inside reedsolomon.Encoder.Encode; this version inlines the
// pipeline so we can capture the canonical step.
func (c *Committer) encode(polys []poly.Polynomial, encoder *reedsolomon.Encoder) (codewords, canonicals []poly.Polynomial) {
	domainsPool := map[int]*fft.Domain{}
	N := encoder.Domain.Cardinality
	codewords = make([]poly.Polynomial, len(polys))
	canonicals = make([]poly.Polynomial, len(polys))
	for i, pol := range polys {
		n := len(pol)
		d, ok := domainsPool[n]
		if !ok {
			d = fft.NewDomain(uint64(n))
			domainsPool[n] = d
		}
		// Lagrange[n] → canonical[n] (bit-reversed) → un-reverse → canonical normal.
		buf := make(poly.Polynomial, N)
		copy(buf, pol)
		d.FFTInverse(buf[:n], fft.DIF)
		utils.BitReverse(buf[:n])

		// Snapshot the canonical-form coefficients before the FFT step
		// destroys them by overwriting the buffer with codeword values.
		canon := make(poly.Polynomial, n)
		copy(canon, buf[:n])
		canonicals[i] = canon

		// canonical[n] (zero-padded to N) → Lagrange[N] (bit-reversed) → normal.
		encoder.Domain.FFT(buf, fft.DIF)
		utils.BitReverse(buf)
		codewords[i] = buf
	}
	return
}

// buildCosetMerkleTree builds a Merkle tree with N/k leaves over the batched
// codewords. Leaf j contains all K polynomials evaluated at the k coset
// positions {j, j+N/k, j+2·(N/k), …, j+(k-1)·(N/k)}.
//
// Byte layout of leaf j:
//
//	poly_0[j], poly_0[j+N/k], …, poly_0[j+(k-1)·(N/k)],
//	poly_1[j], …, poly_{K-1}[j+(k-1)·(N/k)]
func buildCosetMerkleTree(codewords []poly.Polynomial, k int, lh merkle.LeafHasher, nh merkle.NodeHasher) (*merkle.Tree, error) {
	N := len(codewords[0])
	nLeaves := N / k
	K := len(codewords)
	tree, err := merkle.New(nLeaves, lh, nh)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, koalabear.Bytes*K*k)
	for j := range nLeaves {
		for polyI := range K {
			for t := range k {
				pos := j + t*nLeaves
				copy(buf[(polyI*k+t)*koalabear.Bytes:], codewords[polyI][pos].Marshal())
			}
		}
		if err := tree.BuildIthLeaf(buf, j); err != nil {
			return nil, err
		}
	}
	tree.BuildNodes()
	return tree, nil
}

// buildLayerMerkleTree builds a Merkle tree for a single FRI layer codeword g.
// It has len(g)/k leaves; leaf j contains k values at the coset
// {j, j+N/k, …, j+(k-1)·(N/k)}.
func buildLayerMerkleTree(g []koalabear.Element, k int, lh merkle.LeafHasher, nh merkle.NodeHasher) (*merkle.Tree, error) {
	N := len(g)
	nLeaves := N / k
	tree, err := merkle.New(nLeaves, lh, nh)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, koalabear.Bytes*k)
	for j := range nLeaves {
		for t := range k {
			pos := j + t*nLeaves
			copy(buf[t*koalabear.Bytes:], g[pos].Marshal())
		}
		if err := tree.BuildIthLeaf(buf, j); err != nil {
			return nil, err
		}
	}
	tree.BuildNodes()
	return tree, nil
}

// marshalElements serialises a slice of field elements into a byte slice.
func marshalElements(elems []koalabear.Element) []byte {
	buf := make([]byte, len(elems)*koalabear.Bytes)
	for i, e := range elems {
		copy(buf[i*koalabear.Bytes:], e.Marshal())
	}
	return buf
}

// deriveQueryIndices derives m leaf indices in [0, nLeaves) from the transcript.
// nLeaves must be a power of two.
func deriveQueryIndices(transcript *fiatshamir.Transcript, m, nLeaves int) ([]uint64, error) {
	indices := make([]uint64, m)
	mask := uint64(nLeaves - 1)
	for i := range m {
		name := fmt.Sprintf(friQueryChallengeFmt, i)
		if err := transcript.NewChallenge(name); err != nil {
			return nil, err
		}
		b, err := transcript.ComputeChallenge(name)
		if err != nil {
			return nil, err
		}
		indices[i] = binary.BigEndian.Uint64(b[:8]) & mask
	}
	return indices, nil
}

// Proof is the full FRI proximity proof covering all registered openings.
// It is self-describing: the verifier extracts every protocol parameter from
// the proof and checks each against its own configured floor (see
// Verifier.Verify) before performing the cryptographic checks.
type Proof struct {
	// Commitments are the oracle commitments sent by the prover before the FRI
	// query phase.
	Commitments []Commitment

	// LayerCommitments are the Merkle roots of successive folded FRI layers.
	// The verifier binds each root to the transcript to re-derive the folding
	// challenges.
	LayerCommitments [][]byte

	// FinalPolynomial is the small codeword transmitted in full after enough
	// foldings. Its length is ≤ Config.FinalPolynomialMaxLen.
	FinalPolynomial []koalabear.Element

	// OpenedValues[r] is the claimed evaluation f_r(z_r) for the r-th open
	// request, in registration order.
	//
	// The first `Σᵢ |PolynomialNames(Commitments[i])|` entries are the
	// auto-DEEP values bound by Verifier.BindCommitment; the remaining entries
	// are user Open calls in their registration order. Any divergence between
	// prover and verifier Open order causes the transcript to diverge at the
	// next ComputeChallenge call, so failures surface as a transcript mismatch
	// rather than as a downstream FRI rejection.
	OpenedValues []koalabear.Element

	// QueryIndices are the leaf indices used for spot checks, each in [0, N/k).
	// The verifier re-derives these from the transcript and checks they match.
	QueryIndices []uint64

	// OracleOpenings[q][i] is the Merkle opening proof from oracle i's tree at
	// the leaf corresponding to query q.
	OracleOpenings [][]merkle.Proof

	// OracleCosetData[q][i] has len(PolynomialNames_i) · k elements: for
	// polynomial polyIdx (in PolynomialNames order) and coset offset
	// t ∈ [0,k), data[polyIdx·k + t] = f_{polyIdx}(ω^{j + t·(N/k)}).
	OracleCosetData [][][]koalabear.Element

	// LayerOpenings[q][l] is the Merkle opening proof from FRI layer l's tree.
	LayerOpenings [][]merkle.Proof

	// LayerCosetData[q][l][t] = g_l(ω^{j_l + t·(N_l/k)}) for t ∈ [0,k).
	LayerCosetData [][][]koalabear.Element

	// GrindingNonce is the proof-of-work nonce. Meaningful only when the
	// prover's Config.GrindingBits > 0; otherwise it is left at zero and the
	// verifier ignores it.
	GrindingNonce uint64

	// NumQueries records the number of spot checks the prover ran.
	// The verifier rejects the proof if NumQueries < its configured floor.
	NumQueries int

	// FoldingFactor records the k used during the FRI commit phase.
	// The verifier requires an exact match against its configured FoldingFactor.
	FoldingFactor int

	// FinalPolynomialMaxLen records the prover's stop threshold for the fold
	// loop. The verifier rejects if the prover's threshold exceeds the
	// verifier's configured ceiling.
	FinalPolynomialMaxLen int

	// BlowupFactor records the Reed-Solomon rate inverse N/n used by the
	// prover. The verifier rejects if it is below MinBlowupFactor.
	BlowupFactor int

	// GrindingBits records the proof-of-work bit count the prover used.
	// The verifier rejects if the configured floor is non-zero and
	// GrindingBits < that floor.
	GrindingBits int
}
