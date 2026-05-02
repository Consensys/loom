package fri

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/loom/internal/merkle"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/internal/reedsolomon"
)

var ErrInvalidPolynomial = errors.New("fri commitment: invalid polynomial")

const DefaultFRIBlowupFactor = 2
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
)

// Config collects parameters governing the FRI protocol.
type Config struct {
	// BlowupFactor is the Reed-Solomon rate expansion factor (ρ = 1/BlowupFactor).
	// Default: 2.
	BlowupFactor int
	// FoldingFactor k: each FRI round reduces the domain size by k.
	// Must be a power of two. Default: 8.
	FoldingFactor int
	// FinalPolynomialMaxLen: stop folding when the codeword is at most this long.
	// The final codeword is transmitted in full. Default: 16.
	FinalPolynomialMaxLen int
	// NumQueries is the number of random spot-check positions. Default: 20.
	NumQueries int
	// MaxCodewordDomainSize, when non-zero, overrides the per-Commit codeword domain
	// so that every oracle is encoded at this common size. This is required when
	// multiple Commit calls cover polynomials of different degrees; all oracles
	// must share the same codeword domain for the DEEP combiner to operate on a
	// single joint domain. Should be set to BlowupFactor · max(poly sizes across
	// all commits).
	MaxCodewordDomainSize uint64
	// GrindingBits is the number of leading zero bits required from the
	// SHA256 hash of (transcript-derived seed ‖ nonce) before query indices
	// are drawn. Each bit halves the per-bit query soundness cost. Default 0
	// disables grinding.
	GrindingBits int
}

func (c *Config) applyDefaults() {
	if c.BlowupFactor == 0 {
		c.BlowupFactor = DefaultFRIBlowupFactor
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
	// NumPolynomials is the number of polynomials batched into this oracle.
	NumPolynomials int
	// PolynomialNames records the committed polynomials in the deterministic
	// order used to build the batched codeword Merkle tree.
	PolynomialNames []string
	// PolynomialSizes records each batched polynomial's base-domain size before
	// Reed-Solomon extension.
	PolynomialSizes []uint64
}

type committedOracle struct {
	Commitment
	// Codewords holds the RS codewords (Lagrange on codeword domain) for each poly.
	Codewords map[string]poly.Polynomial
	Tree      *merkle.Tree
}

// openRequest records a request to open a named polynomial at a point.
type openRequest struct {
	oracleI int
	name    string
	point   koalabear.Element
}

// deepPoint is collected by Verifier.Bind so VerifyOpening can reconstruct
// the same DEEP-quotient structure the prover used.
type deepPoint struct {
	oracleI int
	name    string
	point   koalabear.Element
}

// Verifier mirrors the prover's Fiat-Shamir transcript replaying and can
// subsequently verify an OpeningProof.
type Verifier struct {
	Transcript *fiatshamir.Transcript
	// GrindingBits, if non-zero, requires that the proof's GrindingNonce
	// produces at least this many leading zero bits when hashed against the
	// grinding seed derived from the transcript. Must be set to the same
	// value used by the prover-side Config.
	GrindingBits int
	deepPoints   []deepPoint
	oracleCount  int
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

func NewVerifier(transcript *fiatshamir.Transcript) Verifier {
	return Verifier{Transcript: transcript}
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
	codewordDomainSize := uint64(c.config.BlowupFactor) * maxBaseDomain
	if c.config.MaxCodewordDomainSize > 0 && c.config.MaxCodewordDomainSize > codewordDomainSize {
		codewordDomainSize = c.config.MaxCodewordDomainSize
	}
	if codewordDomainSize == 0 {
		return fmt.Errorf("%w: zero codeword domain", ErrInvalidPolynomial)
	}
	if int(codewordDomainSize) < c.config.FoldingFactor {
		return fmt.Errorf("%w: codeword domain %d is smaller than folding factor %d",
			ErrInvalidPolynomial, codewordDomainSize, c.config.FoldingFactor)
	}
	encoder := reedsolomon.Encoder{Domain: fft.NewDomain(codewordDomainSize)}

	codewords := c.encode(orderedPolys, &encoder)
	k := c.config.FoldingFactor
	tree, err := buildCosetMerkleTree(codewords, k, c.leafHasher, c.nodeHasher)
	if err != nil {
		return err
	}

	meta := Commitment{
		Root:               tree.Root(),
		CodewordDomainSize: codewordDomainSize,
		NumPolynomials:     len(orderedPolys),
		PolynomialNames:    append([]string(nil), names...),
		PolynomialSizes:    make([]uint64, len(orderedPolys)),
		BaseDomainSize:     maxBaseDomain,
	}
	for i, pol := range orderedPolys {
		meta.PolynomialSizes[i] = uint64(len(pol))
	}

	oracleI := len(c.committedOracles)
	codewordsByName := make(map[string]poly.Polynomial, len(names))
	for i, name := range names {
		codewordsByName[name] = codewords[i]
	}
	c.committedOracles = append(c.committedOracles, committedOracle{
		Commitment: meta,
		Codewords:  codewordsByName,
		Tree:       tree,
	})
	for _, name := range names {
		c.polynomials[name] = oracleI
	}
	if c.transcript == nil {
		return nil
	}
	for _, name := range names {
		if err := c.transcript.NewChallenge(deepChallengeName(challengeName, name)); err != nil {
			return err
		}
	}
	if err := c.transcript.NewChallenge(challengeName); err != nil {
		return err
	}
	if err := c.transcript.Bind(challengeName, meta.Root); err != nil {
		return err
	}
	for _, name := range names {
		dcn := deepChallengeName(challengeName, name)
		if err := c.transcript.Bind(dcn, meta.Root); err != nil {
			return err
		}
		deepBytes, err := c.transcript.ComputeChallenge(dcn)
		if err != nil {
			return err
		}
		var deepPt koalabear.Element
		deepPt.SetBytes(deepBytes)
		if err := c.Open(name, deepPt); err != nil {
			return err
		}
	}
	if _, err := c.transcript.ComputeChallenge(challengeName); err != nil {
		return err
	}
	return nil
}

// Commitment returns the commitment metadata for the oracle containing name.
func (c *Committer) Commitment(name string) Commitment {
	oracleI := c.polynomials[name]
	return c.committedOracles[oracleI].Commitment
}

// Open registers a request to open the named polynomial at point.
// The actual opening proof is produced by Prove.
func (c *Committer) Open(name string, point koalabear.Element) error {
	oracleI, ok := c.polynomials[name]
	if !ok {
		return errors.New("fri: invalid polynomial reference")
	}
	c.openRequests = append(c.openRequests, openRequest{oracleI: oracleI, name: name, point: point})
	return nil
}

// Prove produces a full OpeningProof covering all registered Open requests.
// All committed oracles must have the same CodewordDomainSize.
func (c *Committer) Prove() (OpeningProof, error) {
	commitments := make([]Commitment, len(c.committedOracles))
	for i, oracle := range c.committedOracles {
		commitments[i] = oracle.Commitment
	}

	if len(c.openRequests) == 0 || c.transcript == nil {
		return OpeningProof{Commitments: commitments}, nil
	}

	// All oracles must share the same codeword domain.
	N := int(c.committedOracles[0].CodewordDomainSize)
	for i, oracle := range c.committedOracles {
		if int(oracle.CodewordDomainSize) != N {
			return OpeningProof{}, fmt.Errorf("fri: oracle %d has codeword domain %d, want %d",
				i, oracle.CodewordDomainSize, N)
		}
	}

	k := c.config.FoldingFactor

	// 1. Compute claimed values: y_r = f_r(z_r) for each open request.
	bigDomain := fft.NewDomain(uint64(N))
	claimedValues := make([]koalabear.Element, len(c.openRequests))
	for r, req := range c.openRequests {
		codeword := c.committedOracles[req.oracleI].Codewords[req.name]
		claimedValues[r] = computeClaimedValue(codeword, bigDomain, req.point)
	}

	// 2. Derive combiner challenge β from the transcript.
	if err := c.transcript.NewChallenge(friCombineChallenge); err != nil {
		return OpeningProof{}, err
	}
	betaBytes, err := c.transcript.ComputeChallenge(friCombineChallenge)
	if err != nil {
		return OpeningProof{}, err
	}
	var beta koalabear.Element
	beta.SetBytes(betaBytes)

	// 3. Build DEEP-combined codeword q.
	q, err := buildDEEPCombiner(c.openRequests, claimedValues, c.committedOracles, beta, N)
	if err != nil {
		return OpeningProof{}, err
	}

	// 4. FRI commit phase: fold q repeatedly, committing each layer.
	layerTrees, layerCodewords, layerRoots, finalCodeword, err :=
		runFRICommitPhase(q, c.transcript, c.config, bigDomain.Generator, c.leafHasher, c.nodeHasher)
	if err != nil {
		return OpeningProof{}, err
	}

	// 5. Bind final polynomial to the transcript so query indices depend on it.
	if err := c.transcript.NewChallenge(friFinalChallenge); err != nil {
		return OpeningProof{}, err
	}
	if err := c.transcript.Bind(friFinalChallenge, marshalElements(finalCodeword)); err != nil {
		return OpeningProof{}, err
	}
	if _, err := c.transcript.ComputeChallenge(friFinalChallenge); err != nil {
		return OpeningProof{}, err
	}

	// 6. Optional proof-of-work grinding. Find a nonce so SHA256(seed ‖ nonce)
	// has at least GrindingBits leading zeros, then bind it.
	var grindingNonce uint64
	if c.config.GrindingBits > 0 {
		grindingNonce, err = grindAndBind(c.transcript, c.config.GrindingBits)
		if err != nil {
			return OpeningProof{}, err
		}
	}

	// 7. Derive query leaf indices in [0, N/k).
	nLeaves := N / k
	queryIndices, err := deriveQueryIndices(c.transcript, c.config.NumQueries, nLeaves)
	if err != nil {
		return OpeningProof{}, err
	}

	// 7. Build query proofs (Merkle paths + coset data).
	oracleOpenings, oracleCosetData, layerOpenings, layerCosetData, err :=
		buildQueryProofs(queryIndices, c.committedOracles, layerTrees, layerCodewords, k)
	if err != nil {
		return OpeningProof{}, err
	}

	return OpeningProof{
		Commitments:      commitments,
		LayerCommitments: layerRoots,
		FinalPolynomial:  finalCodeword,
		ClaimedValues:    claimedValues,
		QueryIndices:     queryIndices,
		OracleOpenings:   oracleOpenings,
		OracleCosetData:  oracleCosetData,
		LayerOpenings:    layerOpenings,
		LayerCosetData:   layerCosetData,
		GrindingNonce:    grindingNonce,
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

// Bind mirrors the prover's Commit transcript operations so the verifier's
// Fiat-Shamir state stays in sync. It also collects the DEEP evaluation points
// for use in VerifyOpening.
func (v *Verifier) Bind(challengeName string, commitment Commitment) error {
	if v.Transcript == nil {
		return nil
	}
	oracleI := v.oracleCount
	v.oracleCount++

	for _, name := range commitment.PolynomialNames {
		if err := v.Transcript.NewChallenge(deepChallengeName(challengeName, name)); err != nil {
			return err
		}
	}
	if err := v.Transcript.NewChallenge(challengeName); err != nil {
		return err
	}
	if err := v.Transcript.Bind(challengeName, commitment.Root); err != nil {
		return err
	}
	for _, name := range commitment.PolynomialNames {
		dcn := deepChallengeName(challengeName, name)
		if err := v.Transcript.Bind(dcn, commitment.Root); err != nil {
			return err
		}
		deepBytes, err := v.Transcript.ComputeChallenge(dcn)
		if err != nil {
			return err
		}
		var pt koalabear.Element
		pt.SetBytes(deepBytes)
		v.deepPoints = append(v.deepPoints, deepPoint{oracleI: oracleI, name: name, point: pt})
	}
	if _, err := v.Transcript.ComputeChallenge(challengeName); err != nil {
		return err
	}
	return nil
}

// RegisterOpenAt records an additional open request (prover-side
// Committer.Open call) so that VerifyOpening reconstructs the same
// DEEP-quotient structure. The name must have been committed in a prior
// Bind call. Does NOT touch the transcript.
func (v *Verifier) RegisterOpenAt(name string, point koalabear.Element) error {
	// Find which oracle holds this polynomial by scanning deepPoints that
	// were populated by Bind (auto-DEEP opens).
	for _, dp := range v.deepPoints {
		if dp.name == name {
			v.deepPoints = append(v.deepPoints, deepPoint{oracleI: dp.oracleI, name: name, point: point})
			return nil
		}
	}
	return fmt.Errorf("fri: RegisterOpenAt: polynomial %q not found in any committed oracle", name)
}

// ClaimedValueAt returns the prover's claimed evaluation of the polynomial
// named name at point from a verified OpeningProof. The (name, point) pair
// must have been registered via Bind (auto-DEEP) or RegisterOpenAt before
// VerifyOpening was called. Registration order matches ClaimedValues indexing.
func (v *Verifier) ClaimedValueAt(proof OpeningProof, name string, point koalabear.Element) (koalabear.Element, error) {
	for r, dp := range v.deepPoints {
		if dp.name == name && dp.point.Equal(&point) {
			if r >= len(proof.ClaimedValues) {
				return koalabear.Element{}, fmt.Errorf("fri: ClaimedValueAt: index %d out of range", r)
			}
			return proof.ClaimedValues[r], nil
		}
	}
	return koalabear.Element{}, fmt.Errorf("fri: ClaimedValueAt: polynomial %q at requested point not found", name)
}

func deepChallengeName(commitmentChallengeName, polynomialName string) string {
	return fmt.Sprintf("%s@deep_%s", commitmentChallengeName, polynomialName)
}

func (c *Committer) encode(polys []poly.Polynomial, encoder *reedsolomon.Encoder) []poly.Polynomial {
	domainsPool := map[int]*fft.Domain{}
	encoded := make([]poly.Polynomial, len(polys))
	for i, pol := range polys {
		n := len(pol)
		d, ok := domainsPool[n]
		if !ok {
			d = fft.NewDomain(uint64(n))
			domainsPool[n] = d
		}
		encoded[i] = encoder.Encode(pol, d)
	}
	return encoded
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

// OpeningProof is the full FRI proximity proof covering all registered openings.
type OpeningProof struct {
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

	// ClaimedValues[r] is the claimed evaluation f_r(z_r) for the r-th open
	// request, in the same registration order as the deepPoints collected by
	// Verifier.Bind.
	ClaimedValues []koalabear.Element

	// QueryIndices are the leaf indices used for spot checks, each in [0, N/k).
	// The verifier re-derives these from the transcript and checks they match.
	QueryIndices []uint64

	// OracleOpenings[q][i] is the Merkle opening proof from oracle i's tree at
	// the leaf corresponding to query q.
	OracleOpenings [][]merkle.Proof

	// OracleCosetData[q][i] has NumPolynomials_i · k elements: for polynomial
	// polyIdx (in PolynomialNames order) and coset offset t ∈ [0,k),
	// data[polyIdx·k + t] = f_{polyIdx}(ω^{j + t·(N/k)}).
	OracleCosetData [][][]koalabear.Element

	// LayerOpenings[q][l] is the Merkle opening proof from FRI layer l's tree.
	LayerOpenings [][]merkle.Proof

	// LayerCosetData[q][l][t] = g_l(ω^{j_l + t·(N_l/k)}) for t ∈ [0,k).
	LayerCosetData [][][]koalabear.Element

	// GrindingNonce is the proof-of-work nonce. Meaningful only when the
	// prover's Config.GrindingBits > 0; otherwise it is left at zero and the
	// verifier ignores it.
	GrindingNonce uint64
}
