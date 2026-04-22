package fri

import (
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

// Config collects the parameters that will eventually govern FRI's
// blowup, query count, and folding schedule.
type Config struct {
	BlowupFactor int
	NumQueries   int
}

type Commitment struct {
	// Root is the Merkle root of the Reed-Solomon codeword committed by the prover.
	Root []byte
	// BaseDomainSize is n where the prover's polynomial is initially given by its
	// values on a domain of size n.
	BaseDomainSize uint64
	// CodewordDomainSize is N = blowup * n, the size of the evaluation domain used
	// for the first FRI oracle.
	CodewordDomainSize uint64
	// NumPolynomials is the number of polynomials batched into this oracle.
	NumPolynomials int
	// PolynomialSizes records each batched polynomial's base-domain size before
	// Reed-Solomon extension.
	PolynomialSizes []uint64
	// DeepEvaluationPoint is the out-of-domain point s attached to this
	// commitment's DEEP reduction.
	DeepEvaluationPoint *koalabear.Element
	// DeepEvaluationAtPoint is the claimed evaluation f(s) for this commitment's
	// DEEP reduction.
	DeepEvaluationAtPoint *koalabear.Element
}

type committedOracle struct {
	Commitment
	Codewords map[string]poly.Polynomial
	Tree      *merkle.Tree
}

type openRequest struct {
	name  string
	point koalabear.Element
}

type Verifier struct {
	Transcript *fiatshamir.Transcript
}

// Committer is a FRI-backed commitment scheme. It computes the first enlarged-domain oracle commitment and
// stores the codeword/Merkle state required for later DEEP-FRI openings.
type Committer struct {
	leafHasher       merkle.LeafHasher
	nodeHasher       merkle.NodeHasher
	transcript       *fiatshamir.Transcript
	config           Config
	committedOracles []committedOracle
	polynomials      map[string]int
	openRequests     []openRequest
}

func NewCommitter(transcript *fiatshamir.Transcript, config Config, leafHasher merkle.LeafHasher, nodeHasher merkle.NodeHasher) Committer {
	blowup := config.BlowupFactor
	if blowup == 0 {
		blowup = DefaultFRIBlowupFactor
	}
	config.BlowupFactor = blowup
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
// tree over the interleaved codewords.
func (c *Committer) Commit(challengeName string, polys map[string]poly.Polynomial) error {
	if len(polys) == 0 {
		if c.transcript != nil {
			if err := c.transcript.Bind(challengeName, nil); err != nil {
				return err
			}
		}
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
	if codewordDomainSize == 0 {
		return fmt.Errorf("%w: zero codeword domain", ErrInvalidPolynomial)
	}
	encoder := reedsolomon.Encoder{Domain: fft.NewDomain(codewordDomainSize)}

	codewords := c.encode(orderedPolys, &encoder)
	tree, err := buildCodewordMerkleTree(codewords, c.leafHasher, c.nodeHasher)
	if err != nil {
		return err
	}

	meta := Commitment{
		Root:               tree.Root(),
		CodewordDomainSize: codewordDomainSize,
		NumPolynomials:     len(orderedPolys),
		PolynomialSizes:    make([]uint64, len(orderedPolys)),
	}
	for i, pol := range orderedPolys {
		size := uint64(len(pol))
		meta.PolynomialSizes[i] = size
		if size > maxBaseDomain {
			maxBaseDomain = size
		}
	}
	meta.BaseDomainSize = maxBaseDomain

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
	if c.transcript != nil {
		if err := c.transcript.Bind(challengeName, meta.Root); err != nil {
			return err
		}
	}

	for _, name := range names {
		c.polynomials[name] = oracleI
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
	if _, ok := c.polynomials[name]; !ok {
		return errors.New("fri: invalid polynomial reference")
	}
	c.openRequests = append(c.openRequests, openRequest{name: name, point: point})
	return nil
}

// Prove produces an OpeningProof covering all registered Open requests.
func (c *Committer) Prove() (OpeningProof, error) {
	commitments := make([]Commitment, len(c.committedOracles))
	for i, oracle := range c.committedOracles {
		commitments[i] = oracle.Commitment
	}
	return OpeningProof{Commitments: commitments}, nil
}

func (v Verifier) Bind(challengeName string, commitment Commitment) error {
	if v.Transcript == nil {
		return nil
	}
	return v.Transcript.Bind(challengeName, commitment.Root)
}

func (c *Committer) Verify([]byte, koalabear.Element, []koalabear.Element) error {
	return errors.New("c commitment: not implemented")
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

func buildCodewordMerkleTree(codewords []poly.Polynomial, leafHasher merkle.LeafHasher, nodeHasher merkle.NodeHasher) (*merkle.Tree, error) {
	N := len(codewords[0])
	tree, err := merkle.New(N, leafHasher, nodeHasher)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, koalabear.Bytes*len(codewords))
	for i := range N {
		for j := range codewords {
			copy(buf[j*koalabear.Bytes:], codewords[j][i].Marshal())
		}
		tree.BuildIthLeaf(buf, i)
	}
	tree.BuildNodes()
	return tree, nil
}

// OpeningProof is a placeholder for the eventual FRI transcript:
// layer commitments, query indices, decommitments, and final remainder data.
type OpeningProof struct {
	// Commitments are the oracle commitments sent by the prover before the FRI
	// query phase. Each root authenticates an oracle O : H -> F over the first
	// Reed-Solomon codeword domain H.
	Commitments []Commitment
	// LayerCommitments are the Merkle roots of successive folded FRI layers.
	// Conceptually, each layer reduces a claim about f(X) to a claim about a
	// lower-degree polynomial g(X) derived from f_even(X^2) + alpha f_odd(X^2).
	LayerCommitments [][]byte
	// FinalPolynomial is the last explicitly transmitted low-degree remainder
	// after enough foldings, i.e. the polynomial that should satisfy deg(r) << |H|.
	FinalPolynomial []koalabear.Element
}
