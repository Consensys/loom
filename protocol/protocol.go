package protocol

import (
	"crypto/sha256"
	"fmt"

	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/iop/crypto/dummycommitment"
	"github.com/consensys/iop/pas/sym"
	"github.com/consensys/iop/pas/univariate"
	"github.com/consensys/iop/system"
)

// Protocol represents a Σ protocol
type Protocol struct {
	S system.System
	P Proof
	I Interactions
}

// Interactions keeps track of all the interactions between Prover and Verifier
// At each interaction, FS and Rounds must be updated in sync
type Interactions struct {
	FS     *fiatshamir.Transcript
	Rounds []Round
}

func NewInteractions() Interactions {
	return Interactions{
		FS: fiatshamir.NewTranscript(sha256.New()),
	}
}

// NewHintedIOP callback to record a new interaction in the protocol, creating one or more columns along the way (whose computation is complex and needs to be hinted)
// It models the following Σ protocol:
// 1 - Prover commits to the polys Pi whose ID are in IDs
// 2 - Verifier sends a challenge α, depending on Pi
// 3 - Prover compute a new polynomial (whose computation is complex and needs to be hinted)
// and whose ID is IDresult. It records a constraint C(P, P_i, α) that vanished on X^n-1
type NewHintedIOP func(S *system.System, IDs []string, IDresult string, challenge system.Challenge, opts ...system.IOPOption) error

// NewProtocol returns a new Protocol populated by S
func NewProtocol(S system.System) Protocol {
	return Protocol{
		S: S,
		P: Proof{OpeningProofs: make(map[string]dummycommitment.PackedProof)},
		I: NewInteractions(),
	}
}

// Round an IOP is a list of rounds. At each round, a challenge (referenced by ChallengeName) is sent by the verifier
// to the prover, upon receiving a list of CommittedColumns.
// It is made non interactive with Fiat Shamir: to simulate the randomness without a prover-verifier interaction, prover
// and verifier derive the challenge by hashing committedColumns, simulating the fact that the verifier received the commitments
// prior to sending the challenge.
type Round struct {

	// ChallengeName is the name of the challenge to generate
	ChallengeName string

	// Names of the commitments used to derive the challenge
	Dependencies []string
}

// buildColumnWithChallenge records a new interaction in the protocol creating one columns along the way
// (whose computation amounts to executing E, so it is automated)
// It models the following Σ protocol:
// 1 - Prover commits to the polys Pi whose ID are in E (without placeholders and constants)
// 2 - Verifier sends a challenge α, depending on Pi
// 3 - Prover compute a new polynomial Q = E(Pi, α). It records the constraint Q - E(Pi, α)
func (p *Protocol) buildColumnWithChallenge(E sym.Expr, IDresult string, opts ...system.IOPOption) error {

	var err error

	// IDs of polynomials on which depend the challenge -> it consists of all the leaves (without placeholders) of E
	IDs := sym.RemoveDuplicates(E.LeavesWOPlaceholders())

	// retrieve the challenge in the expression
	placeholders := E.Placeholders()
	if len(placeholders) != 1 {
		return fmt.Errorf("%s should contain exactly one placeholders, found %d", E.String(), len(placeholders))
	}

	// if challengeName=="", we don't generate a challenge. It means that we create a new polynomial Q=E(Pi) (E doesn't depend on a challenge)
	var value koalabear.Element
	challengeName := placeholders[0]
	value, err = p.SendMeAChallenge(IDs, challengeName)
	if err != nil {
		return err
	}

	return system.BuildColumnWithChallenge(&p.S, E, IDresult, value, opts...)
}

// TODO see l.15 system/lagrange.go, special computable columns need not be committed, and should be recomputed by the verifier
//
// NewLagrangeConstraint special treatment for this constraint.
// Syntactic sugar, the inner NewLagrangeConstraint is useful for testing, but it could have be defined directly on Protocol
func (p *Protocol) NewLagrangeConstraint(ID string, entry int, value koalabear.Element, opts ...system.IOPOption) error {
	return system.NewLagrangeConstraint(&p.S, ID, entry, value, opts...)
}

// getVarIdsFromConstraints returns the list of the names of Variable appearing in c
func getVarIdsFromConstraints(constraints []system.Constraint) []string {
	var ids []string
	for _, c := range constraints {
		n := c.LeavesWOPlaceholders()
		sym.RemoveDuplicates(n) // avoid the expression to grow too big
		ids = append(ids, n...)
	}
	ids = sym.RemoveDuplicates(ids)
	return ids
}

// FoldCachedConstraints calls FoldCachedConstraints, and put the folded constraints in the constraint registery.
// Flushes the cached constraints
func (p *Protocol) FoldCachedConstraints(foldingChallenge string) error {

	var err error
	var challenge system.Challenge
	challenge.Name = foldingChallenge

	// the challenge depends on every polynomials appearing in p.S.CachedConstraints
	// var ids []string
	ids := getVarIdsFromConstraints(p.S.CachedConstraints)

	challenge.Value, err = p.SendMeAChallenge(ids, foldingChallenge)
	if err != nil {
		return err
	}
	err = system.FoldCachedConstraints(&p.S, challenge)

	return err
}

// FoldConstraints folds all active constraints in S.Constraints
func (p *Protocol) FoldConstraints(folderID string) error {
	var err error
	var challenge system.Challenge
	challenge.Name = folderID

	// the challenge depends on every polynomials appearing in p.S.CachedConstraints
	// var ids []string
	ids := getVarIdsFromConstraints(p.S.Constraints)

	challenge.Value, err = p.SendMeAChallenge(ids, folderID)
	if err != nil {
		return err
	}

	err = system.FoldConstraints(&p.S, challenge)
	return err
}

// final round :
//
// |------------------------------------------------------------------------------------------------
// |	prover												verifier
// |
// |------------------------------------------------------------------------------------------------
// |computeQuotient,
// |send commitment 					---->
// |------------------------------------------------------------------------------------------------
// |									<----       sample zeta (FINAL_EVALUATION_POINT)
// |------------------------------------------------------------------------------------------------
// | opening everything at zeta			---->		verify final relation C(T)=Q*(X^n-)1, and all the opening proofs
// |------------------------------------------------------------------------------------------------
func (p *Protocol) Finalize() (Proof, error) {

	// check that len(p.S.Constraints)=1 (all constraints must be folded prior to calling RunLastRound)
	if len(p.S.Constraints) != 1 {
		return Proof{}, fmt.Errorf("all constraints must be folded prior to calling RunLastRound, got %d", len(p.S.Constraints))
	}
	C := p.S.Constraints[0]

	// compute the quotient H := C(S.Trace) / (X^N - 1)
	H, err := univariate.ComputeQuotient(p.S.Trace, C, p.S.N)
	if err != nil {
		return Proof{}, fmt.Errorf("ComputeQuotient: %w", err)
	}

	// query the leaves (Without Placeholders and Const)
	l := sym.RemoveDuplicates(C.LeavesWOPlaceholders())

	// commit to any leaf polynomial not yet in OpeningProofs, and collect the IDs of non committed polynomials
	zetaBindings := make([]string, 0)
	for _, id := range l {
		if _, ok := p.P.OpeningProofs[id]; ok {
			continue
		}
		zetaBindings = append(zetaBindings, id)
		poly, ok := p.S.Trace[id]
		if !ok {
			return Proof{}, fmt.Errorf("polynomial %s not found in trace", id)
		}
		com, err := dummycommitment.Commit(poly)
		if err != nil {
			return Proof{}, fmt.Errorf("commit %s: %w", id, err)
		}
		p.P.OpeningProofs[id] = dummycommitment.PackedProof{Digest: com}
	}

	// commit to the quotient H
	hDigest, err := dummycommitment.Commit(&H)
	if err != nil {
		return Proof{}, fmt.Errorf("commit quotient: %w", err)
	}
	p.P.OpeningProofs[FINAL_QUOTIENT] = dummycommitment.PackedProof{Digest: hDigest}
	zetaBindings = append(zetaBindings, FINAL_QUOTIENT)

	// store the constraint and domain size in the proof (needed by the verifier)
	p.P.Constraint = C
	p.P.N = p.S.N

	// derive zeta with zetaBindings
	zeta, err := p.SendMeAChallenge(zetaBindings, FINAL_EVALUATION_POINT)
	if err != nil {
		return Proof{}, fmt.Errorf("SendMeAChallenge zeta: %w", err)
	}

	// open every leaf polynomial at zeta
	d := fft.NewDomain(uint64(p.S.N))
	for _, id := range l {
		poly, ok := p.S.Trace[id]
		if !ok {
			return Proof{}, fmt.Errorf("polynomial %s not found in trace", id)
		}
		var pCopy univariate.Polynomial
		univariate.Copy(&pCopy, poly)
		if !pCopy.IsConstant() {
			if err := pCopy.ToBasis(d, univariate.Canonical); err != nil {
				return Proof{}, fmt.Errorf("convert %s to Canonical: %w", id, err)
			}
		}
		openProof, err := dummycommitment.Open(pCopy, zeta)
		if err != nil {
			return Proof{}, fmt.Errorf("open %s at zeta: %w", id, err)
		}
		packed := p.P.OpeningProofs[id]
		packed.OpeningProof = openProof
		p.P.OpeningProofs[id] = packed
	}

	// open H at zeta
	hBigSize := len(H.EP.Coefficients)
	hDomain := fft.NewDomain(uint64(hBigSize))
	if err := H.ToBasis(hDomain, univariate.Canonical); err != nil {
		return Proof{}, fmt.Errorf("convert H to Canonical: %w", err)
	}
	hOpenProof, err := dummycommitment.Open(H, zeta)
	if err != nil {
		return Proof{}, fmt.Errorf("open H at zeta: %w", err)
	}
	p.P.OpeningProofs[FINAL_QUOTIENT] = dummycommitment.PackedProof{
		Digest:       hDigest,
		OpeningProof: hOpenProof,
	}

	return p.P, nil
}

// SendMeAChallenge prover sends to the verifier the commitments of the polynomials whose ID are in IDs
// and asks for a challenge depending on them
func (p *Protocol) SendMeAChallenge(IDs []string, challenge string) (koalabear.Element, error) {

	// create the round
	var round Round
	round.ChallengeName = challenge
	round.Dependencies = make([]string, len(IDs))
	copy(round.Dependencies, IDs)
	p.P.Rounds = append(p.P.Rounds, round)

	// Commit to all the polynomials whose name matches IDs
	// Record the commitments in the proof, and update FS along the way
	err := p.I.FS.NewChallenge(challenge)
	if err != nil {
		return koalabear.Element{}, err
	}
	for _, id := range IDs {

		// if the commitment exists, we bind it to challenge
		_, ok := p.P.OpeningProofs[id]
		if ok {
			comPacked := p.P.OpeningProofs[id]
			err = p.I.FS.Bind(challenge, comPacked.Digest.Marshal())
			if err != nil {
				return koalabear.Element{}, err
			}
			continue
		}

		// if not, we commit, record the commitment, and bind it to challenge
		poly, ok := p.S.Trace[id]
		if !ok {
			return koalabear.Element{}, fmt.Errorf("polynomial %s not found in the trace", id)
		}
		com, err := dummycommitment.Commit(poly)
		err = p.I.FS.Bind(challenge, com.Marshal())
		if err != nil {
			return koalabear.Element{}, err
		}
		p.P.OpeningProofs[id] = dummycommitment.PackedProof{Digest: com}
	}

	// derive the challenge
	bc, err := p.I.FS.ComputeChallenge(challenge)
	if err != nil {
		return koalabear.Element{}, err
	}
	var c koalabear.Element
	c.SetBytes(bc)

	// add the challenge as a constant column, since it will appear in other constraints
	challengeColumn, err := univariate.NewConstantPolynomial(c)
	if err != nil {
		return koalabear.Element{}, err
	}
	p.S.Trace[challenge] = &challengeColumn

	return c, nil
}
