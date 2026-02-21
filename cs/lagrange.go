package cs

import (
	"crypto/sha256"
	"fmt"

	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/iop/crypto/dummycommitment"
	"github.com/consensys/iop/pas/sym"
	"github.com/consensys/iop/pas/univariate"
)

// Lagrange standard identifier across systems for Lagrange polynomial, suffixed by an integer to specify which Lagrange polynomial
const Lagrange = "LAGRANGE_"

func GetLagrangeID(entry int) string {
	return fmt.Sprintf("%s%d", Lagrange, entry)
}

func GetLagrangeRelation(ID string, entry int, value koalabear.Element) Constraint {
	lagrangeID := GetLagrangeID(entry)
	C := sym.NewVar(ID).Sub(sym.NewConst(value)).Mul(sym.NewVar(lagrangeID))
	return C
}

// NewLagrangeProtocol generates a system whose satisfiability is equivalent to P[entry] == value,
// and a Proof that proves this.
//
// The Proof models the following Σ protocol:
//
//	|-------------------------------–-----------------------------------------------|
//	| [prover]						|				[verifier]						|
//	|-------------------------------–-----------------------------------------------|
//	| Commit(P, L_entry)		 -----→		[Com_P, Com_L, Com_H]					|ROUND 1
//	| Compute H=(P-value)*L/Xⁿ-1												|
//	| Commit(H)																		|
//	|-------------------------------–-----------------------------------------------|
func NewLagrangeProtocol(P univariate.Polynomial, entry int, value koalabear.Element, opts ...IopOption) (System, Proof, error) {

	// Apply config options
	var config IopConfig
	for _, opt := range opts {
		if err := opt(&config); err != nil {
			return System{}, Proof{}, err
		}
	}

	n := univariate.NextPowerOfTwo(len(P.EP.Coefficients))

	// Build the entry-th Lagrange basis polynomial: 1 at position entry, 0 elsewhere
	lagrangeID := GetLagrangeID(entry)
	lagrangeCoeffs := make([]koalabear.Element, n)
	lagrangeCoeffs[entry].SetOne()
	lagrangePoly, err := univariate.NewInterpolatedPolynomial(lagrangeCoeffs, lagrangeID)
	if err != nil {
		return System{}, Proof{}, err
	}

	C := GetLagrangeRelation(P.ID, entry, value)

	// Build proof skeleton
	var proof Proof
	proof.N = n
	proof.Constraint = C
	proof.Bindings = make([]Binding, 1)
	proof.Bindings[0].ChallengeName = EVALUATION_POINT
	proof.Bindings[0].CommitmentsName = []string{P.ID, lagrangeID}

	// Create Fiat-Shamir proof
	fs := fiatshamir.NewTranscript(sha256.New(), EVALUATION_POINT)

	// ROUND 1: Commit P and lagrangePoly, bind both to zeta, then commit quotient and bind it too
	proof.OpeningProofs = make([]dummycommitment.PackedProof, 2)
	proof.OpeningProofs[0].ID = P.ID
	proof.OpeningProofs[0].Digest, err = dummycommitment.Commit(&P)
	if err != nil {
		return System{}, Proof{}, err
	}
	fs.Bind(EVALUATION_POINT, proof.OpeningProofs[0].Digest.Marshal())

	proof.OpeningProofs[1].ID = lagrangeID
	proof.OpeningProofs[1].Digest, err = dummycommitment.Commit(&lagrangePoly)
	if err != nil {
		return System{}, Proof{}, err
	}
	fs.Bind(EVALUATION_POINT, proof.OpeningProofs[1].Digest.Marshal())

	// Compute quotient H = (P - value) * L_entry / (X^n - 1)
	trace := []univariate.Polynomial{P, lagrangePoly}
	H, err := univariate.ComputeQuotient(trace, C, univariate.WithResultBasis(univariate.Canonical))
	if err != nil {
		return System{}, Proof{}, err
	}
	proof.Quotient.Digest, err = dummycommitment.Commit(&H)
	if err != nil {
		return System{}, Proof{}, err
	}
	err = fs.Bind(EVALUATION_POINT, proof.Quotient.Digest.Marshal())
	if err != nil {
		return System{}, Proof{}, err
	}

	// ROUND 2: Derive zeta
	var zeta koalabear.Element
	if config.ChallengeValues == nil {
		bzeta, err := fs.ComputeChallenge(EVALUATION_POINT)
		if err != nil {
			return System{}, Proof{}, err
		}
		zeta.SetBytes(bzeta)
	} else {
		zeta.Set(&config.ChallengeValues[len(config.ChallengeValues)-1])
	}

	// ROUND 3: Open P, lagrangePoly, H at zeta.
	// dummycommitment.Open requires Canonical basis; make copies to avoid modifying inputs.
	d := fft.NewDomain(uint64(n))

	var pCopy univariate.Polynomial
	univariate.Copy(&pCopy, &P)
	if err := pCopy.ToBasis(d, univariate.Canonical); err != nil {
		return System{}, Proof{}, err
	}
	proof.OpeningProofs[0].OpeningProof, err = dummycommitment.Open(pCopy, zeta)
	if err != nil {
		return System{}, Proof{}, err
	}

	var lCopy univariate.Polynomial
	univariate.Copy(&lCopy, &lagrangePoly)
	if err := lCopy.ToBasis(d, univariate.Canonical); err != nil {
		return System{}, Proof{}, err
	}
	proof.OpeningProofs[1].OpeningProof, err = dummycommitment.Open(lCopy, zeta)
	if err != nil {
		return System{}, Proof{}, err
	}

	proof.Quotient.OpeningProof, err = dummycommitment.Open(H, zeta)
	if err != nil {
		return System{}, Proof{}, err
	}

	S := System{
		Trace:      []univariate.Polynomial{P, lagrangePoly},
		Constraint: C,
		N:          n,
	}

	return S, proof, nil
}
