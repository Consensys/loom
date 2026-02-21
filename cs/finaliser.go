package cs

import (
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/iop/crypto/dummycommitment"
	"github.com/consensys/iop/pas/univariate"
)

// FinalizeProof final round of the sigma protocol ->
//
//	|-------------------------------–-----------------------------------------------|
//	| [prover]						|				[verifier]						|
//	|-------------------------------–-----------------------------------------------|
//	| Commit(S.Trace)		 		-----→											|ROUND 1
//	| Compute										[Com_1, Com_2, ...]				|
//	| H=S.Constraint(S.Trace)/Xⁿ-1													|
//	| Commit(H)																		|
//	|-------------------------------–-----------------------------------------------|
//	|	ζ						←-----		Sample random ζ							|
//	|										(zeta=Fiat_Shamir([Com_1, Com_2, ...])	|ROUND 2
//	|-------------------------------–-----------------------------------------------|
//	| Open(P[Com_1, Com_2, ...], H) at ζ	----→		Verify opening proofs		|
//	|												Constraint(ζ) = H(ζ)*(ζⁿ-1)		|ROUND 3
//	|-------------------------------–-----------------------------------------------|
func FinalizeProof(S System, P *Proof, fs *fiatshamir.Transcript) error {

	err := fs.NewChallenge(EVALUATION_POINT)
	if err != nil {
		return nil
	}

	H, err := univariate.ComputeQuotient(S.Trace, S.Constraint, univariate.WithResultBasis(univariate.Canonical))
	if err != nil {
		return err
	}
	P.Quotient.Digest, err = dummycommitment.Commit(&H)
	if err != nil {
		return err
	}

	// record the binding
	err = fs.Bind(EVALUATION_POINT, P.Quotient.Digest.Marshal())
	if err != nil {
		return err
	}
	P.Bindings = append(P.Bindings, Binding{ChallengeName: EVALUATION_POINT, CommitmentsName: []string{P.Quotient.ID}})

	// ROUND 2: Derive zeta
	var zeta koalabear.Element
	bzeta, err := fs.ComputeChallenge(EVALUATION_POINT)
	if err != nil {
		return err
	}
	zeta.SetBytes(bzeta)

	// ROUND 3: Open all polynomials in S.Trace and H at zeta.
	// dummycommitment.Open requires Canonical basis; make copies to avoid modifying inputs.
	d := fft.NewDomain(uint64(S.N))
	for i := 0; i < len(S.Trace); i++ {
		if S.Trace[i].IsConstant() {
			continue
		}
		var pCopy univariate.Polynomial
		univariate.Copy(&pCopy, &S.Trace[i])
		if err := pCopy.ToBasis(d, univariate.Canonical); err != nil {
			return err
		}
		pos, err := getPositionDigestByName(P.OpeningProofs, S.Trace[i].ID)
		if err != nil {
			return err
		}
		P.OpeningProofs[pos].OpeningProof, err = dummycommitment.Open(pCopy, zeta)
		if err != nil {
			return err
		}
	}
	P.Quotient.OpeningProof, err = dummycommitment.Open(H, zeta)
	if err != nil {
		return err
	}

	return nil
}
