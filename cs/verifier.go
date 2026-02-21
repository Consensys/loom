package cs

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/iop/crypto/dummycommitment"
	"github.com/consensys/iop/pas/sym"
)

// Verify verifies a Proof P
//
// The Proof models the following Σ protocol:
//
//	|-------------------------------–-----------------------------------------------|
//	| [prover]						|			[verifier]							|
//	|-------------------------------–-----------------------------------------------|
//	|Commit(Bindings[0])		-----→		[Com0_1,.., Com0_n0]					|ROUND 1																		|
//	|-------------------------------–-----------------------------------------------|
//	|	α₀						←-----			Sample random α₀ 					|
//	|										(α₀=Fiat_Shamir(Com0_i...))				|ROUND 2
//	|-------------------------------–-----------------------------------------------|
//	| [Generate data 		 ------→		[Com1_1,.., Com1_n1]	 				|
//	| with P0_i.., α₀ ]																|ROUND 3
//	| Commit(Bindings[1])															|																|
//	|-------------------------------–-----------------------------------------------|
//	|	α₁						←-----		Sample random α₁ 						|
//	|										(α₁=Fiat_Shamir(Com1_i...))				|ROUND 4
//	|-------------------------------–-----------------------------------------------|
//									....
//	|-------------------------------–-----------------------------------------------|
//	| [Generate data 		 ------→		[Com n₁,.., Com n_nn]	 				|
//	| with Pn-1_i.., α_n-1 ]														|ROUND 2n+1
//	| Commit(Bindings[n])															|																|
//	|-------------------------------–-----------------------------------------------|
//	|	α_n						←-----		Sample random α₁ 						|
//	|										(α_n=Fiat_Shamir(Com n-1_i...))			|ROUND 2n+1
//	|-------------------------------–-----------------------------------------------|
//	| Compute																		|
//	| H := C(P_i..,α_i)/Xⁿ-1 													|
//	| where C := P.Constraint	------→			Comm_H								|ROUND 2n+2
//	| Compute H=(Σ_iαⁱP_i-R)/X^n-1													|
//	| Commit(H)																		|
//	|-------------------------------–-----------------------------------------------|
//	|	ζ						←-----		Sample random ζ							|
//	|										(zeta=Fiat_Shamir(Com_i..., Com_h))		|ROUND 2n+3
//	|-------------------------------–-----------------------------------------------|
//	|	Open(P_i_j..) at zeta		----→		Verify opening proofs 				|
//	|	Open(H) at zeta					Verify C(P_i(ζ),α_i)=H(ζ)(ζⁿ-1)				|ROUND 2n+4
//	|-------------------------------–-----------------------------------------------|
func Verify(P *Proof, opts ...IopOption) error {

	// TODO ensure len(P.Bindings)=1 and len(P.Bindings[0])=len(P.OpeningProofs)

	// create a fiat shamir instance
	// evaluationPointName := P.Bindings[0].ChallengeName
	var config IopConfig
	for _, opt := range opts {
		err := opt(&config)
		if err != nil {
			return err
		}
	}

	// if Config.ChallengeNames is not set, we pick the names in the proof
	// else we use the one in config
	challengesID := make([]string, len(P.Bindings))
	if config.ChallengeNames == nil {
		for i := 0; i < len(P.Bindings); i++ {
			challengesID[i] = P.Bindings[i].ChallengeName
		}
	} else {
		// TODO ensure the  len(config.ChallengeNames) == len(challengesID)
		copy(challengesID, config.ChallengeNames)
	}
	fs := fiatshamir.NewTranscript(sha256.New(), challengesID...)

	// create the bindings. Every bindings but the quotient are in P.Bindings
	for i := 0; i < len(P.Bindings); i++ {
		for j := 0; j < len(P.Bindings[i].CommitmentsName); j++ {
			curCom, err := getDigestByName(P.OpeningProofs, P.Bindings[i].CommitmentsName[j])
			if err != nil {
				return err
			}
			fs.Bind(P.Bindings[i].ChallengeName, curCom.Marshal())
		}
	}
	err := fs.Bind(P.Bindings[len(P.Bindings)-1].ChallengeName, P.Quotient.Digest.Marshal()) // <- the last binding is the quotient
	if err != nil {
		return err
	}

	// derive the challenges
	challenges := make([]koalabear.Element, len(P.Bindings))
	if config.ChallengeValues == nil {
		for i, binding := range P.Bindings {
			bchallenge, err := fs.ComputeChallenge(binding.ChallengeName)
			if err != nil {
				return err
			}
			challenges[i].SetBytes(bchallenge)
		}
	} else { // we force the values
		for i, c := range config.ChallengeValues {
			challenges[i].Set(&c)
		}
	}
	zeta := challenges[len(challenges)-1] // <- the point of evaluation is the last challenge

	// check the opening proofs
	for i := 0; i < len(P.OpeningProofs); i++ {
		err = dummycommitment.Verify(P.OpeningProofs[i].Digest, P.OpeningProofs[i].OpeningProof, zeta)
		if err != nil {
			return err
		}
	}
	err = dummycommitment.Verify(P.Quotient.Digest, P.Quotient.OpeningProof, zeta)
	if err != nil {
		return err
	}

	// check the relation P.C(evaluations) = q*(x^n-1)
	Czeta := ComputeEvaluationWithClaimedValues(*P, challenges[:len(challenges)-1]) // <- all but the last challenge are used in the algebraic expression
	Qzeta := P.Quotient.OpeningProof.ClaimedValue
	zetaNMinusOne := zeta
	var one koalabear.Element
	one.SetOne()
	zetaNMinusOne.Exp(zeta, big.NewInt(int64(P.N))).Sub(&zetaNMinusOne, &one)

	Qzeta.Mul(&Qzeta, &zetaNMinusOne)

	if !Qzeta.Equal(&Czeta) {
		return fmt.Errorf("P.C(evaluations) = q*(x^n-1) does not hold")
	}

	return nil
}

// getPositionDigestByName return the position of the Digest whose ID matches name
func getPositionDigestByName(D []dummycommitment.PackedProof, name string) (int, error) {
	res := -1
	for i := 0; i < len(D); i++ {
		if D[i].ID == name {
			res = i
		}
	}
	if res == -1 {
		return res, fmt.Errorf("polynomial %s not in the list", name)
	}
	return res, nil
}

// getDigestByName return Digest whose ID matches name
func getDigestByName(D []dummycommitment.PackedProof, name string) (dummycommitment.Digest, error) {
	for i := 0; i < len(D); i++ {
		if D[i].ID == name {
			return D[i].Digest, nil
		}
	}
	return dummycommitment.Digest{}, fmt.Errorf("polynomial %s not in the list", name)
}

// computes P.C(evaluations)
// challenges appear in the same order as those in P.Bindings
func ComputeEvaluationWithClaimedValues(P Proof, challenges []koalabear.Element) koalabear.Element {
	numChallenges := len(challenges) // the last binding is the evaluation point, not used in P.Constraint
	varindex := make(sym.VarIndex)
	y := make([]koalabear.Element, len(P.OpeningProofs)+numChallenges)
	for i := 0; i < len(P.OpeningProofs); i++ {
		varindex[P.OpeningProofs[i].ID] = i
		y[i] = P.OpeningProofs[i].OpeningProof.ClaimedValue
	}
	offset := len(P.OpeningProofs)
	for i := 0; i < numChallenges; i++ { // <- the last binding is the point of evaluation, not used in P.Constraint
		varindex[P.Bindings[i].ChallengeName] = i + offset

		// challenges[i] corresponds to P.Bindings[i].ChallengeName
		y[i+offset] = challenges[i]
	}
	CHorner := sym.ToHorner(sym.Convert(P.Constraint, varindex, len(P.OpeningProofs)+numChallenges))
	Cy := CHorner.Eval(y)
	return Cy
}
