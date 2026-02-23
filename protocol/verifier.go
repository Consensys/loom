package protocol

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/iop/pas/sym"
	"github.com/consensys/iop/system"
)

// GenerateChallenges generate the challenges in the same order of generation than the prover
func GenerateChallenges(P Proof, fs *fiatshamir.Transcript) ([]koalabear.Element, error) {

	r := make([]koalabear.Element, len(P.Rounds))
	for i := 0; i < len(P.Rounds); i++ {
		err := fs.NewChallenge(P.Rounds[i].ChallengeName)
		if err != nil {
			return nil, err
		}
		for _, d := range P.Rounds[i].Dependencies {
			com, ok := P.OpeningProofs[d]
			if !ok {
				return nil, fmt.Errorf("%s not found in the list of commitments", d)
			}
			err = fs.Bind(P.Rounds[i].ChallengeName, com.Digest.Marshal())
			if err != nil {
				return nil, err
			}
		}
		br, err := fs.ComputeChallenge(P.Rounds[i].ChallengeName)
		if err != nil {
			return nil, err
		}
		r[i].SetBytes(br)
	}
	return r, nil
}

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
func Verify(P *Proof, opts ...system.IOPOption) error {

	var config system.IOPConfig
	for _, opt := range opts {
		err := opt(&config)
		if err != nil {
			return err
		}
	}

	// crreate FS instance
	fs := fiatshamir.NewTranscript(sha256.New())

	// create the variable index for evaluating P.Constraint. We get all the names, except the constants
	leaves := P.Constraint.Leaves()
	leaves = sym.RemoveDuplicates(leaves)
	varindex := make(sym.VarIndex)
	for i, l := range leaves {
		varindex[l] = i
	}

	// populate the list of variables at which P.Constraint is evaluated
	values := make([]koalabear.Element, len(leaves))
	for k, v := range P.OpeningProofs {
		// FINAL_EVALUATION_POINT and FINAL_QUOTIENT do not appear as leaves of P.Constraint
		// (the quotient is the RHS, not the LHS) and must be skipped here.
		if k == FINAL_EVALUATION_POINT || k == FINAL_QUOTIENT {
			continue
		}
		values[varindex[k]].Set(&v.OpeningProof.ClaimedValue)
	}

	// simulate each rounds with Fiat Shamir. The last round derives zeta, not used in P.C so we let the last round for later
	for i := 0; i < len(P.Rounds)-1; i++ {

		round := P.Rounds[i]

		err := fs.NewChallenge(round.ChallengeName) // round i: receive i-th Commitments, then send i-th challenge
		if err != nil {
			return err
		}
		for _, comID := range round.Dependencies {
			pp, ok := P.OpeningProofs[comID]
			if !ok {
				return fmt.Errorf("commitment %s not found", comID)
			}
			err = fs.Bind(round.ChallengeName, pp.Digest.Marshal())
			if err != nil {
				return err
			}
		}
		bithChallenge, err := fs.ComputeChallenge(round.ChallengeName)
		if err != nil {
			return err
		}
		values[varindex[round.ChallengeName]].SetBytes(bithChallenge)
	}

	// derive zeta
	err := fs.NewChallenge(FINAL_EVALUATION_POINT)
	if err != nil {
		return err
	}
	for _, comID := range P.Rounds[len(P.Rounds)-1].Dependencies {
		pp, ok := P.OpeningProofs[comID]
		if !ok {
			return fmt.Errorf("commitment %s not found", comID)
		}
		err = fs.Bind(P.Rounds[len(P.Rounds)-1].ChallengeName, pp.Digest.Marshal())
		if err != nil {
			return err
		}
	}
	bzeta, err := fs.ComputeChallenge(FINAL_EVALUATION_POINT)
	if err != nil {
		return err
	}
	var zeta koalabear.Element
	zeta.SetBytes(bzeta)

	// check the relation P.C(evaluations) = q*(x^n-1)
	ConstraintHorner := sym.ToHorner(sym.Convert(P.Constraint, varindex, len(leaves)))
	Czeta := ConstraintHorner.Eval(values)
	Qzeta := P.OpeningProofs[FINAL_QUOTIENT].OpeningProof.ClaimedValue
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
