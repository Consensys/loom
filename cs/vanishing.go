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

func getBindingByName(bindings []Binding, name string) (Binding, error) {
	res := -1
	for i, b := range bindings {
		if name == b.ChallengeName {
			res = i
		}
	}
	if res == -1 {
		return Binding{}, fmt.Errorf("name: %s not found in bindings", name)
	}
	return bindings[res], nil
}

func getPolysByNames(names []string, P []univariate.Polynomial) []univariate.Polynomial {
	res := make([]univariate.Polynomial, len(names))
	for i, n := range names {
		for _, p := range P {
			if n == p.ID {
				res[i] = p
			}
		}
	}
	return res
}

// NewVanishingProtocol generates a proof that C(P)=0 mod X^n-1.
//
// To compute C(P)/X^n-1, if the degree of C(P) is too big, we can't use FFT because the domain might not be
// big enough.
//
// To avoid this issue the strategy we compute intermediate expressions of low degree step by step with WithMaxDegree option.
//
// Example: if C(P1,P2) = P1⁵ - P2³ and WithMaxDegree(2), we build new intermediate polynomials of degree N (size of the original polynomials in P):
// * Q1, that satisfies the constraint C1: Q1-P1² = 0 mod X^n-1
// * Q2, that satisfies the constraint C2: Q2-Q1² = 0 mod X^n-1
// * Q3, that satisfies the constraint C3: Q3-Q2*Q = 0 mod X^n-1 <- so Q3 - P1⁵ = 0 mod X^n-1, and for each intermediate relations we can compute the quotient by X^n-1
// * R1, that satisfies the constraint C4: R1-P2² = 0 mod X^n-1
// * R2, that satisfies the constraint C5: R2 - P2*R1 = 0 mod X^n-1 <- so R2 - P2³ = 0 mod X^n-1, and for each intermediate relations we can compute the quotient by X^n-1
// Proving that C(P1, P2) = 0 mod X^n-1 is equivalent (with high probability for a random α) to proving that
// (Q1-P1²)+α(Q2-Q1²)+α²(Q3-Q2*Q)+α³(R1-P2²)+α⁴(R2 - P2*R1) = 0 mod X^n-1
// Now (Q1-P1²)+α(Q2-Q1²)+α²(Q3-Q2*Q)+α³(R1-P2²)+α⁴(R2 - P2*R1) is if low degree, so we can compute
// [ (Q1-P1²)+α(Q2-Q1²)+α²(Q3-Q2*Q)+α³(R1-P2²)+α⁴(R2 - P2*R1) ] / X^n-1 without an fft domain which is too big.
func NewVanishingProtocol(P []univariate.Polynomial, C Constraint, opts ...IopOption) (System, Proof, error) {

	// determine N = size of first non-constant polynomial
	var N int
	for i := 0; i < len(P); i++ {
		if !P[i].IsConstant() {
			N = len(P[i].EP.Coefficients)
			break
		}
	}

	// build Config, apply opts to it
	var config IopConfig
	for _, opt := range opts {
		if err := opt(&config); err != nil {
			return System{}, Proof{}, err
		}
	}

	// create skeleton for Proof, and FiatShamir transcript
	var proof Proof
	proof.N = N
	proof.Constraint = C
	fs := fiatshamir.NewTranscript(sha256.New())
	needFlattening := config.ReduceDegree && C.Degree() > config.TargetDegree

	// create the system
	system := System{Trace: P, Constraint: C, N: N}

	// commit to all polynomials (except the constant polynomials), record the commitments in the proof
	proof.OpeningProofs = make([]dummycommitment.PackedProof, 0, len(P))
	for i := 0; i < len(P); i++ {
		if P[i].IsConstant() { // either P is a public constant, or a challenge, retrieved by the verifier, so don't need to commit
			continue
		}
		curCom, err := dummycommitment.Commit(&P[i])
		if err != nil {
			return System{}, Proof{}, err
		}
		proof.OpeningProofs = append(proof.OpeningProofs, dummycommitment.PackedProof{Digest: curCom, ID: P[i].ID})
	}

	// flatten the system by adding extra columns to it, and populate the proof with the sigma protocol
	// ensuring that the flattening is correct
	if needFlattening {
		Flatten(&system, &proof, fs, config.TargetDegree)
	}

	// compute the quotient H = system.Constraint(system.Trace) / (Xᴺ - 1)
	H, err := univariate.ComputeQuotient(system.Trace, system.Constraint, univariate.WithResultBasis(univariate.Canonical))
	if err != nil {
		return System{}, Proof{}, err
	}

	// commit to the quotient, bind to zeta, then derive zeta
	proof.Quotient.Digest, err = dummycommitment.Commit(&H)
	if err != nil {
		return System{}, Proof{}, err
	}
	err = fs.NewChallenge(EVALUATION_POINT)
	if err != nil {
		return System{}, Proof{}, err
	}
	err = fs.Bind(EVALUATION_POINT, proof.Quotient.Digest.Marshal())
	if err != nil {
		return System{}, Proof{}, err
	}
	proof.Bindings = append(proof.Bindings, Binding{ChallengeName: EVALUATION_POINT, CommitmentsName: []string{H.ID}})

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

	// open every commitment at zeta; skip constant polynomials (not committed)
	d := fft.NewDomain(uint64(N))
	j := 0
	for i := 0; i < len(system.Trace); i++ {
		if system.Trace[i].IsConstant() {
			continue
		}
		var pCopy univariate.Polynomial
		univariate.Copy(&pCopy, &system.Trace[i])
		if err := pCopy.ToBasis(d, univariate.Canonical); err != nil {
			return System{}, Proof{}, err
		}
		proof.OpeningProofs[j].OpeningProof, err = dummycommitment.Open(pCopy, zeta)
		if err != nil {
			return System{}, Proof{}, err
		}
		j++
	}
	proof.Quotient.OpeningProof, err = dummycommitment.Open(H, zeta)
	if err != nil {
		return System{}, Proof{}, err
	}

	return system, proof, nil
}

// Flatten is called when the degree of the constraint C in the system S is too big.
// S is supposed to be correct, that is S.Constraint(S.Trace) = 0 mod X^n-1.
// fs and P are supposed to be correctly formed, that is
// * all polynomials in S are supposed to be committed in P
// * fs has a challenge whose name is FLATTENING_CHALLENGE. The bindings to this challenge are done in Flatten, with the new polynomials created along the way
// The system S will be modified so that
// * S.Trace contains the new polynomials created during the flattening
// * S.Constraint contains the flattened constraint
func Flatten(S *System, P *Proof, fs *fiatshamir.Transcript, targetDegree int) (System, Proof, error) {

	C := S.Constraint

	fs.NewChallenge(FLATTENING_CHALLENGE)
	P.Bindings = append(P.Bindings, Binding{})
	bindingPos := len(P.Bindings) - 1 // <- the last bindings are tied to the newly added challenge, FLATTENING_CHALLENGE

	// build all the intermediate polynomials, by evaluating expressions of degree ⩽ 3 maximum
	lowDegreeConstraints := make([]sym.Expr, 0)

	CLowRecord := make(map[string]struct{})
	for C.Degree() > targetDegree {

		CLow := C.Prune(targetDegree)

		// make sure CLow is not already recorded (might happen if the same expression appears at multiple leaves)
		// Prune already replaced the occurrence in CReduced with NewVar(CLow.String()), so we've made
		// progress regardless; we just skip creating a duplicate intermediate polynomial.
		if _, ok := CLowRecord[CLow.String()]; ok {
			continue
		}
		CLowRecord[CLow.String()] = struct{}{}

		IDs := sym.RemoveDuplicates(CLow.Leaves())
		subPolys := getPolysByNames(IDs, S.Trace)

		// compute CLow(subPolys) mod X^N-1 as a new intermediate polynomial.
		// We evaluate CLow pointwise at the regular Lagrange domain points ωʲ
		// (GetCoefficient(j) returns the j-th evaluation for Lagrange-basis polynomials),
		// then store the result in Lagrange basis via NewInterpolatedPolynomial.
		// We must NOT use ComputeSym here: ComputeSym evaluates at the shifted domain (w·ωʲ),
		// which aliases high-degree compositions incorrectly mod (X^N-1).
		clowVarindex := make(sym.VarIndex)
		for k, id := range IDs {
			clowVarindex[id] = k
		}
		clowHorner := sym.ToHorner(sym.Convert(CLow, clowVarindex, len(IDs)))
		newCoeffs := make([]koalabear.Element, S.N)
		for j := 0; j < S.N; j++ {
			values := make([]koalabear.Element, len(IDs))
			for k := range IDs {
				values[k] = subPolys[k].GetCoefficient(j)
			}
			newCoeffs[j] = clowHorner.Eval(values)
		}
		newPoly, err := univariate.NewInterpolatedPolynomial(newCoeffs, CLow.String())
		if err != nil {
			return System{}, Proof{}, err
		}

		// create the low-degree relation: CLow - newIntermediate = 0
		lowConstraint := CLow.Sub(sym.NewVar(CLow.String()))
		lowDegreeConstraints = append(lowDegreeConstraints, lowConstraint)

		// append the new poly to the trace
		S.Trace = append(S.Trace, newPoly)

		// commit to newPoly, bind the commitment to FLATTENING_CHALLENGE, and record it so the
		// verifier can re-derive the same alpha via CommitmentsName
		curCom, err := dummycommitment.Commit(&newPoly)
		if err != nil {
			return System{}, Proof{}, err
		}
		P.OpeningProofs = append(P.OpeningProofs, dummycommitment.PackedProof{Digest: curCom, ID: newPoly.ID})
		P.Bindings[bindingPos].CommitmentsName = append(P.Bindings[bindingPos].CommitmentsName, newPoly.ID)
		err = fs.Bind(FLATTENING_CHALLENGE, curCom.Marshal())
		if err != nil {
			return System{}, Proof{}, err
		}
	}

	// add the final (fully reduced, degree ⩽ targetDegree) constraint
	lowDegreeConstraints = append(lowDegreeConstraints, C)

	// derive FLATTENING_CHALLENGE
	var alpha koalabear.Element
	balpha, err := fs.ComputeChallenge(FLATTENING_CHALLENGE)
	if err != nil {
		return System{}, Proof{}, err
	}
	alpha.SetBytes(balpha)

	// fold lowDegreeConstraints with alpha: Σᵢ αⁱ·Cᵢ
	// Use NewPlaceholder (degree 0, named) so the folded constraint's symbolic degree
	// equals max(deg Cᵢ), not inflated by alpha's powers, and the verifier can still
	// look up alpha by its name FLATTENING_CHALLENGE in the varindex.
	foldedConstraint := sym.Fold(sym.NewPlaceholder(FLATTENING_CHALLENGE), lowDegreeConstraints)

	// update the full constraint in S and P
	S.Constraint = foldedConstraint
	P.Constraint = foldedConstraint

	// add alpha as a constant polynomial so ComputeQuotient can reference it by name
	alphaColumn, err := univariate.NewConstantPolynomial(alpha, univariate.WithID(FLATTENING_CHALLENGE))
	if err != nil {
		return System{}, Proof{}, err
	}
	S.Trace = append(S.Trace, alphaColumn)

	return System{}, Proof{}, nil
}
