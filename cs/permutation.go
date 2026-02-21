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

// NewPermtutationProtocol
// IOP for proving that:
// [ (P1[0][0], P1[0][1], .., ), .., (P1[n][0], P1[n][1], .., ) ] is equal up to permutation, to
// [ (P2[0][0], P1[0][1], .., ), .., (P2[n][0], P1[n][1], .., ) ]
// It means that for each i there is a j such that (P1[i][0], P1[i][1], .., ) = (P2[j][0], P1[j][1], .., )
//
// It is a similar process than NewPermutationProtocol, except the (Pi[j][0], Pi[j][1], .. ) are folded to Pi'[j], and then
// we are in the same situation as in NewPermutationProtocol, that is we prove that
// (P1'[0], P1[1], ..) is equal up to permutation to (P2'[0], P2[1], ..)
//
// The Proof models the following Σ protocol:
//
//	|-------------------------------–-----------------------------------------------|
//	| [prover]						|				[verifier]						|
//	|-------------------------------–-----------------------------------------------|
//	| Commit(P1..., P2...)		 -----→		[Com_P1, Com_P2]					|ROUND 1
//	|-------------------------------–-----------------------------------------------|
//	|	α						←-----		Sample random α						|
//	|										(alpha=Fiat_Shamir(Com_P1,Com_P2))		|ROUND 2
//	|-------------------------------–-----------------------------------------------|
//	| P1'[i]=Σαʲ·P1[i][j]		 -----→		[Com_P1', Com_P2', Com_L]			|ROUND 3
//	| P2'[i]=Σαʲ·P2[i][j]														|
//	| Commit(P1', P2', L_0)														|
//	|-------------------------------–-----------------------------------------------|
//	|	γ						←-----		Sample random γ						|
//	|										(gamma=Fiat_Shamir(Com_P1',Com_P2'))	|ROUND 4
//	|-------------------------------–-----------------------------------------------|
//	| Compute R (grand product)		------→				Com_R					|ROUND 5
//	| Commit(R)																		|
//	|-------------------------------–-----------------------------------------------|
//	|	ε						←-----		Sample random ε						|
//	|										(epsilon=Fiat_Shamir(Com_R))			|ROUND 6
//	|-------------------------------–-----------------------------------------------|
//	| Compute fullRelation									  Com_H				|ROUND 7
//	| fullRelation=Σεⁱ·Rel_i												        |
//	| (fold rels, grand product, lagrange)										|
//	| Commit(H)																		|
//	|-------------------------------–-----------------------------------------------|
//	|	ζ						←-----		Sample random ζ						|
//	|										(zeta=Fiat_Shamir(Com_R,Com_H))		|ROUND 8
//	|-------------------------------–-----------------------------------------------|
//	| Open all at ζ				----→		Verify opening proofs				|
//	|										Check fullRelation(ζ)=H(ζ)*(ζⁿ-1)	|ROUND 9
//	|-------------------------------–-----------------------------------------------|
func NewPermtutationProtocol(P1, P2 [][]univariate.Polynomial, opts ...IopOption) (System, Proof, error) {

	// Validate inputs
	if len(P1) != len(P2) {
		return System{}, Proof{}, fmt.Errorf("len(P1)!=len(P2)")
	}
	if len(P1) == 0 {
		return System{}, Proof{}, fmt.Errorf("P1 and P2 cannot be empty")
	}
	n := len(P1)
	k := len(P1[0])
	if k < 2 {
		return System{}, Proof{}, fmt.Errorf("each group must have at least 2 polynomials for folding")
	}
	var sizePolys int
	for i := 0; i < n; i++ {
		if len(P1[i]) != k {
			return System{}, Proof{}, fmt.Errorf("P1[%d] has %d polynomials, expected %d", i, len(P1[i]), k)
		}
		if len(P2[i]) != k {
			return System{}, Proof{}, fmt.Errorf("P2[%d] has %d polynomials, expected %d", i, len(P2[i]), k)
		}
		for j := 0; j < k; j++ {
			if sizePolys == 0 {
				sizePolys = len(P1[i][j].EP.Coefficients)
			}
			if len(P1[i][j].EP.Coefficients) != sizePolys {
				return System{}, Proof{}, fmt.Errorf("polynomials are not of the same size")
			}
			if len(P2[i][j].EP.Coefficients) != sizePolys {
				return System{}, Proof{}, fmt.Errorf("polynomials are not of the same size")
			}
		}
	}

	// Apply config options
	var config IopConfig
	for _, opt := range opts {
		if err := opt(&config); err != nil {
			return System{}, Proof{}, err
		}
	}

	// Challenge names:
	//   Binding[0] = alpha   (fold within groups)
	//   Binding[1] = gamma   (grand product challenge)
	//   Binding[2] = epsilon (fold all relations)
	//   Binding[3] = zeta    (evaluation point)
	alphaName := "alpha"
	gammaName := "gamma"
	epsilonName := "epsilon"
	zetaName := "zeta"
	if config.ChallengeNames != nil {
		if len(config.ChallengeNames) >= 1 {
			alphaName = config.ChallengeNames[0]
		}
		if len(config.ChallengeNames) >= 2 {
			gammaName = config.ChallengeNames[1]
		}
		if len(config.ChallengeNames) >= 3 {
			epsilonName = config.ChallengeNames[2]
		}
		if len(config.ChallengeNames) >= 4 {
			zetaName = config.ChallengeNames[3]
		}
	}

	// Build proof skeleton.
	// OpeningProofs layout: [P1 flat, P2 flat, P1' flat, P2' flat, R, RS, lagrangePoly]
	//   indices 0..n*k-1       : P1[i][j] (row-major: i outer, j inner)
	//   indices n*k..2*n*k-1   : P2[i][j]
	//   indices 2*n*k..2*n*k+n-1      : P1'[i]
	//   indices 2*n*k+n..2*n*k+2*n-1  : P2'[i]
	//   index   2*n*k+2*n      : R
	//   index   2*n*k+2*n+1    : RS  (derived from R, not FS-bound)
	//   index   2*n*k+2*n+2    : lagrangePoly (L_0)
	lagrangeID := GetLagrangeID(0)
	numOpenings := 2*n*k + 2*n + 3

	var T Proof
	T.N = sizePolys
	T.Bindings = make([]Binding, 4)
	T.Bindings[0].ChallengeName = alphaName
	T.Bindings[1].ChallengeName = gammaName
	T.Bindings[2].ChallengeName = epsilonName
	T.Bindings[3].ChallengeName = zetaName

	// Binding[0]: all P1[i][j] and P2[i][j]
	T.Bindings[0].CommitmentsName = make([]string, 2*n*k)
	for i := 0; i < n; i++ {
		for j := 0; j < k; j++ {
			T.Bindings[0].CommitmentsName[i*k+j] = P1[i][j].ID
			T.Bindings[0].CommitmentsName[n*k+i*k+j] = P2[i][j].ID
		}
	}

	// Create Fiat-Shamir proof
	fs := fiatshamir.NewTranscript(sha256.New(), alphaName, gammaName, epsilonName, zetaName)

	T.OpeningProofs = make([]dummycommitment.PackedProof, numOpenings)
	var err error

	// ROUND 1: Commit P1[i][j] and P2[i][j], bind to alphaName.
	for i := 0; i < n; i++ {
		for j := 0; j < k; j++ {
			idx := i*k + j
			T.OpeningProofs[idx].ID = P1[i][j].ID
			T.OpeningProofs[idx].Digest, err = dummycommitment.Commit(&P1[i][j])
			if err != nil {
				return System{}, Proof{}, err
			}
			fs.Bind(alphaName, T.OpeningProofs[idx].Digest.Marshal())
		}
	}
	for i := 0; i < n; i++ {
		for j := 0; j < k; j++ {
			idx := n*k + i*k + j
			T.OpeningProofs[idx].ID = P2[i][j].ID
			T.OpeningProofs[idx].Digest, err = dummycommitment.Commit(&P2[i][j])
			if err != nil {
				return System{}, Proof{}, err
			}
			fs.Bind(alphaName, T.OpeningProofs[idx].Digest.Marshal())
		}
	}

	// ROUND 2: Derive alpha.
	var alpha koalabear.Element
	if config.ChallengeValues == nil {
		balpha, err := fs.ComputeChallenge(alphaName)
		if err != nil {
			return System{}, Proof{}, err
		}
		alpha.SetBytes(balpha)
	} else {
		alpha.Set(&config.ChallengeValues[0])
	}

	// FOLD STEP: P1'[i] = Σⱼ αʲ·P1[i][j], P2'[i] = Σⱼ αʲ·P2[i][j].
	// Record folding relations for the full relation later.
	P1prime := make([]univariate.Polynomial, n)
	P2prime := make([]univariate.Polynomial, n)
	foldRelP1 := make([]Constraint, n)
	foldRelP2 := make([]Constraint, n)
	IDs1 := make([][]string, n)
	IDs2 := make([][]string, n)
	for i := 0; i < n; i++ {
		IDs1[i] = make([]string, k)
		IDs2[i] = make([]string, k)
		for j := 0; j < k; j++ {
			IDs1[i][j] = P1[i][j].ID
			IDs2[i][j] = P2[i][j].ID
		}
		P1prime[i], err = univariate.BuildLinComb(P1[i], alpha, univariate.WithOutputName(fmt.Sprintf("P1prime_%d", i)))
		if err != nil {
			return System{}, Proof{}, err
		}
		P2prime[i], err = univariate.BuildLinComb(P2[i], alpha, univariate.WithOutputName(fmt.Sprintf("P2prime_%d", i)))
		if err != nil {
			return System{}, Proof{}, err
		}
		foldRelP1[i] = GetFoldingRelation(IDs1[i], alphaName, P1prime[i].ID)
		foldRelP2[i] = GetFoldingRelation(IDs2[i], alphaName, P2prime[i].ID)
	}

	// ROUND 3: Commit P1'[i], P2'[i] and lagrangePoly, bind to gammaName.
	// Binding[1]: P1'[0..n-1], P2'[0..n-1], lagrangeID
	T.Bindings[1].CommitmentsName = make([]string, 2*n+1)
	for i := 0; i < n; i++ {
		idx := 2*n*k + i
		T.OpeningProofs[idx].ID = P1prime[i].ID
		T.OpeningProofs[idx].Digest, err = dummycommitment.Commit(&P1prime[i])
		if err != nil {
			return System{}, Proof{}, err
		}
		fs.Bind(gammaName, T.OpeningProofs[idx].Digest.Marshal())
		T.Bindings[1].CommitmentsName[i] = P1prime[i].ID
	}
	for i := 0; i < n; i++ {
		idx := 2*n*k + n + i
		T.OpeningProofs[idx].ID = P2prime[i].ID
		T.OpeningProofs[idx].Digest, err = dummycommitment.Commit(&P2prime[i])
		if err != nil {
			return System{}, Proof{}, err
		}
		fs.Bind(gammaName, T.OpeningProofs[idx].Digest.Marshal())
		T.Bindings[1].CommitmentsName[n+i] = P2prime[i].ID
	}

	// Build and commit lagrangePoly (1 at index 0, 0 elsewhere) for the boundary condition R[0]=1.
	lagrangeCoeffs := make([]koalabear.Element, sizePolys)
	lagrangeCoeffs[0].SetOne()
	lagrangePoly, err := univariate.NewInterpolatedPolynomial(lagrangeCoeffs, lagrangeID)
	if err != nil {
		return System{}, Proof{}, err
	}
	lagIdx := 2*n*k + 2*n + 2
	T.OpeningProofs[lagIdx].ID = lagrangeID
	T.OpeningProofs[lagIdx].Digest, err = dummycommitment.Commit(&lagrangePoly)
	if err != nil {
		return System{}, Proof{}, err
	}
	fs.Bind(gammaName, T.OpeningProofs[lagIdx].Digest.Marshal())
	T.Bindings[1].CommitmentsName[2*n] = lagrangeID

	// ROUND 4: Derive gamma.
	var gamma koalabear.Element
	if config.ChallengeValues == nil {
		bgamma, err := fs.ComputeChallenge(gammaName)
		if err != nil {
			return System{}, Proof{}, err
		}
		gamma.SetBytes(bgamma)
	} else {
		gamma.Set(&config.ChallengeValues[1])
	}

	gammaColumn, err := univariate.NewConstantPolynomial(gamma, univariate.WithID(gammaName))
	if err != nil {
		return System{}, Proof{}, err
	}

	// Build grand product constraints C1 = Π(P1'[i]-γ), C2 = Π(P2'[i]-γ).
	IDsP1prime := make([]string, n)
	IDsP2prime := make([]string, n)
	for i := 0; i < n; i++ {
		IDsP1prime[i] = P1prime[i].ID
		IDsP2prime[i] = P2prime[i].ID
	}
	C1 := GetProductRelation(IDsP1prime, gammaName)
	C2 := GetProductRelation(IDsP2prime, gammaName)

	// Build _P1prime, _P2prime augmented with gammaColumn for BuildRatio.
	_P1prime := make([]univariate.Polynomial, n+1)
	copy(_P1prime, P1prime)
	_P1prime[n] = gammaColumn
	_P2prime := make([]univariate.Polynomial, n+1)
	copy(_P2prime, P2prime)
	_P2prime[n] = gammaColumn

	// ROUND 5: Compute R (grand product), materialize RS, commit R, bind to epsilonName.
	// Use a prefixed name to avoid collisions with user-supplied column IDs.
	R, err := univariate.BuildRatio(C1, C2, _P1prime, _P2prime, univariate.WithOutputName("_grandprod_R"))
	if err != nil {
		return System{}, Proof{}, err
	}
	rsID := fmt.Sprintf("%s_shifted", R.ID)

	// Materialize RS as a circular shift of R's Lagrange evaluations by 1 position.
	rsCoeffs := make([]koalabear.Element, sizePolys)
	for i := 0; i < sizePolys; i++ {
		rsCoeffs[i] = R.GetCoefficient((i + 1) % sizePolys)
	}
	RS, err := univariate.NewInterpolatedPolynomial(rsCoeffs, rsID)
	if err != nil {
		return System{}, Proof{}, err
	}

	// Commit R, bind to epsilonName.
	RIdx := 2*n*k + 2*n
	T.OpeningProofs[RIdx].ID = R.ID
	T.OpeningProofs[RIdx].Digest, err = dummycommitment.Commit(&R)
	if err != nil {
		return System{}, Proof{}, err
	}
	T.Bindings[2].CommitmentsName = []string{R.ID}
	fs.Bind(epsilonName, T.OpeningProofs[RIdx].Digest.Marshal())

	// RS: not separately FS-bound (derived from R), but needs an opening proof.
	RSIdx := 2*n*k + 2*n + 1
	T.OpeningProofs[RSIdx].ID = rsID
	T.OpeningProofs[RSIdx].Digest, err = dummycommitment.Commit(&RS)
	if err != nil {
		return System{}, Proof{}, err
	}

	// ROUND 6: Derive epsilon.
	var epsilon koalabear.Element
	if config.ChallengeValues == nil {
		bepsilon, err := fs.ComputeChallenge(epsilonName)
		if err != nil {
			return System{}, Proof{}, err
		}
		epsilon.SetBytes(bepsilon)
	} else {
		epsilon.Set(&config.ChallengeValues[2])
	}

	alphaColumn, err := univariate.NewConstantPolynomial(alpha, univariate.WithID(alphaName))
	if err != nil {
		return System{}, Proof{}, err
	}
	epsilonColumn, err := univariate.NewConstantPolynomial(epsilon, univariate.WithID(epsilonName))
	if err != nil {
		return System{}, Proof{}, err
	}

	// Grand product constraint and Lagrange boundary constraint R[0]=1.
	C_grand := GetGrandProductRelation(C1, C2, R.ID, rsID)
	var one koalabear.Element
	one.SetOne()
	C_lagrange := GetLagrangeRelation(R.ID, 0, one)

	// Build fullRelation = Σᵢ εⁱ·Relᵢ where the relations are:
	//   [foldRelP1[0], ..., foldRelP1[n-1], foldRelP2[0], ..., foldRelP2[n-1], C_grand, C_lagrange]
	allRelations := make([]sym.Expr, 2*n+2)
	for i := 0; i < n; i++ {
		allRelations[i] = foldRelP1[i]
		allRelations[n+i] = foldRelP2[i]
	}
	allRelations[2*n] = C_grand
	allRelations[2*n+1] = C_lagrange

	epsilonVar := sym.NewVar(epsilonName)
	fullRelation := allRelations[0]
	for i := 1; i < len(allRelations); i++ {
		fullRelation = fullRelation.Add(allRelations[i].Mul(epsilonVar.Pow(uint32(i))))
	}
	T.Constraint = fullRelation

	// Build columns for ComputeQuotient. ComputeSym requires unique IDs, so we
	// deduplicate: if P2[i][j] shares an ID with a P1 polynomial already added,
	// skip it (the constraint will correctly reuse the same column data).
	seenIDs := make(map[string]struct{})
	var columns []univariate.Polynomial
	for i := 0; i < n; i++ {
		for j := 0; j < k; j++ {
			columns = append(columns, P1[i][j])
			seenIDs[P1[i][j].ID] = struct{}{}
		}
	}
	for i := 0; i < n; i++ {
		for j := 0; j < k; j++ {
			if _, exists := seenIDs[P2[i][j].ID]; !exists {
				columns = append(columns, P2[i][j])
				seenIDs[P2[i][j].ID] = struct{}{}
			}
		}
	}
	for i := 0; i < n; i++ {
		columns = append(columns, P1prime[i])
	}
	for i := 0; i < n; i++ {
		columns = append(columns, P2prime[i])
	}
	columns = append(columns, R, RS, alphaColumn, gammaColumn, epsilonColumn, lagrangePoly)

	// ROUND 7: Compute quotient H = fullRelation / (Xⁿ-1), commit H, bind to zetaName.
	H, err := univariate.ComputeQuotient(columns, fullRelation, univariate.WithResultBasis(univariate.Canonical))
	if err != nil {
		return System{}, Proof{}, err
	}
	T.Quotient.Digest, err = dummycommitment.Commit(&H)
	if err != nil {
		return System{}, Proof{}, err
	}
	err = fs.Bind(zetaName, T.Quotient.Digest.Marshal())
	if err != nil {
		return System{}, Proof{}, err
	}

	// ROUND 8: Derive zeta.
	var zeta koalabear.Element
	if config.ChallengeValues == nil {
		bzeta, err := fs.ComputeChallenge(zetaName)
		if err != nil {
			return System{}, Proof{}, err
		}
		zeta.SetBytes(bzeta)
	} else {
		zeta.Set(&config.ChallengeValues[len(config.ChallengeValues)-1])
	}

	// ROUND 9: Open all polynomials at zeta.
	// dummycommitment.Open requires Canonical basis; use deep copies to avoid mutating inputs.
	d := fft.NewDomain(uint64(sizePolys))

	// Open P1[i][j]
	for i := 0; i < n; i++ {
		for j := 0; j < k; j++ {
			oidx := i*k + j
			var pCopy univariate.Polynomial
			univariate.Copy(&pCopy, &P1[i][j])
			if err := pCopy.ToBasis(d, univariate.Canonical); err != nil {
				return System{}, Proof{}, err
			}
			T.OpeningProofs[oidx].OpeningProof, err = dummycommitment.Open(pCopy, zeta)
			if err != nil {
				return System{}, Proof{}, err
			}
		}
	}

	// Open P2[i][j]
	for i := 0; i < n; i++ {
		for j := 0; j < k; j++ {
			oidx := n*k + i*k + j
			var pCopy univariate.Polynomial
			univariate.Copy(&pCopy, &P2[i][j])
			if err := pCopy.ToBasis(d, univariate.Canonical); err != nil {
				return System{}, Proof{}, err
			}
			T.OpeningProofs[oidx].OpeningProof, err = dummycommitment.Open(pCopy, zeta)
			if err != nil {
				return System{}, Proof{}, err
			}
		}
	}

	// Open P1'[i]
	for i := 0; i < n; i++ {
		oidx := 2*n*k + i
		var pCopy univariate.Polynomial
		univariate.Copy(&pCopy, &P1prime[i])
		if err := pCopy.ToBasis(d, univariate.Canonical); err != nil {
			return System{}, Proof{}, err
		}
		T.OpeningProofs[oidx].OpeningProof, err = dummycommitment.Open(pCopy, zeta)
		if err != nil {
			return System{}, Proof{}, err
		}
	}

	// Open P2'[i]
	for i := 0; i < n; i++ {
		oidx := 2*n*k + n + i
		var pCopy univariate.Polynomial
		univariate.Copy(&pCopy, &P2prime[i])
		if err := pCopy.ToBasis(d, univariate.Canonical); err != nil {
			return System{}, Proof{}, err
		}
		T.OpeningProofs[oidx].OpeningProof, err = dummycommitment.Open(pCopy, zeta)
		if err != nil {
			return System{}, Proof{}, err
		}
	}

	// Open R
	var rCopy univariate.Polynomial
	univariate.Copy(&rCopy, &R)
	if err := rCopy.ToBasis(d, univariate.Canonical); err != nil {
		return System{}, Proof{}, err
	}
	T.OpeningProofs[RIdx].OpeningProof, err = dummycommitment.Open(rCopy, zeta)
	if err != nil {
		return System{}, Proof{}, err
	}

	// Open RS
	var rsCopy univariate.Polynomial
	univariate.Copy(&rsCopy, &RS)
	if err := rsCopy.ToBasis(d, univariate.Canonical); err != nil {
		return System{}, Proof{}, err
	}
	T.OpeningProofs[RSIdx].OpeningProof, err = dummycommitment.Open(rsCopy, zeta)
	if err != nil {
		return System{}, Proof{}, err
	}

	// Open lagrangePoly
	var lagCopy univariate.Polynomial
	univariate.Copy(&lagCopy, &lagrangePoly)
	if err := lagCopy.ToBasis(d, univariate.Canonical); err != nil {
		return System{}, Proof{}, err
	}
	T.OpeningProofs[lagIdx].OpeningProof, err = dummycommitment.Open(lagCopy, zeta)
	if err != nil {
		return System{}, Proof{}, err
	}

	// Open quotient
	T.Quotient.OpeningProof, err = dummycommitment.Open(H, zeta)
	if err != nil {
		return System{}, Proof{}, err
	}

	S := System{
		Trace:      columns,
		Constraint: fullRelation,
		N:          sizePolys,
	}

	return S, T, nil
}
