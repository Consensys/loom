package arguments

import (
	"testing"

	"github.com/consensys/giop/cs"
	"github.com/consensys/giop/univariate"
	"github.com/consensys/giop/prover"
	proveractions "github.com/consensys/giop/prover_actions"
	"github.com/consensys/giop/trace"
	"github.com/consensys/giop/verifier"
	"github.com/consensys/giop/viz"
	"github.com/consensys/gnark-crypto/field/koalabear"
)

func TestEqualityFilteredMultiColumns(t *testing.T) {

	size := 16

	// Same construction as TestEqualityFilteredColumns, but A and B are
	// duplicated into two-column lists [A, A2] and [B, B2].
	aVals := make(univariate.Polynomial, size)
	for i := range aVals {
		aVals[i].SetRandom()
	}

	f1Vals := make(univariate.Polynomial, size)
	f2Vals := make(univariate.Polynomial, size)
	bVals := make(univariate.Polynomial, size)
	for i := 0; i < size; i++ {
		if i%2 == 0 {
			f1Vals[i].SetOne()
			bVals[i].SetRandom()
		} else {
			f2Vals[i].SetOne()
			bVals[i].Set(&aVals[i-1])
		}
	}

	// Duplicate: A2 = A, B2 = B
	aVals2 := make(univariate.Polynomial, size)
	bVals2 := make(univariate.Polynomial, size)
	copy(aVals2, aVals)
	copy(bVals2, bVals)

	T := trace.Trace{
		"A":  aVals,
		"A2": aVals2,
		"B":  bVals,
		"B2": bVals2,
		"F1": f1Vals,
		"F2": f2Vals,
	}

	system := cs.NewBuilder(size)

	err := ProjectionTuple(&system, []string{"A", "A2"}, "F1", []string{"B", "B2"}, "F2")
	if err != nil {
		t.Fatal(err)
	}

	cciop := cs.Compile(&system)
	proverRunTime := prover.NewRuntime(cciop, T)
	knownColumns := map[string]bool{"A": true, "A2": true, "B": true, "B2": true, "F1": true, "F2": true}
	proof := proveractions.NewProof(system.N)

	viz.WriteDerivationPlanDagToHTML(cciop, "pa_projection_multi.html")

	err = proverRunTime.Solve(knownColumns, &proof, 1)
	if err != nil {
		t.Fatal(err)
	}
	sanityCheck(&proverRunTime, system.Relations, system.N, t)

	err = proverRunTime.DeriveFinalFoldingChallenge(&proof)
	if err != nil {
		t.Fatal(err)
	}
	sanityCheck(&proverRunTime, system.Relations, system.N, t)

	err = proverRunTime.ComputeQuotient(&proof)
	if err != nil {
		t.Fatal(err)
	}
	sanityCheck(&proverRunTime, system.Relations, system.N, t)

	var zeta koalabear.Element
	zeta, err = proverRunTime.DeriveOpeningChallenge(&proof)
	if err != nil {
		t.Fatal(err)
	}
	sanityCheck(&proverRunTime, system.Relations, system.N, t)

	err = proverRunTime.OpenCommitments(&proof, zeta)
	if err != nil {
		t.Fatal(err)
	}

	verifierRunTime := verifier.NewRunTime(cciop)
	err = verifierRunTime.ComputeChallenges(&proof, 1)
	if err != nil {
		t.Fatal(err)
	}
	CheckFiatShamir(&proverRunTime, &verifierRunTime, &proof, zeta, t)

	viz.WriteProofRoundsDagToHTML(proof.Rounds, "projection_multi_rounds.html")

	err = verifierRunTime.Verify(&proof, 1)
	if err != nil {
		t.Fatal(err)
	}
}

func TestEqualityFilteredColumns(t *testing.T) {

	size := 16

	// 1. Build a trace containing:
	//   - A: random column of size 16
	//   - F1: binary filter — selects even-indexed rows of A (F1[i]=1 iff i even)
	//   - B: another column whose F2-selected entries match the F1-selected entries of A in order
	//   - F2: binary filter — selects odd-indexed rows of B (F2[i]=1 iff i odd)
	//
	// A filtered by F1 gives [A[0], A[2], ..., A[14]]  (8 values)
	// B filtered by F2 gives [B[1], B[3], ..., B[15]]  (8 values)
	// We set B[2k+1] = A[2k], so both filtered sequences are identical.
	// Non-selected entries of B are arbitrary.
	aVals := make(univariate.Polynomial, size)
	for i := range aVals {
		aVals[i].SetRandom()
	}

	f1Vals := make(univariate.Polynomial, size) // selects even rows of A
	f2Vals := make(univariate.Polynomial, size) // selects odd  rows of B
	bVals := make(univariate.Polynomial, size)
	for i := 0; i < size; i++ {
		if i%2 == 0 {
			f1Vals[i].SetOne()
			bVals[i].SetRandom() // not selected by F2, arbitrary
		} else {
			f2Vals[i].SetOne()
			bVals[i].Set(&aVals[i-1]) // B[2k+1] = A[2k]
		}
	}

	T := trace.Trace{
		"A":  aVals,
		"B":  bVals,
		"F1": f1Vals,
		"F2": f2Vals,
	}

	// create a new system
	system := cs.NewBuilder(size)

	// call EqualityFilteredColumns
	err := Projection(&system, "A", "F1", "B", "F2")
	if err != nil {
		t.Fatal(err)
	}

	cciop := cs.Compile(&system)
	proverRunTime := prover.NewRuntime(cciop, T)
	knownColumns := map[string]bool{"A": true, "B": true, "F1": true, "F2": true}
	proof := proveractions.NewProof(system.N)

	// 1. Solve + sanity checks
	err = proverRunTime.Solve(knownColumns, &proof, 1)
	if err != nil {
		t.Fatal(err)
	}
	sanityCheck(&proverRunTime, system.Relations, system.N, t)

	// 2. DeriveFinalFoldingChallenge + sanity checks
	err = proverRunTime.DeriveFinalFoldingChallenge(&proof)
	if err != nil {
		t.Fatal(err)
	}
	sanityCheck(&proverRunTime, system.Relations, system.N, t)

	// 3. ComputeQuotient + sanity checks
	err = proverRunTime.ComputeQuotient(&proof)
	if err != nil {
		t.Fatal(err)
	}
	sanityCheck(&proverRunTime, system.Relations, system.N, t)

	// 4. DeriveOpeningChallenge + sanity checks
	var zeta koalabear.Element
	zeta, err = proverRunTime.DeriveOpeningChallenge(&proof)
	if err != nil {
		t.Fatal(err)
	}
	sanityCheck(&proverRunTime, system.Relations, system.N, t)

	// 4b. OpenCommitments
	err = proverRunTime.OpenCommitments(&proof, zeta)
	if err != nil {
		t.Fatal(err)
	}

	// 5. Build verifier runtime and check Fiat-Shamir consistency
	verifierRunTime := verifier.NewRunTime(cciop)
	err = verifierRunTime.ComputeChallenges(&proof, 1)
	if err != nil {
		t.Fatal(err)
	}
	CheckFiatShamir(&proverRunTime, &verifierRunTime, &proof, zeta, t)

	// 6. Verify
	err = verifierRunTime.Verify(&proof, 1)
	if err != nil {
		t.Fatal(err)
	}
}
