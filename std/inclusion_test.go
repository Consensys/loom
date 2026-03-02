package std

import (
	"testing"

	"github.com/consensys/giop/cs"
	"github.com/consensys/giop/pas/univariate"
	"github.com/consensys/giop/prover"
	"github.com/consensys/giop/trace"
	"github.com/consensys/giop/verifier"
	"github.com/consensys/gnark-crypto/field/koalabear"
)

// BuildInclusionTrace creates a trace with two columns T and S such that:
// - T[i] = i+1 (all distinct)
// - S[i] = T[i % (size/2)] (every value in S appears in T, with repetitions)
func BuildInclusionTrace(t *testing.T, size int) trace.Trace {
	Tcoeffs := make([]koalabear.Element, size)
	for i := range Tcoeffs {
		Tcoeffs[i].SetUint64(uint64(i + 1))
	}
	T, err := univariate.NewPolynomial(Tcoeffs, univariate.WithBasis(univariate.Lagrange))
	if err != nil {
		t.Fatalf("Failed to create T: %v", err)
	}

	Scoeffs := make([]koalabear.Element, size)
	for i := range Scoeffs {
		Scoeffs[i] = Tcoeffs[i%(size/2)]
	}
	S, err := univariate.NewPolynomial(Scoeffs, univariate.WithBasis(univariate.Lagrange))
	if err != nil {
		t.Fatalf("Failed to create S: %v", err)
	}

	return trace.Trace{"T": &T, "S": &S}
}

func TestInclusion(t *testing.T) {

	size := 16

	trace := BuildInclusionTrace(t, size)
	system := cs.NewSystem(size)

	InclusionCheckIOP(&system, "S", "T", "M", "GrandSumS", "GrandSumT", "gamma")

	cciop := cs.Compile(&system)

	proverRunTime := prover.NewRuntime(cciop, trace)

	knowncolumns := map[string]bool{"T": true, "S": true}
	proof := cs.NewProof(system.N)

	// 1. Solve + sanity checks
	err := proverRunTime.Solve(knowncolumns, &proof, 1)
	if err != nil {
		t.Fatal(err)
	}
	sanityCheck(&proverRunTime, system.Constraints, system.N, t)

	// 2. DeriveFinalFoldingChallenge + sanity checks
	err = proverRunTime.DeriveFinalFoldingChallenge(&proof)
	if err != nil {
		t.Fatal(err)
	}
	sanityCheck(&proverRunTime, system.Constraints, system.N, t)

	// 3. ComputeQuotient + sanity checks
	err = proverRunTime.ComputeQuotient(&proof)
	if err != nil {
		t.Fatal(err)
	}
	sanityCheck(&proverRunTime, system.Constraints, system.N, t)

	// 4. DeriveOpeningChallenge + sanity checks
	var zeta koalabear.Element
	zeta, err = proverRunTime.DeriveOpeningChallenge(&proof)
	if err != nil {
		t.Fatal(err)
	}
	sanityCheck(&proverRunTime, system.Constraints, system.N, t)

	// 4b. OpenCommitments: evaluate all committed polynomials at zeta
	err = proverRunTime.OpenCommitments(&proof, zeta)
	if err != nil {
		t.Fatal(err)
	}

	// 5. Build verifier runtime and derive challenges
	verifierRunTime := verifier.NewRunTime(cciop)
	err = verifierRunTime.ComputeChallenges(&proof, 1)
	if err != nil {
		t.Fatal(err)
	}
	CheckFiatShamir(&proverRunTime, &verifierRunTime, &proof, zeta, t)

	// 6. Verify
	err = verifierRunTime.Verify(&proof)
	if err != nil {
		t.Fatal(err)
	}
}
