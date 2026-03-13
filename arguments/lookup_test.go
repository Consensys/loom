package arguments

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/constraint"
	"github.com/consensys/loom/expr"
	derive "github.com/consensys/loom/internal/derive"
	"github.com/consensys/loom/internal/prover"
	"github.com/consensys/loom/internal/verifier"
	"github.com/consensys/loom/trace"
	"github.com/consensys/loom/viz"
)

// BuildLookupTrace creates a trace with two columns T and S such that:
// - T[i] = i+1 (all distinct)
// - S[i] = T[i % (size/2)] (every value in S appears in T, with repetitions)
func BuildLookupTrace(t *testing.T, size int) trace.Trace {
	Tcoeffs := make([]koalabear.Element, size)
	for i := range Tcoeffs {
		Tcoeffs[i].SetUint64(uint64(i + 1))
	}

	Scoeffs := make([]koalabear.Element, size)
	for i := range Scoeffs {
		Scoeffs[i] = Tcoeffs[i%(size/2)]
	}

	return trace.Trace{"T": Tcoeffs, "S": Scoeffs}
}

// BuildLookupTupleTrace creates a trace with columns T0, T1, S0, S1 such that
// every row (S0[i], S1[i]) appears in the table {(T0[j], T1[j])} (subset with repetitions).
// T0[i] = i+1, T1[i] = (i+1)*2; S copies the first half of T rows twice.
func BuildLookupTupleTrace(t *testing.T, size int) trace.Trace {
	T0coeffs := make([]koalabear.Element, size)
	T1coeffs := make([]koalabear.Element, size)
	for i := range T0coeffs {
		T0coeffs[i].SetUint64(uint64(i + 1))
		T1coeffs[i].SetUint64(uint64((i + 1) * 2))
	}

	S0coeffs := make([]koalabear.Element, size)
	S1coeffs := make([]koalabear.Element, size)
	for i := range S0coeffs {
		S0coeffs[i] = T0coeffs[i%(size/2)]
		S1coeffs[i] = T1coeffs[i%(size/2)]
	}

	return trace.Trace{"T0": T0coeffs, "T1": T1coeffs, "S0": S0coeffs, "S1": S1coeffs}
}

func TestLookup(t *testing.T) {

	size := 16

	trace := BuildLookupTrace(t, size)
	system := constraint.NewBuilder(size)

	Lookup(&system, expr.Col("S"), expr.Col("T"))

	cciop := system.Compile()

	proverRunTime := prover.NewProver(cciop, trace)

	knowncolumns := map[string]bool{"T": true, "S": true}
	proof := derive.NewProof(system.N)

	// 1. Solve + sanity checks
	err := proverRunTime.Solve(knowncolumns, &proof, 1)
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
	err = verifierRunTime.Verify(&proof, 1)
	if err != nil {
		t.Fatal(err)
	}
}

func TestLookupTuple(t *testing.T) {

	size := 16

	tr := BuildLookupTupleTrace(t, size)
	system := constraint.NewBuilder(size)

	S0 := expr.Col("S0")
	S1 := expr.Col("S1")
	T0 := expr.Col("T0")
	T1 := expr.Col("T1")
	LookupTuple(&system, []expr.Expr{S0, S1}, []expr.Expr{T0, T1})

	cciop := system.Compile()

	proverRunTime := prover.NewProver(cciop, tr)

	knowncolumns := map[string]bool{"T0": true, "T1": true, "S0": true, "S1": true}
	proof := derive.NewProof(system.N)

	// 1. Solve + sanity checks
	err := proverRunTime.Solve(knowncolumns, &proof, 1)
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

	// 4b. OpenCommitments: evaluate all committed polynomials at zeta
	err = proverRunTime.OpenCommitments(&proof, zeta)
	if err != nil {
		t.Fatal(err)
	}

	viz.WriteProofTranscriptRoundsDagToHTML(proof.TranscriptRounds, "rounds.html")

	// 5. Build verifier runtime and derive challenges
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
