package arguments

import (
	"fmt"
	"os"
	"runtime/pprof"
	"testing"

	"github.com/consensys/loom/constraint"
	derive "github.com/consensys/loom/internal/derive"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/internal/prover"
	"github.com/consensys/loom/trace"
	"github.com/consensys/loom/internal/verifier"
	"github.com/consensys/gnark-crypto/field/koalabear"
)

func TestPermutation(t *testing.T) {

	size := 16

	trace := constraint.BuildPermutationCircuit(t, size)
	system := constraint.NewBuilder(size)

	Permutation(&system, []string{"P0"}, []string{"P1"})

	cciop := system.Compile()

	proverRunTime := prover.NewProver(cciop, trace)

	// begin proving
	knowncolumns := map[string]bool{"P0": true, "P1": true}
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
	// viewer.WriteTraceToCSV("trace.csv", proverRunTime.Trace, system.N)
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

	// 4b. OpenCommitments: evaluate all committed polynomials (and the quotient) at zeta
	err = proverRunTime.OpenCommitments(&proof, zeta)
	if err != nil {
		t.Fatal(err)
	}

	// 5. Build verifier verifierRunTime and derive the challenge + sanity check: are the verifier challenges in sync with the prover's
	verifierRunTime := verifier.NewRunTime(cciop)
	err = verifierRunTime.ComputeChallenges(&proof, 1)
	if err != nil {
		t.Fatal(err)
	}
	CheckFiatShamir(&proverRunTime, &verifierRunTime, &proof, zeta, t)

	// 6. verify
	err = verifierRunTime.Verify(&proof, 1)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPermutationTuple(t *testing.T) {

	size := 16

	trace := constraint.BuildPermutationTuple(t, size)
	system := constraint.NewBuilder(size)

	err := PermutationTuple(&system, [][]string{{"P0", "P1"}}, [][]string{{"Q0", "Q1"}})
	if err != nil {
		t.Fatal(err)
	}

	knowncolumns := map[string]bool{"P0": true, "P1": true, "Q0": true, "Q1": true}
	cciop := system.Compile()

	proverRunTime := prover.NewProver(cciop, trace)

	proof := derive.NewProof(system.N)

	// 1. Solve + sanity checks
	err = proverRunTime.Solve(knowncolumns, &proof, 1)
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

func BenchmarkPermutation(b *testing.B) {

	size := 1 << 10
	nbPolys := 5
	p1 := make([]poly.Polynomial, nbPolys)
	for i := 0; i < nbPolys; i++ {
		p1[i] = make(poly.Polynomial, size)
		for j := 0; j < size; j++ {
			p1[i][j].SetRandom()
		}
	}
	p2 := make([]poly.Polynomial, nbPolys)
	for i := 0; i < nbPolys; i++ {
		p2[i] = make(poly.Polynomial, size)
		for j := 0; j < size; j++ {
			p2[i][j].Set(&p1[(i+1)%nbPolys][(j+1)%size])
		}
	}

	trace := make(trace.Trace)
	s1 := make([]string, nbPolys)
	s2 := make([]string, nbPolys)
	for i := 0; i < nbPolys; i++ {
		s1[i] = fmt.Sprintf("P1_%d", i)
		s2[i] = fmt.Sprintf("P2_%d", i)
		trace[fmt.Sprintf("P1_%d", i)] = p1[i]
		trace[fmt.Sprintf("P2_%d", i)] = p2[i]
	}

	system := constraint.NewBuilder(size)

	_ = Permutation(&system, s1, s2)

	knowncolumns := make(map[string]bool)
	for _, s := range s1 {
		knowncolumns[s] = true
	}
	for _, s := range s2 {
		knowncolumns[s] = true
	}
	cciop := system.Compile()

	f, _ := os.Create("cpu.prof")
	pprof.StartCPUProfile(f)
	b.Run("prover", func(b *testing.B) {
		for i := 0; i < b.N; i++ {

			_trace := make(map[string]poly.Polynomial)
			for i := 0; i < nbPolys; i++ {
				_trace[fmt.Sprintf("P1_%d", i)] = trace[fmt.Sprintf("P1_%d", i)]
				_trace[fmt.Sprintf("P2_%d", i)] = trace[fmt.Sprintf("P2_%d", i)]
			}

			proverRunTime := prover.NewProver(cciop, _trace)
			proverRunTime.Prove(knowncolumns, 1)

		}
	})
	pprof.StopCPUProfile()

}
