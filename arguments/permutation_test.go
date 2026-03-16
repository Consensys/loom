package arguments

import (
	"fmt"
	"os"
	"runtime/pprof"
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/constraint"
	"github.com/consensys/loom/expr"
	derive "github.com/consensys/loom/internal/derive"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/internal/prover"
	"github.com/consensys/loom/internal/verifier"
	"github.com/consensys/loom/trace"
)

func TestPermutation(t *testing.T) {

	size := 16

	trace := constraint.BuildPermutationCircuit(t, size)
	system := constraint.NewBuilder(size, nil)

	Permutation(&system, []expr.Expr{expr.Col("P0")}, []expr.Expr{expr.Col("P1")})

	cp := system.Compile()

	proverRunTime := prover.NewProver(cp, trace, nil)

	// begin proving
	knowncolumns := map[string]bool{"P0": true, "P1": true}
	proof := derive.NewProof(system.N)

	// 1. DerivePlan + sanity checks
	err := proverRunTime.DerivePlan(knowncolumns, &proof, 1)
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

	// 4b. OpenCommitments: evaluate all committed polynomials (and the quotient) at zeta
	err = proverRunTime.OpenCommitments(&proof, zeta)
	if err != nil {
		t.Fatal(err)
	}

	// 5. Build verifier verifierRunTime and derive the challenge + sanity check: are the verifier challenges in sync with the prover's
	verifierRunTime := verifier.NewRunTime(cp, nil)
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
	system := constraint.NewBuilder(size, nil)

	P0 := expr.Col("P0")
	P1 := expr.Col("P1")
	Q0 := expr.Col("Q0")
	Q1 := expr.Col("Q1")
	err := PermutationTuple(&system, [][]expr.Expr{{P0, P1}}, [][]expr.Expr{{Q0, Q1}})
	if err != nil {
		t.Fatal(err)
	}

	knowncolumns := map[string]bool{"P0": true, "P1": true, "Q0": true, "Q1": true}
	cp := system.Compile()

	proverRunTime := prover.NewProver(cp, trace, nil)

	proof := derive.NewProof(system.N)

	// 1. DerivePlan + sanity checks
	err = proverRunTime.DerivePlan(knowncolumns, &proof, 1)
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
	verifierRunTime := verifier.NewRunTime(cp, nil)
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
	s1 := make([]expr.Expr, nbPolys)
	s2 := make([]expr.Expr, nbPolys)
	for i := 0; i < nbPolys; i++ {
		s1[i] = expr.Col(fmt.Sprintf("P1_%d", i))
		s2[i] = expr.Col(fmt.Sprintf("P2_%d", i))
		trace[fmt.Sprintf("P1_%d", i)] = p1[i]
		trace[fmt.Sprintf("P2_%d", i)] = p2[i]
	}

	system := constraint.NewBuilder(size, nil)

	_ = Permutation(&system, s1, s2)

	knowncolumns := make(map[string]bool)
	for _, s := range s1 {
		knowncolumns[s.String()] = true
	}
	for _, s := range s2 {
		knowncolumns[s.String()] = true
	}
	cp := system.Compile()

	f, _ := os.Create("cpu.prof")
	pprof.StartCPUProfile(f)
	b.Run("prover", func(b *testing.B) {
		for i := 0; i < b.N; i++ {

			_trace := make(map[string]poly.Polynomial)
			for i := 0; i < nbPolys; i++ {
				_trace[fmt.Sprintf("P1_%d", i)] = trace[fmt.Sprintf("P1_%d", i)]
				_trace[fmt.Sprintf("P2_%d", i)] = trace[fmt.Sprintf("P2_%d", i)]
			}

			proverRunTime := prover.NewProver(cp, _trace, nil)
			proverRunTime.Prove(knowncolumns, 1)

		}
	})
	pprof.StopCPUProfile()

}
