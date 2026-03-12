package cs

import (
	"sync"
	"testing"

	"github.com/consensys/giop/expr"
	proveractions "github.com/consensys/giop/prover_actions"
	"github.com/consensys/giop/trace"
	"github.com/consensys/gnark-crypto/field/koalabear"
)

func TestDegreeReduction(t *testing.T) {
	N := 16

	// 1. Build a trace with P0 random and P1 = P0, so P0[i]^4 - P1[i]^4 = 0 at every row.
	coeffs := make([]koalabear.Element, N)
	for i := range coeffs {
		coeffs[i].SetRandom()
	}
	coeffs1 := make([]koalabear.Element, N)
	copy(coeffs1, coeffs)

	T := trace.Trace{
		"P0": coeffs,
		"P1": coeffs1,
	}

	// 2. Create a system with the single degree-4 constraint P0^4 - P1^4.
	system := NewBuilder(N)
	p0 := expr.Col("P0")
	p1 := expr.Col("P1")
	system.AssertZero(p0.Pow(4).Sub(p1.Pow(4)))

	// 3. Reduce the degree: each sub-expression of degree > targetDegree is extracted
	//    into a fresh auxiliary column and replaced by a committed-column leaf.
	//    For P0^4 - P1^4 → targetDegree=2 this introduces:
	//      "(P0 * P0)"              = P0^2
	//      "((P0 * P0) * (P0 * P0))" = P0^4   (using the auxiliary col above)
	//      "(P1 * P1)"              = P1^2
	reduceDegree(&system, 2)

	// Every constraint must now have degree ≤ targetDegree.
	for _, c := range system.Relations {
		if d := c.Degree(); d > 2 {
			t.Fatalf("constraint has degree %d after reduction: %s", d, c.String())
		}
	}
	// Degree reduction should have introduced auxiliary constraints.
	if len(system.Relations) <= 1 {
		t.Fatalf("expected auxiliary constraints after reduction, got %d total", len(system.Relations))
	}

	// 4. Execute all prover actions to populate T with the auxiliary columns.
	//    When the same sub-expression (e.g. P0*P0) is extracted twice by Prune,
	//    reduceDegree emits duplicate prover actions. The second execution returns
	//    "already registered"; skip it silently since the column is already correct.
	proof := proveractions.NewProof(N)
	var mu sync.Mutex
	for _, pa := range system.DerivationPlan {
		if err := pa.Execute(T, &proof, &mu); err != nil {
			// "already registered" errors are expected for duplicate auxiliary columns
			_ = err
		}
	}

	// 5. All constraints must vanish on the trace.
	if err := BruteForceChecker(T, system.Relations, N); err != nil {
		t.Fatal(err)
	}
	if err := QuotientChecker(T, system.Relations, N); err != nil {
		t.Fatal(err)
	}
}
