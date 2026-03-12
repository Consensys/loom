package constraint

import (
	"sync"
	"testing"

	"github.com/consensys/giop/expr"
	derive "github.com/consensys/giop/derive"
	"github.com/consensys/gnark-crypto/field/koalabear"
)

func TestGrandProductRelation(t *testing.T) {

	size := 16

	trace := BuildPermutationCircuit(t, size)

	// fix a challenge value (gamma for the grand product)
	var gamma koalabear.Element
	gamma.SetUint64(42)
	challenge := Challenge{Name: "gamma", Value: gamma}

	addChallengeInTrace(trace, challenge) // <- simulate SendMeAChallenge

	E1 := expr.Col("P0").Sub(expr.NewChallenge("gamma"))
	E2 := expr.Col("P1").Sub(expr.NewChallenge("gamma"))

	var mu sync.Mutex
	err := derive.ComputeLagrangeColumn(trace, nil, &mu, nil, []string{derive.GetLagrangeID(0, size)}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// add the constraint that the grand product is computed correctly to the system
	system := NewBuilder(size)
	GPRelation := BuildGrandProductRelation(E1, E2, "R", size)
	system.AssertAllZero(GPRelation)
	proof := derive.NewProof(size)
	derive.ComputeGrandProduct(trace, &proof, &mu, []expr.Expr{E1, E2}, []string{"R"}, nil)

	// R[0] must equal 1
	var one koalabear.Element
	one.SetOne()
	R0 := trace["R"][0]
	if !R0.Equal(&one) {
		t.Fatalf("R[0] should be 1, got %s", R0.String())
	}

	// verify recurrence R[i+1] = R[i] * (P0[i]-gamma) / (P1[i]-gamma) at every row
	for i := 0; i < size; i++ {
		Ri := trace["R"][i]
		Ri1 := trace["R"][(i+1)%size]
		Ri1Expected := new(koalabear.Element).Set(&Ri)
		c := trace["P0"][i]
		num := new(koalabear.Element).Sub(&c, &gamma)
		c = trace["P1"][i]
		den := new(koalabear.Element).Sub(&c, &gamma)
		Ri1Expected.Mul(Ri1Expected, num)
		Ri1Expected.Div(Ri1Expected, den)
		if !Ri1.Equal(Ri1Expected) {
			t.Fatalf("R[%d]: expected %s, got %s", (i+1)%size, Ri1Expected.String(), Ri1.String())
		}
	}

	err = BruteForceChecker(trace, system.Relations, system.N)
	if err != nil {
		t.Fatal(err)
	}

	err = QuotientChecker(trace, system.Relations, system.N)
	if err != nil {
		t.Fatal(err)
	}

}
