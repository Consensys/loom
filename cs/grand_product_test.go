package cs

import (
	"sync"
	"testing"

	"github.com/consensys/giop/pas/sym"
	"github.com/consensys/gnark-crypto/field/koalabear"
)

func TestGrandProductConstraint(t *testing.T) {

	size := 16

	trace := BuildPermutationCircuit(t, size)

	// fix a challenge value (gamma for the grand product)
	var gamma koalabear.Element
	gamma.SetUint64(42)
	challenge := Challenge{Name: "gamma", Value: gamma}

	addChallengeInTrace(trace, challenge) // <- simulate SendMeAChallenge

	E1 := sym.NewCommittedColumn("P0").Sub(sym.NewChallenge("gamma"))
	E2 := sym.NewCommittedColumn("P1").Sub(sym.NewChallenge("gamma"))

	var mu sync.Mutex
	err := ComputeLagrangeColumn(trace, nil, &mu, nil, []string{GetLagrangeID(0, size)})
	if err != nil {
		t.Fatal(err)
	}

	// add the constraint that the grand product is computed correctly to the system
	system := NewSystem(size)
	GPConstraint := BuildGrandProductConstraint(E1, E2, "R", size)
	system.RegisterConstraint(GPConstraint)
	proof := NewProof(size)
	ComputeGrandProduct(trace, &proof, &mu, []sym.Expr{E1, E2}, []string{"R"})

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

	err = BruteForceChecker(trace, system.Constraints, system.N)
	if err != nil {
		t.Fatal(err)
	}

	err = QuotientChecker(trace, system.Constraints, system.N)
	if err != nil {
		t.Fatal(err)
	}

}
