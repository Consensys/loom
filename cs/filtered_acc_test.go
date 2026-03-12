package cs

import (
	"sync"
	"testing"

	"github.com/consensys/giop/expr"
	"github.com/consensys/giop/pas/univariate"
	proveractions "github.com/consensys/giop/prover_actions"
	"github.com/consensys/giop/trace"
	"github.com/consensys/gnark-crypto/field/koalabear"
)

func TestComputeFilteredAccPolynomial(t *testing.T) {

	N := 16

	// 1. Build a trace with a random column E and a binary filter F (alternating 0/1).
	eVals := make(univariate.Polynomial, N)
	fVals := make(univariate.Polynomial, N)
	for i := range eVals {
		eVals[i].SetRandom()
		if i%2 == 0 {
			fVals[i].SetOne()
		}
		// fVals[i] stays zero for odd rows
	}

	// 2. Add a challenge alpha to the trace.
	var alphaVal koalabear.Element
	alphaVal.SetUint64(7)
	challenge := Challenge{Name: "alpha", Value: alphaVal}

	T := trace.Trace{
		"E": eVals,
		"F": fVals,
	}
	addChallengeInTrace(T, challenge)

	// 3. Compute R = BuildFilteredAccPolynomial(E, F, alpha) and store it in the trace.
	var mu sync.Mutex
	Eexpr := expr.Col("E")
	Fexpr := expr.Col("F")
	alphaExpr := expr.NewChallenge("alpha")

	R, err := univariate.BuildFilteredAccPolynomial(T, Eexpr, Fexpr, alphaExpr, N, &mu)
	if err != nil {
		t.Fatal(err)
	}
	T["R"] = R

	// Add the L_0 Lagrange column needed for the boundary constraint.
	err = proveractions.ComputeLagrangeColumn(T, nil, &mu, nil, []string{proveractions.GetLagrangeID(0, N)}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// 4. Build the constraints encoding the recurrence:
	//
	//   C1: L_0 · (R − F·E) = 0
	//       enforces R[0] = F[0]·E[0]
	//
	//   C2: (1−L_0) · (R − F·(alpha·R_prev + E) − (1−F)·R_prev) = 0
	//       enforces R[i] = F[i]·(alpha·R[i−1] + E[i]) + (1−F[i])·R[i−1]  for i > 0
	//
	// where R_prev = R(ω^{−1}·X), i.e. the column R shifted by −1.
	Rexpr := expr.Col("R")
	RPrev := expr.Rot("R", -1)
	L0 := expr.Virtual(proveractions.GetLagrangeID(0, N))
	one := expr.Const(koalabear.One())

	C1 := L0.Mul(Rexpr.Sub(Fexpr.Mul(Eexpr)))
	C2 := one.Sub(L0).Mul(
		Rexpr.
			Sub(Fexpr.Mul(alphaExpr.Mul(RPrev).Add(Eexpr))).
			Sub(one.Sub(Fexpr).Mul(RPrev)),
	)

	constraints := []Relation{C1, C2}

	// 5. Verify both constraints vanish on X^N−1.
	if err := BruteForceChecker(T, constraints, N); err != nil {
		t.Fatal(err)
	}
	if err := QuotientChecker(T, constraints, N); err != nil {
		t.Fatal(err)
	}
}
