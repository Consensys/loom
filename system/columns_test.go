package system

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/iop/pas/sym"
	"github.com/consensys/iop/pas/univariate"
)

func prettyPrintTrace(T Trace) {

	type wrap struct {
		id string
		p  univariate.Polynomial
	}

	w := []wrap{}
	for k, t := range T {
		w = append(w, wrap{id: k, p: *t})
	}

	for _, w := range w {
		fmt.Printf("%s\t\t", w.id)
	}
	fmt.Println("")
	for i := 0; i < len(w[0].p.EP.Coefficients); i++ {
		for _, w := range w {
			c := w.p.GetCoefficient(i)
			fmt.Printf("%s\t", c.String())
		}
		fmt.Println("")
	}
	fmt.Println("")
}

// TestGrandProductIOP tests that a system with the grand product constraints vanished on X^n-1
func TestGrandProductIOP(t *testing.T) {

	size := 16

	S := BuildPermutationCircuit(t, size)

	// fix a challenge value (gamma for the grand product)
	var gamma koalabear.Element
	gamma.SetUint64(42)
	challenge := Challenge{Name: "gamma", Value: gamma}

	addChallengeInTrace(&S, challenge)

	var err error
	err = BuildGrandProductConstraint(&S, []sym.Expr{sym.NewVar("P0")}, []sym.Expr{sym.NewVar("P1")}, "R", challenge)
	if err != nil {
		t.Fatal(err)
	}

	// R[0] must equal 1
	var one koalabear.Element
	one.SetOne()
	R0 := S.Trace["R"].GetCoefficient(0)
	if !R0.Equal(&one) {
		t.Fatalf("R[0] should be 1, got %s", R0.String())
	}

	// verify recurrence R[i+1] = R[i] * (P0[i]-gamma) / (P1[i]-gamma) at every row
	for i := 0; i < size; i++ {
		Ri := S.Trace["R"].GetCoefficient(i)
		Ri1 := S.Trace["R"].GetCoefficient((i + 1) % size)
		Ri1Expected := new(koalabear.Element).Set(&Ri)
		c := S.Trace["P0"].GetCoefficient(i)
		num := new(koalabear.Element).Sub(&c, &gamma)
		c = S.Trace["P1"].GetCoefficient(i)
		den := new(koalabear.Element).Sub(&c, &gamma)
		Ri1Expected.Mul(Ri1Expected, num)
		Ri1Expected.Div(Ri1Expected, den)
		if !Ri1.Equal(Ri1Expected) {
			t.Fatalf("R[%d]: expected %s, got %s", (i+1)%size, Ri1Expected.String(), Ri1.String())
		}
	}

	err = BruteForceChecker(S)
	if err != nil {
		t.Fatal(err)
	}

	err = QuotientChecker(S)
	if err != nil {
		t.Fatal(err)
	}

}

func TestFlatten(t *testing.T) {

	const size = 16

	// Build P0 with random evaluations.
	coeffs0 := make([]koalabear.Element, size)
	for i := range coeffs0 {
		coeffs0[i].SetRandom()
	}
	P0, err := univariate.NewInterpolatedPolynomial(coeffs0, "P0")
	if err != nil {
		t.Fatal(err)
	}

	// Build P1 with P1[i] = P0[i]^2, so P0^4 - P1^2 = 0 at every row.
	coeffs1 := make([]koalabear.Element, size)
	for i := range coeffs1 {
		coeffs1[i].Mul(&coeffs0[i], &coeffs0[i])
	}
	P1, err := univariate.NewInterpolatedPolynomial(coeffs1, "P1")
	if err != nil {
		t.Fatal(err)
	}

	S := System{
		Trace:             map[string]*univariate.Polynomial{"P0": &P0, "P1": &P1},
		Constraints:       []Constraint{},
		CachedConstraints: []Constraint{},
		N:                 size,
	}

	// C = P0^4 - P1^2, degree 4. After Flatten with targetDegree=2, C is mutated
	// in-place into a degree-2 expression referencing the intermediate polynomials
	// that Flatten deposited into S.Trace and S.Constraints.
	C := sym.NewVar("P0").Pow(4).Sub(sym.NewVar("P1").Pow(2))

	constraints, err := Flatten(&S, C, 2)
	if err != nil {
		t.Fatal(err)
	}
	S.Constraints = append(S.Constraints, constraints...)

	// Every constraint must have degree ≤ 2.
	for i, constraint := range S.Constraints {
		if d := constraint.Degree(); d > 2 {
			t.Errorf("constraint %d (%s) has degree %d > 2", i, constraint.String(), d)
		}
	}

	if err := BruteForceChecker(S); err != nil {
		t.Fatal(err)
	}
	if err := QuotientChecker(S); err != nil {
		t.Fatal(err)
	}
}

func TestColumnBuilder(t *testing.T) {

	const size = 16

	var alpha koalabear.Element
	alpha.SetUint64(42)

	// makePoly creates a random Lagrange polynomial and returns its raw evaluations.
	makePoly := func(name string) (univariate.Polynomial, []koalabear.Element) {
		coeffs := make([]koalabear.Element, size)
		for i := range coeffs {
			coeffs[i].SetRandom()
		}
		p, err := univariate.NewInterpolatedPolynomial(coeffs, name)
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		return p, coeffs
	}

	makeSystem := func(polys map[string]*univariate.Polynomial) System {
		return System{
			Trace:             polys,
			Constraints:       []Constraint{},
			CachedConstraints: []Constraint{},
			N:                 size,
		}
	}

	// Sub-test 1: E = P0^2
	// BuildColumnWithChallenge evaluates P0 pointwise, stores Q[i] = P0[i]^2, and records P0^2 - Q = 0.
	t.Run("PointwiseSquare", func(t *testing.T) {
		P0, raw0 := makePoly("P0")
		S := makeSystem(map[string]*univariate.Polynomial{"P0": &P0})

		E := sym.NewVar("P0").Pow(2)
		c, err := BuildColumn(&S, E, "Q")
		if err != nil {
			t.Fatal(err)
		}
		S.Constraints = append(S.Constraints, c)

		for i := 0; i < size; i++ {
			var expected koalabear.Element
			expected.Mul(&raw0[i], &raw0[i])
			got := S.Trace["Q"].GetCoefficient(i)
			if !got.Equal(&expected) {
				t.Fatalf("Q[%d]: expected %s, got %s", i, expected.String(), got.String())
			}
		}

		if err := BruteForceChecker(S); err != nil {
			t.Fatal(err)
		}
		if err := QuotientChecker(S); err != nil {
			t.Fatal(err)
		}
	})

	// Sub-test 2: E = P0 * P1 * P2
	// Q[i] = P0[i] * P1[i] * P2[i], constraint P0*P1*P2 - Q = 0.
	t.Run("PointwiseProduct", func(t *testing.T) {
		P0, raw0 := makePoly("P0")
		P1, raw1 := makePoly("P1")
		P2, raw2 := makePoly("P2")
		S := makeSystem(map[string]*univariate.Polynomial{"P0": &P0, "P1": &P1, "P2": &P2})

		E := sym.NewVar("P0").Mul(sym.NewVar("P1")).Mul(sym.NewVar("P2"))
		c, err := BuildColumn(&S, E, "Q")
		if err != nil {
			t.Fatal(err)
		}
		S.Constraints = append(S.Constraints, c)

		for i := 0; i < size; i++ {
			expected := new(koalabear.Element).Mul(&raw0[i], &raw1[i])
			expected.Mul(expected, &raw2[i])
			got := S.Trace["Q"].GetCoefficient(i)
			if !got.Equal(expected) {
				t.Fatalf("Q[%d]: expected %s, got %s", i, expected.String(), got.String())
			}
		}

		if err := BruteForceChecker(S); err != nil {
			t.Fatal(err)
		}
		if err := QuotientChecker(S); err != nil {
			t.Fatal(err)
		}
	})

	// Sub-test 3: E = P0^2 + alpha*P1 - P2
	// Q[i] = P0[i]^2 + alpha*P1[i] - P2[i], constraint P0^2 + alpha*P1 - P2 - Q = 0.
	// Uses NewChallenge for alpha so it contributes degree 0, keeping the constraint degree 2.
	t.Run("QuadraticWithChallenge", func(t *testing.T) {
		P0, raw0 := makePoly("P0")
		P1, raw1 := makePoly("P1")
		P2, raw2 := makePoly("P2")
		S := makeSystem(map[string]*univariate.Polynomial{"P0": &P0, "P1": &P1, "P2": &P2})

		addChallengeInTrace(&S, Challenge{Name: "alpha", Value: alpha})

		E := sym.NewVar("P0").Pow(2).
			Add(sym.NewChallenge("alpha").Mul(sym.NewVar("P1"))).
			Sub(sym.NewVar("P2"))
		c, err := BuildColumn(&S, E, "Q")
		if err != nil {
			t.Fatal(err)
		}
		S.Constraints = append(S.Constraints, c)

		for i := 0; i < size; i++ {
			var expected koalabear.Element
			expected.Mul(&raw0[i], &raw0[i])
			tmp := new(koalabear.Element).Mul(&alpha, &raw1[i])
			expected.Add(&expected, tmp)
			expected.Sub(&expected, &raw2[i])
			got := S.Trace["Q"].GetCoefficient(i)
			if !got.Equal(&expected) {
				t.Fatalf("Q[%d]: expected %s, got %s", i, expected.String(), got.String())
			}
		}

		if err := BruteForceChecker(S); err != nil {
			t.Fatal(err)
		}
		if err := QuotientChecker(S); err != nil {
			t.Fatal(err)
		}
	})

}
