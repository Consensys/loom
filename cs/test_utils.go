package cs

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/iop/pas/sym"
	"github.com/consensys/iop/pas/univariate"
)

// BruteForceChecker checks a system by evaluating on the domain X^n-1,
// and checks that it is zero on this domain
func BruteForceChecker(S System) error {

	// convert S.Constraint to horner form
	C := S.Constraint

	// deep copy the trace to avoid side effects on S
	T := make([]univariate.Polynomial, len(S.Trace))
	for i := 0; i < len(T); i++ {
		univariate.Copy(&T[i], &S.Trace[i])
	}

	// create variable index
	varindex := make(sym.VarIndex, len(T))
	for i := 0; i < len(T); i++ {
		varindex[T[i].ID] = i
	}

	CHorner := sym.ToHorner(sym.Convert(C, varindex, len(T)))

	// Set all the polynomials in S in lagrange basis (domain of size S.n)
	// In Lagrange basis, the coefficient at index j represents the evaluation at ω^j
	d := fft.NewDomain(uint64(S.N))
	for i := 0; i < len(T); i++ {
		err := T[i].ToBasis(d, univariate.Lagrange)
		if err != nil {
			return fmt.Errorf("failed to convert T[%d] to Lagrange basis: %w", i, err)
		}
	}

	// Prepare array to store polynomial evaluations
	xi := make([]koalabear.Element, len(T))

	// Evaluate S.Constraint(S.Trace) line by line, and ensure the result is zero.
	// In Lagrange basis, T[i].GetCoefficient(j) gives us the evaluation at ω^j directly
	for j := 0; j < S.N; j++ {
		// Get the evaluation at ω^j by reading the j-th coefficient in Lagrange basis
		for i := 0; i < len(T); i++ {
			xi[varindex[T[i].ID]] = T[i].GetCoefficient(j)
		}

		// Evaluate the constraint at this point
		z := CHorner.Eval(xi)
		if !z.IsZero() {
			return fmt.Errorf("constraint not satisfied at position %d (ω^%d): got %s, expected 0", j, j, z.String())
		}
	}

	return nil
}

// QuotientChecker checks Constraint satisfiability of S. It returns an error if the constraint is not satisfied by the trace.
// Constraint satisfiability means that C(T)=0 mod X^n-1 where C:=S.Constraint, T:=S.Trace. To make this check, we compute the quotient
// h = C(T) / X^n-1 where n is the size of the columns of T, and verify at a random point x that C(T)(x)-(x^n-1)*h(x)=0.
//
// It is a debugging function
func QuotientChecker(S System) error {

	C := S.Constraint

	// deep copy the trace to avoid side effects on S
	T := make([]univariate.Polynomial, len(S.Trace))
	for i := 0; i < len(T); i++ {
		univariate.Copy(&T[i], &S.Trace[i])
	}

	// create index
	index := make(sym.VarIndex, len(S.Trace))
	for i := 0; i < len(S.Trace); i++ {
		index[S.Trace[i].ID] = i
	}

	// Convert C to Horner form
	CHorner := sym.ToHorner(sym.Convert(C, index, len(T)))

	// compute C(T(x)) / X^n-1
	h, err := univariate.ComputeQuotient(T, C, univariate.WithOutputName("H"), univariate.WithResultBasis(univariate.Canonical))
	if err != nil {
		return err
	}

	// Now we have C(T(x)) - h(x)(x^n-1) everywhere, we check this relation at a random point

	// pick a random number and check that C(T(x)) - (x^n-1)*h(x)=0
	var x koalabear.Element
	x.SetRandom()

	// evaluate h(x)
	hx, err := h.Evaluate(x)
	if err != nil {
		return err
	}

	// assume all the columns in T have the same size (ignore the constant polynomial)
	var targetSize, offset int
	s := len(T[0].EP.Coefficients)
	for i, c := range T {
		if c.IsConstant() {
			continue
		}
		targetSize = len(c.EP.Coefficients)
		offset = i
		break
	}
	for i := offset + 1; i < len(T); i++ {
		if T[i].IsConstant() {
			continue
		}
		if targetSize != len(T[i].EP.Coefficients) {
			return fmt.Errorf("all columns in T should have the same size")
		}
	}

	// set T in canonical form for evaluating
	d := fft.NewDomain(uint64(s))
	for i := 0; i < len(T); i++ {
		err := T[i].ToBasis(d, univariate.Canonical)
		if err != nil {
			return err
		}
	}

	// evaluate C(T(x)) using the already computed CHorner
	xi := make([]koalabear.Element, len(T))
	for i := 0; i < len(T); i++ {
		c, err := T[i].Evaluate(x)
		if err != nil {
			return err
		}
		xi[index[T[i].ID]].Set(&c)
	}
	cx := CHorner.Eval(xi)

	// evaluate x^n-1
	var xPowN, one koalabear.Element
	one.SetOne()
	xPowN.Exp(x, big.NewInt(int64(d.Cardinality)))
	xPowN.Sub(&xPowN, &one)

	// check that cx == (x^n-1)h(x)
	var rhs koalabear.Element
	rhs.Mul(&xPowN, &hx)
	if !rhs.Equal(&cx) {
		return fmt.Errorf("C(T) is not zero on X^n-1")
	}

	return nil
}

func GetTrivialVanishingConstraint(t *testing.T) (Trace, Constraint, int) {

	// create a constraint x0 + x1 - x2 = 0
	C := sym.NewVar("x0").Add(sym.NewVar("x1")).Sub(sym.NewVar("x2"))

	// create a trace matching the constraint
	size := 16
	nbColumns := 3
	columns := make([]univariate.Polynomial, nbColumns)
	for i := 0; i < nbColumns-1; i++ {
		coeffs := make([]koalabear.Element, size)
		for j := 0; j < size; j++ {
			coeffs[j].SetRandom()
		}
		var err error
		columns[i], err = univariate.NewInterpolatedPolynomial(coeffs, fmt.Sprintf("x%d", i))
		if err != nil {
			t.Fatalf("Failed to create column %d: %v", i, err)
		}
	}
	coeffs := make([]koalabear.Element, size)
	for j := 0; j < size; j++ {
		for i := 0; i < nbColumns-1; i++ {
			c := columns[i].GetCoefficient(j)
			coeffs[j].Add(&coeffs[j], &c)
		}
		// No negation needed: x2 = x0 + x1 to satisfy x0 + x1 - x2 = 0
	}
	columns[nbColumns-1], _ = univariate.NewInterpolatedPolynomial(coeffs, fmt.Sprintf("x%d", nbColumns-1))

	// check that the trace satisfies the constraint
	var T Trace
	T = columns

	return T, C, size
}

func GetNonTrivialVanishingConstraint(t *testing.T) (Trace, Constraint, int) {

	// create a constraint x0^2 - x1 = 0 mod X^16-1
	C := sym.NewVar("x0").Pow(2).Sub(sym.NewVar("x1"))

	var T Trace
	index := make(sym.VarIndex)
	index["x0"] = 0
	index["x1"] = 1
	Q := sym.ToHorner(sym.Convert(C, index, 2))

	// generate a trace T such that C(T) = 0 mod X^16-1
	size := 16
	coeffs := make([][]koalabear.Element, 2)
	coeffs[0] = make([]koalabear.Element, size)
	coeffs[1] = make([]koalabear.Element, size)
	for i := 0; i < size; i++ {
		coeffs[0][i].SetRandom()
		coeffs[1][i].Square(&coeffs[0][i])

		// check that Q([coeffs[0][i], coeffs[1][i]]) = 0
		z := Q.Eval([]koalabear.Element{coeffs[0][i], coeffs[1][i]})
		if !z.IsZero() {
			t.Fatal("z should be zero")
		}
	}

	T = make([]univariate.Polynomial, 2)
	var err error
	nbColumns := 2
	for i := 0; i < nbColumns; i++ {
		T[i], err = univariate.NewInterpolatedPolynomial(coeffs[i], fmt.Sprintf("x%d", i))
		if err != nil {
			t.Fatal(err)
		}
	}

	return T, C, size
}

func GetHighDegreeVanishingConstraint(t *testing.T) (Trace, Constraint, int) {

	// create a constraint (x0^5 - x1)*(x0^5 - x1) - x2 = 0 mod X^16-1
	size := 16
	Ctmp := sym.NewVar("x0").Pow(5).Sub(sym.NewVar("x1"))
	Ctmp = Ctmp.Mul(Ctmp)
	index := make(sym.VarIndex)
	index["x0"] = 0
	index["x1"] = 1
	Qtmp := sym.ToHorner(sym.Convert(Ctmp, index, 2))
	coeffs := make([][]koalabear.Element, 3)
	for i := 0; i < 3; i++ {
		coeffs[i] = make([]koalabear.Element, size)
	}
	for i := 0; i < size; i++ {
		coeffs[0][i].SetRandom()
		coeffs[1][i].SetRandom()
	}
	for i := 0; i < size; i++ {
		coeffs[2][i] = Qtmp.Eval([]koalabear.Element{coeffs[0][i], coeffs[1][i]})
	}

	C := Ctmp.Sub(sym.NewVar("x2"))
	index["x2"] = 2
	CHorner := sym.ToHorner(sym.Convert(C, index, 3))
	var err error
	var T Trace
	T = make([]univariate.Polynomial, 3)
	for i := 0; i < 3; i++ {
		T[i], err = univariate.NewPolynomial(coeffs[i], univariate.WithID(fmt.Sprintf("x%d", i)), univariate.WithBasis(univariate.Lagrange))
		if err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < size; i++ { // check that the trace vanishes
		z := CHorner.Eval([]koalabear.Element{coeffs[0][i], coeffs[1][i], coeffs[2][i]})
		if !z.IsZero() {
			t.Fatal("z should be zero")
		}
	}

	return T, C, size
}
