package plonk_example

import (
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/gnark-crypto/field/koalabear/iop"
	gnark_plonk "github.com/consensys/gnark/backend/plonk/koalabear"
	gnark_cs "github.com/consensys/gnark/constraint/koalabear"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/iop/pas/univariate"
	"github.com/consensys/iop/system"
)

const (
	ID_L   string = "L"
	ID_R   string = "R"
	ID_O   string = "O"
	ID_Z   string = "Z"
	ID_ZS  string = "ZS"
	ID_Ql  string = "QL"
	ID_Qr  string = "QR"
	ID_Qm  string = "QM"
	ID_Qo  string = "QO"
	ID_Qk  string = "QK"
	ID_S1  string = "S1"
	ID_S2  string = "S2"
	ID_S3  string = "S3"
	ID_ID1 string = "ID1"
	ID_ID2 string = "ID2"
	ID_ID3 string = "ID3"
)

// gnarkCryptoPolyToUnivariatePoly convesions *iop.Polynomial -> univariate.Polynomial
func gnarkCryptoPolyToUnivariatePoly(p *iop.Polynomial) (*univariate.Polynomial, error) {

	c := p.Coefficients()

	var basis univariate.Basis
	if p.Basis == iop.Canonical {
		basis = univariate.Canonical
	} else if p.Basis == iop.Lagrange {
		basis = univariate.Lagrange
	} else {
		basis = univariate.LagrangeShifted
	}

	var layout univariate.Layout
	if p.Layout == iop.Regular {
		layout = univariate.Normal
	} else {
		layout = univariate.BitReversed
	}

	res, err := univariate.NewPolynomial(
		c,
		univariate.WithBasis(basis),
		univariate.WithLayout(layout),
	)
	if err != nil {
		return &res, iop.ErrInconsistentFormat
	}

	// For Lagrange/LagrangeShifted polynomials, NewPolynomial's degree computation
	// (which strips trailing zeros) is wrong: each of the n evaluation points is a
	// real data point, not a zero high-degree coefficient. The polynomial degree is
	// always n-1 regardless of which evaluations happen to be zero.
	if basis == univariate.Lagrange || basis == univariate.LagrangeShifted {
		res.EP.Degree = len(res.EP.Coefficients) - 1
	}

	return &res, nil
}

// BuildTrace from a plonk trace ([ql, qr, qm, qo, qk, l, r, o], permutation), returns
// a trace.
//
// nbPublicInputs must equal len(spr.Public) (i.e. spr.GetNbPublicVariables()).
// gnark's NewTrace leaves Qk[i]=0 for i < nbPublicInputs (public-input placeholder rows
// where Ql[i]=-1), with the explicit note "to be completed by the prover". The prover
// must set Qk[i]=L[i] so that the vanishing relation Ql[i]*L[i]+Qk[i] = -L[i]+L[i] = 0
// holds on those rows.
func BuildTrace(plonkTrace *gnark_plonk.Trace, plonkSolution *gnark_cs.SparseR1CSSolution, nbPublicInputs int) (system.Trace, error) {

	// ql, qr, qm, qo, qk, id1, id2, id3, s1, s2, s3, l, r, o = 14 columns (z and zs are created in a separate system)
	nbColumns := 16
	T := make(system.Trace, nbColumns)
	var err error
	T[ID_Ql], err = gnarkCryptoPolyToUnivariatePoly(plonkTrace.Ql)
	if err != nil {
		return T, err
	}
	T[ID_Qr], err = gnarkCryptoPolyToUnivariatePoly(plonkTrace.Qr)
	if err != nil {
		return T, err
	}
	T[ID_Qm], err = gnarkCryptoPolyToUnivariatePoly(plonkTrace.Qm)
	if err != nil {
		return T, err
	}
	T[ID_Qo], err = gnarkCryptoPolyToUnivariatePoly(plonkTrace.Qo)
	if err != nil {
		return T, err
	}
	T[ID_Qk], err = gnarkCryptoPolyToUnivariatePoly(plonkTrace.Qk)
	if err != nil {
		return T, err
	}

	T[ID_S1], err = gnarkCryptoPolyToUnivariatePoly(plonkTrace.S1)
	if err != nil {
		return T, err
	}
	T[ID_S2], err = gnarkCryptoPolyToUnivariatePoly(plonkTrace.S2)
	if err != nil {
		return T, err
	}
	T[ID_S3], err = gnarkCryptoPolyToUnivariatePoly(plonkTrace.S3)
	if err != nil {
		return T, err
	}

	// Each polynomial must be declared with its own variable so that &poly gives a
	// distinct address for each entry. Reusing a single variable p and storing &p
	// multiple times would make all map entries alias the same memory location.
	lPoly, err := univariate.NewPolynomial([]koalabear.Element(plonkSolution.L), univariate.WithBasis(univariate.Lagrange))
	if err != nil {
		return T, err
	}
	// lPoly.EP.Degree = len(lPoly.EP.Coefficients) - 1
	T[ID_L] = &lPoly

	// Complete Qk for the public-input placeholder rows. Both Qk and L are in
	// Lagrange basis, Normal layout, so Coefficients[i] is the i-th row value.
	for i := 0; i < nbPublicInputs; i++ {
		T[ID_Qk].EP.Coefficients[i] = T[ID_L].EP.Coefficients[i]
	}

	rPoly, err := univariate.NewPolynomial([]koalabear.Element(plonkSolution.R), univariate.WithBasis(univariate.Lagrange))
	if err != nil {
		return T, err
	}
	// rPoly.EP.Degree = len(rPoly.EP.Coefficients) - 1
	T[ID_R] = &rPoly

	oPoly, err := univariate.NewPolynomial([]koalabear.Element(plonkSolution.O), univariate.WithBasis(univariate.Lagrange))
	if err != nil {
		return T, err
	}
	// oPoly.EP.Degree = len(oPoly.EP.Coefficients) - 1
	T[ID_O] = &oPoly

	n := len(plonkTrace.Ql.Coefficients())
	domain := fft.NewDomain(uint64(n))

	res := make([]koalabear.Element, 3*domain.Cardinality)

	res[0].SetOne()
	res[domain.Cardinality].Set(&domain.FrMultiplicativeGen)
	res[2*domain.Cardinality].Square(&domain.FrMultiplicativeGen)

	for i := uint64(1); i < domain.Cardinality; i++ {
		res[i].Mul(&res[i-1], &domain.Generator)
		res[domain.Cardinality+i].Mul(&res[domain.Cardinality+i-1], &domain.Generator)
		res[2*domain.Cardinality+i].Mul(&res[2*domain.Cardinality+i-1], &domain.Generator)
	}

	id1Poly, err := univariate.NewPolynomial([]koalabear.Element(res[:domain.Cardinality]), univariate.WithBasis(univariate.Lagrange))
	if err != nil {
		return T, err
	}
	id1Poly.EP.Degree = len(id1Poly.EP.Coefficients) - 1
	T[ID_ID1] = &id1Poly

	id2Poly, err := univariate.NewPolynomial([]koalabear.Element(res[domain.Cardinality:2*domain.Cardinality]), univariate.WithBasis(univariate.Lagrange))
	if err != nil {
		return T, err
	}
	id2Poly.EP.Degree = len(id2Poly.EP.Coefficients) - 1
	T[ID_ID2] = &id2Poly

	id3Poly, err := univariate.NewPolynomial([]koalabear.Element(res[2*domain.Cardinality:]), univariate.WithBasis(univariate.Lagrange))
	if err != nil {
		return T, err
	}
	id3Poly.EP.Degree = len(id3Poly.EP.Coefficients) - 1
	T[ID_ID3] = &id3Poly

	return T, nil

}

// plonk circuit
type Circuit struct {
	A, B, C frontend.Variable
	D       frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {

	a := api.Mul(c.A, c.B)
	a = api.Add(a, c.C)

	for i := 0; i < 20; i++ {
		a = api.Mul(a, a)
	}

	api.AssertIsDifferent(a, c.D)

	return nil
}

func GetPlonkSystem() (system.System, error) {

	assignment := Circuit{
		A: 3,
		B: 4,
		C: 5,
		D: 6,
	}
	witness, err := frontend.NewWitness(&assignment, koalabear.Modulus())
	if err != nil {
		return system.System{}, err
	}

	var circuit Circuit

	ccs, err := frontend.CompileU32(koalabear.Modulus(), scs.NewBuilder, &circuit)
	if err != nil {
		return system.System{}, err
	}
	spr, ok := ccs.(*gnark_cs.SparseR1CS)
	if !ok {
		return system.System{}, fmt.Errorf("cannot cast ccs to *gnark_cs.SparseR1CS")

	}

	nbPublic := ccs.GetNbPublicVariables()
	nbConstraints := ccs.GetNbConstraints()
	// Domain size must accommodate both public-input placeholder rows and actual
	// constraint rows, matching gnark's evaluateLROSmallDomain which uses
	// NextPowerOfTwo(nbConstraints + len(cs.Public)).
	size := univariate.NextPowerOfTwo(nbConstraints + nbPublic)
	d := fft.NewDomain(uint64(size))

	publicTrace := gnark_plonk.NewTrace(spr, d)

	isolution, err := spr.Solve(witness)
	if err != nil {
		return system.System{}, err
	}
	solution, ok := isolution.(*gnark_cs.SparseR1CSSolution)
	if !ok {
		return system.System{}, fmt.Errorf("cannot cast isolution to *gnark_cs.SparseR1CSSolution")
	}

	T, err := BuildTrace(publicTrace, solution, nbPublic)
	if err != nil {
		return system.System{}, err
	}

	S := system.NewSystem(T, []system.Constraint{}, []system.Constraint{}, size)

	return S, nil

}
