package plonk_example

import (
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/gnark-crypto/field/koalabear/iop"
	gnark_plonk "github.com/consensys/gnark/backend/plonk/koalabear"
	gnark_cs "github.com/consensys/gnark/constraint/koalabear"
	"github.com/consensys/iop/cs"
	"github.com/consensys/iop/pas/univariate"
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
func gnarkCryptoPolyToUnivariatePoly(p *iop.Polynomial, id string) (univariate.Polynomial, error) {

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
		univariate.WithID(id),
	)
	if err != nil {
		return res, iop.ErrInconsistentFormat
	}

	// For Lagrange/LagrangeShifted polynomials, NewPolynomial's degree computation
	// (which strips trailing zeros) is wrong: each of the n evaluation points is a
	// real data point, not a zero high-degree coefficient. The polynomial degree is
	// always n-1 regardless of which evaluations happen to be zero.
	if basis == univariate.Lagrange || basis == univariate.LagrangeShifted {
		res.EP.Degree = len(res.EP.Coefficients) - 1
	}

	return res, nil
}

// BuildTrace from a plonk trace ([ql, qr, qm, qo, qk, l, r, o], permutation), returns
// a trace.
//
// TODO we assume that Commit has not been used save it for later
func BuildTrace(plonkTrace *gnark_plonk.Trace, plonkSolution *gnark_cs.SparseR1CSSolution) (cs.Trace, error) {

	// ql, qr, qm, qo, qk, id1, id2, id3, s1, s2, s3, l, r, o = 14 columns (z and zs are created in a separate system)
	nbColumns := 16
	T := make(cs.Trace, nbColumns)
	var err error
	T[0], err = gnarkCryptoPolyToUnivariatePoly(plonkTrace.Ql, "QL")
	if err != nil {
		return T, err
	}
	T[1], err = gnarkCryptoPolyToUnivariatePoly(plonkTrace.Qr, "QR")
	if err != nil {
		return T, err
	}
	T[2], err = gnarkCryptoPolyToUnivariatePoly(plonkTrace.Qm, "QM")
	if err != nil {
		return T, err
	}
	T[3], err = gnarkCryptoPolyToUnivariatePoly(plonkTrace.Qo, "QO")
	if err != nil {
		return T, err
	}
	T[4], err = gnarkCryptoPolyToUnivariatePoly(plonkTrace.Qk, "QK")
	if err != nil {
		return T, err
	}

	T[5], err = gnarkCryptoPolyToUnivariatePoly(plonkTrace.S1, "S1")
	if err != nil {
		return T, err
	}
	T[6], err = gnarkCryptoPolyToUnivariatePoly(plonkTrace.S2, "S2")
	if err != nil {
		return T, err
	}
	T[7], err = gnarkCryptoPolyToUnivariatePoly(plonkTrace.S3, "S3")
	if err != nil {
		return T, err
	}

	T[8], err = univariate.NewPolynomial(
		[]koalabear.Element(plonkSolution.L),
		univariate.WithID("L"),
		univariate.WithBasis(univariate.Lagrange),
		univariate.WithLayout(univariate.Normal))
	if err != nil {
		return T, err
	}

	T[9], err = univariate.NewPolynomial(
		[]koalabear.Element(plonkSolution.R),
		univariate.WithID("R"),
		univariate.WithBasis(univariate.Lagrange),
		univariate.WithLayout(univariate.Normal))
	if err != nil {
		return T, err
	}

	T[10], err = univariate.NewPolynomial(
		[]koalabear.Element(plonkSolution.O),
		univariate.WithID("O"),
		univariate.WithBasis(univariate.Lagrange),
		univariate.WithLayout(univariate.Normal))
	if err != nil {
		return T, err
	}

	n := len(plonkTrace.Ql.Coefficients())
	domain := fft.NewDomain(uint64(n))
	if err != nil {
		return T, err
	}

	res := make([]koalabear.Element, 3*domain.Cardinality)

	res[0].SetOne()
	res[domain.Cardinality].Set(&domain.FrMultiplicativeGen)
	res[2*domain.Cardinality].Square(&domain.FrMultiplicativeGen)

	for i := uint64(1); i < domain.Cardinality; i++ {
		res[i].Mul(&res[i-1], &domain.Generator)
		res[domain.Cardinality+i].Mul(&res[domain.Cardinality+i-1], &domain.Generator)
		res[2*domain.Cardinality+i].Mul(&res[2*domain.Cardinality+i-1], &domain.Generator)
	}

	T[11], err = univariate.NewPolynomial(
		res[:domain.Cardinality],
		univariate.WithBasis(univariate.Lagrange),
		univariate.WithLayout(univariate.Normal),
		univariate.WithID("ID1"))
	if err != nil {
		return T, err
	}

	T[12], err = univariate.NewPolynomial(
		res[domain.Cardinality:2*domain.Cardinality],
		univariate.WithBasis(univariate.Lagrange),
		univariate.WithLayout(univariate.Normal),
		univariate.WithID("ID2"))
	if err != nil {
		return T, err
	}

	T[13], err = univariate.NewPolynomial(
		res[2*domain.Cardinality:],
		univariate.WithBasis(univariate.Lagrange),
		univariate.WithLayout(univariate.Normal),
		univariate.WithID("ID3"))
	if err != nil {
		return T, err
	}

	return T, nil

}
