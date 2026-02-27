package system

import (
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/iop/pas/sym"
	"github.com/consensys/iop/pas/univariate"
)

// BuildGrandProductAndRegisterConstraints computes the grand product polynomial R such that:
//
//	R[0] = 1
//	R[i+1] = R[i] * (E1[0][i]*E1[1][i]*..) / (E2[0][i]*E2[1][i]*..)
//
// where the notation Ei[j] means the j-th entry of Ei evaluated on S.Trace.
//
// It adds R and R_shifted (R[i+1 mod N]) to the trace, then records the constraint
// E2 * R_shifted - E1 * R = 0 mod X^N-1.
func BuildGrandProductAndRegisterConstraints(S *System, E1, E2 []sym.Expr, IDGrandProduct string, opts ...Option) error {

	prod1 := E1[0]
	for i := 1; i < len(E1); i++ {
		prod1 = prod1.Mul(E1[i])
	}
	prod2 := E2[0]
	for i := 1; i < len(E2); i++ {
		prod2 = prod2.Mul(E2[i])
	}

	return buildGrandProductAndRegisterConstraints(S, prod1, prod2, IDGrandProduct, opts...)

}

func buildGrandProductAndRegisterConstraints(S *System, E1, E2 sym.Expr, IDGrandProduct string, opts ...Option) error {

	// build the config
	var config Config
	for _, opt := range opts {
		if err := opt(&config); err != nil {
			return err
		}
	}

	// build the polynomial R, R(wX)
	R, err := univariate.BuildGrandProduct(
		S.Trace,
		E1, E2,
		S.N,
	)
	if err != nil {
		return err
	}
	rsID := IDGrandProduct + GetShiftSuffix(1)
	RSCoeffs := make([]koalabear.Element, S.N)
	for i := 0; i < S.N; i++ {
		RSCoeffs[i] = R.GetCoefficient((i + 1) % S.N)
	}
	RS, err := univariate.NewInterpolatedPolynomial(RSCoeffs, rsID)
	if err != nil {
		return err
	}

	// register the polynomials
	err = RegisterColumn(S, IDGrandProduct, &R)
	if err != nil {
		return err
	}
	err = RegisterColumn(S, IDGrandProduct+GetShiftSuffix(1), &RS)
	if err != nil {
		return err
	}

	// create the grand product constraint: E2 * RS - E1 * R = 0 mod X^N-1 and record it
	C := GetGrandProductConstraint(E1, E2, IDGrandProduct, rsID)
	if config.CacheMe {
		S.CachedConstraints = append(S.CachedConstraints, C)
	} else {
		S.Constraints = append(S.Constraints, C)
	}

	return nil
}
