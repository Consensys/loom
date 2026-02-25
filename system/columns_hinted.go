package system

import (
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/iop/pas/sym"
	"github.com/consensys/iop/pas/univariate"
)

// TODO It is a particular case of a column which need to be hinted... Should I make this pattern general ?

// BuildGrandProductConstraint computes the grand product polynomial R such that:
//
//	R[0] = 1
//	R[i+1] = R[i] * E1(ID1[i]) / E2(ID2[i])
//
// E1 = Π_j (E1[j] - challenge) and E2 = Π_j (E2[j] - challenge).
//
// It adds R and R_shifted (R[i+1 mod N]) to the trace, then records the constraint
// E2 * R_shifted - E1 * R = 0 mod X^N-1.
func BuildGrandProductConstraint(S *System, E1, E2 []sym.Expr, IDGrandProduct string, challenge Challenge, opts ...Option) error {

	// build the config
	var config Config
	for _, opt := range opts {
		if err := opt(&config); err != nil {
			return err
		}
	}

	challengeColumn := S.Trace[challenge.Name]

	// build a trace map containing the variables in E1 and E2, including the placeholders column so EvalPointWise can resolve it
	// (all the placeholders must be in the trace, ensureChallengeInTrace ensures that challenge is in the trace, but some other challenge
	// might exist, and should have been correctly added)
	T1 := make(map[string]*univariate.Polynomial, len(E1)+1)
	for _, id := range E1 {
		curLeaves := sym.RemoveDuplicates(id.Leaves())
		for _, l := range curLeaves {
			if _, ok := S.Trace[l]; !ok {
				continue
			}
			T1[l] = S.Trace[l]
		}
	}
	T1[challenge.Name] = challengeColumn

	T2 := make(map[string]*univariate.Polynomial, len(E2)+1)
	for _, id := range E2 {
		curLeaves := sym.RemoveDuplicates(id.Leaves())
		for _, l := range curLeaves {
			if _, ok := S.Trace[l]; !ok {
				continue
			}
			T2[l] = S.Trace[l]
		}
	}
	T2[challenge.Name] = challengeColumn

	// build E1 = Π_j (E1[j] - gamma), E2 = Π_j (E2[j] - gamma)
	Prod1 := GetProductExpression(E1, challenge.Name)
	Prod2 := GetProductExpression(E2, challenge.Name)

	// compute R in Lagrange basis
	R, err := univariate.BuildGrandProduct(
		[2]map[string]*univariate.Polynomial{T1, T2},
		[2]sym.Expr{Prod1, Prod2},
		S.N,
	)
	if err != nil {
		return err
	}
	if _, ok := S.Trace[IDGrandProduct]; ok {
		return fmt.Errorf("%s already recorded in the trace (name already taken)", IDGrandProduct)
	}
	S.Trace[IDGrandProduct] = &R

	// build RS as an explicit Lagrange polynomial with RS[i] = R[i+1 mod N].
	// We store it as a regular polynomial (not a ShallowCopy+Shift) so that FFT-based
	// operations in ComputeQuotient see the correct shifted evaluations directly.
	rsID := IDGrandProduct + "_shifted"
	RSCoeffs := make([]koalabear.Element, S.N)
	for i := 0; i < S.N; i++ {
		RSCoeffs[i] = R.GetCoefficient((i + 1) % S.N)
	}
	RS, err := univariate.NewInterpolatedPolynomial(RSCoeffs, rsID)
	if err != nil {
		return err
	}
	if _, ok := S.Trace[rsID]; ok {
		return fmt.Errorf("%s already recorded in the trace (name already taken)", rsID)
	}
	S.Trace[rsID] = &RS

	// record the grand product constraint: E2 * RS - E1 * R = 0 mod X^N-1
	C := GetGrandProductConstraint(Prod1, Prod2, IDGrandProduct, rsID)
	if config.CacheMe {
		S.CachedConstraints = append(S.CachedConstraints, C)
	} else {
		S.Constraints = append(S.Constraints, C)
	}

	return nil
}
