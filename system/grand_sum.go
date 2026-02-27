package system

import (
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/iop/pas/sym"
	"github.com/consensys/iop/pas/univariate"
)

// buildGrandSumAndRegisterConstraints constructs ΣE such that:
// ΣE[0] = M[0]/E[0], ΣE[i] = ΣE[i-1] + M[i]/E[i]
// (the notation E[i] means the i-th entry of E evaluated on S.Trace)
//
// It registers the following constraints, ensuring that ΣE is built correctly:
// 1. (1-LAGRANGE_0)*((ΣE - ΣE(ω^-1 X))*E - M) = 0
// 2. LAGRANGE_0*(ΣE*E - M) = 0
func buildGrandSumAndRegisterConstraints(S *System, E, M sym.Expr, ΣE string, opts ...Option) error {

	// build the config
	var config Config
	for _, opt := range opts {
		if err := opt(&config); err != nil {
			return err
		}
	}

	// build the polynomial ΣE, ΣE(ω^-1 X)
	ΣEp, err := univariate.BuildGrandSum(S.Trace, E, M, S.N)
	if err != nil {
		return err
	}
	ΣEpShiftedCoeffs := make([]koalabear.Element, S.N)
	for i := 0; i < S.N; i++ {
		ΣEpShiftedCoeffs[i] = ΣEp.GetCoefficient((i - 1 + S.N) % S.N)
	}
	ΣEpShifted, err := univariate.NewPolynomial(ΣEpShiftedCoeffs, univariate.WithBasis(univariate.Lagrange), univariate.WithLayout(univariate.Normal))
	if err != nil {
		return err
	}

	// register the polynomials
	err = RegisterColumn(S, ΣE, &ΣEp)
	if err != nil {
		return err
	}
	ΣEShifted := ΣE + GetShiftSuffix(-1)
	err = RegisterColumn(S, ΣEShifted, &ΣEpShifted)
	if err != nil {
		return err
	}

	// ensure the Lagrange column is in the trace so BruteForceChecker can resolve it
	lagrangeID := GetLagrangeID(0, S.N)
	lagrangeCC, err := GetComputationableColumn(lagrangeID)
	if err != nil {
		return err
	}
	AddComputableColumn(S, lagrangeCC)

	// register the two constraints
	symLagrange := sym.NewVar(lagrangeID)
	oneMinusLagrange := sym.NewConst(koalabear.One()).Sub(symLagrange)
	diffΣE := sym.NewVar(ΣE).Sub(sym.NewVar(ΣEShifted))
	diffΣETimesE := diffΣE.Mul(E)
	C1 := oneMinusLagrange.Mul(diffΣETimesE.Sub(M))       //(1-LAGRANGE_0)*((ΣE - ΣE(ω^-1 X))*E - M) = 0
	C2 := symLagrange.Mul((sym.NewVar(ΣE).Mul(E)).Sub(M)) // LAGRANGE_0*(Σ_T*(T-γ) - M)

	if config.CacheMe {
		S.CachedConstraints = append(S.CachedConstraints, C1, C2)
	} else {
		S.Constraints = append(S.Constraints, C1, C2)
	}

	return nil

}

// BuildGrandSumAndRegisterConstraints creates two polynomials Σ_S and Σ_T such that:
// Σ_S[0] = ES[0],  Σ_S[i] = Σ_S[i-1] + ES[i]
// Σ_T[0] = M[0]*ET[0],  Σ_T[i] = Σ_T[i-1] + M[i]*ET[i]
// (the notation Ei[j] means the j-th entry of Ei evaluated on S.Trace)
// M[i] counts the number of occurences of ET[i] in ES.
//
// BuildGrandSum records the following constraints:
// 1. (1-LAGRANGE_0)*((Σ_T - Σ_T(ω^-1 X))((ET-γ)) - M) = 0 (Σ_T[i] = Σ_T[i-1]+M[i]/(T[i]-γ), without wraparound at 0)
// 2. (1-LAGRANGE_0)*((Σ_S - Σ_S(ω^-1 X))((ES-γ)) - 1) = 0 (Σ_S[i] = Σ_S[i-1]+1/(S[i]-γ), without wraparound at 0)
// 3. LAGRANGE_0*(Σ_T*(T-γ) - M) = 0 (<- ensures Σ_T[0] = M[0]/(T[0]-γ))
// 4. LAGRANGE_0*(Σ_S*(S-γ) - 1) = 0 (<- ensures Σ_S[0] = 1/(S[0]-γ))
func BuildGrandSumAndRegisterConstraints(S *System, ES, ET sym.Expr, M, ΣS, ΣT string, opts ...Option) error {

	err := buildGrandSumAndRegisterConstraints(S, ES, sym.NewConst(koalabear.One()), ΣS, opts...)
	if err != nil {
		return err
	}

	err = buildGrandSumAndRegisterConstraints(S, ET, sym.NewVar(M), ΣT, opts...)
	if err != nil {
		return err
	}

	return nil
}
