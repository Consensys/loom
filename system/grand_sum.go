package system

import (
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/iop/pas/sym"
	"github.com/consensys/iop/pas/univariate"
)

// BuildGrandSumAndRegisterConstraints creates two polynomials Σ_S and Σ_T such that:
// Σ_S[i] = \Sum_{j⩽i} 1/(S[j]-γ)
// Σ_T[i] = \Sum_{j⩽i} M[j]/(T[j]-γ)
// T = Table (distinct values), S = lookup values appearing in T, M[i] = number of times T[i] appears in S
// M_ID must be built prior to calling this function.
//
// BuildGrandSum records the following constraints:
// 1. (1-LAGRANGE_0)*((Σ_T - Σ_T(ω^-1 X))((T-γ)) - M) = 0 (Σ_T[i] = Σ_T[i-1]+M[i]/(T[i]-γ), without wraparound at 0)
// 2. (1-LAGRANGE_0)*((Σ_S - Σ_S(ω^-1 X))((S-γ)) - 1) = 0 (Σ_S[i] = Σ_S[i-1]+1/(S[i]-γ), without wraparound at 0)
// 3. LAGRANGE_0*(Σ_T*(T-γ) - M) = 0 (<- ensures Σ_T[0] = M[0]/(T[0]-γ))
// 4. LAGRANGE_0*(Σ_S*(S-γ) - 1) = 0 (<- ensures Σ_S[0] = 1/(S[0]-γ))
func BuildGrandSumAndRegisterConstraints(S *System, S_ID, T_ID, M_ID string, Σ_S_ID, Σ_T_ID string, gamma string, opts ...Option) error {

	// build the config
	var config Config
	for _, opt := range opts {
		if err := opt(&config); err != nil {
			return err
		}
	}

	// S and T must already be in the trace (they are input columns)
	if _, ok := S.Trace[S_ID]; !ok {
		return fmt.Errorf("column %s not found in the trace", S_ID)
	}
	if _, ok := S.Trace[T_ID]; !ok {
		return fmt.Errorf("column %s not found in the trace", T_ID)
	}

	// gamma is already registered in the trace (either from addChallengeInTrace or SendMeAChallenge)
	if _, ok := S.Trace[gamma]; !ok {
		return fmt.Errorf("challenge %s not in the trace", gamma)
	}

	// symbolic expressions for S-γ and T-γ (reused in constraints below)
	sMinusGamma := sym.NewVar(S_ID).Sub(sym.NewChallenge(gamma))
	tMinusGamma := sym.NewVar(T_ID).Sub(sym.NewChallenge(gamma))

	// compute 1/(S-γ) pointwise
	localTraceS := map[string]*univariate.Polynomial{
		S_ID:  S.Trace[S_ID],
		gamma: S.Trace[gamma],
	}
	sMinusGammaP, err := univariate.EvalPointWise(localTraceS, sMinusGamma, S.N)
	if err != nil {
		return err
	}
	univariate.InvertPointWiseInPlace(&sMinusGammaP)

	// build Σ_S = cumulative sum of 1/(S-γ)
	sigmaS, err := univariate.BuildGrandSum(&sMinusGammaP, S.N)
	if err != nil {
		return err
	}
	err = RegisterColumn(S, Σ_S_ID, &sigmaS)
	if err != nil {
		return err
	}

	// compute T-γ pointwise
	localTraceT := map[string]*univariate.Polynomial{
		T_ID:  S.Trace[T_ID],
		gamma: S.Trace[gamma],
	}
	tMinusGammaP, err := univariate.EvalPointWise(localTraceT, tMinusGamma, S.N)
	if err != nil {
		return err
	}

	// compute M/(T-γ) pointwise
	mDivTMinusGamma, err := univariate.DivPointWise(S.Trace[M_ID], &tMinusGammaP, S.N)
	if err != nil {
		return err
	}

	// build Σ_T = cumulative sum of M/(T-γ)
	sigmaT, err := univariate.BuildGrandSum(&mDivTMinusGamma, S.N)
	if err != nil {
		return err
	}
	err = RegisterColumn(S, Σ_T_ID, &sigmaT)
	if err != nil {
		return err
	}

	// build explicit shifted polynomials: Σ_S_shifted[i] = Σ_S[i-1], Σ_T_shifted[i] = Σ_T[i-1]
	// (wrap-around at i=0 is handled by multiplying by (1-LAGRANGE_0) in C1/C2)
	Σ_T_ID_shifted := Σ_T_ID + GetShiftSuffix(-1)
	sigmaTShiftedCoeffs := make([]koalabear.Element, S.N)
	for i := 0; i < S.N; i++ {
		sigmaTShiftedCoeffs[i] = sigmaT.GetCoefficient((i - 1 + S.N) % S.N)
	}
	sigmaTShifted, err := univariate.NewInterpolatedPolynomial(sigmaTShiftedCoeffs, Σ_T_ID_shifted)
	if err != nil {
		return err
	}
	err = RegisterColumn(S, Σ_T_ID_shifted, &sigmaTShifted)
	if err != nil {
		return err
	}

	Σ_S_ID_shifted := Σ_S_ID + GetShiftSuffix(-1)
	sigmaSShiftedCoeffs := make([]koalabear.Element, S.N)
	for i := 0; i < S.N; i++ {
		sigmaSShiftedCoeffs[i] = sigmaS.GetCoefficient((i - 1 + S.N) % S.N)
	}
	sigmaSShifted, err := univariate.NewInterpolatedPolynomial(sigmaSShiftedCoeffs, Σ_S_ID_shifted)
	if err != nil {
		return err
	}
	err = RegisterColumn(S, Σ_S_ID_shifted, &sigmaSShifted)
	if err != nil {
		return err
	}

	// add Lagrange column L0 to the trace
	lagrangeID := GetLagrangeID(0, S.N)
	cc, err := GetComputationableColumn(lagrangeID)
	if err != nil {
		return err
	}
	AddComputableColumn(S, cc)

	// 1. (1-LAGRANGE_0)*((Σ_T - Σ_T(ω^-1 X))(T-γ)) - M) = 0
	// 2. (1-LAGRANGE_0)*((Σ_S - Σ_S(ω^-1 X))((S-γ)) - 1) = 0
	// 3. LAGRANGE_0*(Σ_T*(T-γ) - M) = 0  (<- initial condition: Σ_T[0] = M[0]/(T[0]-γ))
	// 4. LAGRANGE_0*(Σ_S*(S-γ) - 1) = 0  (<- initial condition: Σ_S[0] = 1/(S[0]-γ))
	symLagrange := sym.NewVar(lagrangeID)
	oneMinusLagrange := sym.NewConst(koalabear.One()).Sub(symLagrange)
	diffΣ_T := sym.NewVar(Σ_T_ID).Sub(sym.NewVar(Σ_T_ID_shifted))
	diffΣ_S := sym.NewVar(Σ_S_ID).Sub(sym.NewVar(Σ_S_ID_shifted))
	C1 := oneMinusLagrange.Mul(diffΣ_T.Mul(tMinusGamma).Sub(sym.NewVar(M_ID)))
	C2 := oneMinusLagrange.Mul(diffΣ_S.Mul(sMinusGamma).Sub(sym.NewConst(koalabear.One())))
	C3 := symLagrange.Mul(sym.NewVar(Σ_T_ID).Mul(tMinusGamma).Sub(sym.NewVar(M_ID)))
	C4 := symLagrange.Mul(sym.NewVar(Σ_S_ID).Mul(sMinusGamma).Sub(sym.NewConst(koalabear.One())))

	if config.CacheMe {
		S.CachedConstraints = append(S.CachedConstraints, C1, C2, C3, C4)
	} else {
		S.Constraints = append(S.Constraints, C1, C2, C3, C4)
	}

	return nil
}
