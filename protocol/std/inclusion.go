package std

import (
	"github.com/consensys/iop/pas/univariate"
	"github.com/consensys/iop/protocol"
	"github.com/consensys/iop/system"
)

// InclusionCheckIOP proves that every value of S appears in T (S ⊂ T as multisets),
// using the LogUp grand-sum argument. M[i] counts how many times T[i] appears in S.
//
// It models the following Σ protocol (N = domain size):
//
//	|-------------------------------–-----------------------------------------------|
//	| [prover]                      |              [verifier]                       |
//	|-------------------------------–-----------------------------------------------|
//	| Compute M s.t.                |                                               |
//	|   M[i] = #{j : S[j] = T[i]}  |                                               |
//	| Commit(S, T, M)       -----→  | [Com(S), Com(T), Com(M)]                     | ROUND 1
//	|-------------------------------–-----------------------------------------------|
//	|                               ←-----  Sample random γ (gamma)                |
//	|                               |       (γ = Fiat-Shamir(Com(S),Com(T),Com(M))) | ROUND 2
//	|-------------------------------–-----------------------------------------------|
//	| Compute running sums:         |                                               |
//	|   Σ_S[i] = Σ_{j⩽i} 1/(S[j]-γ)       (lookup side)                          |
//	|   Σ_T[i] = Σ_{j⩽i} M[j]/(T[j]-γ)   (table side)                            |
//	| Commit(Σ_S, Σ_T)      -----→  | [Com(Σ_S), Com(Σ_T)]                        | ROUND 3
//	|-------------------------------–-----------------------------------------------|
//	|       (done via FoldConstraints + Finalize + Verify)                          |
//	| Records four constraints (L_0 = Lagrange basis polynomial at 0):              |
//	|   C1: (1-L_0)·((Σ_T-Σ_T(ω⁻¹X))·(T-γ) - M) = 0 mod X^N-1                  |
//	|   C2: (1-L_0)·((Σ_S-Σ_S(ω⁻¹X))·(S-γ) - 1) = 0 mod X^N-1                  |
//	|   C3: L_0·(Σ_T·(T-γ) - M) = 0  (enforces Σ_T[0] = M[0]/(T[0]-γ))          |
//	|   C4: L_0·(Σ_S·(S-γ) - 1) = 0  (enforces Σ_S[0] = 1/(S[0]-γ))             |
//	| Soundness: if S ⊂ T then Σ_S[N-1] = Σ_T[N-1],                              |
//	|   i.e. Σ_j 1/(S[j]-γ) = Σ_j M[j]/(T[j]-γ)                                 |
//	|-------------------------------–-----------------------------------------------|
func InclusionCheckIOP(prot *protocol.Protocol, S, T, M, Σ_S, Σ_T, gamma string, opts ...system.Option) error {

	// build M, the multiplicities polynomial: M[i] = number of times T[i] appears in S
	MPoly, err := univariate.BuildMultiplicityPolynomial(prot.S.Trace["S"], prot.S.Trace["T"])
	if err != nil {
		return err
	}
	err = system.RegisterColumn(&prot.S, M, &MPoly)
	if err != nil {
		return err
	}

	// ask the verifier a challenge depending on M, T, S
	_, err = prot.SendMeAChallenge([]string{S, T, M}, gamma)

	// compute Σ_S, Σ_T such that
	// Σ_S[i] = \Sum_{j⩽i} M[i]/(S[i]-γ)
	// Σ_T[i] = \Sum_{j⩽i} M[i]/(T[i]-γ)
	// and add the constraint ensuring the soundness of the construction
	err = system.BuildGrandSum(&prot.S, S, T, M, Σ_S, Σ_T, gamma, opts...)

	return err
}
