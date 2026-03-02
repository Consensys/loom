package std

import (
	"github.com/consensys/giop/cs"
	"github.com/consensys/giop/pas/sym"
	"github.com/consensys/gnark-crypto/field/koalabear"
)

// InclusionCheckIOP proves that every value in S appears in T (S ⊆ T as multisets).
// It implements the lookup argument of section 5.4.1 of https://eprint.iacr.org/2022/1633.pdf.
//
// The core identity checked is:
//
//	Σ_i M[i]/(T[i]−γ) = Σ_j 1/(S[j]−γ)
//
// where M[i] = #{j | S[j]=T[i]} is the multiplicity of T[i] in S. This identity holds iff
// every element of S appears in T with the correct count.
//
//	|-------------------------------–-----------------------------------------------|
//	| [prover]                      |              [verifier]                       |
//	|-------------------------------–-----------------------------------------------|
//	| Commit(S, T)          -----→  | [Com(S), Com(T)]                             | ROUND 1
//	|-------------------------------–-----------------------------------------------|
//	| Compute M s.t.                |                                               |
//	|   M[i] = #{j | S[j]=T[i]}    |                                               |
//	| Commit(M)             -----→  | [Com(M)]                                     | ROUND 2
//	|-------------------------------–-----------------------------------------------|
//	|                               ←-----  Sample random γ (gamma)                |
//	|                               |   (γ = Fiat-Shamir(Com(S),Com(T),Com(M)))    |
//	|-------------------------------–-----------------------------------------------|
//	| Compute running sums:         |                                               |
//	|   GrandSumT[i] = Σ_{j≤i} M[j]/(T[j]−γ)                                     |
//	|   GrandSumS[i] = Σ_{j≤i} 1/(S[j]−γ)                                        |
//	| Commit(GrandSumT, GrandSumS)  |                                               |
//	|                       -----→  | [Com(GrandSumT), Com(GrandSumS)]             | ROUND 3
//	|-------------------------------–-----------------------------------------------|
//	|       (done via FoldConstraints + Finalize + Verify)                          |
//	| Records five constraints:                                                     |
//	|   C1: (1−L_0)·((GrandSumT−GrandSumT_{ω^{−1}X})·(T−γ) − M) = 0             |
//	|   C2: L_0·(GrandSumT·(T−γ) − M) = 0  (GrandSumT[0] = M[0]/(T[0]−γ))       |
//	|   C3: (1−L_0)·((GrandSumS−GrandSumS_{ω^{−1}X})·(S−γ) − 1) = 0             |
//	|   C4: L_0·(GrandSumS·(S−γ) − 1) = 0  (GrandSumS[0] = 1/(S[0]−γ))          |
//	|   C5: L_{N−1}·(GrandSumS − GrandSumT) = 0  (total sums equal)               |
//	|-------------------------------–-----------------------------------------------|
func InclusionCheckIOP(system *cs.System, S, T string, M, grandSumS, grandSumT string, gamma string) {

	// 1. create the multiplicity polynomial
	Texpr := sym.NewCommittedColumn(T)
	Sexpr := sym.NewCommittedColumn(S)

	inclusionCheckIOP(system, Sexpr, Texpr, M, grandSumS, grandSumT, gamma)

}

func inclusionCheckIOP(system *cs.System, S, T sym.Expr, M, grandSumS, grandSumT string, gamma string) {

	// 1. create the multiplicity polynomial
	Mexpr := sym.NewCommittedColumn(M)
	system.RegisterProverAction([]sym.Expr{S, T}, []string{M}, cs.ComputeMultiplicity)

	// 2. sample a challenge gamma, depending on M, S, and T
	gammaDeps := []sym.Expr{S, T, Mexpr}
	system.RegisterProverAction(gammaDeps, []string{gamma}, cs.ComputeChallenge)

	// 4. compute the grand sums grandSum1:=Σ_i M[i]/(T[i]-γ), grandSum2:=Σ_i 1/(S[i]-γ)
	oneExpr := sym.NewConst(koalabear.One())
	SminusGamma := S.Sub(sym.NewChallenge(gamma))
	system.RegisterProverAction([]sym.Expr{oneExpr, SminusGamma}, []string{grandSumS}, cs.ComputeGrandSum)

	TminusGamma := T.Sub(sym.NewChallenge(gamma))
	system.RegisterProverAction([]sym.Expr{Mexpr, TminusGamma}, []string{grandSumT}, cs.ComputeGrandSum)

	// 5. register the constraints ensuring the grand sums are correctly constructed
	cs.EnforceGrandSumConstraint(system, Mexpr, TminusGamma, grandSumT, system.N)
	cs.EnforceGrandSumConstraint(system, oneExpr, SminusGamma, grandSumS, system.N)

	// 6. ensure that grandSumT[N-1] = grandSumS[N-1]
	grandSumSExpr := sym.NewCommittedColumn(grandSumS)
	grandSumTExpr := sym.NewCommittedColumn(grandSumT)
	cs.EnforceLocalConstraintAndRegisterLagrangeColumn(system, grandSumSExpr, grandSumTExpr, system.N-1)

}

// InclusionCheckMultiSetIOP proves that  the rows of [S[0], S[1], ..] for a subset of the rows of
// [T[0], T[1], ..]. It runs by folding the S[i] and the T[i] with a random challenge, and then run
// the InclusionCheckIOP on the result
func InclusionCheckMultiSetIOP(system *cs.System, S, T []string, M, grandSumS, grandSumT string, gamma string, folding string) {

	// 1. sample a challenge for folding
	foldingDeps := make([]sym.Expr, len(S)+len(T))
	for i := 0; i < len(S); i++ {
		foldingDeps[i] = sym.NewCommittedColumn(S[i])
	}
	for i := 0; i < len(T); i++ {
		foldingDeps[i+len(S)] = sym.NewCommittedColumn(T[i])
	}
	system.RegisterProverAction(foldingDeps, []string{folding}, cs.ComputeChallenge)

	// 2. fold S and T
	gammaExpr := sym.NewChallenge(folding)
	SExpr := make([]sym.Expr, len(S))
	TExpr := make([]sym.Expr, len(T))
	for i := 0; i < len(S); i++ {
		SExpr[i] = sym.NewCommittedColumn(S[i])
	}
	for i := 0; i < len(T); i++ {
		TExpr[i] = sym.NewCommittedColumn(T[i])
	}
	SFolded := cs.Fold(SExpr, gammaExpr)
	TFolded := cs.Fold(TExpr, gammaExpr)

	// 3. calls the InclusionCheckIOP on the folded S and T
	inclusionCheckIOP(system, SFolded, TFolded, M, grandSumS, grandSumT, gamma)

}
