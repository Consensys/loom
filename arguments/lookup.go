package arguments

import (
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/constraint"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/constants"
	"github.com/consensys/loom/internal/utils"
)

// Lookup proves that every value in S appears in T (S ⊆ T as multisets).
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
//	|       (done via FoldRelations + Finalize + Verify)                          |
//	| Records five constraints:                                                     |
//	|   C1: (1−L_0)·((GrandSumT−GrandSumT_{ω^{−1}X})·(T−γ) − M) = 0             |
//	|   C2: L_0·(GrandSumT·(T−γ) − M) = 0  (GrandSumT[0] = M[0]/(T[0]−γ))       |
//	|   C3: (1−L_0)·((GrandSumS−GrandSumS_{ω^{−1}X})·(S−γ) − 1) = 0             |
//	|   C4: L_0·(GrandSumS·(S−γ) − 1) = 0  (GrandSumS[0] = 1/(S[0]−γ))          |
//	|   C5: L_{N−1}·(GrandSumS − GrandSumT) = 0  (total sums equal)               |
//	|-------------------------------–-----------------------------------------------|
func Lookup(system *constraint.Builder, S, T expr.Expr) error {

	_M, err := utils.RandomString(constants.SIZE_RANDOM_STRING)
	if err != nil {
		return err
	}
	M := fmt.Sprintf("Mult_%s", _M)
	_grandSumS, err := utils.RandomString(constants.SIZE_RANDOM_STRING)
	if err != nil {
		return err
	}
	grandSumS := fmt.Sprintf("GSum_S_%s", _grandSumS)
	_grandSumT, err := utils.RandomString(constants.SIZE_RANDOM_STRING)
	if err != nil {
		return err
	}
	grandSumT := fmt.Sprintf("GSum_T_%s", _grandSumT)
	gamma, err := utils.RandomString(constants.SIZE_RANDOM_STRING)
	if err != nil {
		return err
	}

	// 1. create the multiplicity polynomial
	Mexpr := expr.Col(M)
	system.AddMultiplicityStep([]expr.Expr{S, T}, M)

	// 2. sample a challenge gamma, depending on M, S, and T
	gammaDeps := []expr.Expr{S, T, Mexpr}
	system.AddChallengeStep(gammaDeps, gamma)

	// 3. compute the grand sums grandSum1:=Σ_i M[i]/(T[i]-γ), grandSum2:=Σ_i 1/(S[i]-γ)
	oneExpr := expr.Const(koalabear.One())
	SminusGamma := S.Sub(expr.NewChallenge(gamma))
	system.AddGrandSumStep([]expr.Expr{oneExpr, SminusGamma}, grandSumS)

	TminusGamma := T.Sub(expr.NewChallenge(gamma))
	system.AddGrandSumStep([]expr.Expr{Mexpr, TminusGamma}, grandSumT)

	// 4. register the constraints ensuring the grand sums are correctly constructed
	grandSumRelationsT := constraint.BuildGrandSumRelations(Mexpr, TminusGamma, grandSumT, system.N)
	grandSumRelationsS := constraint.BuildGrandSumRelations(oneExpr, SminusGamma, grandSumS, system.N)
	system.AssertAllZero(grandSumRelationsT)
	system.AssertAllZero(grandSumRelationsS)

	// 5. ensure that grandSumT[N-1] = grandSumS[N-1]
	grandSumSExpr := expr.Col(grandSumS)
	grandSumTExpr := expr.Col(grandSumT)
	boundaryEquality := constraint.BuildLocalRelation(grandSumSExpr, grandSumTExpr, system.N-1, system.N)
	system.AssertZero(boundaryEquality)

	// 6. register the creation of the 2 lagrange columns 0 and N-1
	system.AddLagrangeColumn(0)
	system.AddLagrangeColumn(system.N - 1)

	return nil
}

// LookupTuple proves that every row-tuple (S[0][i], …, S[k−1][i])
// appears in the multiset of row-tuples {(T[0][j], …, T[m−1][j])}.
//
// Tuples are compressed into scalars via a Fiat-Shamir folding challenge α:
//
//	S_fold[i] = Σ_{0≤j<k} α^j · S[j][i]
//	T_fold[i] = Σ_{0≤j<m} α^j · T[j][i]
//
// By Schwartz-Zippel, tuple inclusion holds iff (with overwhelming probability
// over α) {S_fold[i]} ⊆ {T_fold[i]}. This scalar inclusion is then checked via
// Lookup using the core identity:
//
//	Σ_i M[i]/(T_fold[i]−γ) = Σ_j 1/(S_fold[j]−γ)
//
// where M[i] = #{j | S_fold[j] = T_fold[i]} is the multiplicity of T_fold[i] in S_fold.
//
//	|----------------------------------–---------------------------------------------|
//	| [prover]                         |              [verifier]                     |
//	|----------------------------------–---------------------------------------------|
//	| Commit(S[0],…,S[k−1],            |                                             |
//	|        T[0],…,T[m−1])    -----→  | [Com(S[0]),…,Com(S[k−1]),                   | ROUND 1
//	|                                  |  Com(T[0]),…,Com(T[m−1])]                   |
//	|----------------------------------–---------------------------------------------|
//	|                                  ←-----  Sample random α (folding)             |
//	|                                  |  (α = Fiat-Shamir(Com(S[·]), Com(T[·])))    |
//	|----------------------------------–---------------------------------------------|
//	| Compute:                         |                                             |
//	|   S_fold = Σ_j α^j · S[j]       |                                             |
//	|   T_fold = Σ_j α^j · T[j]       |                                             |
//	|   M[i] = #{j | S_fold[j]=T_fold[i]} |                                         |
//	| Commit(M)                 -----→ | [Com(M)]                                    | ROUND 2
//	|----------------------------------–---------------------------------------------|
//	|                                  ←-----  Sample random γ (gamma)               |
//	|                                  |  (γ = Fiat-Shamir(Com(S[·]), Com(T[·]),     |
//	|                                  |                   Com(M)))                  |
//	|----------------------------------–---------------------------------------------|
//	| Compute running sums:            |                                             |
//	|   GrandSumT[i] = Σ_{j≤i} M[j]/(T_fold[j]−γ)                                  |
//	|   GrandSumS[i] = Σ_{j≤i} 1/(S_fold[j]−γ)                                     |
//	| Commit(GrandSumT, GrandSumS)     |                                             |
//	|                          -----→  | [Com(GrandSumT), Com(GrandSumS)]            | ROUND 3
//	|----------------------------------–---------------------------------------------|
//	|       (done via FoldRelations + Finalize + Verify)                           |
//	| Records five constraints:        |                                             |
//	|   C1: (1−L_0)·((GrandSumT−GrandSumT_{ω^{−1}X})·(T_fold−γ) − M) = 0          |
//	|   C2: L_0·(GrandSumT·(T_fold−γ) − M) = 0                                     |
//	|   C3: (1−L_0)·((GrandSumS−GrandSumS_{ω^{−1}X})·(S_fold−γ) − 1) = 0          |
//	|   C4: L_0·(GrandSumS·(S_fold−γ) − 1) = 0                                     |
//	|   C5: L_{N−1}·(GrandSumS − GrandSumT) = 0  (total sums equal)                |
//	|----------------------------------–---------------------------------------------|
func LookupTuple(system *constraint.Builder, S, T []expr.Expr) error {

	gamma, err := utils.RandomString(constants.SIZE_RANDOM_STRING)
	if err != nil {
		return err
	}

	// 1. sample a challenge for folding
	foldingDeps := make([]expr.Expr, 0, len(S)+len(T))
	foldingDeps = append(S, T...)
	system.AddChallengeStep(foldingDeps, gamma)

	// 2. fold S and T
	gammaExpr := expr.NewChallenge(gamma)
	SFolded := constraint.Fold(S, gammaExpr)
	TFolded := constraint.Fold(T, gammaExpr)

	// 3. calls the Lookup on the folded S and T
	return Lookup(system, SFolded, TFolded)

}
