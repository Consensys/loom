package arguments

import (
	"fmt"

	"github.com/consensys/giop/constants"
	"github.com/consensys/giop/constraint"
	"github.com/consensys/giop/expr"
	derive "github.com/consensys/giop/derive"
	"github.com/consensys/giop/internal/utils"
)

// EqualityUpToPermutation proves that the multiset { ID1[j][i] } equals { ID2[j][i] }, up to permutation.
// For every i, j there is k, l such that ID1[i][j] = ID2[k][l].
//
// It models the following Σ systemocol (N = domain size, P_j := ID1[j], Q_j := ID2[j]):
//
//	|-------------------------------–-----------------------------------------------|
//	| [prover]                      |              [verifier]                       |
//	|-------------------------------–-----------------------------------------------|
//	| Commit(P_0,..,P_k,            |                                               |
//	|        Q_0,..,Q_l)    -----→  | [Com(P_0),..,Com(P_k),Com(Q_0),..,Com(Q_l)] | ROUND 1
//	|-------------------------------–-----------------------------------------------|
//	|                               ←-----  Sample random γ (challengeName)         |
//	|                               |       (γ = Fiat-Shamir(Com(P_j), Com(Q_j)))   | ROUND 2
//	|-------------------------------–-----------------------------------------------|
//	| Compute Z s.t.                |                                               |
//	|   Z[0]   = 1                  |                                               |
//	|   Z[i+1] = Z[i] ·            |                                               |
//	|     ∏_j(P_j[i] - γ)          |                                               |
//	|    ─────────────────          |                                               |
//	|     ∏_j(Q_j[i] - γ)          |                                               |
//	| Commit(Z, Z_shifted)  -----→  | [Com(Z), Com(Z_shifted)]                     | ROUND 3
//	|-------------------------------–-----------------------------------------------|
//	|       (done via FoldRelations + Finalize + Verify)                          |
//	| Records two constraints:                                                      |
//	|   C1: ∏_j(Q_j-γ)·Z_shifted - ∏_j(P_j-γ)·Z = 0 mod X^N-1                   |
//	|   C2: (Z-1)·L_0 = 0  (enforces Z[0]=1)                                      |
//	|-------------------------------–-----------------------------------------------|
func Permutation(system *constraint.Builder, ID1, ID2 []string) error {

	// 1. sample gamma: register the prover action ComputeChallenge
	E1 := make([]expr.Expr, len(ID1))
	for i := 0; i < len(ID1); i++ {
		E1[i] = expr.Col(ID1[i])
	}
	E2 := make([]expr.Expr, len(ID2))
	for i := 0; i < len(ID2); i++ {
		E2[i] = expr.Col(ID2[i])
	}

	return equalityUpToPermutationIOP(system, E1, E2)

}

func equalityUpToPermutationIOP(system *constraint.Builder, E1, E2 []expr.Expr) error {

	_IDGrandProduct, err := utils.RandomString(constants.SIZE_RANDOM_STRING)
	if err != nil {
		return err
	}
	IDGrandProduct := fmt.Sprintf("GP_%s", _IDGrandProduct)
	gamma, err := utils.RandomString(constants.SIZE_RANDOM_STRING)
	if err != nil {
		return err
	}

	system.RegisterDerivationStep(append(E1, E2...), []string{gamma}, derive.NewIDStepContext(derive.FIAT_SHAMIR))

	// 1. sample gamma
	E1MinusGamma := E1[0].Sub(expr.NewChallenge(gamma))
	for i := 1; i < len(E1); i++ {
		E1MinusGamma = E1MinusGamma.Mul(E1[i].Sub(expr.NewChallenge(gamma)))
	}
	E2MinusGamma := E2[0].Sub(expr.NewChallenge(gamma))
	for i := 1; i < len(E2); i++ {
		E2MinusGamma = E2MinusGamma.Mul(E2[i].Sub(expr.NewChallenge(gamma)))
	}

	// 2. register the grand product constraint (including the boundary constraint)
	gpRelation := constraint.BuildGrandProductRelation(E1MinusGamma, E2MinusGamma, IDGrandProduct, system.N)
	system.AssertAllZero(gpRelation)

	// 3. register the prover action for creating the grand product and grand product shifted
	system.RegisterDerivationStep([]expr.Expr{E1MinusGamma, E2MinusGamma}, []string{IDGrandProduct}, derive.NewIDStepContext(derive.GRAND_PRODUCT))

	// 4. register the creation of the lagrange column
	system.AddLagrangeColumn(0)

	return nil
}

// TupleEqualityUpToPermutation proves that the multiset of tuples { (ID1[i][0][j], ID1[i][1][j], ..) }
// equals the multiset of tuples { (ID2[i][0][j], ID2[i][1][j], ..) }.
// It means that for each i, j there is k, l such that (ID1[i][0][j], ID1[i][1][j], ..) = (ID2[k][0][l], ID2[k][1][l], ..)
//
// Tuples are first compressed into scalars with α, then EqualityUpToPermutation is applied on the scalars.
//
// It models the following Σ systemocol (N = domain size, P_s := ID1[s], Q_s := ID2[s]):
//
//	|-------------------------------–-----------------------------------------------|
//	| [prover]                      |              [verifier]                       |
//	|-------------------------------–-----------------------------------------------|
//	| Commit(P_s[0],..,P_s[d],      |                                               |
//	|        Q_s[0],..,Q_s[d])      |                                               |
//	|   for all subsets s   -----→  | [Com(P_s[k]), Com(Q_s[k])]  ∀ s, k           | ROUND 1
//	|-------------------------------–-----------------------------------------------|
//	|                               ←-----  Sample random α (alpha)                 |
//	|                               |       (α = Fiat-Shamir(Com(P_s[k]),Com(Q_s[k])))| ROUND 2
//	|-------------------------------–-----------------------------------------------|
//	| Fold each subset into a scalar column:                                        |
//	|   F1_s[i] = Σ_k α^k · P_s[i][k]                                             |
//	|   F2_s[i] = Σ_k α^k · Q_s[i][k]                                             |
//	| (reduces tuple equality to scalar equality)                                   |
//	|-------------------------------–-----------------------------------------------|
//	|                               ←-----  Sample random γ (gamma)                 |
//	|                               |       (γ = Fiat-Shamir(Com(P_s[k]),Com(Q_s[k])))| ROUND 3
//	|-------------------------------–-----------------------------------------------|
//	| Compute Z s.t.                |                                               |
//	|   Z[0]   = 1                  |                                               |
//	|   Z[i+1] = Z[i] ·            |                                               |
//	|     ∏_s(F1_s[i] - γ)         |                                               |
//	|    ─────────────────          |                                               |
//	|     ∏_s(F2_s[i] - γ)         |                                               |
//	| Commit(Z, Z_shifted)  -----→  | [Com(Z), Com(Z_shifted)]                     | ROUND 4
//	|-------------------------------–-----------------------------------------------|
//	|       (done via FoldRelations + Finalize + Verify)                          |
//	| Records two constraints:                                                      |
//	|   C1: ∏_s(F2_s-γ)·Z_shifted - ∏_s(F1_s-γ)·Z = 0 mod X^N-1                 |
//	|   C2: (Z-1)·L_0 = 0  (enforces Z[0]=1)                                      |
//	|-------------------------------–-----------------------------------------------|
//
// func PermutationMultiset(system *constraint.Builder, ID1, ID2 [][]string, IDGrandProduct string, alpha, gamma string) error {
func PermutationMultiset(system *constraint.Builder, ID1, ID2 [][]string) error {

	// 1. sample alpha: register the prover action ComputeChallenge, depending on all ids in ID1, ID2
	E1 := make([][]expr.Expr, len(ID1))
	for i := 0; i < len(E1); i++ {
		E1[i] = make([]expr.Expr, len(ID1[i]))
		for j := 0; j < len(ID1[i]); j++ {
			E1[i][j] = expr.Col(ID1[i][j])
		}
	}
	E2 := make([][]expr.Expr, len(ID2))
	for i := 0; i < len(E2); i++ {
		E2[i] = make([]expr.Expr, len(ID2[i]))
		for j := 0; j < len(ID2[i]); j++ {
			E2[i][j] = expr.Col(ID2[i][j])
		}
	}

	return multiSetPermutation(system, E1, E2)
}

func multiSetPermutation(system *constraint.Builder, E1, E2 [][]expr.Expr) error {

	// 1. derive alpha
	alpha, err := utils.RandomString(constants.SIZE_RANDOM_STRING)
	if err != nil {
		return err
	}
	var deps []expr.Expr
	for i := 0; i < len(E1); i++ {
		deps = append(deps, E1[i]...)
	}
	for i := 0; i < len(E1); i++ {
		deps = append(deps, E2[i]...)
	}
	system.RegisterDerivationStep(deps, []string{alpha}, derive.NewIDStepContext(derive.FIAT_SHAMIR))

	// 2. fold ID1[i], ID2[i] for all i with alpha
	alphaExpr := expr.NewChallenge(alpha)
	F1 := make([]expr.Expr, len(E1))
	for i := 0; i < len(E1); i++ {
		F1[i] = constraint.Fold(E1[i], alphaExpr)
	}
	F2 := make([]expr.Expr, len(E2))
	for i := 0; i < len(E2); i++ {
		F2[i] = constraint.Fold(E2[i], alphaExpr)
	}

	// 3. equalityUpToPermutationIOP
	equalityUpToPermutationIOP(system, F1, F2)

	return nil

}
