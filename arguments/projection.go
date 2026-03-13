package arguments

import (
	"fmt"

	"github.com/consensys/loom/constraint"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/constants"
	"github.com/consensys/loom/internal/utils"
)

// Projection proves that the ordered sequence of A-values selected by F1
// equals the ordered sequence of B-values selected by F2, where F1 and F2 are binary columns.
// I.e., if the selected indices are i_0 < i_1 < ... < i_{m-1} and j_0 < j_1 < ... < j_{m-1}, then
// A[i_0] = B[j_0], A[i_1] = B[j_1], ..., A[i_{m-1}] = B[j_{m-1}].
//
// It models the following Σ-protocol (N = domain size):
//
//	|-------------------------------–-------------------------------------------------|
//	| [prover]                      |              [verifier]                         |
//	|-------------------------------–-------------------------------------------------|
//	| Commit(A, F1, B, F2)  -----→  | [Com(A), Com(F1), Com(B), Com(F2)]             | ROUND 1
//	|-------------------------------–-------------------------------------------------|
//	|                               ←-----  Sample random α                          |
//	|                               |       (α = Fiat-Shamir(Com(A),Com(F1),         |
//	|                               |                        Com(B),Com(F2)))         | ROUND 2
//	|-------------------------------–-------------------------------------------------|
//	| Compute filtered accumulators FA, FB via Horner on the selected entries:       |
//	|   FA[0]   = F1[0] · A[0]                                                       |
//	|   FA[i]   = F1[i]·(α·FA[i-1] + A[i]) + (1-F1[i])·FA[i-1]   for i > 0        |
//	|   (FB defined exprmetrically with B, F2)                                        |
//	|   So FA[N-1] = Σ_{F1[i]=1} A[i] · α^(m-1-rank(i))  (Horner of selected A)    |
//	| Commit(FA, FB)        -----→  | [Com(FA), Com(FB)]                             | ROUND 3
//	|-------------------------------–-------------------------------------------------|
//	|       (done via FoldRelations + Finalize + Verify)                            |
//	| Records constraints:                                                            |
//	|   C1: L_0·(FA - F1·A) = 0                (boundary for FA)                    |
//	|   C2: (1-L_0)·(FA - F1·(α·FA_prev+A) - (1-F1)·FA_prev) = 0  (recurrence FA) |
//	|   C3, C4: exprmetric constraints for FB                                         |
//	|   C5: L_{N-1}·(FA - FB) = 0              (final accumulated values match)     |
//	|-------------------------------–-------------------------------------------------|
// func Projection(system *constraint.Builder, A, F1, B, F2 string) error {

// 	Aexpr := expr.Col(A)
// 	Bexpr := expr.Col(B)
// 	F1expr := expr.Col(F1)
// 	F2expr := expr.Col(F2)

// 	return ProjectionExpr(system, Aexpr, Bexpr, F1expr, F2expr)
// }

// ProjectionTuple proves that the ordered sequence of row-tuples of A selected by F1
// equals the ordered sequence of row-tuples of B selected by F2, where F1 and F2 are binary columns.
// I.e., A[0],..,A[k-1] and B[0],..,B[l-1] are column lists, and the tuples
// (A[0][i],..,A[k-1][i]) for F1[i]=1 must match (B[0][i],..,B[l-1][i]) for F2[i]=1 in order.
//
// Row-tuples are first compressed into scalars via γ, then Projection is applied.
//
// It models the following Σ-protocol (N = domain size):
//
//	|-------------------------------–-------------------------------------------------|
//	| [prover]                      |              [verifier]                         |
//	|-------------------------------–-------------------------------------------------|
//	| Commit(A[0],..,A[k-1],        |                                                 |
//	|        B[0],..,B[l-1])-----→  | [Com(A[j]), Com(B[j])]  ∀ j                   | ROUND 1
//	|-------------------------------–-------------------------------------------------|
//	|                               ←-----  Sample random γ                          |
//	|                               |       (γ = Fiat-Shamir(Com(A[j]),Com(B[j])))   | ROUND 2
//	|-------------------------------–-------------------------------------------------|
//	| Fold each row-tuple into a scalar column:                                       |
//	|   Ã[i] = Σ_j γ^j · A[j][i]                                                    |
//	|   B̃[i] = Σ_j γ^j · B[j][i]                                                    |
//	| (reduces tuple equality to scalar equality)                                     |
//	|-------------------------------–-------------------------------------------------|
//	| Commit(F1, F2)        -----→  | [Com(F1), Com(F2)]                             | ROUND 3
//	|-------------------------------–-------------------------------------------------|
//	|                               ←-----  Sample random α                          |
//	|                               |       (α = Fiat-Shamir(...,Com(F1),Com(F2)))   | ROUND 4
//	|-------------------------------–-------------------------------------------------|
//	| Compute filtered accumulators FÃ, FB̃ via Horner on the selected entries:       |
//	|   FÃ[0]   = F1[0] · Ã[0]                                                       |
//	|   FÃ[i]   = F1[i]·(α·FÃ[i-1] + Ã[i]) + (1-F1[i])·FÃ[i-1]   for i > 0       |
//	|   (FB̃ defined exprmetrically with B̃, F2)                                        |
//	| Commit(FÃ, FB̃)       -----→  | [Com(FÃ), Com(FB̃)]                             | ROUND 5
//	|-------------------------------–-------------------------------------------------|
//	|       (done via FoldRelations + Finalize + Verify)                            |
//	| Records constraints:                                                            |
//	|   C1–C4: recurrence + boundary constraints for FÃ and FB̃                       |
//	|   C5:    L_{N-1}·(FÃ - FB̃) = 0   (final accumulated values match)             |
//	|-------------------------------–-------------------------------------------------|
func ProjectionTuple(system *constraint.Builder, A []expr.Expr, F1 expr.Expr, B []expr.Expr, F2 expr.Expr) error {

	gamma, err := utils.RandomString(constants.SIZE_RANDOM_STRING)
	if err != nil {
		return err
	}

	// 1. sample a challenge for folding
	foldingDeps := make([]expr.Expr, 0, len(A)+len(B))
	foldingDeps = append(A, B...)
	system.AddChallengeStep(foldingDeps, gamma)

	// 2. fold A and B
	gammaExpr := expr.NewChallenge(gamma)
	// AExpr := make([]expr.Expr, len(A))
	// BExpr := make([]expr.Expr, len(B))
	// for i := 0; i < len(A); i++ {
	// 	AExpr[i] = expr.Col(A[i])
	// }
	// for i := 0; i < len(B); i++ {
	// 	BExpr[i] = expr.Col(B[i])
	// }
	AFolded := constraint.Fold(A, gammaExpr)
	BFolded := constraint.Fold(B, gammaExpr)

	// 3. call equalityFilteredColumns
	return Projection(system, AFolded, BFolded, F1, F2)

}

func Projection(system *constraint.Builder, A, B, F1, F2 expr.Expr) error {

	// 1. build filtered acc polynomials for A and B
	_idAccFA, err := utils.RandomString(constants.SIZE_RANDOM_STRING)
	if err != nil {
		return err
	}
	idAccFA := fmt.Sprintf("FiltAcc_%s", _idAccFA)

	_idAccFB, err := utils.RandomString(constants.SIZE_RANDOM_STRING)
	if err != nil {
		return err
	}
	idAccFB := fmt.Sprintf("FiltAcc_%s", _idAccFB)

	// 2. sample alpha
	_alpha, err := utils.RandomString(constants.SIZE_RANDOM_STRING)
	if err != nil {
		return err
	}
	alpha := expr.NewChallenge(_alpha)
	// F1Expr := expr.Col(F1)
	// F2Expr := expr.Col(F2)
	depsAlpha := []expr.Expr{A, B, F1, F2}
	system.AddChallengeStep(depsAlpha, _alpha)

	// 3. create the filtered acc polynomials
	system.AddFilteredAccStep([]expr.Expr{A, F1, alpha}, idAccFA)
	system.AddFilteredAccStep([]expr.Expr{B, F2, alpha}, idAccFB)

	// 4. register the constraints ensuring that the filtered acc polynomials
	// FA and FB are correclty constructed
	system.AssertAllZero(constraint.BuildFilteredAccPolynomialRelation(A, F1, alpha, idAccFA, system.N))
	system.AssertAllZero(constraint.BuildFilteredAccPolynomialRelation(B, F2, alpha, idAccFB, system.N))

	// 5. ensure FA[N-1]=FB[N-1]: the last entry holds the full filtered accumulation
	accFA := expr.Col(idAccFA)
	accFB := expr.Col(idAccFB)
	system.AssertZero(constraint.BuildLocalRelation(accFA, accFB, system.N-1, system.N))

	// 6. Register Lagrange columns needed by BuildFilteredAccPolynomialRelation (L_0) and step 5 (L_{N-1})
	system.AddLagrangeColumn(0)
	system.AddLagrangeColumn(system.N - 1)

	return nil
}
