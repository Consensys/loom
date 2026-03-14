package arguments

import (
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/constraint"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/constants"
	derive "github.com/consensys/loom/internal/derive"
	"github.com/consensys/loom/internal/utils"
)

// * R[0] = F[0]*E[0]
// * R[i] = F[i]*(α*R[i-1]+E[i]) + (1-F[i])R[i-1] for i>0
func BuildProjectionRelation(E, F, alpha expr.Expr, R string, N int) []constraint.Relation {

	// 1. R[0] = F[0]*E[0]
	boundaryRelation := localRelation(expr.Col(R), E.Mul(F), 0, N)

	// 2. R[i] = F[i]*(α*R[i-1]+E[i]) + (1-F[i])R[i-1] for i>0
	one := koalabear.One()
	RShifted := expr.Rot(R, -1)
	path1 := F.Mul(alpha.Mul(RShifted).Add(E))
	path2 := RShifted.Mul(expr.Const(one).Sub(F))
	path1 = path1.Add(path2) //  F[i]*(α*R[i-1]+E[i]) + (1-F[i])R[i-1]
	lagrange0 := expr.Virtual(derive.GetLagrangeID(0, N))
	recurrenceRelation := expr.Col(R).Sub(path1).Mul(expr.Const(one).Sub(lagrange0)) // (R[i] - (F[i]*(α*R[i-1]+E[i]) + (1-F[i])R[i-1])) * (1 - lagrange0)

	return []constraint.Relation{boundaryRelation, recurrenceRelation}

}

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
	AFolded := constraint.Fold(A, gammaExpr)
	BFolded := constraint.Fold(B, gammaExpr)

	// 3. call equalityFilteredColumns
	return Projection(system, AFolded, F1, BFolded, F2)

}

func Projection(system *constraint.Builder, A, F1, B, F2 expr.Expr) error {

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
	system.AssertAllZero(BuildProjectionRelation(A, F1, alpha, idAccFA, system.N))
	system.AssertAllZero(BuildProjectionRelation(B, F2, alpha, idAccFB, system.N))

	// 5. ensure FA[N-1]=FB[N-1]: the last entry holds the full filtered accumulation
	accFA := expr.Col(idAccFA)
	accFB := expr.Col(idAccFB)
	system.AssertEqualAt(accFA, accFB, system.N-1)

	// 6. Register Lagrange columns needed by BuildFilteredAccPolynomialRelation (L_0) and step 5 (L_{N-1})
	system.AddLagrangeColumn(0)

	return nil
}
