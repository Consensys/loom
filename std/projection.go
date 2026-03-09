package std

import (
	"fmt"

	"github.com/consensys/giop/constants"
	"github.com/consensys/giop/cs"
	"github.com/consensys/giop/pas/sym"
	proveractions "github.com/consensys/giop/prover_actions"
)

// EqualityFilteredColumnsIOP proves that the ordered sequence of A-values selected by F1
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
//	|   (FB defined symmetrically with B, F2)                                        |
//	|   So FA[N-1] = Σ_{F1[i]=1} A[i] · α^(m-1-rank(i))  (Horner of selected A)    |
//	| Commit(FA, FB)        -----→  | [Com(FA), Com(FB)]                             | ROUND 3
//	|-------------------------------–-------------------------------------------------|
//	|       (done via FoldConstraints + Finalize + Verify)                            |
//	| Records constraints:                                                            |
//	|   C1: L_0·(FA - F1·A) = 0                (boundary for FA)                    |
//	|   C2: (1-L_0)·(FA - F1·(α·FA_prev+A) - (1-F1)·FA_prev) = 0  (recurrence FA) |
//	|   C3, C4: symmetric constraints for FB                                         |
//	|   C5: L_{N-1}·(FA - FB) = 0              (final accumulated values match)     |
//	|-------------------------------–-------------------------------------------------|
func EqualityFilteredColumnsIOP(system *cs.System, A, F1, B, F2 string) error {

	Aexpr := sym.NewCommittedColumn(A)
	Bexpr := sym.NewCommittedColumn(B)

	return equalityFilteredColumnsIOP(system, Aexpr, Bexpr, F1, F2)
}

// EqualityFilteredMultiColumnsIOP proves that the ordered sequence of row-tuples of A selected by F1
// equals the ordered sequence of row-tuples of B selected by F2, where F1 and F2 are binary columns.
// I.e., A[0],..,A[k-1] and B[0],..,B[l-1] are column lists, and the tuples
// (A[0][i],..,A[k-1][i]) for F1[i]=1 must match (B[0][i],..,B[l-1][i]) for F2[i]=1 in order.
//
// Row-tuples are first compressed into scalars via γ, then EqualityFilteredColumnsIOP is applied.
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
//	|   (FB̃ defined symmetrically with B̃, F2)                                        |
//	| Commit(FÃ, FB̃)       -----→  | [Com(FÃ), Com(FB̃)]                             | ROUND 5
//	|-------------------------------–-------------------------------------------------|
//	|       (done via FoldConstraints + Finalize + Verify)                            |
//	| Records constraints:                                                            |
//	|   C1–C4: recurrence + boundary constraints for FÃ and FB̃                       |
//	|   C5:    L_{N-1}·(FÃ - FB̃) = 0   (final accumulated values match)             |
//	|-------------------------------–-------------------------------------------------|
func EqualityFilteredMultiColumnsIOP(system *cs.System, A []string, F1 string, B []string, F2 string) error {

	gamma, err := RandomString(constants.SIZE_RANDOM_STRING)
	if err != nil {
		return err
	}

	// 1. sample a challenge for folding
	foldingDeps := make([]sym.Expr, len(A)+len(B))
	for i := 0; i < len(A); i++ {
		foldingDeps[i] = sym.NewCommittedColumn(A[i])
	}
	for i := 0; i < len(B); i++ {
		foldingDeps[i+len(A)] = sym.NewCommittedColumn(B[i])
	}
	system.RegisterProverAction(foldingDeps, []string{gamma}, proveractions.ComputeChallenge)

	// 2. fold A and B
	gammaExpr := sym.NewChallenge(gamma)
	AExpr := make([]sym.Expr, len(A))
	BExpr := make([]sym.Expr, len(B))
	for i := 0; i < len(A); i++ {
		AExpr[i] = sym.NewCommittedColumn(A[i])
	}
	for i := 0; i < len(B); i++ {
		BExpr[i] = sym.NewCommittedColumn(B[i])
	}
	AFolded := cs.Fold(AExpr, gammaExpr)
	BFolded := cs.Fold(BExpr, gammaExpr)

	// 3. call equalityFilteredColumns
	return equalityFilteredColumnsIOP(system, AFolded, BFolded, F1, F2)

}

func equalityFilteredColumnsIOP(system *cs.System, A, B sym.Expr, F1, F2 string) error {

	// 1. build filtered acc polynomials for A and B
	_idAccFA, err := RandomString(constants.SIZE_RANDOM_STRING)
	if err != nil {
		return err
	}
	idAccFA := fmt.Sprintf("FiltAcc_%s", _idAccFA)

	_idAccFB, err := RandomString(constants.SIZE_RANDOM_STRING)
	if err != nil {
		return err
	}
	idAccFB := fmt.Sprintf("FiltAcc_%s", _idAccFB)

	// 2. sample alpha
	_alpha, err := RandomString(constants.SIZE_RANDOM_STRING)
	if err != nil {
		return err
	}
	alpha := sym.NewChallenge(_alpha)
	F1Expr := sym.NewCommittedColumn(F1)
	F2Expr := sym.NewCommittedColumn(F2)
	depsAlpha := []sym.Expr{A, B, F1Expr, F2Expr}
	system.RegisterProverAction(depsAlpha, []string{_alpha}, proveractions.ComputeChallenge)

	// 3. create the filtered acc polynomials
	inputsFA := []sym.Expr{A, F1Expr, alpha}
	system.RegisterProverAction(inputsFA, []string{idAccFA}, proveractions.ComputeFilteredAccPolynomial)
	inputsFB := []sym.Expr{B, F2Expr, alpha}
	system.RegisterProverAction(inputsFB, []string{idAccFB}, proveractions.ComputeFilteredAccPolynomial)

	// 4. register the constraints ensuring that the filtered acc polynomials
	// FA and FB are correclty constructed
	system.RegisterConstraints(cs.BuildFilteredAccPolynomialConstraint(A, F1Expr, alpha, idAccFA, system.N))
	system.RegisterConstraints(cs.BuildFilteredAccPolynomialConstraint(B, F2Expr, alpha, idAccFB, system.N))

	// 5. ensure FA[N-1]=FB[N-1]: the last entry holds the full filtered accumulation
	accFA := sym.NewCommittedColumn(idAccFA)
	accFB := sym.NewCommittedColumn(idAccFB)
	system.RegisterConstraint(cs.BuildLocalConstraint(accFA, accFB, system.N-1, system.N))

	// 6. Register Lagrange columns needed by BuildFilteredAccPolynomialConstraint (L_0) and step 5 (L_{N-1})
	system.RegisterithLagrangeColumn(0)
	system.RegisterithLagrangeColumn(system.N - 1)

	return nil
}
