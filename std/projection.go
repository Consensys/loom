package std

import (
	"fmt"

	"github.com/consensys/giop/constants"
	"github.com/consensys/giop/cs"
	"github.com/consensys/giop/pas/sym"
	proveractions "github.com/consensys/giop/prover_actions"
)

// EqualityFilteredColumns proves that A filterd by F1 = B filtered by F2,
// where F1 and F2 are binary columns
func EqualityFilteredColumns(system *cs.System, A, F1, B, F2 string) error {

	Aexpr := sym.NewCommittedColumn(A)
	Bexpr := sym.NewCommittedColumn(B)

	return equalityFilteredColumns(system, Aexpr, Bexpr, F1, F2)
}

func equalityFilteredColumns(system *cs.System, A, B sym.Expr, F1, F2 string) error {

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
