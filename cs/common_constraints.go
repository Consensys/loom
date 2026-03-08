package cs

import (
	"github.com/consensys/giop/pas/sym"
	proveractions "github.com/consensys/giop/prover_actions"
	"github.com/consensys/gnark-crypto/field/koalabear"
)

// BuildGrandProductConstraint
// 1. GP*E2-GP*E1=0
// 2. GP_Shifted[0]=1
func BuildGrandProductConstraint(E1, E2 sym.Expr, GP string, N int) []Constraint {

	// 1. IDGrandProductShifted*E2-IDGrandProduct*E1=0
	A := sym.NewShiftedColumn(GP, 1).Mul(E2)
	B := sym.NewCommittedColumn(GP).Mul(E1)
	recurrenceConstraint := A.Sub(B)

	// 2. GP[0]=1
	boundaryConstraint := BuildLocalConstraint(sym.NewCommittedColumn(GP), sym.NewConst(koalabear.One()), 0, N)
	return []Constraint{recurrenceConstraint, boundaryConstraint}
}

// BuildGrandSumConstraints :
// 1. (1-Lagrange_0) * ( (IDGrandSum - IDGrandSum(w^1 X))*E - M)=0 -> ensures that IDGrandSum[i] = IDGrandSum[i-1]+M[i]/E[i]
// 2. Lagrange_0*( IDGrandSum*E-M)=0 -> ensures IDGrandSum[0] = M[0]/E[0]
func BuildGrandSumConstraints(M, E sym.Expr, grandSum string, N int) []Constraint {

	// 1. (1-Lagrange_0) * ( (IDGrandSum - IDGrandSum(w^1 X))*E - M)=0
	lagrange := sym.NewComputableColumn(proveractions.GetLagrangeID(0, N))
	p1 := sym.NewConst(koalabear.One()).Sub(lagrange)
	diffGrandSum := sym.NewCommittedColumn(grandSum).Sub(sym.NewShiftedColumn(grandSum, -1))
	p2 := diffGrandSum.Mul(E).Sub(M)
	recurrenceConstraint := p1.Mul(p2)

	// 2. Lagrange_0*( IDGrandSum*E-M)=0
	grandSumTimesE := sym.NewCommittedColumn(grandSum).Mul(E)
	localConstraint := BuildLocalConstraint(grandSumTimesE, M, 0, N)

	return []Constraint{recurrenceConstraint, localConstraint}
	// EnforceLocalConstraintAndRegisterLagrangeColumn(system, grandSumTimesE, M, 0)
}

// BuildLocalConstraint builds the constraints Lagrange_i(E-M) whose vanishing at X^n-1
// is equivalent to E[i]=M[i]
func BuildLocalConstraint(E, M sym.Expr, i int, N int) Constraint {
	lagrangeID := proveractions.GetLagrangeID(i, N)
	localConstraint := sym.NewComputableColumn(lagrangeID).Mul(E.Sub(M))
	return localConstraint
}

// BuildCorrectConstructionConstraint adds a constraint idRes - E=0, to ensure that IdRes is correcly
// constructed with E
func BuildCorrectConstructionConstraint(E sym.Expr, IdRes string) Constraint {
	res := sym.NewCommittedColumn(IdRes)
	E = E.Sub(res)
	return E
}

// * R[0] = F[0]*E[0]
// * R[i] = F[i]*(α*R[i-1]+E[i]) + (1-F[i])R[i-1] for i>0
func BuildFilteredAccPolynomialConstraint(E, F, alpha sym.Expr, R string, N int) []Constraint {

	// 1. R[0] = F[0]*E[0]
	boundaryConstraint := BuildLocalConstraint(sym.NewCommittedColumn(R), E.Mul(F), 0, N)

	// 2. R[i] = F[i]*(α*R[i-1]+E[i]) + (1-F[i])R[i-1] for i>0
	one := koalabear.One()
	RShifted := sym.NewShiftedColumn(R, -1)
	path1 := F.Mul(alpha.Mul(RShifted).Add(E))
	path2 := RShifted.Mul(sym.NewConst(one).Sub(F))
	path1 = path1.Add(path2) //  F[i]*(α*R[i-1]+E[i]) + (1-F[i])R[i-1]
	lagrange0 := sym.NewComputableColumn(proveractions.GetLagrangeID(0, N))
	recurrenceConstraint := sym.NewCommittedColumn(R).Sub(path1).Mul(sym.NewConst(one).Sub(lagrange0)) // (R[i] - (F[i]*(α*R[i-1]+E[i]) + (1-F[i])R[i-1])) * (1 - lagrange0)

	return []Constraint{boundaryConstraint, recurrenceConstraint}

}
