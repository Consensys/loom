package cs

import (
	"github.com/consensys/giop/expr"
	proveractions "github.com/consensys/giop/prover_actions"
	"github.com/consensys/gnark-crypto/field/koalabear"
)

// BuildGrandProductRelation
// 1. GP*E2-GP*E1=0
// 2. GP_Shifted[0]=1
func BuildGrandProductRelation(E1, E2 expr.Expr, GP string, N int) []Relation {

	// 1. IDGrandProductShifted*E2-IDGrandProduct*E1=0
	A := expr.NewShiftedColumn(GP, 1).Mul(E2)
	B := expr.NewCommittedColumn(GP).Mul(E1)
	recurrenceRelation := A.Sub(B)

	// 2. GP[0]=1
	boundaryRelation := BuildLocalRelation(expr.NewCommittedColumn(GP), expr.NewConst(koalabear.One()), 0, N)
	return []Relation{recurrenceRelation, boundaryRelation}
}

// BuildGrandSumRelations :
// 1. (1-Lagrange_0) * ( (IDGrandSum - IDGrandSum(w^1 X))*E - M)=0 -> ensures that IDGrandSum[i] = IDGrandSum[i-1]+M[i]/E[i]
// 2. Lagrange_0*( IDGrandSum*E-M)=0 -> ensures IDGrandSum[0] = M[0]/E[0]
func BuildGrandSumRelations(M, E expr.Expr, grandSum string, N int) []Relation {

	// 1. (1-Lagrange_0) * ( (IDGrandSum - IDGrandSum(w^1 X))*E - M)=0
	lagrange := expr.NewComputableColumn(proveractions.GetLagrangeID(0, N))
	p1 := expr.NewConst(koalabear.One()).Sub(lagrange)
	diffGrandSum := expr.NewCommittedColumn(grandSum).Sub(expr.NewShiftedColumn(grandSum, -1))
	p2 := diffGrandSum.Mul(E).Sub(M)
	recurrenceRelation := p1.Mul(p2)

	// 2. Lagrange_0*( IDGrandSum*E-M)=0
	grandSumTimesE := expr.NewCommittedColumn(grandSum).Mul(E)
	localRelation := BuildLocalRelation(grandSumTimesE, M, 0, N)

	return []Relation{recurrenceRelation, localRelation}
	// EnforceLocalRelationAndRegisterLagrangeColumn(system, grandSumTimesE, M, 0)
}

// BuildLocalRelation builds the constraints Lagrange_i(E-M) whose vanishing at X^n-1
// is equivalent to E[i]=M[i]
func BuildLocalRelation(E, M expr.Expr, i int, N int) Relation {
	lagrangeID := proveractions.GetLagrangeID(i, N)
	localRelation := expr.NewComputableColumn(lagrangeID).Mul(E.Sub(M))
	return localRelation
}

// BuildCorrectConstructionRelation adds a constraint idRes - E=0, to ensure that IdRes is correcly
// constructed with E
func BuildCorrectConstructionRelation(E expr.Expr, IdRes string) Relation {
	res := expr.NewCommittedColumn(IdRes)
	E = E.Sub(res)
	return E
}

// * R[0] = F[0]*E[0]
// * R[i] = F[i]*(α*R[i-1]+E[i]) + (1-F[i])R[i-1] for i>0
func BuildFilteredAccPolynomialRelation(E, F, alpha expr.Expr, R string, N int) []Relation {

	// 1. R[0] = F[0]*E[0]
	boundaryRelation := BuildLocalRelation(expr.NewCommittedColumn(R), E.Mul(F), 0, N)

	// 2. R[i] = F[i]*(α*R[i-1]+E[i]) + (1-F[i])R[i-1] for i>0
	one := koalabear.One()
	RShifted := expr.NewShiftedColumn(R, -1)
	path1 := F.Mul(alpha.Mul(RShifted).Add(E))
	path2 := RShifted.Mul(expr.NewConst(one).Sub(F))
	path1 = path1.Add(path2) //  F[i]*(α*R[i-1]+E[i]) + (1-F[i])R[i-1]
	lagrange0 := expr.NewComputableColumn(proveractions.GetLagrangeID(0, N))
	recurrenceRelation := expr.NewCommittedColumn(R).Sub(path1).Mul(expr.NewConst(one).Sub(lagrange0)) // (R[i] - (F[i]*(α*R[i-1]+E[i]) + (1-F[i])R[i-1])) * (1 - lagrange0)

	return []Relation{boundaryRelation, recurrenceRelation}

}
