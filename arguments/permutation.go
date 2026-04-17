package arguments

import (
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/constants"
)

// PermutationCrossModules we use the lookup in this case, so that each module has its own logup
func PermutationCrossModules(builder *board.Builder, A, B board.Input) error {

	// 1. sample challenge
	_gamma, err := constants.RandomString(10)
	if err != nil {
		return err
	}
	fsInputs := []expr.Expr{A.In, B.In}
	builder.AddFiatShamirStep(fsInputs, _gamma)

	// 2. register lookup for both parties
	gamma := expr.Challenge(_gamma)
	prefixLogup := "logup"
	_logupA, err := constants.RandomString(10)
	if err != nil {
		return err
	}
	_logupB, err := constants.RandomString(10)
	if err != nil {
		return err
	}
	_logupA = fmt.Sprintf("%s_%s", prefixLogup, _logupA)
	_logupB = fmt.Sprintf("%s_%s", prefixLogup, _logupB)
	{
		aMinusGamma := A.In.Sub(gamma)
		builder.AddLogupStep(A.Module, aMinusGamma, expr.Const(koalabear.One()), _logupA)
	}
	{
		bMinusGamma := B.In.Sub(gamma)
		builder.AddLogupStep(B.Module, bMinusGamma, expr.Const(koalabear.One()), _logupB)
	}

	// 3. Check logup relation
	logupA := expr.Col(_logupA)
	logupB := expr.Col(_logupB)
	AddLogupEqualityCheck(builder, A.Module, B.Module, []expr.Expr{logupA}, []expr.Expr{logupB})

	return nil
}

// PermutationWithinModule we use the grand product argument in that case, it saves a column (1 grand product instead of 2 logups+bus)
// Generates an argument to prove that (A[0] || A[1] || ..) and (B[0] || B[1] || ..) are equal up to permutation
func PermutationWithinModule(builder *board.Builder, module string, A, B []expr.Expr) error {

	// 1. sample challenge
	_gamma, err := constants.RandomString(10)
	if err != nil {
		return err
	}
	inputA := make([]board.Input, len(A))
	inputB := make([]board.Input, len(B))
	for i, a := range A {
		inputA[i] = board.Input{Module: module, In: a}
	}
	for i, b := range B {
		inputB[i] = board.Input{Module: module, In: b}
	}
	// fsInputs := append(inputA, inputB...)
	fsInputs := append(A, B...)
	builder.AddFiatShamirStep(fsInputs, _gamma)

	// 2. register permutation
	gamma := expr.Col(_gamma)
	AminusGamma := make([]expr.Expr, len(A))
	BminusGamma := make([]expr.Expr, len(B))
	for i, a := range A {
		AminusGamma[i] = a.Sub(gamma)
	}
	for i, b := range B {
		BminusGamma[i] = b.Sub(gamma)
	}
	_gp, err := constants.RandomString(10)
	if err != nil {
		return err
	}
	Amul := AminusGamma[0]
	Bmul := BminusGamma[0]
	for i := 1; i < len(AminusGamma); i++ {
		Amul = Amul.Mul(AminusGamma[i])
	}
	for i := 1; i < len(BminusGamma); i++ {
		Bmul = Bmul.Mul(BminusGamma[i])
	}
	builder.AddGrandProductStep(module, Amul, Bmul, _gp)
	m := builder.Modules[module]
	m.AssertEqualAt(expr.Const(koalabear.One()), expr.Col(_gp), 0)
	builder.Modules[module] = m

	return nil
}

// PermutationTupleWithinModule
// Generates an argument to prove that
// (A[0][0] || A[1][0] || A[2][0] || ..) |
// (A[0][1] || A[1][1] || A[2][1] || ..) | <- the rows are folded
// (A[0][2] || A[1][2] || A[2][2] || ..) |
// ..
// and
// (B[0][0] || B[1][0] || B[2][0] || ..) |
// (B[0][1] || B[1][1] || B[2][1] || ..) | <- the rows are folded
// (B[0][2] || B[1][2] || B[2][2] || ..) |
// are equal up to permutation
// The rows of each matrix are folded, and we call PermutationWithinModule afterwards
func PermutationTupleWithinModule(builder *board.Builder, module string, A, B [][]expr.Expr) error {

	// 1. sample folding challenge
	_gamma, err := constants.RandomString(10)
	if err != nil {
		return err
	}
	tableWidth := len(A[0])
	inputA := make([]expr.Expr, len(A)*tableWidth)
	inputB := make([]expr.Expr, len(B)*tableWidth)
	for i, a := range A {
		copy(inputA[i*tableWidth:], a)
	}
	for i, b := range B {
		copy(inputB[i*tableWidth:], b)
	}
	fsInputs := append(inputA, inputB...)
	builder.AddFiatShamirStep(fsInputs, _gamma)

	// 2. fold relations
	gamma := expr.Challenge(_gamma)
	foldedA := make([]expr.Expr, len(A))
	foldedB := make([]expr.Expr, len(B))
	for i := 0; i < len(A); i++ { // A and B must be of the same size
		foldedA[i] = expr.Fold(gamma, A[i])
		foldedB[i] = expr.Fold(gamma, B[i])
	}

	// 3. call 1 dimensional permutation
	return PermutationWithinModule(builder, module, foldedA, foldedB)
}

// func FixedPermutationWithinModule(builder *board.Builder, module string, A, B [][]expr.Expr, S board.PermutationGen) error {

// 	// 1 - register the permutation in the module

// 	// 2 -

// }
