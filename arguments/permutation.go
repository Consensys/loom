package arguments

import (
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
)

func PermutationWithinModule(builder *board.Builder, module string, A, B []expr.Expr) error {

	// 1. sample challenge
	_gamma, err := RandomString(10)
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
	fsInputs := append(inputA, inputB...)
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
	_gp, err := RandomString(10)
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

	return nil
}

func PermutationTupleWithinModule(builder *board.Builder, module string, A, B [][]expr.Expr) error {

	// 1. sample folding challenge
	_gamma, err := RandomString(10)
	if err != nil {
		return err
	}
	tableWidth := len(A[0])
	inputA := make([]board.Input, len(A)*tableWidth)
	inputB := make([]board.Input, len(B)*tableWidth)
	for i, a := range A {
		for j := 0; j < tableWidth; j++ {
			inputA[i*tableWidth+j] = board.Input{Module: module, In: a[j]}
		}
	}
	for i, b := range B {
		for j := 0; j < tableWidth; j++ {
			inputB[i*tableWidth+j] = board.Input{Module: module, In: b[j]}
		}
	}
	fsInputs := append(inputA, inputB...)
	builder.AddFiatShamirStep(fsInputs, _gamma)

	// 2. fold relations
	gamma := expr.NewChallenge(_gamma)
	foldedA := make([]expr.Expr, len(A))
	foldedB := make([]expr.Expr, len(B))
	for i := 0; i < len(A); i++ { // A and B must be of the same size
		foldedA[i] = expr.Fold(gamma, A[i])
		foldedB[i] = expr.Fold(gamma, B[i])
	}

	// 3. call 1 dimensional permutation
	return PermutationWithinModule(builder, module, foldedA, foldedB)
}
