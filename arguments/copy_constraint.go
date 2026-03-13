package arguments

import (
	"github.com/consensys/loom/constraint"
	"github.com/consensys/loom/expr"
)

// CopyPermutation IOP generating a proof that Wires and S(Wires) are identical,
// where S(Wires) is the permutation S applied on Wires:=(Wires[0] || Wires[1] || ...),
// laid out horizontall.
//
// The name Wires comes from plonk, this constraint is here to ensure that a wiring
// is correct.
func CopyPermutation(system *constraint.Builder, wires []expr.Expr, S []int64) error {

	// 1. register the permutation
	allOutputs, err := system.AddPermutationColumns(S)
	if err != nil {
		return err
	}

	// 2. call PermutationMultiset on {Wires, ID}, {Wires, Permuation}
	multiSet1 := make([][]expr.Expr, len(wires))
	multiSet2 := make([][]expr.Expr, len(wires))
	for i := 0; i < len(wires); i++ {
		multiSet1[i] = []expr.Expr{wires[i], expr.Col(allOutputs[i])}
		multiSet2[i] = []expr.Expr{wires[i], expr.Col(allOutputs[len(wires)+i])}
	}

	return PermutationTuple(system, multiSet1, multiSet2)
}

// CopyRelation IOP generating a proof that Wires and S(Wires) are identical,
// where S(Wires) is the permutation S applied on each column of
// (Wires[0][0] || Wires[0][1] || ...)
// (Wires[1][0] || Wires[1][1] || ...)
// (Wires[2][0] || Wires[2][1] || ...)
// ...
// The name Wires comes from plonk, this constraint is here to ensure that a wiring
// is correct.
func CopyPermtutationTuple(system *constraint.Builder, wires [][]expr.Expr, S []int64) error {

	// 1. register the permutation
	allOutputs, err := system.AddPermutationColumns(S)
	if err != nil {
		return err
	}

	// 2. build the multi set
	// wiresExpr := makeWiresAsExpr(wires)
	multiSet1 := make([][]expr.Expr, len(wires))
	multiSet2 := make([][]expr.Expr, len(wires))
	for i := 0; i < len(wires); i++ {
		multiSet1[i] = make([]expr.Expr, len(wires)+1)
		multiSet2[i] = make([]expr.Expr, len(wires)+1)
		copy(multiSet1[i], wires[i])
		copy(multiSet2[i], wires[i])
		multiSet1[i][len(wires)] = expr.Col(allOutputs[i])
		multiSet2[i][len(wires)] = expr.Col(allOutputs[len(wires)+i])
	}

	return PermutationTuple(system, multiSet1, multiSet2)
}
