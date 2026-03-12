package arguments

import (
	"github.com/consensys/giop/cs"
	"github.com/consensys/giop/expr"
)

// CopyPermutation IOP generating a proof that Wires and S(Wires) are identical,
// where S(Wires) is the permutation S applied on Wires:=(Wires[0] || Wires[1] || ...),
// laid out horizontall.
//
// The name Wires comes from plonk, this constraint is here to ensure that a wiring
// is correct.
func CopyPermutation(system *cs.System, wires []string, S []int64) error {

	// 1. register the permutation
	allOutputs, err := system.RegisterPermutation(S)
	if err != nil {
		return err
	}

	// 2. call PermutationMultiset on {Wires, ID}, {Wires, Permuation}
	multiSet1 := make([][]string, len(wires))
	multiSet2 := make([][]string, len(wires))
	for i := 0; i < len(wires); i++ {
		multiSet1[i] = []string{wires[i], allOutputs[i]}
		multiSet2[i] = []string{wires[i], allOutputs[len(wires)+i]}
	}

	return PermutationMultiset(system, multiSet1, multiSet2)
}

func makeWiresAsExpr(wires [][]string) [][]expr.Expr {
	res := make([][]expr.Expr, len(wires))
	for i := 0; i < len(wires); i++ {
		res[i] = make([]expr.Expr, len(wires[i]))
		for j := 0; j < len(res[i]); j++ {
			res[i][j] = expr.NewCommittedColumn(wires[i][j])
		}
	}
	return res
}

// CopyRelation IOP generating a proof that Wires and S(Wires) are identical,
// where S(Wires) is the permutation S applied on each column of
// (Wires[0][0] || Wires[0][1] || ...)
// (Wires[1][0] || Wires[1][1] || ...)
// (Wires[2][0] || Wires[2][1] || ...)
// ...
// The name Wires comes from plonk, this constraint is here to ensure that a wiring
// is correct.
func CopyPermtutationMultiSet(system *cs.System, wires [][]string, S []int64) error {

	// 1. register the permutation
	allOutputs, err := system.RegisterPermutation(S)
	if err != nil {
		return err
	}

	// 2. build the multi set
	wiresExpr := makeWiresAsExpr(wires)
	multiSet1 := make([][]expr.Expr, len(wires))
	multiSet2 := make([][]expr.Expr, len(wires))
	for i := 0; i < len(wires); i++ {
		multiSet1[i] = make([]expr.Expr, len(wires)+1)
		multiSet2[i] = make([]expr.Expr, len(wires)+1)
		copy(multiSet1[i], wiresExpr[i])
		copy(multiSet2[i], wiresExpr[i])
		multiSet1[i][len(wires)] = expr.NewCommittedColumn(allOutputs[i])
		multiSet2[i][len(wires)] = expr.NewCommittedColumn(allOutputs[len(wires)+i])
	}

	return multiSetPermutation(system, multiSet1, multiSet2)
}
