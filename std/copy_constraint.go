package std

import (
	"fmt"

	"github.com/consensys/giop/constants"
	"github.com/consensys/giop/cs"
	"github.com/consensys/giop/pas/sym"
	proveractions "github.com/consensys/giop/prover_actions"
)

// CopyConstraint IOP generating a proof that Wires and S(Wires) are identical,
// where S(Wires) is the permutation S applied on Wires:=(Wires[0] || Wires[1] || ...),
// laid out horizontall.
//
// The name Wires comes from plonk, this constraint is here to ensure that a wiring
// is correct.
func CopyConstraint(system *cs.System, wires []string, S []int) error {

	// 1. register the permutation S
	permutationContext := proveractions.NewPermutationContext(S)
	SId := make([]string, len(wires))
	pid, err := RandomString(constants.SIZE_RANDOM_STRING)
	if err != nil {
		return err
	}
	for i := 0; i < len(wires); i++ {
		SId[i] = fmt.Sprintf("perm_%s_%d", pid, i)
	}
	// Declare both the permuted columns (SId) and the identity support columns (ID_i)
	// as outputs so the Kahn scheduler knows they are produced by this prover action.
	allOutputs := make([]string, 2*len(wires))
	for i := 0; i < len(wires); i++ {
		allOutputs[i] = SId[i]
		allOutputs[len(wires)+i] = proveractions.GetPermutationSupportID(i)
	}
	system.RegisterProverAction(nil, allOutputs, permutationContext)

	// 2. call MultiSetEqualityUpToPermutationIOP on {Wires, ID}, {Wires, Permuation}
	multiSet1 := make([][]string, len(wires))
	multiSet2 := make([][]string, len(wires))
	for i := 0; i < len(wires); i++ {
		IDi := proveractions.GetPermutationSupportID(i)
		multiSet1[i] = []string{wires[i], IDi}
		multiSet2[i] = []string{wires[i], SId[i]}
	}

	return MultiSetEqualityUpToPermutationIOP(system, multiSet1, multiSet2)
}

func makeWiresAsExpr(wires [][]string) [][]sym.Expr {
	res := make([][]sym.Expr, len(wires))
	for i := 0; i < len(wires); i++ {
		res[i] = make([]sym.Expr, len(wires[i]))
		for j := 0; j < len(res[i]); j++ {
			res[i][j] = sym.NewCommittedColumn(wires[i][j])
		}
	}
	return res
}

// CopyConstraint IOP generating a proof that Wires and S(Wires) are identical,
// where S(Wires) is the permutation S applied on each column of
// (Wires[0][0] || Wires[0][1] || ...)
// (Wires[1][0] || Wires[1][1] || ...)
// (Wires[2][0] || Wires[2][1] || ...)
// ...
// The name Wires comes from plonk, this constraint is here to ensure that a wiring
// is correct.
func CopyConstraintMultiSet(system *cs.System, wires [][]string, S []int) error {

	// 1. register the permutation S
	// 1. register the permutation S
	permutationContext := proveractions.NewPermutationContext(S)
	SId := make([]string, len(wires))
	pid, err := RandomString(constants.SIZE_RANDOM_STRING)
	if err != nil {
		return err
	}
	for i := 0; i < len(wires); i++ {
		SId[i] = fmt.Sprintf("perm_%s_%d", pid, i)
	}
	// Declare both the permuted columns (SId) and the identity support columns (ID_i)
	// as outputs so the Kahn scheduler knows they are produced by this prover action.
	allOutputs := make([]string, 2*len(wires))
	for i := 0; i < len(wires); i++ {
		allOutputs[i] = SId[i]
		allOutputs[len(wires)+i] = proveractions.GetPermutationSupportID(i)
	}
	system.RegisterProverAction(nil, allOutputs, permutationContext)

	// build the multi set
	wiresExpr := makeWiresAsExpr(wires)
	multiSet1 := make([][]sym.Expr, len(wires))
	multiSet2 := make([][]sym.Expr, len(wires))
	for i := 0; i < len(wires); i++ {
		IDi := proveractions.GetPermutationSupportID(i)
		multiSet1[i] = make([]sym.Expr, len(wires)+1)
		multiSet2[i] = make([]sym.Expr, len(wires)+1)
		copy(multiSet1[i], wiresExpr[i])
		copy(multiSet2[i], wiresExpr[i])
		multiSet1[i][len(wires)] = sym.NewCommittedColumn(IDi)
		multiSet2[i][len(wires)] = sym.NewCommittedColumn(SId[i])
	}

	return multiSetEqualityUpToPermutationIOP(system, multiSet1, multiSet2)
}
