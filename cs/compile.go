package cs

import (
	"github.com/consensys/giop/constants"
	"github.com/consensys/giop/pas/dag"
	"github.com/consensys/giop/pas/sym"
)

// Fold returns Σ_i αⁱE[i]
func Fold(E []sym.Expr, alpha sym.Expr) sym.Expr {
	res := E[0]
	for i := 1; i < len(E); i++ {
		res = res.Add(E[i].Mul(alpha.Pow(uint32(i))))
	}
	return res
}

// CompiledIOP DAG containing all tha proverActions, and the final constraint that must vanish
// on X^N-1
type CompiledIOP struct {
	ProverActions     []ProverAction
	VanishingRelation dag.DAG
	N                 int
}

// Fold all the constraints by sampling a random challenge, derived from the necessary data to ensure that this challenge
// cannot have been derived derived prior to any of the prover<->interactions and commitments
func Compile(system *System) CompiledIOP {

	// 1. symoblically fold all the constraints using the folding challenge. The actual challenge is derived in prover/.
	C := Fold(system.Constraints, sym.NewChallenge(constants.FINAL_FOLDING_CHALLENGE))
	CDag := dag.ExprToDAG(C)
	return CompiledIOP{
		ProverActions:     system.ProverActions,
		VanishingRelation: *CDag,
		N:                 system.N,
	}
}
