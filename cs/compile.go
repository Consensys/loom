package cs

import (
	"github.com/consensys/giop/constants"
	"github.com/consensys/giop/pas/dag"
	"github.com/consensys/giop/expr"
	proveractions "github.com/consensys/giop/prover_actions"
)

// Fold returns Σ_i αⁱE[i]
func Fold(E []expr.Expr, alpha expr.Expr) expr.Expr {
	res := E[len(E)-1]
	for i := len(E) - 2; i >= 0; i-- {
		res = res.Mul(alpha).Add(E[i])
		// res = res.Add(E[i].Mul(alpha.Pow(uint32(i))))
	}
	return res
}

// Program DAG containing all tha proverActions, and the final constraint that must vanish
// on X^N-1
type Program struct {
	ProverActions     []proveractions.ProverAction
	VanishingRelation dag.DAG
	Cache             map[string]int // not serialised, used for building the IOP only, used to track already registered prover actions which have no inputs (lagrange, permutation)
	N                 int
}

type Config struct {
	targetDegree int
}

type Option func(c *Config)

func WithTargetDegree(targetDegree int) Option {
	return func(c *Config) {
		c.targetDegree = targetDegree
	}
}

// Fold all the constraints by sampling a random challenge, derived from the necessary data to ensure that this challenge
// cannot have been derived derived prior to any of the prover<->interactions and commitments
func Compile(system *Builder, opts ...Option) Program {

	var config Config
	for _, opt := range opts {
		opt(&config)
	}

	// 0. if config.targetDegree > 0 it means targetDegree is set: we reduce the constraints degree before folding them
	if config.targetDegree > 0 {
		reduceDegree(system, config.targetDegree)
	}

	// 1. exproblically fold all the constraints using the folding challenge. The actual challenge is derived in prover/.
	C := Fold(system.Relations, expr.NewChallenge(constants.FINAL_FOLDING_CHALLENGE))
	CDag := dag.ExprToDAG(C)
	CDag = CDag.Flatten()
	return Program{
		ProverActions:     system.ProverActions,
		VanishingRelation: *CDag,
		N:                 system.N,
	}
}
