package cs

import (
	"github.com/consensys/giop/constants"
	"github.com/consensys/giop/crypto/dummycommitment"
	"github.com/consensys/giop/pas/sym"
)

// Round an IOP is a list of rounds. At each round, a challenge (referenced by ChallengeName) is sent by the verifier
// to the prover, upon receiving a list of CommittedColumns.
// It is made non interactive with Fiat Shamir: to simulate the randomness without a prover-verifier interaction, prover
// and verifier derive the challenge by hashing committedColumns, simulating the fact that the verifier received the commitments
// prior to sending the challenge.
type Round struct {

	// ChallengeName is the name of the challenge to generate
	ChallengeName string

	// Names of the commitments used to derive the challenge
	DependenciesCommittedColumns []string

	// Names of other challenfes used to derive the challenge
	DependenciesChallenges []string
}

type Proof struct {
	OpeningProofs map[string]dummycommitment.PackedProof

	// The final constraint. The verifier checks a relation of the form C(P1, P2.. ) = Quotient * (X^n-1)
	VanishingRelation Constraint

	// List of Rounds, simulating a \Sigma protocol.
	// The last challenge derive is always the evaluation point, and the last binded poly is the quotient.
	// The list of Rounds is seen as a DAG whose nodes are {inputs: DependenciesChallenges, output: challengeName}.
	// This allows to do stuff like:
	// * scheduling the challenge generation using Kahn style algo during the verification
	// * querying the last outputs of the DAG, useful to ensure that a challenge depends on every previous rounds
	Rounds []Round

	// N size of the domain on which the constraints vanish (the "n" in C(P1, P2.. ) = Quotient * (X^n-1) )
	N int
}

func NewProof(N int) Proof {
	return Proof{
		OpeningProofs: make(map[string]dummycommitment.PackedProof),
		Rounds:        make([]Round, 0),
		N:             N,
	}
}

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
	VanishingRelation Constraint
	N                 int
}

// Fold all the constraints by sampling a random challenge, derived from the necessary data to ensure that this challenge
// cannot have been derived derived prior to any of the prover<->interactions and commitments
func Compile(system *System) CompiledIOP {

	// 1. symoblically fold all the constraints using the folding challenge. The actual challenge is derived in prover/.
	C := Fold(system.Constraints, sym.NewChallenge(constants.FINAL_FOLDING_CHALLENGE))
	return CompiledIOP{
		ProverActions:     system.ProverActions,
		VanishingRelation: C,
		N:                 system.N,
	}
}
