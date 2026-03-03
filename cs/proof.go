package cs

import (
	"github.com/consensys/giop/crypto/dummycommitment"
	"github.com/consensys/giop/pas/sym"
	"github.com/consensys/giop/trace"
)

type Action = func(trace.Trace, *Proof, []sym.Expr, []string) error

// ProverAction functions telling how to solve for intermediate columns in a list of constraints
type ProverAction struct {
	Inputs  []sym.Expr
	Outputs []string
	Exec    Action
}

func (proverAction ProverAction) Execute(trace trace.Trace, proof *Proof) error {
	return proverAction.Exec(trace, proof, proverAction.Inputs, proverAction.Outputs)
}

// List of functions needed for solving all the columns in FinalVanishingRelation
type ProverActions = []ProverAction

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
	// VanishingRelation Constraint

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
