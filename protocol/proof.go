package protocol

import (
	"github.com/consensys/iop/crypto/dummycommitment"
	"github.com/consensys/iop/system"
)

type Proof struct {
	OpeningProofs map[string]dummycommitment.PackedProof

	// The final constraint. The verifier checks a relation of the form C(P1, P2.. ) = Quotient * (X^n-1)
	Constraint system.Constraint

	// List of Rounds, simulating a \Sigma protocol.
	// The last challenge derive is always the evaluation point, and the last binded poly is the quotient.
	Rounds []Round

	// N size of the domain on which the constraints vanish (the "n" in C(P1, P2.. ) = Quotient * (X^n-1) )
	N int
}
