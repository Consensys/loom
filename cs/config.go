package cs

import (
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/iop/crypto/dummycommitment"
	"github.com/consensys/iop/pas/univariate"
)

// Trace represents a trace of execution of a program, where each column is a polynomial representing the values of a variable at each step of the execution, and Index is the variable that represents the step index in the trace.
// Index maps each columns to a variable that appears in a symbolic expression.
type Trace = []univariate.Polynomial

// System represents a constraint system, satisfying Constraint(Trace) = 0 mod X^n-1
type System struct {
	Trace      Trace
	Constraint Constraint
	N          int
}

// 	// create a system System{T, C, n} and return it
// 	return System{Trace: T, Constraint: C, N: n}, nil

// }

// Binding is used for challenge derivation. They populate the 'Bindings' field
// of a fiat shamir instance, and orchestrate the rounds of a sigma protocol.
type Binding struct {

	// ChallengeName is the name of the challenge to generate
	ChallengeName string

	// Names of the commitments used to derive the challenge
	CommitmentsName []string
}

type Proof struct {
	OpeningProofs []dummycommitment.PackedProof
	Quotient      dummycommitment.PackedProof
	Constraint    Constraint

	// Bindings.
	// The last challenge derive is always the evaluation point, and the last binded poly is the quotient.
	Bindings []Binding

	// N size of the domain on which the constraints vanish -> the "n" in
	// Constraints
	N int
}

type IopConfig struct {
	ChallengeNames  []string
	ChallengeValues []koalabear.Element

	// when ReduceDegree=true, the polynomial C(P) is flatten to have degree <= TargetDegree.
	// This parameter allows to compute C(P)/X^n-1 without having a numerator of large degree, so we are not limited by the
	// fft domain size.
	ReduceDegree bool
	TargetDegree int
}

type IopOption func(config *IopConfig) error

// WithMaxDegree sets the max degree of C(P) to TargetDegree by flattening C(P).
// It allows to compute C(P)/X^n-1 without having a numerator of large degree, so we are not limited by the
// fft domain size.
func WithMaxDegree(degree int) IopOption {
	return func(config *IopConfig) error {
		config.ReduceDegree = true
		config.TargetDegree = degree
		return nil
	}
}
