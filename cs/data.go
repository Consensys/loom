package cs

import (
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/iop/crypto/dummycommitment"
	"github.com/consensys/iop/pas/univariate"
)

// Trace represents a trace of execution. It is just a list of columns, referenced by an ID.
type Trace = map[string]*univariate.Polynomial

// System represents a constraint system, satisfying Constraint(Trace) = 0 mod X^n-1
type System struct {
	Trace             Trace
	Constraints       []Constraint // list of constraints
	CachedConstraints []Constraint // list of constraints which are not yet recorded (useful to accumulate constraints that we will fold later)
	N                 int
}

func NewSystem(T Trace, C, CC []Constraint, N int) System {
	return System{
		Trace:             T,
		Constraints:       C,
		CachedConstraints: CC,
		N:                 N,
	}
}

type Proof struct {
	OpeningProofs map[string]dummycommitment.PackedProof

	// The final constraint. The verifier checks a relation of the form C(P1, P2.. ) = Quotient * (X^n-1)
	Constraint Constraint

	// List of Rounds, simulating a \Sigma protocol.
	// The last challenge derive is always the evaluation point, and the last binded poly is the quotient.
	Rounds []Round

	// N size of the domain on which the constraints vanish (the "n" in C(P1, P2.. ) = Quotient * (X^n-1) )
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
