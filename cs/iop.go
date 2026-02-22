package cs

import (
	"fmt"

	"github.com/consensys/iop/pas/sym"
	"github.com/consensys/iop/pas/univariate"
)

// AddConstraint populates the constraints with C
func AddConstraint(S *System, C Constraint, opts ...IOPOption) error {

	// build the config file
	var config IOPConfig
	for _, opt := range opts {
		err := opt(&config)
		if err != nil {
			return err
		}
	}

	if config.CacheMe {
		S.CachedConstraints = append(S.CachedConstraints, C)
	} else {
		S.Constraints = append(S.Constraints, C)
	}
	return nil
}

// ensureChallengeInTrace adds challenge as a constant column to S.Trace if it has a
// name and is not already present. This allows functions like NewSimpleIOP and
// NewGrandProductIOP to be called directly (without Protocol.SendMeAChallenge) while
// still resolving placeholder references during pointwise evaluation and brute-force checks.
func ensureChallengeInTrace(S *System, challenge Challenge) error {
	if challenge.Name == "" {
		return nil
	}
	if _, ok := S.Trace[challenge.Name]; ok {
		return nil
	}
	col, err := univariate.NewConstantPolynomial(challenge.Value)
	if err != nil {
		return err
	}
	S.Trace[challenge.Name] = &col
	return nil
}

// NewSimpleIOP computes a new polynomial Q (so new column in the trace) so that Q =E(IDs, Challenge), and adds the constraint
// Q - E(IDs, Challenge)
func NewSimpleIOP(S *System, E sym.Expr, IDresult string, challenge Challenge, opts ...IOPOption) error {

	// build the config file
	var config IOPConfig
	for _, opt := range opts {
		err := opt(&config)
		if err != nil {
			return err
		}
	}

	if err := ensureChallengeInTrace(S, challenge); err != nil {
		return err
	}

	sum, err := univariate.EvalPointWise(S.Trace, E, S.N, univariate.WithOutputBasis(univariate.Lagrange))
	if err != nil {
		return err
	}

	// record the result polynomial
	if _, ok := S.Trace[IDresult]; ok {
		return fmt.Errorf("%s already recorded in the trace (name already taken)", IDresult)
	}
	S.Trace[IDresult] = &sum

	// record the constraint
	C := E.Sub(sym.NewVar(IDresult))
	if config.CacheMe {
		S.CachedConstraints = append(S.CachedConstraints, C)
	} else {
		S.Constraints = append(S.Constraints, C)
	}

	return nil
}
