package system

import (
	"github.com/consensys/iop/pas/sym"
	"github.com/consensys/iop/pas/univariate"
)

// Trace represents a trace of execution. It is just a list of columns, referenced by an ID,
// represented by a polynomial in lagrange form, whose i-th coeff is the i-th entry of the column
type Trace = map[string]*univariate.Polynomial

// System represents a constraint system, satisfying Constraint(Trace) = 0 mod X^n-1
type System struct {
	Trace             Trace
	VirtualColumns    map[string]sym.Expr // columns which are not actually computed, but referenced as Expressions in other columns
	Constraints       []Constraint        // list of constraints
	CachedConstraints []Constraint        // list of constraints which are not yet recorded (useful to accumulate constraints that we will fold later)
	N                 int
}

func NewSystem(T Trace, C, CC []Constraint, N int) System {
	return System{
		Trace:             T,
		VirtualColumns:    make(map[string]sym.Expr),
		Constraints:       C,
		CachedConstraints: CC,
		N:                 N,
	}
}
