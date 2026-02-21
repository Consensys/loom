package cs

import "github.com/consensys/iop/pas/sym"

// A Constraint is a multivariate polynomial that we want to be
// equal to zero when evaluated on the trace. It is represented
// as a sym.Expr, which can be a variable, a constant, or a
// combination of variables and constants using addition, multiplication,
// and exponentiation. The actual evaluation of the constraint
// on the trace will be done in CheckTrace, where we will convert
// the sym.Expr into a univariate polynomial and evaluate it at
// a random point in the trace.
type Constraint = sym.Expr
