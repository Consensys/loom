package trace

import "github.com/consensys/giop/univariate"

// Trace list of columns with the size N of each column
// type Trace = map[string]*univariate.Polynomial

// Trace contains a list of columns, which are interpreted as interpolated polynomials.
// E.g: Trace[i] is a polynomial such that Trace[i](\omega^j) = Trace[i][j]
type Trace = map[string]univariate.Polynomial
