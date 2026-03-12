package trace

import "github.com/consensys/loom/internal/poly"

// Trace list of columns with the size N of each column
// type Trace = map[string]*poly.Polynomial

// Trace contains a list of columns, which are interpreted as interpolated polynomials.
// E.g: Trace[i] is a polynomial such that Trace[i](\omega^j) = Trace[i][j]
type Trace = map[string]poly.Polynomial
