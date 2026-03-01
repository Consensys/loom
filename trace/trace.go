package trace

import "github.com/consensys/giop/pas/univariate"

// Trace list of columns with the size N of each column
type Trace = map[string]*univariate.Polynomial
