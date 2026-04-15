package trace

import (
	"fmt"

	"github.com/consensys/loom/internal/poly"
)

// RawTrace list of columns with the size N of each column
// type RawTrace = map[string]*poly.Polynomial

// RawTrace contains a list of columns, which are interpreted as interpolated polynomials.
// E.g: RawTrace[i] is a polynomial such that RawTrace[i](\omega^j) = RawTrace[i][j]
type Trace = map[string]poly.Polynomial

func RegisterColumn(t Trace, name string, c poly.Polynomial) error {
	if _, ok := t[name]; ok {
		return fmt.Errorf("%s already registered in the trace", name)
	}
	t[name] = c
	return nil
}
