package cs

import (
	"fmt"

	"github.com/consensys/iop/pas/univariate"
	"github.com/consensys/iop/trace"
)

// GetShiftSuffix returns a suffix for identifying shifted polynomials. i tells by how much a polynomial is shifted,
// example: shit=2 means P is interpreted as P(\omega^2X)
func GetShiftSuffix(i int) string {
	return fmt.Sprintf("(w^%dX)", i)
}

// RegisterColumn registers P, whose id is ID, in T. Returns an error if the trace already exists
func RegisterColumn(T trace.Trace, ID string, P *univariate.Polynomial) error {
	if _, ok := T[ID]; ok {
		return fmt.Errorf("column %s already registered in the trace", ID)
	}
	T[ID] = P
	return nil
}
