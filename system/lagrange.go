package system

import (
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/iop/pas/univariate"
)

// Lagrange standard identifier across systems for Lagrange polynomial, suffixed by an integer to specify which Lagrange polynomial
//
// TODO this is a special case (maybe the only case ?) of a simple column, that should be recomputed by the verifier. We need
// a special expression for such columns, like "Computable" or something, which should not be added in the commitments... During the verification
// process, when a "Computable" Expr is found in the expression, we should have map [Lagrange_i]->func(i) koalabear.Element, so the verifier can recompute its value at zeta
const Lagrange = "LAGRANGE_"

func GetLagrangeColumn(idx, N int) univariate.Polynomial {
	col := make([]koalabear.Element, N)
	col[idx].SetOne()
	P, _ := univariate.NewPolynomial(col, univariate.WithBasis(univariate.Lagrange))
	return P
}

func GetLagrangeID(entry int) string {
	return fmt.Sprintf("%s%d", Lagrange, entry)
}

// NewLagrangeConstraint modifies S to add the constraint the S.Trace[ID][entry]=value
func NewLagrangeConstraint(S *System, ID string, entry int, value koalabear.Element, opts ...IOPOption) error {

	var config IOPConfig
	for _, opt := range opts {
		err := opt(&config)
		if err != nil {
			return err
		}
	}

	lagrangeID := GetLagrangeID(entry)

	// if the lagrange column is not in the trace, we add it. No need for a sigma protocol to check that the column is correctly formed
	// As it is public column known by the verifier
	_, ok := S.Trace[lagrangeID]
	if !ok {
		lagrangeColumn := GetLagrangeColumn(entry, S.N)
		S.Trace[lagrangeID] = &lagrangeColumn
	}

	if config.CacheMe {
		S.CachedConstraints = append(S.CachedConstraints, GetLagrangeConstraint(ID, entry, value))
	} else {
		S.Constraints = append(S.Constraints, GetLagrangeConstraint(ID, entry, value))
	}

	return nil
}
