package system

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/iop/pas/univariate"
)

// Lagrange standard identifier across systems for Lagrange polynomial, suffixed by an integer to specify which Lagrange polynomial
//
// TODO this is a special case (maybe the only case ?) of a simple column, that should be recomputed by the verifier. We need
// a special expression for such columns, like "Computable" or something, which should not be added in the commitments... During the verification
// process, when a "Computable" Expr is found in the expression, we should have map [Lagrange_i]->func(i) koalabear.Element, so the verifier can recompute its value at zeta
const Lagrange = "LAGRANGE"

func GetLagrangeID(entry int, N int) string {
	return fmt.Sprintf("%s_%d_%d", Lagrange, entry, N)
}

// NewLagrangeConstraint modifies S to add the constraint the S.Trace[ID][entry]=value
func NewLagrangeConstraint(S *System, ID string, entry int, value koalabear.Element, opts ...Option) error {

	var config Config
	for _, opt := range opts {
		err := opt(&config)
		if err != nil {
			return err
		}
	}

	// lagrangeID := GetLagrangeID(entry, S.N)

	// if the lagrange column is not in the trace, we add it. No need for a sigma protocol to check that the column is correctly formed
	// As it is public column known by the verifier
	lagrangeCC, err := GetComputationableColumn(GetLagrangeID(entry, S.N))
	if err != nil {
		return err
	}
	AddComputableColumn(S, lagrangeCC)

	if config.CacheMe {
		S.CachedConstraints = append(S.CachedConstraints, GetLagrangeConstraint(ID, entry, value, S.N))
	} else {
		S.Constraints = append(S.Constraints, GetLagrangeConstraint(ID, entry, value, S.N))
	}

	return nil
}

// ParseLagrangeID parses an id produced by GetLagrangeID (format: LAGRANGE__<entry>_<N>)
// and returns entry and N as integers.
// example: ParseLagrangeID(GetLagrangeID(3, 16)) -> (3, 16)
// Assumes id is correctly formed.
func ParseLagrangeID(id string) (int64, uint64, error) {
	var entry int64
	var N uint64
	_, err := fmt.Sscanf(id, Lagrange+"_%d_%d", &entry, &N)
	return entry, N, err
}

// NewLagrangeColumn from id of format: LAGRANGE__<entry>_<N> returns the
// entry-th lagrange function on domain N: L_i(z)->z
// It assumes id is correctly formed
func NewLagrangeColumn(id string) (ComputableColumn, error) {

	i, N, err := ParseLagrangeID(id)
	if err != nil {
		return ComputableColumn{"", nil, nil}, err
	}

	// L_i(z) = (ω^i / N) · (z^N − 1) / (z − ω^i)
	omegai, _ := koalabear.Generator(N)
	omegai.Exp(omegai, big.NewInt(i)) // ω^i
	one := koalabear.One()
	var nk koalabear.Element
	nk.SetUint64(uint64(N))

	var omegaiOverN koalabear.Element
	omegaiOverN.Div(&omegai, &nk) // ω^i / N

	var res ComputableColumn
	res.id = id
	res.F = func(_z koalabear.Element) koalabear.Element {
		var num koalabear.Element
		num.Exp(_z, big.NewInt(int64(N)))
		num.Sub(&num, &one)         // z^N - 1
		num.Mul(&num, &omegaiOverN) // ω^i/N · (z^N - 1)

		var denom koalabear.Element
		denom.Sub(&_z, &omegai) // z - ω^i
		denom.Inverse(&denom)   // 1 / (z - ω^i)

		num.Mul(&num, &denom) // ω^i/N · (z^N - 1) / (z - ω^i)
		return num
	}
	res.Gen = func() univariate.Polynomial {
		col := make([]koalabear.Element, N)
		col[i].SetOne()
		P, _ := univariate.NewPolynomial(col, univariate.WithBasis(univariate.Lagrange))
		return P
	}

	return res, nil
}
