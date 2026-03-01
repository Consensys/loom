package sym

import (
	"github.com/consensys/gnark-crypto/field/koalabear"
)

// Q(X1,..,Xn), T = (P1, .., Pn)
// Q(P1, .., Pn)   = H*(X^n-1)

type Horner struct {
	// coefficients in the last variable
	// Coeffs[k] = polynomial multiplying Y_n^k
	Coeffs []*Horner

	// leaf case: constant polynomial
	Constant koalabear.Element
	IsLeaf   bool
}

func ToHorner(p Polynomial) *Horner {
	return buildHorner(p, p.numCommittedColumns)
}

func buildHorner(p Polynomial, numCommittedColumns int) *Horner {

	var zero koalabear.Element

	// Base case: no variables left → scalar
	if numCommittedColumns == 0 {
		if len(p.Coeff) == 0 {
			return &Horner{
				IsLeaf:   true,
				Constant: zero,
			}
		}

		// Only possible monomial is empty exponent
		for _, c := range p.Coeff {
			return &Horner{
				IsLeaf:   true,
				Constant: c,
			}
		}
	}

	// Group by exponent of last variable
	groups := make(map[uint32]map[string]koalabear.Element)

	for key, coeff := range p.Coeff {
		exp := decode(key)
		last := exp[numCommittedColumns-1]

		// remove last coordinate
		subExp := make([]uint32, numCommittedColumns-1)
		copy(subExp, exp[:numCommittedColumns-1])

		subKey := encode(subExp)

		if _, ok := groups[last]; !ok {
			groups[last] = make(map[string]koalabear.Element)
		}

		groups[last][subKey] = coeff
	}

	// Find maximum exponent
	var maxExp uint32
	for k := range groups {
		if k > maxExp {
			maxExp = k
		}
	}

	coeffs := make([]*Horner, maxExp+1)

	// Build each coefficient polynomial
	for k := uint32(0); k <= maxExp; k++ {

		subMap, ok := groups[k]
		if !ok {
			// zero polynomial
			coeffs[k] = &Horner{
				IsLeaf:   true,
				Constant: zero,
			}
			continue
		}

		subPoly := Polynomial{
			numCommittedColumns: numCommittedColumns - 1,
			Coeff:   subMap,
		}

		coeffs[k] = buildHorner(subPoly, numCommittedColumns-1)
	}

	return &Horner{
		Coeffs: coeffs,
		IsLeaf: false,
	}
}

func (h *Horner) Eval(values []koalabear.Element) koalabear.Element {
	return evalRecursive(h, values, len(values))
}

func evalRecursive(h *Horner, values []koalabear.Element, numCommittedColumns int) koalabear.Element {

	if h.IsLeaf {
		return h.Constant
	}

	x := values[numCommittedColumns-1]

	// Horner evaluation
	var result koalabear.Element

	for i := len(h.Coeffs) - 1; i >= 0; i-- {
		result.Mul(&result, &x)
		c := evalRecursive(h.Coeffs[i], values, numCommittedColumns-1)
		result.Add(&result, &c)
	}

	return result
}

// Degree returns the total degree of the polynomial represented by the Horner form
func (h *Horner) Degree() int {
	if h.IsLeaf {
		if h.Constant.IsZero() {
			return NegInf // Zero polynomial has degree -infinity
		}
		return 0 // Non-zero constant has degree 0
	}

	// For non-leaf: h = Coeffs[0] + Coeffs[1]*X + Coeffs[2]*X^2 + ...
	// Degree is max(degree(Coeffs[k]) + k) for all non-zero Coeffs[k]
	maxDegree := NegInf

	for k, coeff := range h.Coeffs {
		coeffDegree := coeff.Degree()
		if coeffDegree != NegInf { // Skip zero coefficients
			totalDegree := coeffDegree + k
			if totalDegree > maxDegree {
				maxDegree = totalDegree
			}
		}
	}

	return maxDegree
}

// NumCommittedColumns returns the number of variables in the Horner form
func (h *Horner) NumCommittedColumns() int {
	if h.IsLeaf {
		return 0 // Leaf nodes (constants) use no variables
	}

	// For non-leaf: this level uses one variable, and coefficients use the rest
	if len(h.Coeffs) == 0 {
		return 0
	}

	// Recursively get the number of variables from coefficients
	maxCommittedColumns := 0
	for _, coeff := range h.Coeffs {
		vars := coeff.NumCommittedColumns()
		if vars > maxCommittedColumns {
			maxCommittedColumns = vars
		}
	}

	// This level adds one more variable
	return maxCommittedColumns + 1
}
