package univariate

import (
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
)

// BuildLinComb returns ΣᵢαⁱP[i]
func BuildLinComb(P []Polynomial, alpha koalabear.Element, opts ...BuilderOption) (Polynomial, error) {

	// Process config options
	config := NewBuilderConfig()
	for _, opt := range opts {
		if err := opt(&config); err != nil {
			return Polynomial{}, err
		}
	}

	// check that P is not empty
	if len(P) == 0 {
		return Polynomial{}, fmt.Errorf("P cannot be empty")
	}

	// check that len(P)>1
	if len(P) <= 1 {
		return Polynomial{}, fmt.Errorf("P must have more than 1 polynomial, got %d", len(P))
	}

	// check that elements in P are of the same size, same layout, same basis
	size := len(P[0].EP.Coefficients)
	layout := P[0].EP.Layout
	basis := P[0].EP.Basis

	for i := 1; i < len(P); i++ {
		if len(P[i].EP.Coefficients) != size {
			return Polynomial{}, fmt.Errorf("P[%d] has size %d, expected %d", i, len(P[i].EP.Coefficients), size)
		}
		if P[i].EP.Layout != layout {
			return Polynomial{}, fmt.Errorf("P[%d] has layout %v, expected %v", i, P[i].EP.Layout, layout)
		}
		if P[i].EP.Basis != basis {
			return Polynomial{}, fmt.Errorf("P[%d] has basis %v, expected %v", i, P[i].EP.Basis, basis)
		}
	}

	// compute the result: R := ΣᵢαⁱP[i]
	// R = P[0] + α*P[1] + α²*P[2] + ... + αⁿ⁻¹*P[n-1]
	coeffs := make([]koalabear.Element, size)

	// Start with P[0]
	for j := 0; j < size; j++ {
		coeffs[j] = P[0].EP.Coefficients[j]
	}

	// Compute powers of alpha and accumulate
	var alphaPower koalabear.Element
	alphaPower.Set(&alpha) // alphaPower = α

	for i := 1; i < len(P); i++ {
		// Add αⁱ * P[i] to the result
		for j := 0; j < size; j++ {
			var term koalabear.Element
			term.Mul(&alphaPower, &P[i].EP.Coefficients[j])
			coeffs[j].Add(&coeffs[j], &term)
		}

		// Update alphaPower for next iteration
		if i < len(P)-1 {
			alphaPower.Mul(&alphaPower, &alpha)
		}
	}

	// Create the result polynomial with the same basis and layout
	ep := &EPolynomial{
		Coefficients: coeffs,
		Basis:        basis,
		Layout:       layout,
		Degree:       P[0].Degree(),
	}

	// return R
	var res Polynomial
	res.EP = ep
	res.Shift = 0 // No shift for the linear combination
	res.ID = config.OutputName
	return res, nil
}
