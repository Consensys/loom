package proof

import "github.com/consensys/gnark-crypto/field/koalabear"

// PublicColumnInfo contains the indices and values of a public column
type PublicColumnInfo struct {
	Idx  []int
	Vals []koalabear.Element
}

// PublicInputs
type PublicInputs map[string]PublicColumnInfo
