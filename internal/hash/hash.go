package hash

import (
	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/gnark-crypto/field/koalabear/poseidon2"
)

const (
	WIDTH             = 16
	NB_FULL_ROUND     = 6
	NB_PARTIAL_ROUNDS = 21
)

// 8 to land in a space big enough to be collision resistant
type HashOutput [8]koalabear.Element

type FieldHasher interface {
	Reset()
	WriteElements(...koalabear.Element)
	WriteExt(...ext.E4)
	Sum() HashOutput
}

type Poseidon2MDHasher struct {
	Perm  *poseidon2.Permutation
	State []koalabear.Element
}

func NewPoseidon2MDHasher() Poseidon2MDHasher {
	return Poseidon2MDHasher{
		Perm:  poseidon2.NewPermutation(WIDTH, NB_FULL_ROUND, NB_PARTIAL_ROUNDS),
		State: make([]koalabear.Element, 0, WIDTH),
	}
}

func (ph *Poseidon2MDHasher) Reset() {
	ph.State = ph.State[:0]
}

func (ph *Poseidon2MDHasher) WriteElements(elmts ...koalabear.Element) {
	ph.State = append(ph.State, elmts...)
}

func (ph *Poseidon2MDHasher) WriteExt(elmts ...ext.E4) {
	for _, elmt := range elmts {
		ph.State = append(ph.State, elmt.B0.A0)
		ph.State = append(ph.State, elmt.B0.A1)
		ph.State = append(ph.State, elmt.B1.A0)
		ph.State = append(ph.State, elmt.B1.A1)
	}
}

func (ph *Poseidon2MDHasher) Sum() HashOutput {
	if len(ph.State)%WIDTH != 0 {
		padding := make([]koalabear.Element, WIDTH-len(ph.State)%WIDTH)
		ph.State = append(ph.State, padding...)
	}

	numPoseidonCall := len(ph.State) / WIDTH

	tmp := make([]koalabear.Element, WIDTH/2)
	for i := 0; i < numPoseidonCall; i++ {
		copy(tmp, ph.State[WIDTH/2:])
		if err := ph.Perm.Permutation(ph.State[:WIDTH]); err != nil {
			panic(err)
		}
		for i := 0; i < WIDTH/2; i++ {
			tmp[i].Add(&tmp[i], &ph.State[WIDTH/2+i])
		}
		ph.State = ph.State[WIDTH/2:]
		copy(ph.State, tmp)
	}

	var res HashOutput
	copy(res[:], tmp)
	return res
}
