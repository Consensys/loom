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

const StringChunkSize = 3

type FieldHasher interface {
	Reset()
	WriteElements(...koalabear.Element)
	WriteExt(...ext.E4)
	Sum() HashOutput
}

func NewElement(v uint64) koalabear.Element {
	var e koalabear.Element
	e.SetUint64(v)
	return e
}

func StringToElements(domainTag uint64, s string) []koalabear.Element {
	nbChunks := (len(s) + StringChunkSize - 1) / StringChunkSize
	res := make([]koalabear.Element, 2, 2+nbChunks)
	res[0].SetUint64(domainTag)
	res[1].SetUint64(uint64(len(s)))

	for i := 0; i < len(s); i += StringChunkSize {
		var limb uint64
		for j := 0; j < StringChunkSize && i+j < len(s); j++ {
			limb |= uint64(s[i+j]) << (8 * j)
		}
		var e koalabear.Element
		e.SetUint64(limb)
		res = append(res, e)
	}

	return res
}

func OutputToExt(out HashOutput) ext.E4 {
	return ElementsToExt(out[0], out[1], out[2], out[3])
}

func ElementsToExt(a0, a1, b0, b1 koalabear.Element) ext.E4 {
	var res ext.E4
	res.B0.A0.Set(&a0)
	res.B0.A1.Set(&a1)
	res.B1.A0.Set(&b0)
	res.B1.A1.Set(&b1)
	return res
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
