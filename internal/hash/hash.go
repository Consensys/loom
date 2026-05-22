package hash

import (
	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/gnark-crypto/field/koalabear/poseidon2"
)

const (
	WIDTH              = 16
	SPONGE_WIDTH       = 24
	SPONGE_RATE        = 16
	NB_FULL_ROUND      = 6
	NB_PARTIAL_ROUNDS  = 21
	DIGEST_NB_ELEMENTS = 8
)

// 8 to land in a space big enough to be collision resistant
type Digest [DIGEST_NB_ELEMENTS]koalabear.Element

const StringChunkSize = 3

type FieldHasher interface {
	Reset()
	WriteElements(...koalabear.Element)
	WriteExt(...ext.E4)
	Sum() Digest
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

func OutputToExt(out Digest) ext.E4 {
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
	Perm *poseidon2.Permutation

	state      [WIDTH]koalabear.Element
	pos        int
	wrote      bool
	compressed bool
	finalized  bool
}

// Poseidon2SpongeHasher is a padding-free overwrite-mode sponge with width 24,
// rate 16, and an 8-element digest. It is used for Fiat-Shamir and Merkle
// leaves, while Merkle node compression keeps the width-16 MD hasher.
type Poseidon2SpongeHasher struct {
	Perm *poseidon2.Permutation

	state     [SPONGE_WIDTH]koalabear.Element
	block     [SPONGE_RATE]koalabear.Element
	blockLen  int
	wrote     bool
	finalized bool
}

// Poseidon2 permutations only hold immutable parameters/round keys. The
// permutation call mutates the input state slice, so hashers can share these
// values while keeping independent state buffers.
var (
	defaultPoseidon2Perm       = poseidon2.NewPermutation(WIDTH, NB_FULL_ROUND, NB_PARTIAL_ROUNDS)
	defaultPoseidon2SpongePerm = poseidon2.NewPermutation(SPONGE_WIDTH, NB_FULL_ROUND, NB_PARTIAL_ROUNDS)
)

func NewPoseidon2MDHasher() Poseidon2MDHasher {
	return Poseidon2MDHasher{
		Perm: defaultPoseidon2Perm,
	}
}

// NewPoseidon2SpongeHasher returns the width-24/rate-16 Poseidon2 sponge.
func NewPoseidon2SpongeHasher() Poseidon2SpongeHasher {
	return Poseidon2SpongeHasher{
		Perm: defaultPoseidon2SpongePerm,
	}
}

func (ph *Poseidon2MDHasher) Reset() {
	for i := range ph.state {
		ph.state[i].SetZero()
	}
	ph.pos = 0
	ph.wrote = false
	ph.compressed = false
	ph.finalized = false
}

func (ph *Poseidon2MDHasher) WriteElements(elmts ...koalabear.Element) {
	for i := range elmts {
		ph.writeElement(elmts[i])
	}
}

func (ph *Poseidon2MDHasher) WriteExt(elmts ...ext.E4) {
	for _, elmt := range elmts {
		ph.writeElement(elmt.B0.A0)
		ph.writeElement(elmt.B0.A1)
		ph.writeElement(elmt.B1.A0)
		ph.writeElement(elmt.B1.A1)
	}
}

func (ph *Poseidon2MDHasher) Sum() Digest {
	if ph.finalized {
		return ph.digest()
	}
	if !ph.wrote {
		ph.finalized = true
		return Digest{}
	}
	if !ph.compressed || ph.pos > WIDTH/2 {
		ph.zeroFromPos()
		ph.compress()
	}
	ph.finalized = true
	return ph.digest()
}

func (ph *Poseidon2MDHasher) writeElement(elmt koalabear.Element) {
	ph.state[ph.pos].Set(&elmt)
	ph.pos++
	ph.wrote = true
	ph.finalized = false
	if ph.pos == WIDTH {
		ph.compress()
	}
}

func (ph *Poseidon2MDHasher) compress() {
	if ph.Perm == nil {
		ph.Perm = defaultPoseidon2Perm
	}
	var upper [WIDTH / 2]koalabear.Element
	copy(upper[:], ph.state[WIDTH/2:])
	if err := ph.Perm.Permutation(ph.state[:]); err != nil {
		panic(err)
	}
	for i := 0; i < WIDTH/2; i++ {
		ph.state[i].Add(&upper[i], &ph.state[WIDTH/2+i])
	}
	for i := WIDTH / 2; i < WIDTH; i++ {
		ph.state[i].SetZero()
	}
	ph.pos = WIDTH / 2
	ph.compressed = true
}

func (ph *Poseidon2MDHasher) zeroFromPos() {
	for i := ph.pos; i < WIDTH; i++ {
		ph.state[i].SetZero()
	}
}

func (ph *Poseidon2MDHasher) digest() Digest {
	var res Digest
	copy(res[:], ph.state[:WIDTH/2])
	return res
}

func (ph *Poseidon2SpongeHasher) Reset() {
	for i := range ph.state {
		ph.state[i].SetZero()
	}
	for i := range ph.block {
		ph.block[i].SetZero()
	}
	ph.blockLen = 0
	ph.wrote = false
	ph.finalized = false
}

func (ph *Poseidon2SpongeHasher) WriteElements(elmts ...koalabear.Element) {
	for i := range elmts {
		ph.writeElement(elmts[i])
	}
}

func (ph *Poseidon2SpongeHasher) WriteExt(elmts ...ext.E4) {
	for _, elmt := range elmts {
		ph.writeElement(elmt.B0.A0)
		ph.writeElement(elmt.B0.A1)
		ph.writeElement(elmt.B1.A0)
		ph.writeElement(elmt.B1.A1)
	}
}

func (ph *Poseidon2SpongeHasher) Sum() Digest {
	if ph.finalized {
		return ph.digest()
	}
	if !ph.wrote && ph.blockLen == 0 {
		ph.finalized = true
		return Digest{}
	}
	if ph.blockLen > 0 {
		ph.absorbPartialBlock()
	}
	ph.finalized = true
	return ph.digest()
}

func (ph *Poseidon2SpongeHasher) writeElement(elmt koalabear.Element) {
	ph.block[ph.blockLen].Set(&elmt)
	ph.blockLen++
	ph.finalized = false
	if ph.blockLen == SPONGE_RATE {
		ph.absorbFullBlock()
	}
}

func (ph *Poseidon2SpongeHasher) absorbFullBlock() {
	copy(ph.state[:SPONGE_RATE], ph.block[:])
	ph.permute()
	ph.clearBlock()
	ph.blockLen = 0
	ph.wrote = true
}

func (ph *Poseidon2SpongeHasher) absorbPartialBlock() {
	for i := 0; i < ph.blockLen; i++ {
		ph.state[i].Set(&ph.block[i])
	}
	ph.permute()
	ph.clearBlock()
	ph.blockLen = 0
	ph.wrote = true
}

func (ph *Poseidon2SpongeHasher) permute() {
	if ph.Perm == nil {
		ph.Perm = defaultPoseidon2SpongePerm
	}
	if err := ph.Perm.Permutation(ph.state[:]); err != nil {
		panic(err)
	}
}

func (ph *Poseidon2SpongeHasher) clearBlock() {
	for i := range ph.block {
		ph.block[i].SetZero()
	}
}

func (ph *Poseidon2SpongeHasher) digest() Digest {
	var res Digest
	copy(res[:], ph.state[:DIGEST_NB_ELEMENTS])
	return res
}
