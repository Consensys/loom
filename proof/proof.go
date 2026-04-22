package proof

import (
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/internal/commitment/fri"
)

type Commitment struct {
	// Digest  commitment.Digest
	Columns []string
}

type Proof struct {
	ValuesAtZeta       map[string]koalabear.Element // map string -> evaluation of the column whose String() is the key at zeta
	PublicColumns      map[string]PublicInput       // extracted values from columns of the trace, those values are passed as public inputs
	CommitmentOpenings fri.OpeningProof
}

func NewProof() Proof {
	var res Proof
	res.ValuesAtZeta = make(map[string]koalabear.Element)
	res.PublicColumns = make(map[string]PublicInput)
	return res
}
