package proof

import (
	"github.com/consensys/gnark-crypto/field/koalabear"
)

type Commitment struct {
	// Digest  commitment.Digest
	Columns []string
}

type Proof struct {
	ValuesAtZeta           map[string]koalabear.Element // map string -> evaluation of the column whose String() is the key at zeta
	PublicColumns          map[string]PublicInput       // extracted values from columns of the trace, those values are passed as public inputs
	FSInputs               [][]byte                     // rounds of FS, entry i stores the data to hash at round i to derive 'challenge@loom_<i>'
	AIRQuotientsCommitment []byte
}

func NewProof() Proof {
	var res Proof
	res.ValuesAtZeta = make(map[string]koalabear.Element)
	res.PublicColumns = make(map[string]PublicInput)
	res.FSInputs = make([][]byte, 0)
	return res
}
