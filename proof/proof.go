package proof

import (
	"github.com/consensys/loom/internal/commitment/fri"
)

type Commitment struct {
	// Digest  commitment.Digest
	Columns []string
}

type Proof struct {
	PublicColumns      map[string]PublicInput // extracted values from columns of the trace, those values are passed as public inputs
	CommitmentOpenings fri.OpeningProof
}

func NewProof() Proof {
	var res Proof
	res.PublicColumns = make(map[string]PublicInput)
	return res
}
