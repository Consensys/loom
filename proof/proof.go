package proof

import "github.com/consensys/loom/internal/commitment"

type Commitment struct {
	Digest  commitment.Digest
	Columns []string
}

type Proof struct {
	CrossModulesLogupBus []CrossModulesLogupBus
}

// // Proof holds the output of the prover in the batched commitment model.
// // Polynomials are committed stage by stage (one batch per challenge level).
// type Proof struct {

// 	// opening of public columns
// 	OpeningProofPublicColumns commitment.Opening

// 	// Commitments[k] contains the commitments of the columns whose name appear in Columns, in that order
// 	Commitments []Commitment

// 	// OpeningProofs[k] is the batch opening proof for Batch[k].
// 	// OpeningProofs[k].ClaimedValues[i][j] = evaluation of BatchColumns[k][i]
// 	// at zeta shifted by OpeningProofs[k].Shift[i][j].
// 	OpeningProofs []commitment.Opening

// 	// N is the size of the domain on which the constraints vanish.
// 	N int
// }

// func NewCommitment(digest commitment.Digest, columns []string) Commitment {
// 	return Commitment{Digest: digest, Columns: columns}
// }

// func NewProof(N int) Proof {
// 	return Proof{
// 		Commitments:   make([]Commitment, 0),
// 		OpeningProofs: make([]commitment.Opening, 0),
// 		N:             N,
// 	}
// }
