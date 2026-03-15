package proof

import "github.com/consensys/loom/internal/commitment"

// TranscriptRound represents one round of the Fiat-Shamir transcript.
// A challenge (ChallengeName) is derived from the committed columns and
// prior challenges listed in the dependency fields.
type TranscriptRoundBatched struct {
	ChallengeName   string
	DependencyBatch int // batch from which the challenge depends
}

type ProofBatched struct {
	TranscriptRounds []TranscriptRoundBatched
	Batch            []commitment.Batch             // commitment to a batch of polynomials
	OpeningProofs    []commitment.BatchOpeningProof // one batch opening proof per batch
}
