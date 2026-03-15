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

	// commitment to a batch of polynomials (TranscriptRoundBatched.DependencyBatch points to a Batch)
	Batch []commitment.Batch

	// one batch opening proof per batch. ClaimedValues, Shift follow the ordering of the list of poly in the batch
	// That is ClaimedValues[i] are the claimed values shifted by shift[i], of the the i-th polynomial in the list when the list was committed.
	OpeningProofs []commitment.BatchOpeningProof
}
