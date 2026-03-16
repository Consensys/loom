package proof

import "github.com/consensys/loom/internal/commitment"

// TranscriptRoundBatched represents one Fiat-Shamir round in the batched model.
// The challenge is derived from the batch commitment identified by DependencyBatch,
// plus all previously derived challenge values.
type TranscriptRoundBatched struct {
	ChallengeName   string
	DependencyBatch int // index into ProofBatched.Batch
}

// ProofBatched holds the output of the prover in the batched commitment model.
// Polynomials are committed stage by stage (one batch per challenge level).
type ProofBatched struct {
	TranscriptRounds []TranscriptRoundBatched

	// Batch[k] is the batch commitment to all polynomials committed at stage k.
	Batch []commitment.Batch
	// BatchColumns[k][i] is the name of the i-th polynomial in Batch[k].
	// This bookkeeping is needed by FillClaimedValues and VerifyOpeningProofs
	// to map column names to positions inside the BatchOpeningProof.
	BatchColumns [][]string

	// OpeningProofs[k] is the batch opening proof for Batch[k].
	// OpeningProofs[k].ClaimedValues[i][j] = evaluation of BatchColumns[k][i]
	// at zeta shifted by OpeningProofs[k].Shift[i][j].
	OpeningProofs []commitment.BatchProofOpening

	// N is the size of the domain on which the constraints vanish.
	N int

	// Internal prover state — not transmitted to the verifier.
	// cacheChallengeDependencies map[string][]string
}

func NewProofBatched(N int) ProofBatched {
	return ProofBatched{
		TranscriptRounds: make([]TranscriptRoundBatched, 0),
		Batch:            make([]commitment.Batch, 0),
		BatchColumns:     make([][]string, 0),
		OpeningProofs:    make([]commitment.BatchProofOpening, 0),
		N:                N,
		// cacheChallengeDependencies: make(map[string][]string),
	}
}

// GetChallengeDeps returns the committed-column dependencies cached for the
// given challenge name, and whether the entry exists.
// func (p *ProofBatched) GetChallengeDeps(name string) ([]string, bool) {
// 	deps, ok := p.cacheChallengeDependencies[name]
// 	return deps, ok
// }

// // SetChallengeDeps records the committed-column dependencies for a challenge.
// func (p *ProofBatched) SetChallengeDeps(name string, deps []string) {
// 	p.cacheChallengeDependencies[name] = deps
// }

// IsColumnCommitted reports whether the column with the given name has already
// been included in a batch commitment.
func (p *ProofBatched) IsColumnCommitted(name string) bool {
	for _, cols := range p.BatchColumns {
		for _, c := range cols {
			if c == name {
				return true
			}
		}
	}
	return false
}
