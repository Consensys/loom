package proof

import (
	"github.com/consensys/loom/internal/commitment"
)

// TranscriptRound represents one round of the Fiat-Shamir transcript.
// A challenge (ChallengeName) is derived from the committed columns and
// prior challenges listed in the dependency fields.
type TranscriptRound struct {
	ChallengeName                string
	DependenciesCommittedColumns []string
	DependenciesChallenges       []string
}

// Proof holds the output of the prover: opening proofs for each committed
// column and the transcript rounds needed for Fiat-Shamir replay.
type Proof struct {
	// cacheChallengeDependencies maps each challenge name to the committed
	// columns it (transitively) depends on. Used during proving to avoid
	// double-counting columns in later rounds.
	cacheChallengeDependencies map[string][]string

	OpeningProofs   map[string]commitment.PackedProof
	TranscriptRounds []TranscriptRound

	// N is the size of the domain on which the constraints vanish.
	N int
}

func NewProof(N int) Proof {
	return Proof{
		OpeningProofs:              make(map[string]commitment.PackedProof),
		TranscriptRounds:           make([]TranscriptRound, 0),
		cacheChallengeDependencies: make(map[string][]string),
		N:                          N,
	}
}

// GetChallengeDeps returns the committed-column dependencies cached for the
// given challenge name, and whether the entry exists.
func (p *Proof) GetChallengeDeps(name string) ([]string, bool) {
	deps, ok := p.cacheChallengeDependencies[name]
	return deps, ok
}

// SetChallengeDeps records the committed-column dependencies for a challenge.
func (p *Proof) SetChallengeDeps(name string, deps []string) {
	p.cacheChallengeDependencies[name] = deps
}
