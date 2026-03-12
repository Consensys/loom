package derive

import (
	"github.com/consensys/giop/proof"
)

// Re-export proof types so callers within internal/ can use the short names.
type Proof = proof.Proof
type TranscriptRound = proof.TranscriptRound

var NewProof = proof.NewProof
