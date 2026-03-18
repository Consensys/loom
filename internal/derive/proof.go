package derive

import (
	"github.com/consensys/loom/proof"
)

// Re-export proof types so callers within internal/ can use the short names.
type Proof = proof.Proof
type PublicColumnInfo = proof.PublicColumnInfo
type PublicInputs = proof.PublicInputs
type Commitment = proof.Commitment

var NewProof = proof.NewProof

var NewCommitment = proof.NewCommitment
