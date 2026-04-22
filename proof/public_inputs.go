package proof

import "github.com/consensys/gnark-crypto/field/koalabear"

type PublicEntry struct {
	Idx   int
	Value koalabear.Element
}

type PublicInput struct {
	N       int // N = size of the module that the public column corresponding to this publicEntry belongs to
	Entries []PublicEntry
}

type PublicInputs map[string]PublicInput

// Bus stores the running sums of the sender and receiver
// participating in a log derivative based interaction, for instance a lookup
// The logup must satisfy Σ_i Logup_Sender_val_i - Σ_i Logup_Receiver_val_i=0
type LogupBus struct {
	Positive []string // Positive[i] = name of the public column whose n-1-th entry is the logup of the i-th positive logup column (the corresponding public column is in PublicInputs[name])
	Negative []string // Negative[i] = name of the public column whose n-1-th entry is the logup of the i-th negative logup column (the corresponding public column is in PublicInputs[name])
}
