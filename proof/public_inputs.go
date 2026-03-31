package proof

import "github.com/consensys/gnark-crypto/field/koalabear"

// PublicColumnInfo contains the indices and values of a public column
type PublicColumnInfo struct {
	Idx  []int
	Vals []koalabear.Element
}

// PublicInputs string -> ([]PublicColumnInfo) where
// PublicInputs[i] is the public info of the i-th segment of the column whose name is the key
type PublicInputs map[string][]PublicColumnInfo

// stores the logup sum of a column in a given module. Value is considered a public value, it must be given to the
// verifier. The value corresponds to the last entry of the column interpolating the running sum (the logup column).
type Logup struct {
	Module string
	Column string
	Value  koalabear.Element
}

// Bus stores the running sums of the sender and receiver
// participating in a log derivative based interaction, for instance a lookup
// The logup must satisfy Σ_i Logup_Sender_val_i - Σ_i Logup_Receiver_val_i=0
type CrossModulesLogupBus struct {
	Positive []Logup // Positive[i] = logup of the i-th segment of the positive logup column
	Negative []Logup // Negative[i] = logup of the i-th segment of the negative logup column
}

// CrossSegmentBus bus to ensure that a column is split correctly
// ex: column A is split in two, the last two entries of the first half = first two entries of the second half
// the bus stores that info. Split in 2 -> Stitches has only one entry, and Stitches[0] stores the values common
// to both half of the splitted column.
// The values to pass from one segment to another are passed as public values
// Stitches[k][0].Vals = Stitches[k][1].Vals, where Stitches[k] is the stich between the k-th and k+1-th chunk of
// a splitted column
type CrossSegmentBus struct {
	Module   string
	Column   string
	Stitches [][2]PublicColumnInfo
}
