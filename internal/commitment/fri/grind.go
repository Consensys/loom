package fri

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
)

// grindingHash computes SHA256(seed ‖ nonce_be64).
func grindingHash(seed []byte, nonce uint64) [sha256.Size]byte {
	var nb [8]byte
	binary.BigEndian.PutUint64(nb[:], nonce)
	h := sha256.New()
	h.Write(seed)
	h.Write(nb[:])
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

// hasLeadingZeroBits reports whether h starts with at least bits zero bits.
// Bits are read from the most-significant end of the first byte.
func hasLeadingZeroBits(h []byte, bits int) bool {
	full := bits / 8
	if full > len(h) {
		return false
	}
	for i := range full {
		if h[i] != 0 {
			return false
		}
	}
	rem := bits % 8
	if rem == 0 {
		return true
	}
	if full >= len(h) {
		return false
	}
	return h[full]>>(8-rem) == 0
}

// deriveGrindingSeed pulls a fresh challenge from the transcript to seed the
// grinding hash. Both prover and verifier must call this at the same point.
func deriveGrindingSeed(t *fiatshamir.Transcript) ([]byte, error) {
	if err := t.NewChallenge(friGrindingSeedChallenge); err != nil {
		return nil, err
	}
	return t.ComputeChallenge(friGrindingSeedChallenge)
}

// bindGrindingNonce binds the chosen nonce back to the transcript so query
// indices depend on it.
func bindGrindingNonce(t *fiatshamir.Transcript, nonce uint64) error {
	var nb [8]byte
	binary.BigEndian.PutUint64(nb[:], nonce)
	if err := t.NewChallenge(friGrindingNonceName); err != nil {
		return err
	}
	if err := t.Bind(friGrindingNonceName, nb[:]); err != nil {
		return err
	}
	if _, err := t.ComputeChallenge(friGrindingNonceName); err != nil {
		return err
	}
	return nil
}

// grindAndBind searches for a nonce satisfying the leading-zero-bit
// requirement and binds it to the transcript. Returns the nonce.
func grindAndBind(t *fiatshamir.Transcript, bits int) (uint64, error) {
	seed, err := deriveGrindingSeed(t)
	if err != nil {
		return 0, err
	}
	for nonce := uint64(0); nonce < ^uint64(0); nonce++ {
		h := grindingHash(seed, nonce)
		if hasLeadingZeroBits(h[:], bits) {
			if err := bindGrindingNonce(t, nonce); err != nil {
				return 0, err
			}
			return nonce, nil
		}
	}
	return 0, fmt.Errorf("fri: grinding exhausted nonce space without finding %d-bit PoW", bits)
}

// verifyAndBindGrinding checks the proof's nonce satisfies the leading-zero-bit
// requirement and replays the same transcript operations as the prover.
func verifyAndBindGrinding(t *fiatshamir.Transcript, bits int, nonce uint64) error {
	seed, err := deriveGrindingSeed(t)
	if err != nil {
		return err
	}
	h := grindingHash(seed, nonce)
	if !hasLeadingZeroBits(h[:], bits) {
		return fmt.Errorf("fri: grinding nonce %d does not yield %d leading zero bits", nonce, bits)
	}
	return bindGrindingNonce(t, nonce)
}
