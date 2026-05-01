package fri_test

import (
	"crypto/sha256"
	"testing"

	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/internal/commitment"
	"github.com/consensys/loom/internal/commitment/fri"
	"github.com/consensys/loom/internal/poly"
)

// testConfig uses small parameters so tests run quickly.
// FoldingFactor=2 keeps test polynomials small enough.
var testConfig = fri.Config{
	BlowupFactor:          2,
	FoldingFactor:         2,
	FinalPolynomialMaxLen: 4,
	NumQueries:            4,
}

func newTestTranscripts() (*fiatshamir.Transcript, *fiatshamir.Transcript) {
	return fiatshamir.NewTranscript(sha256.New()), fiatshamir.NewTranscript(sha256.New())
}

// randomPoly returns a random polynomial of length n in Lagrange form.
func randomPoly(n int) poly.Polynomial {
	p := make(poly.Polynomial, n)
	for i := range p {
		p[i].MustSetRandom()
	}
	return p
}

// constantPoly returns a constant polynomial (all zeros except first coefficient).
func zeroPoly(n int) poly.Polynomial {
	return make(poly.Polynomial, n)
}

// TestRoundTrip commits one polynomial, proves, verifies — must accept.
func TestRoundTrip(t *testing.T) {
	proverFS, verifierFS := newTestTranscripts()

	committer := fri.NewCommitter(proverFS, testConfig, commitment.LeafHash, commitment.NodeHash)
	verifier := fri.NewVerifier(verifierFS)

	p := randomPoly(16) // base domain 16, codeword 32, 2-way → 4 layers → stops at 2
	polys := map[string]poly.Polynomial{"f": p}

	if err := committer.Commit("round0", polys); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	proof, err := committer.Prove()
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	if err := verifier.Bind("round0", proof.Commitments[0]); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := verifier.VerifyOpening(proof, commitment.LeafHash, commitment.NodeHash); err != nil {
		t.Fatalf("VerifyOpening: %v", err)
	}
}

// TestMultiOracle commits two batches of polynomials (same codeword domain) and verifies.
func TestMultiOracle(t *testing.T) {
	proverFS, verifierFS := newTestTranscripts()

	committer := fri.NewCommitter(proverFS, testConfig, commitment.LeafHash, commitment.NodeHash)
	verifier := fri.NewVerifier(verifierFS)

	batch1 := map[string]poly.Polynomial{
		"a": randomPoly(16),
		"b": randomPoly(16),
	}
	batch2 := map[string]poly.Polynomial{
		"c": randomPoly(16),
	}

	if err := committer.Commit("round0", batch1); err != nil {
		t.Fatalf("Commit batch1: %v", err)
	}
	if err := committer.Commit("round1", batch2); err != nil {
		t.Fatalf("Commit batch2: %v", err)
	}

	proof, err := committer.Prove()
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	if err := verifier.Bind("round0", proof.Commitments[0]); err != nil {
		t.Fatalf("Bind round0: %v", err)
	}
	if err := verifier.Bind("round1", proof.Commitments[1]); err != nil {
		t.Fatalf("Bind round1: %v", err)
	}
	if err := verifier.VerifyOpening(proof, commitment.LeafHash, commitment.NodeHash); err != nil {
		t.Fatalf("VerifyOpening: %v", err)
	}
}

// TestTamperedOracleData mutates one codeword value — verifier must reject.
func TestTamperedOracleData(t *testing.T) {
	proverFS, verifierFS := newTestTranscripts()

	committer := fri.NewCommitter(proverFS, testConfig, commitment.LeafHash, commitment.NodeHash)
	verifier := fri.NewVerifier(verifierFS)

	p := randomPoly(16)
	if err := committer.Commit("round0", map[string]poly.Polynomial{"f": p}); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	proof, err := committer.Prove()
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	// Flip one bit in the oracle coset data.
	if len(proof.OracleCosetData) > 0 && len(proof.OracleCosetData[0]) > 0 {
		var one koalabear.Element
		one.SetOne()
		proof.OracleCosetData[0][0][0].Add(&proof.OracleCosetData[0][0][0], &one)
	}

	if err := verifier.Bind("round0", proof.Commitments[0]); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	err = verifier.VerifyOpening(proof, commitment.LeafHash, commitment.NodeHash)
	if err == nil {
		t.Fatal("VerifyOpening: expected rejection for tampered oracle data, got nil")
	}
}

// TestTamperedClaimedValue changes one claimed evaluation — verifier must reject.
func TestTamperedClaimedValue(t *testing.T) {
	proverFS, verifierFS := newTestTranscripts()

	committer := fri.NewCommitter(proverFS, testConfig, commitment.LeafHash, commitment.NodeHash)
	verifier := fri.NewVerifier(verifierFS)

	p := randomPoly(16)
	if err := committer.Commit("round0", map[string]poly.Polynomial{"f": p}); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	proof, err := committer.Prove()
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	// Tamper with the first claimed value.
	if len(proof.ClaimedValues) > 0 {
		var one koalabear.Element
		one.SetOne()
		proof.ClaimedValues[0].Add(&proof.ClaimedValues[0], &one)
	}

	if err := verifier.Bind("round0", proof.Commitments[0]); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	err = verifier.VerifyOpening(proof, commitment.LeafHash, commitment.NodeHash)
	if err == nil {
		t.Fatal("VerifyOpening: expected rejection for tampered claimed value, got nil")
	}
}

// TestTamperedFinalPolynomial changes the final polynomial — verifier must reject.
func TestTamperedFinalPolynomial(t *testing.T) {
	proverFS, verifierFS := newTestTranscripts()

	committer := fri.NewCommitter(proverFS, testConfig, commitment.LeafHash, commitment.NodeHash)
	verifier := fri.NewVerifier(verifierFS)

	p := randomPoly(16)
	if err := committer.Commit("round0", map[string]poly.Polynomial{"f": p}); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	proof, err := committer.Prove()
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	// Tamper with the final polynomial.
	if len(proof.FinalPolynomial) > 0 {
		var one koalabear.Element
		one.SetOne()
		proof.FinalPolynomial[0].Add(&proof.FinalPolynomial[0], &one)
	}

	if err := verifier.Bind("round0", proof.Commitments[0]); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	err = verifier.VerifyOpening(proof, commitment.LeafHash, commitment.NodeHash)
	if err == nil {
		t.Fatal("VerifyOpening: expected rejection for tampered final polynomial, got nil")
	}
}

// TestGrindingRoundTrip exercises the proof-of-work grinding path: prover
// must find a small nonce, verifier must accept it.
func TestGrindingRoundTrip(t *testing.T) {
	proverFS, verifierFS := newTestTranscripts()

	cfg := testConfig
	cfg.GrindingBits = 8 // small enough to find quickly (~256 trials expected)

	committer := fri.NewCommitter(proverFS, cfg, commitment.LeafHash, commitment.NodeHash)
	verifier := fri.NewVerifier(verifierFS)
	verifier.GrindingBits = cfg.GrindingBits

	p := randomPoly(16)
	if err := committer.Commit("round0", map[string]poly.Polynomial{"f": p}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	proof, err := committer.Prove()
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	if err := verifier.Bind("round0", proof.Commitments[0]); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := verifier.VerifyOpening(proof, commitment.LeafHash, commitment.NodeHash); err != nil {
		t.Fatalf("VerifyOpening: %v", err)
	}
}

// TestGrindingTamperedNonce flips the nonce — verifier must reject the
// grinding check (or, if the bumped nonce happens to also satisfy PoW, the
// query indices will mismatch the prover's, which also rejects).
func TestGrindingTamperedNonce(t *testing.T) {
	proverFS, verifierFS := newTestTranscripts()

	cfg := testConfig
	cfg.GrindingBits = 8

	committer := fri.NewCommitter(proverFS, cfg, commitment.LeafHash, commitment.NodeHash)
	verifier := fri.NewVerifier(verifierFS)
	verifier.GrindingBits = cfg.GrindingBits

	p := randomPoly(16)
	if err := committer.Commit("round0", map[string]poly.Polynomial{"f": p}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	proof, err := committer.Prove()
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	// Replace the prover-found nonce with one that almost certainly fails the
	// PoW check. The smallest nonce satisfying 8 zero bits is unlikely to also
	// be the one that's GrindingNonce+1.
	proof.GrindingNonce++

	if err := verifier.Bind("round0", proof.Commitments[0]); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := verifier.VerifyOpening(proof, commitment.LeafHash, commitment.NodeHash); err == nil {
		t.Fatal("VerifyOpening: expected rejection for tampered grinding nonce, got nil")
	}
}

// TestGrindingDisabled confirms grinding is opt-in: with GrindingBits=0 on
// both sides, the proof's GrindingNonce is ignored and round-trip succeeds.
func TestGrindingDisabled(t *testing.T) {
	proverFS, verifierFS := newTestTranscripts()

	committer := fri.NewCommitter(proverFS, testConfig, commitment.LeafHash, commitment.NodeHash)
	verifier := fri.NewVerifier(verifierFS)

	p := randomPoly(16)
	if err := committer.Commit("round0", map[string]poly.Polynomial{"f": p}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	proof, err := committer.Prove()
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	if proof.GrindingNonce != 0 {
		t.Fatalf("GrindingNonce should be 0 when grinding is disabled, got %d", proof.GrindingNonce)
	}

	if err := verifier.Bind("round0", proof.Commitments[0]); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := verifier.VerifyOpening(proof, commitment.LeafHash, commitment.NodeHash); err != nil {
		t.Fatalf("VerifyOpening: %v", err)
	}
}

// TestZeroPolynomial commits a zero polynomial — should succeed (trivially low-degree).
func TestZeroPolynomial(t *testing.T) {
	proverFS, verifierFS := newTestTranscripts()

	committer := fri.NewCommitter(proverFS, testConfig, commitment.LeafHash, commitment.NodeHash)
	verifier := fri.NewVerifier(verifierFS)

	p := zeroPoly(16)
	if err := committer.Commit("round0", map[string]poly.Polynomial{"zero": p}); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	proof, err := committer.Prove()
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	if err := verifier.Bind("round0", proof.Commitments[0]); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := verifier.VerifyOpening(proof, commitment.LeafHash, commitment.NodeHash); err != nil {
		t.Fatalf("VerifyOpening: %v", err)
	}
}

// TestRoundTripNoLayers exercises the 0-layer branch directly: codeword is
// already at or below FinalPolynomialMaxLen so the fold loop never runs and
// the proof's FinalPolynomial is the full DEEP-combined codeword.
func TestRoundTripNoLayers(t *testing.T) {
	proverFS, verifierFS := newTestTranscripts()

	cfg := fri.Config{
		BlowupFactor:          2,
		FoldingFactor:         2,
		FinalPolynomialMaxLen: 8, // base=4 → N=8 → fold guard 8>8 is false
		NumQueries:            2,
	}
	committer := fri.NewCommitter(proverFS, cfg, commitment.LeafHash, commitment.NodeHash)
	verifier := fri.NewVerifier(verifierFS)

	p := randomPoly(4)
	if err := committer.Commit("round0", map[string]poly.Polynomial{"f": p}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	proof, err := committer.Prove()
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}
	if len(proof.LayerCommitments) != 0 {
		t.Fatalf("expected 0 FRI layers, got %d", len(proof.LayerCommitments))
	}
	if len(proof.FinalPolynomial) != 8 {
		t.Fatalf("FinalPolynomial size: want 8, got %d", len(proof.FinalPolynomial))
	}

	if err := verifier.Bind("round0", proof.Commitments[0]); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := verifier.VerifyOpening(proof, commitment.LeafHash, commitment.NodeHash); err != nil {
		t.Fatalf("VerifyOpening: %v", err)
	}
}

// TestNoLayersTamperedFinalPolynomial confirms tampering is still detected
// in the 0-layer branch (where the DEEP quotient check goes directly against
// FinalPolynomial).
func TestNoLayersTamperedFinalPolynomial(t *testing.T) {
	proverFS, verifierFS := newTestTranscripts()

	cfg := fri.Config{
		BlowupFactor:          2,
		FoldingFactor:         2,
		FinalPolynomialMaxLen: 8,
		NumQueries:            2,
	}
	committer := fri.NewCommitter(proverFS, cfg, commitment.LeafHash, commitment.NodeHash)
	verifier := fri.NewVerifier(verifierFS)

	if err := committer.Commit("round0", map[string]poly.Polynomial{"f": randomPoly(4)}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	proof, err := committer.Prove()
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	var one koalabear.Element
	one.SetOne()
	proof.FinalPolynomial[0].Add(&proof.FinalPolynomial[0], &one)

	if err := verifier.Bind("round0", proof.Commitments[0]); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := verifier.VerifyOpening(proof, commitment.LeafHash, commitment.NodeHash); err == nil {
		t.Fatal("VerifyOpening: expected rejection for tampered final polynomial in 0-layer mode")
	}
}

// TestFoldingFactor4 exercises k=4 (between the k=2 default tests and k=8
// loom default).
func TestFoldingFactor4(t *testing.T) {
	proverFS, verifierFS := newTestTranscripts()

	cfg := fri.Config{
		BlowupFactor:          2,
		FoldingFactor:         4,
		FinalPolynomialMaxLen: 4,
		NumQueries:            4,
	}
	committer := fri.NewCommitter(proverFS, cfg, commitment.LeafHash, commitment.NodeHash)
	verifier := fri.NewVerifier(verifierFS)

	p := randomPoly(16) // N=32 → fold to 8 → fold to 2 (stops, 2 < FinalMaxLen=4)
	if err := committer.Commit("round0", map[string]poly.Polynomial{"f": p}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	proof, err := committer.Prove()
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}
	if len(proof.LayerCommitments) < 1 {
		t.Fatalf("expected at least one FRI layer with k=4, got %d", len(proof.LayerCommitments))
	}

	if err := verifier.Bind("round0", proof.Commitments[0]); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := verifier.VerifyOpening(proof, commitment.LeafHash, commitment.NodeHash); err != nil {
		t.Fatalf("VerifyOpening: %v", err)
	}
}

// TestMixedPolySizes commits two polynomials of different base sizes within a
// single Commit call. The encoder pads each to the same codeword domain
// (BlowupFactor · max base size) so the batched Merkle tree is well-formed.
func TestMixedPolySizes(t *testing.T) {
	proverFS, verifierFS := newTestTranscripts()

	committer := fri.NewCommitter(proverFS, testConfig, commitment.LeafHash, commitment.NodeHash)
	verifier := fri.NewVerifier(verifierFS)

	polys := map[string]poly.Polynomial{
		"small": randomPoly(8),
		"big":   randomPoly(16),
	}
	if err := committer.Commit("round0", polys); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	proof, err := committer.Prove()
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}
	if proof.Commitments[0].CodewordDomainSize != 32 { // 2 · max(8,16)
		t.Fatalf("CodewordDomainSize: want 32, got %d", proof.Commitments[0].CodewordDomainSize)
	}

	if err := verifier.Bind("round0", proof.Commitments[0]); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := verifier.VerifyOpening(proof, commitment.LeafHash, commitment.NodeHash); err != nil {
		t.Fatalf("VerifyOpening: %v", err)
	}
}

// TestMaxCodewordDomainSize tests the cross-Commit codeword-size unification:
// two Commit calls with different max polynomial sizes can share one FRI run
// when MaxCodewordDomainSize is set on the Config.
func TestMaxCodewordDomainSize(t *testing.T) {
	proverFS, verifierFS := newTestTranscripts()

	cfg := testConfig
	cfg.MaxCodewordDomainSize = 32 // base 16 · BlowupFactor 2

	committer := fri.NewCommitter(proverFS, cfg, commitment.LeafHash, commitment.NodeHash)
	verifier := fri.NewVerifier(verifierFS)

	if err := committer.Commit("round0", map[string]poly.Polynomial{"a": randomPoly(16)}); err != nil {
		t.Fatalf("Commit round0: %v", err)
	}
	if err := committer.Commit("round1", map[string]poly.Polynomial{"b": randomPoly(8)}); err != nil {
		t.Fatalf("Commit round1: %v", err)
	}
	proof, err := committer.Prove()
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}
	for i, c := range proof.Commitments {
		if c.CodewordDomainSize != 32 {
			t.Fatalf("oracle %d CodewordDomainSize: want 32, got %d", i, c.CodewordDomainSize)
		}
	}

	if err := verifier.Bind("round0", proof.Commitments[0]); err != nil {
		t.Fatalf("Bind round0: %v", err)
	}
	if err := verifier.Bind("round1", proof.Commitments[1]); err != nil {
		t.Fatalf("Bind round1: %v", err)
	}
	if err := verifier.VerifyOpening(proof, commitment.LeafHash, commitment.NodeHash); err != nil {
		t.Fatalf("VerifyOpening: %v", err)
	}
}

// TestDifferentDomainSizesError checks Prove rejects a session where the
// committed oracles disagree on codeword domain size and no override was set.
func TestDifferentDomainSizesError(t *testing.T) {
	proverFS, _ := newTestTranscripts()

	committer := fri.NewCommitter(proverFS, testConfig, commitment.LeafHash, commitment.NodeHash)
	if err := committer.Commit("round0", map[string]poly.Polynomial{"a": randomPoly(16)}); err != nil {
		t.Fatalf("Commit round0: %v", err)
	}
	if err := committer.Commit("round1", map[string]poly.Polynomial{"b": randomPoly(8)}); err != nil {
		t.Fatalf("Commit round1: %v", err)
	}

	if _, err := committer.Prove(); err == nil {
		t.Fatal("Prove: expected error for mismatched codeword domains")
	}
}

// TestOpenUnknownPolynomial checks Open() rejects names that were never
// committed.
func TestOpenUnknownPolynomial(t *testing.T) {
	proverFS, _ := newTestTranscripts()

	committer := fri.NewCommitter(proverFS, testConfig, commitment.LeafHash, commitment.NodeHash)
	if err := committer.Commit("round0", map[string]poly.Polynomial{"f": randomPoly(16)}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	var z koalabear.Element
	z.MustSetRandom()
	if err := committer.Open("ghost", z); err == nil {
		t.Fatal("Open(\"ghost\"): expected error for unregistered polynomial")
	}
}

// TestTamperedOracleMerkleSibling flips a byte in a Merkle sibling for the
// oracle opening — verifier must reject (Merkle root won't match).
func TestTamperedOracleMerkleSibling(t *testing.T) {
	proverFS, verifierFS := newTestTranscripts()

	committer := fri.NewCommitter(proverFS, testConfig, commitment.LeafHash, commitment.NodeHash)
	verifier := fri.NewVerifier(verifierFS)

	if err := committer.Commit("round0", map[string]poly.Polynomial{"f": randomPoly(16)}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	proof, err := committer.Prove()
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	if len(proof.OracleOpenings) == 0 || len(proof.OracleOpenings[0]) == 0 ||
		len(proof.OracleOpenings[0][0].Siblings) == 0 ||
		len(proof.OracleOpenings[0][0].Siblings[0]) == 0 {
		t.Fatal("setup: empty oracle opening Merkle proof")
	}
	proof.OracleOpenings[0][0].Siblings[0][0] ^= 0xFF

	if err := verifier.Bind("round0", proof.Commitments[0]); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := verifier.VerifyOpening(proof, commitment.LeafHash, commitment.NodeHash); err == nil {
		t.Fatal("VerifyOpening: expected rejection for tampered oracle sibling")
	}
}

// TestTamperedLayerMerkleSibling flips a byte in a layer Merkle sibling.
func TestTamperedLayerMerkleSibling(t *testing.T) {
	proverFS, verifierFS := newTestTranscripts()

	committer := fri.NewCommitter(proverFS, testConfig, commitment.LeafHash, commitment.NodeHash)
	verifier := fri.NewVerifier(verifierFS)

	if err := committer.Commit("round0", map[string]poly.Polynomial{"f": randomPoly(16)}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	proof, err := committer.Prove()
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	if len(proof.LayerOpenings) == 0 || len(proof.LayerOpenings[0]) == 0 ||
		len(proof.LayerOpenings[0][0].Siblings) == 0 ||
		len(proof.LayerOpenings[0][0].Siblings[0]) == 0 {
		t.Fatal("setup: empty layer opening Merkle proof")
	}
	proof.LayerOpenings[0][0].Siblings[0][0] ^= 0xFF

	if err := verifier.Bind("round0", proof.Commitments[0]); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := verifier.VerifyOpening(proof, commitment.LeafHash, commitment.NodeHash); err == nil {
		t.Fatal("VerifyOpening: expected rejection for tampered layer sibling")
	}
}

// TestTamperedLayerCommitment mutates a layer Merkle root — this perturbs the
// transcript so re-derived αs and query indices diverge, and the proof is
// rejected.
func TestTamperedLayerCommitment(t *testing.T) {
	proverFS, verifierFS := newTestTranscripts()

	committer := fri.NewCommitter(proverFS, testConfig, commitment.LeafHash, commitment.NodeHash)
	verifier := fri.NewVerifier(verifierFS)

	if err := committer.Commit("round0", map[string]poly.Polynomial{"f": randomPoly(16)}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	proof, err := committer.Prove()
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	if len(proof.LayerCommitments) == 0 || len(proof.LayerCommitments[0]) == 0 {
		t.Fatal("setup: no layer commitments to tamper")
	}
	proof.LayerCommitments[0][0] ^= 0xFF

	if err := verifier.Bind("round0", proof.Commitments[0]); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := verifier.VerifyOpening(proof, commitment.LeafHash, commitment.NodeHash); err == nil {
		t.Fatal("VerifyOpening: expected rejection for tampered layer commitment")
	}
}

// TestTamperedQueryIndex changes one query index — verifier re-derives the
// indices and detects the mismatch.
func TestTamperedQueryIndex(t *testing.T) {
	proverFS, verifierFS := newTestTranscripts()

	committer := fri.NewCommitter(proverFS, testConfig, commitment.LeafHash, commitment.NodeHash)
	verifier := fri.NewVerifier(verifierFS)

	if err := committer.Commit("round0", map[string]poly.Polynomial{"f": randomPoly(16)}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	proof, err := committer.Prove()
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	if len(proof.QueryIndices) == 0 {
		t.Fatal("setup: no query indices")
	}
	proof.QueryIndices[0] ^= 1 // flip the lowest bit; toggles the leaf

	if err := verifier.Bind("round0", proof.Commitments[0]); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := verifier.VerifyOpening(proof, commitment.LeafHash, commitment.NodeHash); err == nil {
		t.Fatal("VerifyOpening: expected rejection for tampered query index")
	}
}

// TestVerifierGrindingMismatch — verifier requires more PoW bits than the
// prover did, so the supplied nonce fails the leading-zero check.
func TestVerifierGrindingMismatch(t *testing.T) {
	proverFS, verifierFS := newTestTranscripts()

	cfg := testConfig
	cfg.GrindingBits = 4 // small target the prover finds easily

	committer := fri.NewCommitter(proverFS, cfg, commitment.LeafHash, commitment.NodeHash)
	verifier := fri.NewVerifier(verifierFS)
	verifier.GrindingBits = 24 // far harder than what the prover satisfied

	if err := committer.Commit("round0", map[string]poly.Polynomial{"f": randomPoly(16)}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	proof, err := committer.Prove()
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	if err := verifier.Bind("round0", proof.Commitments[0]); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := verifier.VerifyOpening(proof, commitment.LeafHash, commitment.NodeHash); err == nil {
		t.Fatal("VerifyOpening: expected rejection when verifier requires more grinding bits than prover")
	}
}

// TestVerifierMissingGrinding — prover used grinding, verifier didn't enable
// it. The transcripts diverge (prover absorbed seed+nonce; verifier didn't),
// and proof validation fails.
func TestVerifierMissingGrinding(t *testing.T) {
	proverFS, verifierFS := newTestTranscripts()

	cfg := testConfig
	cfg.GrindingBits = 4

	committer := fri.NewCommitter(proverFS, cfg, commitment.LeafHash, commitment.NodeHash)
	verifier := fri.NewVerifier(verifierFS) // GrindingBits = 0

	if err := committer.Commit("round0", map[string]poly.Polynomial{"f": randomPoly(16)}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	proof, err := committer.Prove()
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}

	if err := verifier.Bind("round0", proof.Commitments[0]); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := verifier.VerifyOpening(proof, commitment.LeafHash, commitment.NodeHash); err == nil {
		t.Fatal("VerifyOpening: expected rejection when verifier ignores prover grinding")
	}
}

// TestHasLeadingZeroBitsBoundary exercises the bit-counting helper at byte
// boundaries: this is the kind of off-by-one that's easy to get wrong.
func TestHasLeadingZeroBitsBoundary(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		bits int
		want bool
	}{
		{"zero bits trivial", []byte{0xFF}, 0, true},
		{"one zero bit on 0x7F", []byte{0x7F}, 1, true},
		{"one zero bit on 0xFF", []byte{0xFF}, 1, false},
		{"eight zero bits on 0x00", []byte{0x00}, 8, true},
		{"eight zero bits on 0x01", []byte{0x01}, 8, false},
		{"nine zero bits on 0x00, 0x7F", []byte{0x00, 0x7F}, 9, true},
		{"nine zero bits on 0x00, 0xFF", []byte{0x00, 0xFF}, 9, false},
	}
	for _, tc := range cases {
		got := fri.HasLeadingZeroBitsForTest(tc.in, tc.bits)
		if got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
