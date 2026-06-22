// Copyright Consensys Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package fri

import (
	"testing"

	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	fiatshamir "github.com/consensys/loom/internal/fiat-shamir"
	"github.com/consensys/loom/internal/hash"
	"github.com/consensys/loom/internal/poly"
)

// TestPCSVerifyRoundtrip is the full Open + Verify roundtrip on a small
// fixture matching deep_test.go / open_test.go: two batches at sizes
// {8, 4}, three polynomials, two distinct shifts at size 8.
//
// Verify must accept the OpeningProof produced by Open when the
// verifier-side transcript was driven through the same external pre-Open
// activity (register zeta, bind roots, sample zeta).
func TestPCSVerifyRoundtrip(t *testing.T) {
	batches, shifts, committed, openProof, params, zeta := buildVerifyFixture(t)

	roots, shapes := rootsAndShapes(committed)
	verifierFS := buildVerifierTranscript(t, committed)

	pcs := NewPCSWithParams(params)
	if err := pcs.Verify(roots, shapes, shifts, zeta, openProof, verifierFS); err != nil {
		t.Fatalf("PCS.Verify rejected a valid OpeningProof: %v", err)
	}
	_ = batches // exercised via openProof
}

// TestPCSVerifyRejectsTamperedClaimedValue confirms Verify fails when
// any claimed value is flipped after Open. The break can manifest as
// either the FRI proof failing (because alpha_DEEP changes) or the
// bridge check failing -- both are correct rejections.
func TestPCSVerifyRejectsTamperedClaimedValue(t *testing.T) {
	_, shifts, committed, openProof, params, zeta := buildVerifyFixture(t)

	// Flip the first claimed value of batch 0's first base poly at the
	// first shift.
	openProof.ClaimedValues[0][0].Base[0][0].B0.A0.SetUint64(0xdeadbeef)

	roots, shapes := rootsAndShapes(committed)
	verifierFS := buildVerifierTranscript(t, committed)

	pcs := NewPCSWithParams(params)
	if err := pcs.Verify(roots, shapes, shifts, zeta, openProof, verifierFS); err == nil {
		t.Fatal("PCS.Verify accepted a proof with a tampered claimed value")
	}
}

// TestPCSVerifyRejectsTamperedRoot confirms Verify fails when one of
// the batch commitments has its root replaced. The break manifests as
// the Merkle-path check for that batch failing.
func TestPCSVerifyRejectsTamperedRoot(t *testing.T) {
	_, shifts, committed, openProof, params, zeta := buildVerifyFixture(t)

	roots, shapes := rootsAndShapes(committed)
	// Corrupt the first byte of batch 0's root.
	roots[0][0].SetUint64(0xdeadbeef)

	verifierFS := buildVerifierTranscript(t, committed)

	pcs := NewPCSWithParams(params)
	if err := pcs.Verify(roots, shapes, shifts, zeta, openProof, verifierFS); err == nil {
		t.Fatal("PCS.Verify accepted a proof against a tampered root")
	}
}

// TestPCSVerifyRejectsTamperedRawLeaf confirms Verify fails when one of
// the raw leaves in PointSamplings is flipped. The break manifests as
// the Merkle-path authentication failing for that (query, batch).
func TestPCSVerifyRejectsTamperedRawLeaf(t *testing.T) {
	_, shifts, committed, openProof, params, zeta := buildVerifyFixture(t)

	// Flip the first base raw leaf of the first query, first batch.
	openProof.PointSamplings[0][0].InjectionRawLeaves[0].RawLeafBase[0][0].SetUint64(0xdeadbeef)

	roots, shapes := rootsAndShapes(committed)
	verifierFS := buildVerifierTranscript(t, committed)

	pcs := NewPCSWithParams(params)
	if err := pcs.Verify(roots, shapes, shifts, zeta, openProof, verifierFS); err == nil {
		t.Fatal("PCS.Verify accepted a proof with a tampered raw leaf")
	}
}

// TestPCSVerifyRejectsCommitOnlyPCS confirms Verify errors out when
// invoked on a PCS that was built without Params.
func TestPCSVerifyRejectsCommitOnlyPCS(t *testing.T) {
	_, shifts, committed, openProof, _, zeta := buildVerifyFixture(t)

	roots, shapes := rootsAndShapes(committed)
	fs := freshTranscriptForTest()

	commitOnly := NewPCS(2, DefaultLeafHasher, DefaultNodeHasher)
	if err := commitOnly.Verify(roots, shapes, shifts, zeta, openProof, fs); err == nil {
		t.Fatal("expected Verify to reject a PCS without Params")
	}
}

// TestPCSVerifyShapeMismatch exercises the top-level length-alignment
// rejections. Per-poly invariants (empty / duplicate shift lists) are
// covered by layout_test.go.
func TestPCSVerifyShapeMismatch(t *testing.T) {
	_, shifts, committed, openProof, params, zeta := buildVerifyFixture(t)
	roots, shapes := rootsAndShapes(committed)
	pcs := NewPCSWithParams(params)

	t.Run("roots length mismatch", func(t *testing.T) {
		fs := buildVerifierTranscript(t, committed)
		// One extra root.
		bad := append([]hash.Digest{}, roots...)
		bad = append(bad, hash.Digest{})
		if err := pcs.Verify(bad, shapes, shifts, zeta, openProof, fs); err == nil {
			t.Fatal("expected roots-length mismatch error")
		}
	})

	t.Run("shifts length mismatch", func(t *testing.T) {
		fs := buildVerifierTranscript(t, committed)
		bad := append([]BatchShifts{}, shifts...)
		bad = append(bad, BatchShifts{})
		if err := pcs.Verify(roots, shapes, bad, zeta, openProof, fs); err == nil {
			t.Fatal("expected shifts-length mismatch error")
		}
	})

	t.Run("ClaimedValues length mismatch", func(t *testing.T) {
		fs := buildVerifierTranscript(t, committed)
		tampered := openProof
		tampered.ClaimedValues = append([]BatchClaimedValues{}, openProof.ClaimedValues...)
		tampered.ClaimedValues = append(tampered.ClaimedValues, nil)
		if err := pcs.Verify(roots, shapes, shifts, zeta, tampered, fs); err == nil {
			t.Fatal("expected ClaimedValues-length mismatch error")
		}
	})
}

// buildVerifyFixture sets up the standard Open fixture and returns
// everything needed to drive Verify.
func buildVerifyFixture(t *testing.T) (
	[]Batch, []BatchShifts, []Committed, OpeningProof, Params, ext.E6,
) {
	t.Helper()
	const rate uint64 = 2
	const numQueries = 4

	batches := []Batch{
		{{
			Base: []poly.Polynomial{
				{baseElement(2), baseElement(3), baseElement(5), baseElement(7),
					baseElement(11), baseElement(13), baseElement(17), baseElement(19)},
			},
			Ext: []poly.ExtPolynomial{
				{
					extElement(101, 102, 103, 104),
					extElement(201, 202, 203, 204),
					extElement(301, 302, 303, 304),
					extElement(401, 402, 403, 404),
					extElement(501, 502, 503, 504),
					extElement(601, 602, 603, 604),
					extElement(701, 702, 703, 704),
					extElement(801, 802, 803, 804),
				},
			},
		}},
		{{
			Base: []poly.Polynomial{
				{baseElement(21), baseElement(23), baseElement(29), baseElement(31)},
			},
		}},
	}
	shifts := []BatchShifts{
		{{Base: [][]int{{0, 1}}, Ext: [][]int{{0}}}},
		{{Base: [][]int{{0}}}},
	}

	committed, openProof, params, zeta := runOpenFixture(t, batches, shifts, rate, numQueries)
	return batches, shifts, committed, openProof, params, zeta
}

// rootsAndShapes derives the verifier-side `roots` and `shapes` inputs
// from the per-batch Committed blobs the prover holds. In production
// callers, the outer protocol assembles these (setup roots from a
// verification key, witness roots from the proof).
func rootsAndShapes(committed []Committed) ([]hash.Digest, [][]GroupShape) {
	roots := make([]hash.Digest, len(committed))
	shapes := make([][]GroupShape, len(committed))
	for b, c := range committed {
		roots[b] = c.Tree.Root()
		shapes[b] = append([]GroupShape{}, c.Tree.Groups()...)
	}
	return roots, shapes
}

// buildVerifierTranscript re-runs the exact pre-Open transcript activity
// the prover did via runOpenFixture: register "test_zeta", bind every
// committed tree root, sample zeta. Leaves the transcript in the state
// PCS.Verify expects.
func buildVerifierTranscript(t *testing.T, committed []Committed) *fiatshamir.Transcript {
	t.Helper()
	fs := freshTranscriptForTest()
	if err := fs.NewChallenge(testZetaName); err != nil {
		t.Fatal(err)
	}
	for _, c := range committed {
		root := c.Tree.Root()
		if err := fs.Bind(testZetaName, root[:]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := fs.ComputeChallenge(testZetaName); err != nil {
		t.Fatal(err)
	}
	return fs
}
