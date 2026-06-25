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
	"github.com/consensys/loom/field"
	fiatshamir "github.com/consensys/loom/internal/fiat-shamir"
	"github.com/consensys/loom/internal/hash"
	"github.com/consensys/loom/internal/poly"
)

// TestOpenShape pins down OpeningProof's structural contract on a small
// fixture matching deep_test.go: two batches at sizes {8, 4}, three
// polynomials total, two distinct shifts at size 8.
//
// What we check:
//   - ClaimedValues mirrors `shifts` shape exactly.
//   - DeepQuotientRoots length == number of distinct native sizes.
//   - FRIProof is structurally populated (non-nil FinalPoly, query count
//     matches Params.NumQueries).
//   - PointSamplings has shape [NumQueries][len(batches)] and each
//     WMerkleProof carries one authenticated RawRowPair per Group of its batch.
func TestOpenShape(t *testing.T) {
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

	committed, openProof, _, _ := runOpenFixture(t, batches, shifts, rate, numQueries)

	// 1- ClaimedValues shape mirrors shifts.
	if got, want := len(openProof.ClaimedValues), len(shifts); got != want {
		t.Fatalf("ClaimedValues outer length = %d, want %d", got, want)
	}
	for b := range shifts {
		if got, want := len(openProof.ClaimedValues[b]), len(shifts[b]); got != want {
			t.Fatalf("ClaimedValues[%d] groups = %d, want %d", b, got, want)
		}
		for g := range shifts[b] {
			gv, gs := openProof.ClaimedValues[b][g], shifts[b][g]
			if got, want := len(gv.Base), len(gs.Base); got != want {
				t.Fatalf("ClaimedValues[%d][%d].Base width = %d, want %d", b, g, got, want)
			}
			if got, want := len(gv.Ext), len(gs.Ext); got != want {
				t.Fatalf("ClaimedValues[%d][%d].Ext width = %d, want %d", b, g, got, want)
			}
			for i := range gs.Base {
				if got, want := len(gv.Base[i]), len(gs.Base[i]); got != want {
					t.Fatalf("ClaimedValues[%d][%d].Base[%d] shifts = %d, want %d", b, g, i, got, want)
				}
			}
			for i := range gs.Ext {
				if got, want := len(gv.Ext[i]), len(gs.Ext[i]); got != want {
					t.Fatalf("ClaimedValues[%d][%d].Ext[%d] shifts = %d, want %d", b, g, i, got, want)
				}
			}
		}
	}

	// 2- One DEEP root per distinct native size {8, 4}.
	if got, want := len(openProof.DeepQuotientRoots), 2; got != want {
		t.Fatalf("DeepQuotientRoots length = %d, want %d", got, want)
	}

	// 3- FRIProof is populated. The DEEP-quotient rail is extension, so
	//    FinalField must be Ext and FinalPolyExt must be non-empty.
	if openProof.FRIProof.FinalField != field.Ext {
		t.Fatalf("FRIProof.FinalField = %s, want %s", openProof.FRIProof.FinalField, field.Ext)
	}
	if len(openProof.FRIProof.FinalPolyExt) == 0 {
		t.Fatal("FRIProof.FinalPolyExt is empty")
	}
	if got, want := len(openProof.FRIProof.FRIQueries), numQueries; got != want {
		t.Fatalf("FRIProof.FRIQueries = %d, want %d", got, want)
	}

	// 4- PointSamplings has [NumQueries][len(batches)] shape; each
	//    WMerkleProof carries one RawRowPair per Group of its batch.
	if got, want := len(openProof.PointSamplings), numQueries; got != want {
		t.Fatalf("PointSamplings outer length = %d, want %d", got, want)
	}
	for q := range openProof.PointSamplings {
		if got, want := len(openProof.PointSamplings[q]), len(batches); got != want {
			t.Fatalf("PointSamplings[%d] length = %d, want %d", q, got, want)
		}
		for b := range openProof.PointSamplings[q] {
			wp := openProof.PointSamplings[q][b]
			wantOpenings := len(committed[b].Sources)
			if got := len(wp.GroupOpenings); got != wantOpenings {
				t.Fatalf("PointSamplings[%d][%d].GroupOpenings = %d, want %d",
					q, b, got, wantOpenings)
			}
			// Top-group row widths must match the batch's top Group.
			top := wp.GroupOpenings[0].Rows.Lo
			topGroup := batches[b][0] // single-group batch in this fixture
			if got, want := len(top.RawRowBase), len(topGroup.Base); got != want {
				t.Fatalf("PointSamplings[%d][%d].RawRowBase width = %d, want %d",
					q, b, got, want)
			}
			if got, want := len(top.RawRowExt), len(topGroup.Ext); got != want {
				t.Fatalf("PointSamplings[%d][%d].RawRowExt width = %d, want %d",
					q, b, got, want)
			}
		}
	}
}

// TestOpenFRIVerifyRoundtrip exercises the strongest roundtrip available
// before PR6 lands Verify: rebuild the prover's transcript state up to
// the point where fri.Prove was invoked (bind tree roots, sample zeta,
// register + bind claimed values, sample alpha_DEEP), then call
// fri.Verify on the OpeningProof's FRI proof against the returned
// DeepQuotientRoots. The roundtrip succeeds iff Open's transcript
// bindings and FRI invocation match the public fri.Verify spec.
func TestOpenFRIVerifyRoundtrip(t *testing.T) {
	const rate uint64 = 2
	const numQueries = 4

	batches := []Batch{
		{{
			Base: []poly.Polynomial{
				{baseElement(2), baseElement(3), baseElement(5), baseElement(7),
					baseElement(11), baseElement(13), baseElement(17), baseElement(19)},
			},
		}},
		{{
			Base: []poly.Polynomial{
				{baseElement(21), baseElement(23), baseElement(29), baseElement(31)},
			},
		}},
	}
	shifts := []BatchShifts{
		{{Base: [][]int{{0, 1}}}},
		{{Base: [][]int{{0}}}},
	}

	committed, openProof, params, zeta := runOpenFixture(t, batches, shifts, rate, numQueries)

	// Rebuild a verifier-side transcript replaying the same bindings as
	// the prover did up to (but not including) fri.Prove. We only need
	// to mirror what Open does internally before delegating to FRI.
	verifierFS := freshTranscriptForTest()

	// Same external setup the prover did via runOpenFixture: register
	// "test_zeta", bind every committed[b].Tree.Root() to it, then
	// sample zeta.
	if err := verifierFS.NewChallenge(testZetaName); err != nil {
		t.Fatal(err)
	}
	for _, c := range committed {
		root := c.Tree.Root()
		if err := verifierFS.Bind(testZetaName, root[:]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := verifierFS.ComputeChallenge(testZetaName); err != nil {
		t.Fatal(err)
	}

	// Replay Open's internal bindings: alpha_DEEP registration, claimed
	// values bound in canonical order, sample alpha_DEEP.
	if err := verifierFS.NewChallenge(deepAlphaName); err != nil {
		t.Fatal(err)
	}
	lay, err := canonicalLayout(batches, shifts)
	if err != nil {
		t.Fatal(err)
	}
	if err := bindClaimedValuesInLayoutOrder(verifierFS, openProof.ClaimedValues, shifts, lay); err != nil {
		t.Fatal(err)
	}
	if _, err := verifierFS.ComputeChallenge(deepAlphaName); err != nil {
		t.Fatal(err)
	}

	// sizesDesc is just the set of distinct group sizes in descending
	// order -- the same enumeration Open used to build FRI levels.
	sizesDesc := distinctSizesDescending(batches)
	if got := len(openProof.DeepQuotientRoots); got != len(sizesDesc) {
		t.Fatalf("DeepQuotientRoots = %d, sizesDesc = %d", got, len(sizesDesc))
	}

	if err := Verify(params, openProof.DeepQuotientRoots, sizesDesc, openProof.FRIProof, verifierFS); err != nil {
		t.Fatalf("fri.Verify: %v", err)
	}

	_ = zeta // silence unused
}

// TestOpenRejectsCommitOnlyPCS confirms Open errors out when the PCS was
// built via NewPCS (no Params) -- only NewPCSWithParams supports Open.
func TestOpenRejectsCommitOnlyPCS(t *testing.T) {
	batches := []Batch{
		{{Base: []poly.Polynomial{
			{baseElement(1), baseElement(2), baseElement(3), baseElement(4)},
		}}},
	}
	shifts := []BatchShifts{
		{{Base: [][]int{{0}}}},
	}

	pcs := NewPCS(2, DefaultLeafHasher, DefaultNodeHasher)
	committed, err := pcs.Commit(batches[0])
	if err != nil {
		t.Fatal(err)
	}
	fs := freshTranscriptForTest()
	_, err = pcs.Open(batches, []Committed{committed}, shifts, ext.E6{}, fs)
	if err == nil {
		t.Fatal("expected Open to reject a PCS without Params")
	}
}

// TestOpenRejectsShapeMismatch confirms Open propagates the canonical-
// layout shape-mismatch errors from PR2 (top-level batches/shifts length
// mismatch in this case; per-poly invariants are exhaustively tested in
// layout_test.go / values_test.go).
func TestOpenRejectsShapeMismatch(t *testing.T) {
	batches := []Batch{
		{{Base: []poly.Polynomial{{baseElement(1), baseElement(2), baseElement(3), baseElement(4)}}}},
	}
	shifts := []BatchShifts{
		{{Base: [][]int{{0}}}},
		{}, // extra
	}

	params, err := NewParams(8, 4, 4, DefaultLeafHasher, DefaultNodeHasher)
	if err != nil {
		t.Fatal(err)
	}
	pcs := NewPCSWithParams(params)
	committed, err := pcs.Commit(batches[0])
	if err != nil {
		t.Fatal(err)
	}
	fs := freshTranscriptForTest()
	if _, err := pcs.Open(batches, []Committed{committed}, shifts, ext.E6{}, fs); err == nil {
		t.Fatal("expected Open to reject shape-mismatched inputs")
	}
}

// runOpenFixture is the shared test setup: builds Params, instantiates a
// PCS, commits every batch, binds tree roots to a fresh transcript and
// samples zeta, calls Open, returns everything the caller might want to
// inspect.
func runOpenFixture(
	t *testing.T,
	batches []Batch,
	shifts []BatchShifts,
	rate uint64,
	numQueries int,
) ([]Committed, OpeningProof, Params, ext.E6) {
	t.Helper()

	maxN := 0
	for _, b := range batches {
		for _, g := range b {
			N, err := groupNativeSize(g)
			if err != nil {
				t.Fatal(err)
			}
			if N > maxN {
				maxN = N
			}
		}
	}

	params, err := NewParams(int(rate)*maxN, maxN, numQueries, DefaultLeafHasher, DefaultNodeHasher)
	if err != nil {
		t.Fatal(err)
	}
	pcs := NewPCSWithParams(params)

	var domainCache poly.DomainCache
	committed := make([]Committed, len(batches))
	for b := range batches {
		c, err := pcs.Commit(batches[b], WithDomainCache(&domainCache))
		if err != nil {
			t.Fatalf("Commit(batches[%d]): %v", b, err)
		}
		committed[b] = c
	}

	// Minimal outer-protocol transcript activity: register "test_zeta",
	// bind every tree root, sample zeta.
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
	zetaOut, err := fs.ComputeChallenge(testZetaName)
	if err != nil {
		t.Fatal(err)
	}
	zeta := hash.OutputToExt(zetaOut)

	openProof, err := pcs.Open(batches, committed, shifts, zeta, fs, WithOpenDomainCache(&domainCache))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return committed, openProof, params, zeta
}

// distinctSizesDescending mirrors what computeDeepQuotientCodewords
// returns as sizesDesc -- needed by the caller of fri.Verify, which
// must know the level Ds independently of the proof.
func distinctSizesDescending(batches []Batch) []int {
	seen := map[int]struct{}{}
	for _, b := range batches {
		for _, g := range b {
			N, _ := groupNativeSize(g)
			seen[N] = struct{}{}
		}
	}
	out := make([]int, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	// Insertion sort descending; tiny n.
	for i := 1; i < len(out); i++ {
		j := i
		for j > 0 && out[j] > out[j-1] {
			out[j], out[j-1] = out[j-1], out[j]
			j--
		}
	}
	return out
}

// Test-only constants and helpers shared between Open tests.
const testZetaName = "test_zeta"

func freshTranscriptForTest() *fiatshamir.Transcript {
	hasher := hash.NewPoseidon2SpongeHasher()
	return fiatshamir.NewTranscript(&hasher)
}

// Silence unused import warning when only a subset of tests references
// field.Kind via canonicalLayout indirection.
var _ = field.Base
