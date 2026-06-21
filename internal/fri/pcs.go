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
	"fmt"

	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/loom/internal/hash"
)

// PCS is a batch polynomial commitment scheme built on top of RSCommit and
// multi-degree FRI. It is the entry point intended to subsume direct use of
// RSCommit and the prover-side DEEP/FRI machinery: callers Commit each
// independent batch of polynomials, bind the returned root to their
// transcript at the appropriate Fiat-Shamir round, and (in a later PR)
// hand the whole list to Open at zeta to produce one OpeningProof.
//
// PCS keeps no global state across Commit calls -- the per-batch Committed
// blob carries the Merkle tree and the per-Group RS-encoded LeafSources
// that Open will later consume.
//
// The current PR exposes only Commit. Later PRs will extend PCS with
// multi-degree FRI parameters needed by Open / Verify.
type PCS struct {
	leafHasher LeafHasher
	nodeHasher NodeHasher
	rate       uint64
}

// NewPCS constructs a PCS bound to a Reed-Solomon blowup factor (rate) and
// the leaf/node hashers used at every Merkle tree level. Open / Verify
// will be added in subsequent PRs and will need additional FRI parameters
// supplied at that time.
func NewPCS(rate uint64, leafHasher LeafHasher, nodeHasher NodeHasher) PCS {
	return PCS{
		leafHasher: leafHasher,
		nodeHasher: nodeHasher,
		rate:       rate,
	}
}

// Committed is the per-batch prover-side blob returned by Commit. Tree
// carries the Merkle root the caller binds to its transcript; Sources
// retains, per Group in decreasing-size order, the RS-encoded paired
// evaluations Open will need to build the DEEP quotient and to open the
// committed polynomials at FRI query positions.
type Committed struct {
	Tree    WMerkleTree
	Sources []LeafSource
}

// GroupShifts assigns a list of rotation shifts to each polynomial of a
// Group. Base[i] is the shift list for the i-th base polynomial of the
// Group; Ext[i] is the shift list for the i-th extension polynomial.
//
// A shift s means the polynomial is opened at zeta * omega_N^s where
// omega_N is the generator of the polynomial's native size-N domain (the
// Group's size). Shift lists must be non-empty and contain no duplicates;
// the future Open / Verify will reject inputs violating either rule.
type GroupShifts struct {
	Base [][]int
	Ext  [][]int
}

// BatchShifts gives, for every Group in a Batch (in declaration order),
// the per-polynomial shift list. Shape must align with the corresponding
// Batch: same number of Groups, same Base/Ext widths per Group.
type BatchShifts = []GroupShifts

// GroupClaimedValues holds the claimed polynomial evaluations produced by
// Open for one Group of one Batch. The shape mirrors the matching
// GroupShifts exactly:
//   - Base[i][k] is the claimed value of the i-th base polynomial at
//     zeta * omega_N^shifts.Base[i][k];
//   - Ext[i][k] is the claimed value of the i-th extension polynomial at
//     zeta * omega_N^shifts.Ext[i][k].
type GroupClaimedValues struct {
	Base [][]ext.E6
	Ext  [][]ext.E6
}

// BatchClaimedValues is one GroupClaimedValues per Group of a Batch.
type BatchClaimedValues = []GroupClaimedValues

// OpeningProof bundles everything Verify needs to convince the verifier
// that every polynomial in every committed Batch evaluates to the listed
// ClaimedValues at zeta times the requested rotation shifts.
//
//   - ClaimedValues[b] is the GroupClaimedValues slice for batches[b], in
//     the same order Open / Verify received batches and shifts.
//   - DeepQuotientRoots is one Merkle root per distinct native size in
//     decreasing size order (same order as the FRI levels).
//   - FRIProof is the multi-degree FRI proof on the DEEP-quotient
//     codewords.
//   - PointSamplings[q][b] is the WMerkleProof opening batches[b] at the
//     q-th FRI query position. Each WMerkleProof carries one RawLeaf per
//     Group of the batch in decreasing-size order (matches the tree's
//     injection schedule).
//
// All fields default to nil/empty; PR1 only declares the type. Open is
// added in a later PR.
type OpeningProof struct {
	ClaimedValues     []BatchClaimedValues
	DeepQuotientRoots []hash.Digest
	FRIProof          Proof
	PointSamplings    [][]WMerkleProof
}

// Commit commits to one Batch of polynomials and returns the per-batch
// prover-side blob. The current implementation is a thin wrapper over
// RSCommit; PCS keeps no state across Commit calls -- callers stash one
// Committed per Commit invocation and (in a later PR) hand the whole
// slice to Open.
//
// The caller is responsible for binding committed.Tree.Root() to the
// shared Fiat-Shamir transcript at the appropriate round before invoking
// Open: Commit does not bind anything itself.
func (pcs *PCS) Commit(batch Batch, opts ...CommitOption) (Committed, error) {
	if len(batch) == 0 {
		return Committed{}, fmt.Errorf("PCS.Commit: empty batch")
	}
	// The transient RSCommit's primary Encoder is just a fast path for
	// whichever Group happens to share its size; encoderForSize handles
	// every other size on the fly. We seed it with the first Group's
	// size so the single-group hot path matches the legacy direct-
	// RSCommit call site exactly.
	primaryN, err := groupNativeSize(batch[0])
	if err != nil {
		return Committed{}, fmt.Errorf("PCS.Commit: batch[0]: %w", err)
	}
	rs := NewRSCommit(uint64(primaryN), pcs.rate, pcs.leafHasher, pcs.nodeHasher)
	tree, sources, err := rs.Commit(batch, opts...)
	if err != nil {
		return Committed{}, err
	}
	return Committed{Tree: tree, Sources: sources}, nil
}
