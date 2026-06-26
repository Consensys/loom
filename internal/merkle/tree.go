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

package merkle

import (
	"fmt"
	"sync"

	"github.com/consensys/loom/internal/hash"
	"github.com/consensys/loom/internal/parallel"
)

// parallelLevelThreshold is the smallest level width (in nodes) at which
// fan-out beats serial bottom-up hashing.
const parallelLevelThreshold = 64

type LeafHash = hash.Digest
type NodeHash = hash.Digest

// NodeHasher combines two child digests into a parent digest.
type NodeHasher interface {
	HashNode(left, right hash.Digest) hash.Digest
}

// BatchNodeHasher is an optional fast path for hashers that can compress
// BatchSize() (left, right) pairs in parallel (e.g. Poseidon2 via the
// 16-lane batched permutation). Tree construction falls back to per-pair
// HashNode for the tail (count < BatchSize()) and for hashers that don't
// implement this interface.
type BatchNodeHasher interface {
	NodeHasher
	BatchSize() int
	HashNodes(dst, left, right []hash.Digest)
}

// LevelInjection adds an extra leaf-hash payload at an internal level of the
// tree. It is the mechanism that lets a single Tree commit to several
// polynomials whose row domains have different sizes: the largest
// polynomial occupies the actual leaves, and each smaller polynomial is
// introduced as an injection at the level whose node count matches its
// number of encoded rows.
//
// Semantics: at the level whose width equals LevelWidth, each running-hash
// node j (j in 0..LevelWidth-1) is replaced by HashNode(running, LeafHashes[j])
// after the standard 2-to-1 compression of the level below. Above this level
// the build proceeds normally with 2-to-1 compression on the post-fold
// digests.
//
// Invariants (enforced by NewWithInjections):
//   - LevelWidth is a positive power of two strictly less than nLeaves.
//   - len(LeafHashes) == LevelWidth.
//   - LevelWidth values across injections are pairwise distinct.
//   - Injections are sorted by *decreasing* LevelWidth (= increasing depth
//     from the leaves), which matches the bottom-up order buildInternalNodes
//     visits levels in.
type LevelInjection struct {
	LevelWidth int
	LeafHashes []hash.Digest
}

// Tree is a binary Merkle tree whose number of leaves is a power of two.
//
// Nodes are stored 1-indexed in a flat slice of length 2*nLeaves:
//   - nodes[1]              = root
//   - nodes[nLeaves..2*nLeaves-1] = leaves (leaf i at nodes[nLeaves+i])
//   - children of node k   = nodes[2k] (left) and nodes[2k+1] (right)
//   - parent of node k     = nodes[k/2]
//
// If the tree was constructed with injections (NewWithInjections), the
// digest stored at any node on an injection level is the post-fold value
// HashNode(standard_2_to_1, LeafHashes[j]). For compact openings, the tree
// also retains the pre-injection running nodes at each injection width.
type Tree struct {
	nodes             []hash.Digest
	nLeaves           int
	nodeHasher        NodeHasher
	injections        []LevelInjection
	preInjectionNodes map[int][]hash.Digest
}

// Proof is an opening proof for a single leaf.
//
// Siblings[0] is the sibling at the leaf level; Siblings[depth-1] is the
// sibling one level below the root.
//
// InjectionLeaves carries, in the same order as the tree's injection
// schedule (decreasing LevelWidth), the injection-leaf digest at the
// position the opening path crosses. It is nil for trees without
// injections.
type Proof struct {
	LeafIdx         int           // 0-based index of the opened leaf
	Siblings        []hash.Digest // sibling digests, leaf-level first
	InjectionLeaves []hash.Digest // injection leaves along the path, one per injection level
}

// New creates a Tree with nLeaves leaves and no injections. nLeaves must be
// a positive power of two.
func New(nLeaves int, nh NodeHasher) (*Tree, error) {
	return NewWithInjections(nLeaves, nh, nil)
}

// NewWithInjections creates a Tree with nLeaves leaves and the supplied
// per-level injection schedule. injections may be nil or empty, in which
// case the tree behaves exactly like one created by New.
func NewWithInjections(nLeaves int, nh NodeHasher, injections []LevelInjection) (*Tree, error) {
	if nLeaves <= 0 || nLeaves&(nLeaves-1) != 0 {
		return nil, fmt.Errorf("merkle: nLeaves must be a positive power of two, got %d", nLeaves)
	}
	if err := validateInjections(nLeaves, injections); err != nil {
		return nil, err
	}
	// Copy the injection slice to insulate the tree from caller mutation.
	var injCopy []LevelInjection
	if len(injections) > 0 {
		injCopy = make([]LevelInjection, len(injections))
		copy(injCopy, injections)
	}
	return &Tree{
		nodes:      make([]hash.Digest, 2*nLeaves),
		nLeaves:    nLeaves,
		nodeHasher: nh,
		injections: injCopy,
	}, nil
}

// validateInjections checks the structural invariants on the injection
// schedule. The injection slice itself is not mutated.
func validateInjections(nLeaves int, injections []LevelInjection) error {
	if len(injections) == 0 {
		return nil
	}
	prevWidth := nLeaves // strict upper bound; injections must be strictly smaller
	for k, inj := range injections {
		w := inj.LevelWidth
		if w <= 0 || w&(w-1) != 0 {
			return fmt.Errorf("merkle: injection[%d].LevelWidth must be a positive power of two, got %d", k, w)
		}
		if w >= nLeaves {
			return fmt.Errorf("merkle: injection[%d].LevelWidth %d must be < nLeaves %d", k, w, nLeaves)
		}
		if w >= prevWidth {
			return fmt.Errorf("merkle: injections must be sorted by decreasing LevelWidth (got %d after %d at index %d)", w, prevWidth, k)
		}
		if len(inj.LeafHashes) != w {
			return fmt.Errorf("merkle: injection[%d] has %d leaf hashes, want LevelWidth=%d", k, len(inj.LeafHashes), w)
		}
		prevWidth = w
	}
	return nil
}

// BuildIthLeaf sets the i-th already-hashed leaf.
func (t *Tree) BuildIthLeaf(leaf hash.Digest, i int) error {
	if i < 0 || i >= t.nLeaves {
		return fmt.Errorf("merkle: leaf index %d out of range [0, %d)", i, t.nLeaves)
	}
	n := t.nLeaves
	t.nodes[n+i] = leaf
	return nil
}

// BuildNodes call this function after all the BuildIthLeaf have been called
func (t *Tree) BuildNodes() error {
	t.buildInternalNodes()
	return nil
}

// Build sets all already-hashed leaves, then builds internal nodes bottom-up.
// len(leaves) must equal nLeaves.
func (t *Tree) Build(leaves []hash.Digest) error {
	if len(leaves) != t.nLeaves {
		return fmt.Errorf("merkle: got %d leaves, want %d", len(leaves), t.nLeaves)
	}
	n := t.nLeaves
	copy(t.nodes[n:], leaves)
	t.buildInternalNodes()
	return nil
}

// batchScratch is the per-worker scratch space used by the SIMD-batched
// node-hashing fast path. Gather/scatter through pooled buffers keeps the
// hot loop free of per-batch heap allocations.
type batchScratch struct{ left, right, dst []hash.Digest }

// buildInternalNodes hashes internal nodes bottom-up, fanning out across
// goroutines once a level is wide enough. Within a level all nodes are
// independent; only the level-to-level walk is serial. When the node hasher
// implements BatchNodeHasher, each level is processed in BatchSize() chunks
// to amortise the SIMD-batched permutation; the tail (count < BatchSize) and
// non-batched hashers fall back to HashNode.
//
// When the tree has injections, each injection level runs an additional
// fold pass after the standard 2-to-1 compression: nodes[start+j] is
// replaced by HashNode(nodes[start+j], injection.LeafHashes[j]). Inputs to
// the fold are contiguous, so it skips the gather scratch entirely.
func (t *Tree) buildInternalNodes() {
	if len(t.injections) == 0 {
		t.preInjectionNodes = nil
	} else {
		t.preInjectionNodes = make(map[int][]hash.Digest, len(t.injections))
	}

	batchHasher, hasBatch := t.nodeHasher.(BatchNodeHasher)
	batchSize := 0
	if hasBatch {
		batchSize = batchHasher.BatchSize()
		if batchSize <= 1 {
			hasBatch = false
		}
	}

	// O(1) injection lookup keyed by level width.
	var injectionByWidth map[int]int
	if len(t.injections) > 0 {
		injectionByWidth = make(map[int]int, len(t.injections))
		for i := range t.injections {
			injectionByWidth[t.injections[i].LevelWidth] = i
		}
	}

	// Per-worker scratch slices for the batched gather/scatter path used by
	// the standard 2-to-1 compression. Allocated once and reused across all
	// levels (a worker takes a buffer for the duration of one level's
	// ExecuteWithThreshold and returns it on completion). The slice header
	// escapes through the BatchNodeHasher interface call, so a pool avoids
	// per-batch heap allocation.
	var scratchPool sync.Pool
	if hasBatch {
		scratchPool.New = func() any {
			return &batchScratch{
				left:  make([]hash.Digest, batchSize),
				right: make([]hash.Digest, batchSize),
				dst:   make([]hash.Digest, batchSize),
			}
		}
	}

	// At each iteration 'start' is the index of the leftmost node on the
	// current level and 'start' nodes live on the level (its width).
	for start := t.nLeaves >> 1; start >= 1; start >>= 1 {
		// Phase 1: standard 2-to-1 compression of children at level
		// (start*2) into level (start).
		if !hasBatch || start < batchSize {
			parallel.ExecuteWithThreshold(start, parallelLevelThreshold, func(lo, hi int) {
				for i := start + lo; i < start+hi; i++ {
					t.nodes[i] = t.nodeHasher.HashNode(t.nodes[2*i], t.nodes[2*i+1])
				}
			})
		} else {
			// Batched fast path. Each goroutine works on a contiguous range
			// of batches; the per-batch gather/scatter goes through pooled
			// scratch buffers so there's no shared contention and no
			// per-batch alloc.
			nbBatches := start / batchSize
			parallel.ExecuteWithThreshold(nbBatches, parallelLevelThreshold/batchSize+1, func(lo, hi int) {
				s := scratchPool.Get().(*batchScratch)
				defer scratchPool.Put(s)
				for b := lo; b < hi; b++ {
					base := start + b*batchSize
					for k := 0; k < batchSize; k++ {
						i := base + k
						s.left[k] = t.nodes[2*i]
						s.right[k] = t.nodes[2*i+1]
					}
					batchHasher.HashNodes(s.dst, s.left, s.right)
					for k := 0; k < batchSize; k++ {
						t.nodes[base+k] = s.dst[k]
					}
				}
			})

			// Tail: nodes beyond the last full batch.
			tail := start - nbBatches*batchSize
			if tail > 0 {
				base := start + nbBatches*batchSize
				for i := base; i < base+tail; i++ {
					t.nodes[i] = t.nodeHasher.HashNode(t.nodes[2*i], t.nodes[2*i+1])
				}
			}
		}

		// Phase 2: if this level has an injection, fold in the per-position
		// injection leaf. Inputs (the running hashes just written and the
		// injection.LeafHashes slice) are both contiguous, so we can pass
		// subslices directly — the Poseidon2 BatchNodeHasher copies its
		// inputs locally, so dst aliasing left is safe.
		if injectionByWidth == nil {
			continue
		}
		injIdx, ok := injectionByWidth[start]
		if !ok {
			continue
		}
		inj := &t.injections[injIdx]

		preInjection := make([]hash.Digest, start)
		copy(preInjection, t.nodes[start:start+start])
		t.preInjectionNodes[start] = preInjection

		if !hasBatch || start < batchSize {
			parallel.ExecuteWithThreshold(start, parallelLevelThreshold, func(lo, hi int) {
				for j := lo; j < hi; j++ {
					t.nodes[start+j] = t.nodeHasher.HashNode(t.nodes[start+j], inj.LeafHashes[j])
				}
			})
			continue
		}
		nbBatches := start / batchSize
		parallel.ExecuteWithThreshold(nbBatches, parallelLevelThreshold/batchSize+1, func(lo, hi int) {
			for b := lo; b < hi; b++ {
				base := b * batchSize
				dst := t.nodes[start+base : start+base+batchSize]
				batchHasher.HashNodes(dst, dst, inj.LeafHashes[base:base+batchSize])
			}
		})
		tail := start - nbBatches*batchSize
		if tail > 0 {
			base := nbBatches * batchSize
			for j := base; j < base+tail; j++ {
				t.nodes[start+j] = t.nodeHasher.HashNode(t.nodes[start+j], inj.LeafHashes[j])
			}
		}
	}
}

// PreInjectionSibling returns the pre-injection running digest of the sibling
// node at the injection level with the supplied width.
//
// pathRowAtWidth is the row index crossed by an opening path at that width;
// the returned digest is for pathRowAtWidth^1. The value exists only after
// Build or BuildNodes on a tree constructed with an injection at levelWidth.
func (t *Tree) PreInjectionSibling(levelWidth int, pathRowAtWidth int) (hash.Digest, error) {
	if levelWidth <= 0 || levelWidth&(levelWidth-1) != 0 {
		return hash.Digest{}, fmt.Errorf("merkle: levelWidth must be a positive power of two, got %d", levelWidth)
	}
	if pathRowAtWidth < 0 || pathRowAtWidth >= levelWidth {
		return hash.Digest{}, fmt.Errorf("merkle: path row %d out of range [0, %d)", pathRowAtWidth, levelWidth)
	}
	nodes, ok := t.preInjectionNodes[levelWidth]
	if !ok {
		return hash.Digest{}, fmt.Errorf("merkle: no pre-injection nodes retained at width %d", levelWidth)
	}
	sibling := pathRowAtWidth ^ 1
	if sibling >= len(nodes) {
		return hash.Digest{}, fmt.Errorf("merkle: sibling row %d out of retained range [0, %d)", sibling, len(nodes))
	}
	return nodes[sibling], nil
}

// Root returns the Merkle root digest. Build must be called first.
func (t *Tree) Root() hash.Digest {
	return t.nodes[1]
}

// OpenProof returns the Merkle opening proof for the leaf at 0-based index idx.
//
// When the tree has injections, Proof.InjectionLeaves contains, in
// decreasing-LevelWidth order (same as the tree's injection schedule), the
// injection-leaf digest at the position the opening path crosses at each
// injection level. The path position at level d (depth d above the leaves)
// is idx >> d.
func (t *Tree) OpenProof(idx int) (Proof, error) {
	if idx < 0 || idx >= t.nLeaves {
		return Proof{}, fmt.Errorf("merkle: leaf index %d out of range [0, %d)", idx, t.nLeaves)
	}
	depth := log2(t.nLeaves)
	siblings := make([]hash.Digest, depth)
	pos := t.nLeaves + idx
	for k := 0; k < depth; k++ {
		siblings[k] = t.nodes[pos^1] // pos^1 flips the last bit to select the sibling
		pos >>= 1
	}

	var injectionLeaves []hash.Digest
	if len(t.injections) > 0 {
		injectionLeaves = make([]hash.Digest, len(t.injections))
		for k, inj := range t.injections {
			// Width w sits at depth d = log2(nLeaves/w) above the leaves.
			d := log2(t.nLeaves / inj.LevelWidth)
			injectionLeaves[k] = inj.LeafHashes[idx>>d]
		}
	}

	return Proof{
		LeafIdx:         idx,
		Siblings:        siblings,
		InjectionLeaves: injectionLeaves,
	}, nil
}

// Verify checks that proof is a valid Merkle opening proof for leaf under
// root. The same node hasher used to build the tree must be supplied. This
// is the legacy signature for trees without injections; it fails if the
// proof carries injection leaves (use VerifyWithInjections instead).
func Verify(root hash.Digest, proof Proof, leaf hash.Digest, nh NodeHasher) bool {
	return VerifyWithInjections(root, proof, leaf, nil, nh)
}

// VerifyWithInjections checks that proof is a valid Merkle opening proof
// for leaf under root, against a tree built with the supplied injection
// schedule.
//
// injectionWidths must list the LevelWidth of each injection in
// decreasing order, identical to the schedule used at construction time.
// proof.InjectionLeaves must have the same length as injectionWidths;
// proof.InjectionLeaves[k] is the injection leaf at the position the path
// crosses on the level whose width is injectionWidths[k].
//
// When injectionWidths is nil/empty, this is equivalent to the standard
// Merkle proof check.
func VerifyWithInjections(root hash.Digest, proof Proof, leaf hash.Digest, injectionWidths []int, nh NodeHasher) bool {
	if len(proof.InjectionLeaves) != len(injectionWidths) {
		return false
	}

	// Map level width -> index into proof.InjectionLeaves for O(1) lookup
	// during the walk up. Also validates the schedule's structural shape.
	var injectionByWidth map[int]int
	if len(injectionWidths) > 0 {
		injectionByWidth = make(map[int]int, len(injectionWidths))
		prevWidth := -1
		for k, w := range injectionWidths {
			if w <= 0 || w&(w-1) != 0 {
				return false
			}
			if prevWidth >= 0 && w >= prevWidth {
				return false
			}
			if _, dup := injectionByWidth[w]; dup {
				return false
			}
			injectionByWidth[w] = k
			prevWidth = w
		}
	}

	h := leaf
	idx := proof.LeafIdx
	// We don't know nLeaves on the verifier side; the depth of the path is
	// len(proof.Siblings). Level width *above* level k (i.e., after k+1
	// transitions) is nLeaves >> (k+1) = 1 << (depth - k - 1).
	depth := len(proof.Siblings)
	for k, sibling := range proof.Siblings {
		if idx&1 == 0 {
			h = nh.HashNode(h, sibling) // current node is the left child
		} else {
			h = nh.HashNode(sibling, h) // current node is the right child
		}
		idx >>= 1

		// After this transition we are at level (k+1) of width
		// 1 << (depth-k-1). If that level has an injection, fold the
		// matching injection leaf in.
		if injectionByWidth != nil {
			width := 1 << (depth - k - 1)
			if injIdx, ok := injectionByWidth[width]; ok {
				h = nh.HashNode(h, proof.InjectionLeaves[injIdx])
			}
		}
	}
	return h == root
}

func log2(n int) int {
	k := 0
	for n > 1 {
		n >>= 1
		k++
	}
	return k
}
