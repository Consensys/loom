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
	"sort"

	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/loom/internal/hash"
	"github.com/consensys/loom/internal/merkle"
	"github.com/consensys/loom/internal/parallel"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/internal/reedsolomon"
)

const (
	leafDomainTag uint64 = 0x4c454146 // "LEAF"
	nodeDomainTag uint64 = 0x4e4f4445 // "NODE"
)

type LeafHash = hash.Digest
type NodeHash = hash.Digest

type LeafHasher interface {
	HashLeaf(base []koalabear.Element, ext []ext.E6) hash.Digest
}

// LeafSource describes the encoded column-oriented data used to build Merkle
// leaves. Leaf i absorbs one row value at i for every base and extension
// polynomial.
type LeafSource struct {
	Base []poly.Polynomial
	Ext  []poly.ExtPolynomial
}

// BatchLeafHasher hashes a consecutive range of leaves into dst. HashLeaf
// remains the compatibility path and the source of truth for single-leaf
// verifier checks.
type BatchLeafHasher interface {
	LeafHasher
	BatchSize() int
	HashLeaves(dst []hash.Digest, src LeafSource, start int)
}

type NodeHasher interface {
	HashNode(left, right hash.Digest) hash.Digest
}

type Poseidon2LeafHasher struct{}

type Poseidon2NodeHasher struct{}

var (
	DefaultLeafHasher Poseidon2LeafHasher
	DefaultNodeHasher Poseidon2NodeHasher
)

type RSCommit struct {
	// Encoder is the Reed-Solomon encoder built for the size N passed to
	// NewRSCommit / NewRSCommitWithDomainCache. It is reused inside Commit
	// whenever a group's size matches it; groups of any other size build a
	// fresh encoder on the fly (using rate). Kept exported for back-compat
	// with code that reads Encoder.Domain.Cardinality.
	Encoder    reedsolomon.Encoder
	LeafHasher LeafHasher
	NodeHasher NodeHasher

	// rate is the RS blowup factor (encoded domain size = rate * N).
	rate uint64
}

// Group bundles base- and extension-rail polynomials that share the same
// native size. A single Commit call accepts a slice of Groups, each with a
// distinct size: the largest group occupies the actual Merkle leaves and
// each smaller group becomes a per-level injection in the underlying
// merkle.Tree (see internal/merkle/tree.go).
type Group struct {
	Base []poly.Polynomial
	Ext  []poly.ExtPolynomial
}

// GroupShape records the per-group layout of a committed tree, in
// decreasing-size order (groups[0] is the largest, hashed at the actual
// leaves; groups[1..] are injection levels). PairedLeaves is the number of
// paired Merkle positions at this group's level, i.e. ρ · N_native / 2.
type GroupShape struct {
	PairedLeaves int
	BaseWidth    int
	ExtWidth     int
}

// BatchShapes gives, for every Group in a Batch (in declaration order),
// the per-group shape list.
type BatchShapes = []GroupShape

type WMerkleTree struct {
	Tree *merkle.Tree

	// groups in decreasing PairedLeaves order. Length 1 for the typical
	// single-size Commit call; length > 1 when multiple sizes were committed
	// into one tree via merkle injections.
	groups BatchShapes
}

// RawLeaf holds one encoded row for one Group of the committed tree: one base
// value per base-rail polynomial and one extension value per extension-rail
// polynomial, in declaration order. Hashing a RawLeaf with
// LeafHasher.HashLeaf reproduces the digest that lives at the matching
// position in the Merkle tree (either the leaf-level digest for the top
// group or one of merkle.Proof.InjectionLeaves for the smaller groups).
type RawLeaf struct {
	RawLeafBase []koalabear.Element
	RawLeafExt  []ext.E6
}

// WMerkleProof is an opening proof for a WMerkleTree at one query position.
// InjectionRawLeaves carries the raw pair evaluations needed to reconstruct
// the digests that Proof authenticates: one RawLeaf per Group of the
// committed tree, in the same decreasing-size order used by
// WMerkleTree.Groups().
//
// Specifically:
//   - InjectionRawLeaves[0]    is the top group; its HashLeaf digest is the
//     leaf at position Proof.LeafIdx that starts the standard Merkle path
//     encoded in Proof.Siblings.
//   - InjectionRawLeaves[k>0] corresponds to the (k-1)-th smaller group;
//     its HashLeaf digest must match Proof.InjectionLeaves[k-1].
//
// In the current single-group call path the slice has length 1 and Proof
// has no InjectionLeaves. When multi-size Commit calls are wired through,
// each smaller group contributes one additional RawLeaf and one matching
// digest in Proof.InjectionLeaves.
type WMerkleProof struct {
	InjectionRawLeaves []RawLeaf
	Proof              merkle.Proof
}

func (wt WMerkleTree) Root() hash.Digest {
	return wt.Tree.Root()
}

// NumLeaves returns the number of paired leaves of the top (largest) group.
// For trees committed with several sizes, smaller groups live at higher
// levels and their per-group widths are accessible via Groups.
func (wt WMerkleTree) NumLeaves() int {
	if len(wt.groups) == 0 {
		return 0
	}
	return wt.groups[0].PairedLeaves
}

// BaseWidth returns the number of base-field pairs in the top group.
func (wt WMerkleTree) BaseWidth() int {
	if len(wt.groups) == 0 {
		return 0
	}
	return wt.groups[0].BaseWidth
}

// ExtWidth returns the number of extension-field pairs in the top group.
func (wt WMerkleTree) ExtWidth() int {
	if len(wt.groups) == 0 {
		return 0
	}
	return wt.groups[0].ExtWidth
}

// Groups returns the per-group shape descriptors in decreasing-size order
// (groups[0] is the top / largest group). The returned slice is owned by
// the tree; callers must not mutate it.
func (wt WMerkleTree) Groups() BatchShapes {
	return wt.groups
}

// InjectionWidths returns the LevelWidth of each merkle injection in the
// same order as the tree's injection schedule (decreasing widths). It is
// nil for single-group trees. Suitable for passing to
// merkle.VerifyWithInjections.
func (wt WMerkleTree) InjectionWidths() []int {
	if len(wt.groups) <= 1 {
		return nil
	}
	res := make([]int, len(wt.groups)-1)
	for i := range res {
		res[i] = wt.groups[i+1].PairedLeaves
	}
	return res
}

// OpenProof returns the Merkle proof for leaf i. Raw leaf values are
// reconstructed by the prover from the committed polynomials when needed.
// For multi-group trees the returned proof carries InjectionLeaves matching
// InjectionWidths.
func (wt WMerkleTree) OpenProof(i int) (merkle.Proof, error) {
	return wt.Tree.OpenProof(i)
}

func NewRSCommit(N uint64, rate uint64, leafHasher LeafHasher, nodehasher NodeHasher) RSCommit {
	return NewRSCommitWithDomainCache(N, rate, leafHasher, nodehasher, nil)
}

// NewRSCommitWithDomainCache constructs an RSCommit using cache for the
// Reed-Solomon encoder domain. N is the natural size used to seed the
// reusable Encoder; Commit can still accept groups of other sizes by
// building fresh encoders from rate on the fly.
func NewRSCommitWithDomainCache(N uint64, rate uint64, leafHasher LeafHasher, nodehasher NodeHasher, cache *poly.DomainCache) RSCommit {
	rsEncoder := reedsolomon.NewEncoder(rate*N, reedsolomon.WithCache(cache))
	return RSCommit{
		Encoder:    rsEncoder,
		LeafHasher: leafHasher,
		NodeHasher: nodehasher,
		rate:       rate,
	}
}

// CommitConfig configures RSCommit.Commit.
type CommitConfig struct {
	DomainCache *poly.DomainCache
}

// CommitOption configures RSCommit.Commit.
type CommitOption func(c *CommitConfig) error

// WithDomainCache reuses cache for input-polynomial FFT domains.
func WithDomainCache(cache *poly.DomainCache) CommitOption {
	return func(c *CommitConfig) error {
		c.DomainCache = cache
		return nil
	}
}

func (Poseidon2LeafHasher) HashLeaf(base []koalabear.Element, ext []ext.E6) hash.Digest {
	h := hash.NewPoseidon2SpongeHasher()
	h.WriteElements(hash.NewElement(leafDomainTag), hash.NewElement(uint64(len(base))), hash.NewElement(uint64(len(ext))))
	for _, v := range base {
		h.WriteElements(v)
	}
	for _, v := range ext {
		h.WriteExt(v)
	}
	return h.Sum()
}

func (lh Poseidon2LeafHasher) HashLeaves(dst []hash.Digest, src LeafSource, start int) {
	if len(dst) < hash.Poseidon2SpongeBatchSize {
		hashLeavesScalar(lh, dst, src, start)
		return
	}

	fullBatches := len(dst) / hash.Poseidon2SpongeBatchSize
	for batch := 0; batch < fullBatches; batch++ {
		offset := batch * hash.Poseidon2SpongeBatchSize
		lh.hashLeavesBatch16(dst[offset:offset+hash.Poseidon2SpongeBatchSize], src, start+offset)
	}
	if tail := fullBatches * hash.Poseidon2SpongeBatchSize; tail < len(dst) {
		hashLeavesScalar(lh, dst[tail:], src, start+tail)
	}
}

func (Poseidon2LeafHasher) BatchSize() int {
	return hash.Poseidon2SpongeBatchSize
}

func (Poseidon2NodeHasher) HashNode(left, right hash.Digest) hash.Digest {
	return hash.Poseidon2NodeCompress(nodeDomainTag, left, right)
}

// BatchSize is the lane width of the SIMD-batched Poseidon2 permutation.
func (Poseidon2NodeHasher) BatchSize() int { return hash.Poseidon2SpongeBatchSize }

// HashNodes compresses BatchSize() (left, right) pairs in one batched
// permutation. dst, left, right must all have length BatchSize().
func (Poseidon2NodeHasher) HashNodes(dst, left, right []hash.Digest) {
	const n = hash.Poseidon2SpongeBatchSize
	if len(dst) != n || len(left) != n || len(right) != n {
		panic("Poseidon2NodeHasher.HashNodes: input slices must have length BatchSize()")
	}
	var l, r [n]hash.Digest
	copy(l[:], left)
	copy(r[:], right)
	out := hash.Poseidon2NodeCompressBatch16(nodeDomainTag, &l, &r)
	copy(dst, out[:])
}

// Batch list of Group, one Group = one list of polynomials of the same size
type Batch = []Group

// Commit commits to one or more Groups of polynomials into a single Merkle
// tree. Each Group in batch must hold polynomials sharing a single power-of-two
// length; group sizes must be pairwise distinct. The largest group's paired
// leaf hashes form the actual tree leaves; each smaller group is folded in
// as a merkle.LevelInjection at the level whose width matches its number of
// paired leaves.
//
// Within a group, leaf i absorbs the pair (f(ω^i), f(−ω^i)) for every base
// polynomial in declaration order, then for every extension polynomial in
// declaration order. The leaf-hash layout is unchanged from the legacy
// single-group API; multi-group calls simply add injection levels above the
// top group.
//
// In addition to the committed tree, Commit returns the per-group LeafSource
// in the same decreasing-size order used internally to build the tree (i.e.
// sources[0] is the top group whose RS-encoded paired evaluations form the
// Merkle leaves; sources[k>0] corresponds to a smaller group folded in as a
// LevelInjection at the level whose width matches that group's number of
// paired leaves). Callers needing to reopen committed values at FRI query
// positions can read RS-encoded evaluations directly from the LeafSource.
func (rs *RSCommit) Commit(batch Batch, opts ...CommitOption) (WMerkleTree, []LeafSource, error) {
	var config CommitConfig
	for _, opt := range opts {
		if err := opt(&config); err != nil {
			return WMerkleTree{}, nil, err
		}
	}
	domainCache := config.DomainCache
	if domainCache == nil {
		domainCache = &poly.DomainCache{}
	}

	if len(batch) == 0 {
		return WMerkleTree{}, nil, fmt.Errorf("commitment: Commit requires at least one Group")
	}

	// 1- validate every group and sort by descending native size.
	sizes := make([]int, len(batch))
	for k, g := range batch {
		N, err := groupNativeSize(g)
		if err != nil {
			return WMerkleTree{}, nil, fmt.Errorf("commitment: Group[%d]: %w", k, err)
		}
		sizes[k] = N
	}
	order := make([]int, len(batch))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return sizes[order[a]] > sizes[order[b]] })
	for i := 1; i < len(order); i++ {
		if sizes[order[i]] == sizes[order[i-1]] {
			return WMerkleTree{}, nil, fmt.Errorf("commitment: duplicate Group size %d (groups must have distinct native sizes)", sizes[order[i]])
		}
	}

	// 2- encode each group's polynomials on its RS-encoded domain and hash
	//    the paired leaves into one digest slice per group. The largest
	//    group's slice is the tree's leaf layer; the rest become injections.
	//    The per-group LeafSource is retained and returned to the caller in
	//    the same `order` (decreasing native size) used here.
	perGroupLeaves := make([][]hash.Digest, len(batch))
	sources := make([]LeafSource, len(batch))
	for k, gi := range order {
		g := batch[gi]
		N := sizes[gi]
		encoder := rs.encoderForSize(uint64(N), domainCache)

		fftOuter := max(len(g.Base), len(g.Ext))
		var fftOpt fft.Option
		if fftOuter > 0 {
			fftOpt = fft.WithNbTasks(parallel.NbTasksPerJob(fftOuter))
		}

		encodedBase := make([]poly.Polynomial, len(g.Base))
		parallel.Execute(len(g.Base), func(start, end int) {
			for i := start; i < end; i++ {
				pol := g.Base[i]
				if fftOpt != nil {
					encodedBase[i] = encoder.Encode(pol, domainCache.Get(uint64(len(pol))), fftOpt)
				} else {
					encodedBase[i] = encoder.Encode(pol, domainCache.Get(uint64(len(pol))))
				}
			}
		})

		encodedExt := make([]poly.ExtPolynomial, len(g.Ext))
		parallel.Execute(len(g.Ext), func(start, end int) {
			for i := start; i < end; i++ {
				pol := g.Ext[i]
				if fftOpt != nil {
					encodedExt[i] = encoder.EncodeExt(pol, domainCache.Get(uint64(len(pol))), fftOpt)
				} else {
					encodedExt[i] = encoder.EncodeExt(pol, domainCache.Get(uint64(len(pol))))
				}
			}
		})

		halfN := int(encoder.Domain.Cardinality >> 1)
		src := LeafSource{
			Base: encodedBase,
			Ext:  encodedExt,
		}
		leaves := make([]hash.Digest, halfN)
		HashLeavesParallel(rs.LeafHasher, leaves, src)
		perGroupLeaves[k] = leaves
		sources[k] = src
	}

	// 3- build the underlying merkle tree. Smaller groups become injections
	//    on the way up; their LevelWidth equals the number of paired leaves
	//    at that group's level.
	topLeaves := perGroupLeaves[0]
	var injections []merkle.LevelInjection
	if len(perGroupLeaves) > 1 {
		injections = make([]merkle.LevelInjection, len(perGroupLeaves)-1)
		for k := 1; k < len(perGroupLeaves); k++ {
			injections[k-1] = merkle.LevelInjection{
				LevelWidth: len(perGroupLeaves[k]),
				LeafHashes: perGroupLeaves[k],
			}
		}
	}
	tree, err := merkle.NewWithInjections(len(topLeaves), rs.NodeHasher, injections)
	if err != nil {
		return WMerkleTree{}, nil, err
	}
	if err := tree.Build(topLeaves); err != nil {
		return WMerkleTree{}, nil, err
	}

	// 4- record the per-group shape in decreasing-size order so callers can
	//    locate each rail's pairs within the tree.
	shapes := make(BatchShapes, len(order))
	for k, gi := range order {
		shapes[k] = GroupShape{
			PairedLeaves: len(perGroupLeaves[k]),
			BaseWidth:    len(batch[gi].Base),
			ExtWidth:     len(batch[gi].Ext),
		}
	}

	return WMerkleTree{
		Tree:   tree,
		groups: shapes,
	}, sources, nil
}

// groupNativeSize validates that every polynomial in g has the same
// power-of-two length and returns it. Empty groups are rejected.
func groupNativeSize(g Group) (int, error) {
	N := 0
	for k, p := range g.Base {
		if k == 0 {
			N = len(p)
			continue
		}
		if len(p) != N {
			return 0, fmt.Errorf("base polynomial %d has length %d, want %d", k, len(p), N)
		}
	}
	for k, p := range g.Ext {
		if N == 0 && k == 0 {
			N = len(p)
			continue
		}
		if len(p) != N {
			return 0, fmt.Errorf("ext polynomial %d has length %d, want %d", k, len(p), N)
		}
	}
	if N == 0 {
		return 0, fmt.Errorf("group has no polynomials")
	}
	if N&(N-1) != 0 {
		return 0, fmt.Errorf("group size %d is not a power of two", N)
	}
	return N, nil
}

// encoderForSize returns the committer's reusable Encoder when N matches its
// native size (typical single-group path), otherwise constructs a fresh
// encoder for the requested size. Both paths share the same domain cache.
func (rs *RSCommit) encoderForSize(N uint64, cache *poly.DomainCache) reedsolomon.Encoder {
	want := rs.rate * N
	if want == rs.Encoder.Domain.Cardinality {
		return rs.Encoder
	}
	return reedsolomon.NewEncoder(want, reedsolomon.WithCache(cache))
}

// HashLeavesParallel hashes len(dst) paired leaves from src into dst, using
// the batched leaf hasher when available (rate-16 Poseidon2 sponge) and
// fanning the work out across goroutines.
func HashLeavesParallel(lh LeafHasher, dst []hash.Digest, src LeafSource) {
	if batchHasher, ok := lh.(BatchLeafHasher); ok {
		hashLeavesBatchParallel(batchHasher, dst, src)
		return
	}
	parallel.Execute(len(dst), func(start, end int) {
		hashLeavesScalar(lh, dst[start:end], src, start)
	})
}

func hashLeavesBatchParallel(lh BatchLeafHasher, dst []hash.Digest, src LeafSource) {
	batchSize := lh.BatchSize()
	if batchSize <= 0 {
		batchSize = 1
	}

	if batchSize == 1 || len(dst) < batchSize {
		parallel.Execute(len(dst), func(start, end int) {
			lh.HashLeaves(dst[start:end], src, start)
		})
		return
	}

	full := (len(dst) / batchSize) * batchSize
	parallel.Execute(full/batchSize, func(startBatch, endBatch int) {
		start := startBatch * batchSize
		end := endBatch * batchSize
		lh.HashLeaves(dst[start:end], src, start)
	})
	if full < len(dst) {
		lh.HashLeaves(dst[full:], src, full)
	}
}

func hashLeavesScalar(lh LeafHasher, dst []hash.Digest, src LeafSource, start int) {
	baseLeaf := make([]koalabear.Element, len(src.Base))
	extLeaf := make([]ext.E6, len(src.Ext))
	for k := range dst {
		i := start + k
		if len(src.Base) > 0 {
			for j := range src.Base {
				baseLeaf[j].Set(&src.Base[j][i])
			}
		}
		if len(src.Ext) > 0 {
			for j := range src.Ext {
				extLeaf[j].Set(&src.Ext[j][i])
			}
		}
		dst[k] = lh.HashLeaf(baseLeaf, extLeaf)
	}
}

func (lh Poseidon2LeafHasher) hashLeavesBatch16(dst []hash.Digest, src LeafSource, start int) {
	sponge := hash.NewPoseidon2SpongeBatch16()
	sponge.WriteSameElement(hash.NewElement(leafDomainTag))
	sponge.WriteSameElement(hash.NewElement(uint64(len(src.Base))))
	sponge.WriteSameElement(hash.NewElement(uint64(len(src.Ext))))

	for _, pol := range src.Base {
		var row [hash.Poseidon2SpongeBatchSize]koalabear.Element
		for lane := 0; lane < hash.Poseidon2SpongeBatchSize; lane++ {
			i := start + lane
			row[lane].Set(&pol[i])
		}
		sponge.WriteElementBatch(row)
	}

	for _, pol := range src.Ext {
		var row [hash.Poseidon2SpongeBatchSize]ext.E6
		for lane := 0; lane < hash.Poseidon2SpongeBatchSize; lane++ {
			i := start + lane
			row[lane].Set(&pol[i])
		}
		sponge.WriteExtBatch(row)
	}

	digests := sponge.Sum()
	copy(dst, digests[:])
}
