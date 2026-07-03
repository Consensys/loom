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

// Package challenger24 implements an in-circuit Fiat-Shamir challenge
// computation using the width-24 Poseidon2 sponge (the same hasher Loom's
// native transcript uses). One module per challenge: a sequence of
// width-24 permutations linked by input-overwrite + capacity-carry
// constraints between consecutive rows.
//
// API:
//
//   - BuildModule(builder, name, inputs): creates a new module computing
//     the Poseidon2-sponge digest of `inputs`. Returns ColumnNames
//     including the 8 digest limb columns and the row index they live on.
//   - GenerateTrace: runs the native sponge on the given native inputs,
//     filling every witness column (input state per row + sponge
//     sub-columns from the poseidon2sponge gadget).
//
// Compatibility note: this matches the absorb-overwrite mode used by
// Loom's hash.Poseidon2SpongeHasher — state[0..len(chunk)-1] is
// overwritten by the input chunk; state[len(chunk)..23] is preserved
// from the previous permutation output (rate-suffix + capacity).
package challenger24

import (
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
	nativeposeidon2 "github.com/consensys/gnark-crypto/field/koalabear/poseidon2"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/hash"
	"github.com/consensys/loom/recursion/gadgets/poseidon2sponge"
)

// DigestLen is the number of base-field limbs in a Poseidon2 sponge
// digest.
const DigestLen = hash.DIGEST_NB_ELEMENTS // 8

// Rate / Width / Capacity mirror poseidon2sponge.
const (
	Rate     = poseidon2sponge.Rate
	Width    = poseidon2sponge.Width
	Capacity = poseidon2sponge.Capacity
)

// ColumnNames identifies the columns of one challenge module.
type ColumnNames struct {
	ModuleName string
	Sponge     poseidon2sponge.ColumnNames
	// DigestRow is the 0-based row in the module where the final digest
	// lives. Read tr.Base[Digest[i]][DigestRow] to get the i-th limb.
	DigestRow int
	Digest    [DigestLen]string
	// NPermutations is the number of real permutations in this sponge.
	NPermutations int
	// StartRow is the module row where this sponge's first permutation
	// is registered. The sponge occupies rows [StartRow, StartRow+NPermutations).
	StartRow int
}

// BuildModule creates a challenge module that computes the Poseidon2
// sponge digest of inputs and registers it in builder.
//
// nPerms = ceil(len(inputs) / Rate) (with at least 1 permutation, even
// for empty input — though empty input is rejected for clarity). The
// module's N is rounded up to a power of two, padded rows replay an
// all-zero input.
func BuildModule(builder *board.Builder, name string, inputs []expr.Expr) ColumnNames {
	if len(inputs) == 0 {
		panic("challenger24.BuildModule: empty input — caller should special-case this")
	}

	nPerms := numPermutations(len(inputs))
	n := nextPow2(nPerms)

	mod := board.NewModule(name)
	mod.N = n

	cn := Register(&mod, name, inputs)
	builder.AddModule(mod)
	return cn
}

// NumPermutationsExternal is the exported form of numPermutations,
// useful when callers need to size their own modules to match the
// sponge before calling Register.
func NumPermutationsExternal(n int) int {
	return numPermutations(n)
}

// GenerateTraceWithSize fills sponge sub-columns for a module of size
// nModuleRows. The sponge data is placed at rows [cn.StartRow,
// cn.StartRow+nPerms); other rows are filled with all-zero input state
// (yielding Poseidon2(zero) — self-consistent but unused by the
// challenger's cross-row constraints which don't fire at those rows).
//
// Returns the resulting digest from the digest row (cn.DigestRow).
func GenerateTraceWithSize(cn ColumnNames, nModuleRows int, nativeInputs []koalabear.Element) (map[string][]koalabear.Element, hash.Digest) {
	if len(nativeInputs) == 0 {
		panic("challenger24.GenerateTraceWithSize: empty input")
	}
	nPerms := numPermutations(len(nativeInputs))
	if cn.NPermutations != nPerms {
		panic(fmt.Sprintf("challenger24.GenerateTraceWithSize: nPerms mismatch: cn=%d input=%d", cn.NPermutations, nPerms))
	}
	if nModuleRows < cn.StartRow+nPerms {
		panic(fmt.Sprintf("challenger24.GenerateTraceWithSize: nModuleRows=%d < startRow+nPerms=%d", nModuleRows, cn.StartRow+nPerms))
	}

	inputStates := make([][poseidon2sponge.Width]koalabear.Element, nModuleRows)
	var carryState [poseidon2sponge.Width]koalabear.Element // initially zero

	nFull := len(nativeInputs) / Rate
	partial := len(nativeInputs) % Rate
	for k := 0; k < nPerms; k++ {
		var rowIn [poseidon2sponge.Width]koalabear.Element
		rowIn = carryState
		chunkLen := Rate
		if k == nFull && partial > 0 {
			chunkLen = partial
		}
		for i := 0; i < chunkLen; i++ {
			rowIn[i].Set(&nativeInputs[k*Rate+i])
		}
		inputStates[cn.StartRow+k] = rowIn

		// Run the native permutation to update the carry for the next
		// row's input state.
		var permuted [poseidon2sponge.Width]koalabear.Element
		permuted = rowIn
		if err := newSpongePerm().Permutation(permuted[:]); err != nil {
			panic(err)
		}
		carryState = permuted
	}
	// Other rows (before startRow or after the sponge) keep their
	// default zero input state — poseidon2sponge.GenerateTrace will
	// compute Poseidon2(0) for them, which satisfies the permutation
	// constraint.

	cols, _ := poseidon2sponge.GenerateTrace(cn.Sponge, nModuleRows, inputStates)

	var digest hash.Digest
	for i := 0; i < DigestLen; i++ {
		digest[i].Set(&cols[cn.Sponge.Post[poseidon2sponge.NbRounds-1][i]][cn.DigestRow])
	}
	return cols, digest
}

func newSpongePerm() *nativeposeidon2.Permutation {
	return nativeposeidon2.NewPermutation(
		poseidon2sponge.Width, poseidon2sponge.NbFullRounds, poseidon2sponge.NbPartialRound,
	)
}

// numPermutations returns the number of sponge permutations needed to
// absorb `n` input elements.
func numPermutations(n int) int {
	if n == 0 {
		return 0
	}
	nFull := n / Rate
	partial := n % Rate
	if partial > 0 {
		return nFull + 1
	}
	return nFull
}

// Register is RegisterAt at startRow == 0.
func Register(mod *board.Module, name string, inputs []expr.Expr) ColumnNames {
	return RegisterAt(mod, name, inputs, 0)
}

// RegisterAt appends a challenger sponge sequence to mod that absorbs
// inputs across rows [startRow, startRow+nPerms). mod.N must already
// be set to at least startRow + nPerms and must be a power of two.
//
// Use startRow > 0 to chain multiple sponge sequences in one module
// (e.g. for a FS transcript with multiple challenges). The capacity
// region (state[Rate..]) resets to zero at the start of every sponge,
// matching Loom's native Transcript.ComputeChallenge which resets the
// hasher per challenge.
func RegisterAt(mod *board.Module, name string, inputs []expr.Expr, startRow int) ColumnNames {
	if len(inputs) == 0 {
		panic("challenger24.RegisterAt: empty input")
	}
	nPerms := numPermutations(len(inputs))
	if startRow < 0 {
		panic("challenger24.RegisterAt: startRow must be non-negative")
	}
	if mod.N < startRow+nPerms {
		panic(fmt.Sprintf("challenger24.RegisterAt: mod.N=%d < startRow+nPerms=%d", mod.N, startRow+nPerms))
	}

	spongeCN := poseidon2sponge.Register(mod, name+".sp")

	var zeroElem koalabear.Element
	zero := expr.Const(zeroElem)

	nFull := len(inputs) / Rate
	partial := len(inputs) % Rate

	// Per-row input wiring. For sequence-row k (0..nPerms-1), the actual
	// module row is (startRow + k):
	//   chunk_k = inputs[k*Rate .. min((k+1)*Rate, len)]
	//   input[0..len(chunk_k)-1]  = chunk_k                        (overwrite)
	//   input[len(chunk_k)..23]   = previous output[same indices]  (carry)
	// For k == 0, "previous output" = zeros (this matches Loom's
	// native transcript which resets the hasher state per challenge).
	for k := 0; k < nPerms; k++ {
		chunkLen := Rate
		if k == nFull && partial > 0 {
			chunkLen = partial
		}
		rowIdx := startRow + k

		// Overwrite region.
		for i := 0; i < chunkLen; i++ {
			elemIdx := k*Rate + i
			mod.AssertEqualAt(expr.Col(spongeCN.In[i]), inputs[elemIdx], rowIdx)
		}

		// Preserve region.
		for i := chunkLen; i < Width; i++ {
			inCol := expr.Col(spongeCN.In[i])
			if k == 0 {
				mod.AssertEqualAt(inCol, zero, rowIdx)
			} else {
				prevOut := expr.Rot(spongeCN.Post[poseidon2sponge.NbRounds-1][i], -1)
				mod.AssertEqualAt(inCol, prevOut, rowIdx)
			}
		}
	}

	cn := ColumnNames{
		ModuleName:    name,
		Sponge:        spongeCN,
		DigestRow:     startRow + nPerms - 1,
		NPermutations: nPerms,
		StartRow:      startRow,
	}
	for i := 0; i < DigestLen; i++ {
		cn.Digest[i] = spongeCN.Post[poseidon2sponge.NbRounds-1][i]
	}
	return cn
}

// GenerateTrace runs the native Poseidon2 sponge on `nativeInputs` and
// returns all witness columns the challenger module needs. Caller merges
// into the global trace.
//
// Pad rows (beyond nPerms) replay a self-consistent extra permutation
// with all-zero input + zero capacity carry, which satisfies every
// per-row constraint that AssertEqualAt only enforces at specific rows.
func GenerateTrace(cn ColumnNames, nativeInputs []koalabear.Element) (map[string][]koalabear.Element, hash.Digest) {
	if len(nativeInputs) == 0 {
		panic("challenger24.GenerateTrace: empty input")
	}

	nFull := len(nativeInputs) / Rate
	partial := len(nativeInputs) % Rate
	nPerms := nFull
	if partial > 0 {
		nPerms++
	}

	// We need to know the module size to fill columns; derive from
	// cn.NPermutations rounded up to pow2.
	n := nextPow2(nPerms)
	if cn.NPermutations != nPerms {
		panic(fmt.Sprintf("challenger24.GenerateTrace: nPerms mismatch: cn=%d input=%d", cn.NPermutations, nPerms))
	}

	perm := nativeposeidon2.NewPermutation(
		poseidon2sponge.Width, poseidon2sponge.NbFullRounds, poseidon2sponge.NbPartialRound,
	)

	// Reconstruct per-row input states.
	inputStates := make([][poseidon2sponge.Width]koalabear.Element, n)
	var carryState [poseidon2sponge.Width]koalabear.Element // initially zero

	for k := 0; k < nPerms; k++ {
		var rowIn [poseidon2sponge.Width]koalabear.Element
		// Carry from previous output: copy all 24 first, then overwrite the chunk region.
		rowIn = carryState
		chunkLen := Rate
		if k == nFull && partial > 0 {
			chunkLen = partial
		}
		for i := 0; i < chunkLen; i++ {
			rowIn[i].Set(&nativeInputs[k*Rate+i])
		}
		inputStates[k] = rowIn

		// Compute output state for the next row's carry.
		var permuted [poseidon2sponge.Width]koalabear.Element
		permuted = rowIn
		if err := perm.Permutation(permuted[:]); err != nil {
			panic(err)
		}
		carryState = permuted
	}
	// Padding rows: input = previous carry; permutation continues self-consistently.
	for k := nPerms; k < n; k++ {
		inputStates[k] = carryState
		var permuted [poseidon2sponge.Width]koalabear.Element
		permuted = carryState
		if err := perm.Permutation(permuted[:]); err != nil {
			panic(err)
		}
		carryState = permuted
	}

	cols, _ := poseidon2sponge.GenerateTrace(cn.Sponge, n, inputStates)

	// Compute the actual digest (= permuted state of the LAST real
	// permutation's INPUT, i.e. inputStates[nPerms-1] permuted).
	// Easier: take post[NbRounds-1][0..7] from the cols map at row
	// nPerms-1.
	var digest hash.Digest
	for i := 0; i < DigestLen; i++ {
		digest[i].Set(&cols[cn.Sponge.Post[poseidon2sponge.NbRounds-1][i]][nPerms-1])
	}

	return cols, digest
}

func nextPow2(n int) int {
	if n <= 1 {
		return 1
	}
	r := 1
	for r < n {
		r <<= 1
	}
	return r
}
