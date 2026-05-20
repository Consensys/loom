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

package setup

import (
	"fmt"
	"sort"

	"github.com/consensys/loom/board"
	"github.com/consensys/loom/field"
	"github.com/consensys/loom/internal/commitment"
	"github.com/consensys/loom/internal/constants"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/trace"
)

// ProvingKey is the prover-side setup material. Trees contain the setup
// commitments and Trace contains the fixed columns in Lagrange form, so the
// prover can evaluate setup columns without carrying them in each witness.
type ProvingKey struct {
	Trace trace.Trace
	Trees []commitment.WMerkleTree
}

// VerificationKey is the verifier-side setup material.
type VerificationKey struct {
	Roots [][]byte
}

// VerificationKey returns the verifier-side roots corresponding to pk.
func (pk ProvingKey) VerificationKey() VerificationKey {
	res := make([][]byte, len(pk.Trees))
	for i, tree := range pk.Trees {
		res[i] = tree.Root()
	}
	return VerificationKey{Roots: res}
}

func Setup(t trace.Trace, program board.Program) (ProvingKey, VerificationKey, error) {
	setupTrace, err := setupTraceFromProgram(t, program)
	if err != nil {
		return ProvingKey{}, VerificationKey{}, err
	}

	if len(program.PublicColumns) == 0 {
		pk := ProvingKey{Trace: setupTrace}
		return pk, pk.VerificationKey(), nil
	}

	// Group public columns by their owning module's domain size, then
	// sort each group by name so the polynomial order inside the per-size
	// commitment tree matches prover.BuildLayout (which sorts setup columns
	// by name before assigning rail-local PolyIdx). Without this, the verifier's
	// layout.ColSlot[name].PolyIdx points at the wrong polynomial in the
	// setup tree.
	colsByN := map[int][]board.ColumnRef{}
	for _, c := range program.PublicColumns {
		m, ok := program.Modules[c.Module]
		if !ok {
			continue
		}
		colsByN[m.N] = append(colsByN[m.N], c)
	}
	sizes := make([]int, 0, len(colsByN))
	for n := range colsByN {
		sizes = append(sizes, n)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(sizes)))

	trees := make([]commitment.WMerkleTree, len(sizes))
	var domainCache poly.DomainCache
	for i, N := range sizes {
		refs := colsByN[N]
		sort.Slice(refs, func(i, j int) bool { return refs[i].Name < refs[j].Name })
		basePublic := make([]poly.Polynomial, 0, len(refs))
		extPublic := make([]poly.ExtPolynomial, 0, len(refs))
		for _, ref := range refs {
			if ref.Field == field.Base {
				p, ok := setupTrace.Base[ref.Name]
				if !ok {
					return ProvingKey{}, VerificationKey{}, fmt.Errorf("setup: base public column %q not found", ref.Name)
				}
				basePublic = append(basePublic, p)
			}
		}
		for _, ref := range refs {
			if ref.Field == field.Ext {
				p, ok := setupTrace.Ext[ref.Name]
				if !ok {
					return ProvingKey{}, VerificationKey{}, fmt.Errorf("setup: extension public column %q not found", ref.Name)
				}
				extPublic = append(extPublic, p)
			}
		}
		committer := commitment.NewRSCommitWithDomainCache(uint64(N), uint64(constants.RATE), commitment.LeafHash, commitment.NodeHash, &domainCache)
		tree, err := committer.Commit(basePublic, extPublic, commitment.WithDomainCache(&domainCache))
		if err != nil {
			return ProvingKey{}, VerificationKey{}, err
		}
		trees[i] = tree
	}
	pk := ProvingKey{Trace: setupTrace, Trees: trees}
	return pk, pk.VerificationKey(), nil
}

func setupTraceFromProgram(t trace.Trace, program board.Program) (trace.Trace, error) {
	res := trace.New(len(program.PublicColumns))
	for _, ref := range program.PublicColumns {
		switch ref.Field {
		case field.Base:
			p, ok := t.Base[ref.Name]
			if !ok {
				return trace.Trace{}, fmt.Errorf("setup: base public column %q not found", ref.Name)
			}
			if err := res.PutBase(ref.Name, p); err != nil {
				return trace.Trace{}, err
			}
		case field.Ext:
			p, ok := t.Ext[ref.Name]
			if !ok {
				return trace.Trace{}, fmt.Errorf("setup: extension public column %q not found", ref.Name)
			}
			if err := res.PutExt(ref.Name, p); err != nil {
				return trace.Trace{}, err
			}
		default:
			return trace.Trace{}, fmt.Errorf("setup: unsupported field kind for public column %q", ref.Name)
		}
	}
	return res, nil
}
