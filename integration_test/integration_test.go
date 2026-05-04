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

package integrationtest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/consensys/loom/board"
	"github.com/consensys/loom/internal/commitment/fri"
	"github.com/consensys/loom/prover"
	"github.com/consensys/loom/verifier"
)

// smallModuleOpts returns FRI prover options for programs whose largest module
// base domain is too small for the default folding factor. When all modules
// are large enough to use the library default (k=8), returns nil.
func smallModuleOpts(pg *board.Program) []prover.Option {
	var maxN uint64
	for _, m := range pg.Modules {
		if n := uint64(m.N); n > maxN {
			maxN = n
		}
	}
	if maxN == 0 {
		return nil
	}
	codewordSize := fri.DefaultFRIMinBlowupFactor * maxN
	if codewordSize >= uint64(fri.DefaultFRIFoldingFactor) {
		return nil
	}
	// Largest power of 2 that fits inside the codeword domain.
	k := uint64(2)
	for k*2 <= codewordSize {
		k *= 2
	}
	return []prover.Option{prover.WithFRIFoldingFactor(int(k))}
}

func TestIntegration(t *testing.T) {

	// 1. For every .lisp file in ./testdata (naming convention <main_name>_xx.lisp,
	// xx starting from 01): compile it, turn it into a loom program, load the
	// corresponding traces, and call Prove + Verify.
	lispFiles, err := filepath.Glob("testdata/*.lisp")
	if err != nil {
		t.Fatal(err)
	}

	// 2. For each file: compile, prove, verify.
	for _, lispFile := range lispFiles {
		base := strings.TrimSuffix(lispFile, ".lisp")
		t.Run(filepath.Base(base), func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic: %v", r)
				}
			}()

			lispBytes, err := os.ReadFile(lispFile)
			if err != nil {
				t.Fatal(err)
			}

			airSchema, mapping, err := CompileLisp(lispFile, lispBytes)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}

			builder := board.NewBuilder()
			bridge := NewCorsetBridge(&builder, airSchema)
			bridge.SetupModules()
			ScanConstraints(bridge)
			pg, err := board.Compile(bridge.Builder)
			if err != nil {
				t.Fatalf("board.Compile: %v", err)
			}

			runTraces := func(path string, expectOK bool) {
				f, err := os.Open(path)
				if os.IsNotExist(err) {
					return
				}
				if err != nil {
					t.Errorf("open %s: %v", path, err)
					return
				}
				defer f.Close()

				traces, err := TracesFromLT(f, airSchema, mapping)
				if err != nil {
					t.Errorf("load %s: %v", path, err)
					return
				}

				for i, tr := range traces {
					setSizes(&pg, tr)
					opts := smallModuleOpts(&pg)

					prf, proveErr := prover.Prove(tr, nil, nil, pg, opts...)
					if proveErr != nil {
						if expectOK {
							t.Errorf("%s[%d] prove: %v", filepath.Base(path), i, proveErr)
						}
						continue
					}

					verifyErr := verifier.Verify(nil, nil, pg, prf)
					if expectOK && verifyErr != nil {
						t.Errorf("%s[%d] verify: %v", filepath.Base(path), i, verifyErr)
					}
					if !expectOK && verifyErr == nil {
						t.Errorf("%s[%d]: expected failure but proof verified", filepath.Base(path), i)
					}
				}
			}

			runTraces(base+".accepts", true)
			runTraces(base+".rejects", false)
		})
	}
}
