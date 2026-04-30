package integrationtest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/consensys/loom/board"
	"github.com/consensys/loom/prover"
	"github.com/consensys/loom/verifier"
)

func IntegrationTest(t *testing.T) {

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

			lispBytes, err := os.ReadFile(lispFile)
			if err != nil {
				t.Fatal(err)
			}

			airSchema, _, err := CompileLisp(lispFile, lispBytes)
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

				traces, err := TracesFromLT(f)
				if err != nil {
					t.Errorf("load %s: %v", path, err)
					return
				}

				for i, tr := range traces {
					setSizes(&pg, tr)

					prf, proveErr := prover.Prove(tr, nil, nil, pg)
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
