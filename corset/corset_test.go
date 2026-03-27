package corset

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestConstraintBuilderFromFile(t *testing.T) {
	bins, err := filepath.Glob("testdata/*.bin")
	if err != nil {
		t.Fatal(err)
	}
	if len(bins) == 0 {
		t.Fatal("no .bin files found in testdata/")
	}
	for _, path := range bins {
		t.Run(filepath.Base(path), func(t *testing.T) {
			if _, err = ConstraintBuilderFromFile(path, 8); err != nil {
				t.Errorf("ConstraintBuilderFromFile(%q): %v", path, err)
			}
		})
	}
}

func TestTraceFromFile(t *testing.T) {
	lts, err := filepath.Glob("testdata/*.lt")
	if err != nil {
		t.Fatal(err)
	}
	if len(lts) == 0 {
		t.Fatal("no .lt files found in testdata/")
	}
	for _, path := range lts {
		t.Run(filepath.Base(path), func(t *testing.T) {
			tr, _, err := TraceFromFile(path)
			if err != nil {
				t.Fatalf("TraceFromFile(%q): %v", path, err)
			}
			if len(tr) == 0 {
				t.Fatal("trace is empty")
			}
			// Every key must be non-empty and must not use the dot separator
			// (which belongs to go-corset's trace format, not loom's).
			for key, col := range tr {
				if key == "" {
					t.Error("empty column key")
				}
				if strings.Contains(key, ".") {
					t.Errorf("column key %q uses dot separator; want colon", key)
				}
				if len(col) == 0 {
					t.Errorf("column %q is empty", key)
				}
			}
		})
	}
}
