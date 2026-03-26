package corset

import (
	"path/filepath"
	"testing"
)

func TestBuildFromCorsetBin(t *testing.T) {
	bins, err := filepath.Glob("testdata/*.bin")
	if err != nil {
		t.Fatal(err)
	}
	if len(bins) == 0 {
		t.Fatal("no .bin files found in testdata/")
	}
	for _, path := range bins {
		t.Run(filepath.Base(path), func(t *testing.T) {
			if _, err = BuildFromCorsetBin(path, 8); err != nil {
				t.Errorf("BuildFromCorsetBin(%q): %v", path, err)
			}
		})
	}
}
