package fri

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/loom/field"
	"github.com/consensys/loom/internal/merkle"
)

func TestOpenQueryBaseUsesFullRows(t *testing.T) {
	layers := [][]koalabear.Element{
		testBaseLayer(8, 10),
		testBaseLayer(4, 100),
		testBaseLayer(2, 1000),
	}
	trees := make([]*merkle.Tree, len(layers))
	for i, layer := range layers {
		tree, err := buildTreeBase(layer, DefaultLeafHasher, DefaultNodeHasher)
		if err != nil {
			t.Fatalf("buildTreeBase(%d): %v", i, err)
		}
		trees[i] = tree
	}

	for _, s := range []int{2, 5} {
		q, err := openQueryBase(s, layers, trees, len(layers))
		if err != nil {
			t.Fatalf("openQueryBase(%d): %v", s, err)
		}
		for j, layer := range layers {
			got := q.Layers[j]
			row := s >> j
			lo, hi := siblingRows(row)
			if got.Field != field.Base {
				t.Fatalf("s=%d layer=%d: field = %s, want base", s, j, got.Field)
			}
			if got.Row != row {
				t.Fatalf("s=%d layer=%d: row = %d, want %d", s, j, got.Row, row)
			}
			if got.PathP.LeafIdx != lo {
				t.Fatalf("s=%d layer=%d: PathP row = %d, want %d", s, j, got.PathP.LeafIdx, lo)
			}
			if got.PathQ.LeafIdx != hi {
				t.Fatalf("s=%d layer=%d: PathQ row = %d, want %d", s, j, got.PathQ.LeafIdx, hi)
			}
			if !got.LeafPBase.Equal(&layer[lo]) {
				t.Fatalf("s=%d layer=%d: LeafP mismatch", s, j)
			}
			if !got.LeafQBase.Equal(&layer[hi]) {
				t.Fatalf("s=%d layer=%d: LeafQ mismatch", s, j)
			}
		}
	}
}

func TestOpenQueryExtUsesFullRows(t *testing.T) {
	layers := [][]ext.E6{
		testExtLayer(8, 10),
		testExtLayer(4, 100),
		testExtLayer(2, 1000),
	}
	trees := make([]*merkle.Tree, len(layers))
	for i, layer := range layers {
		tree, err := buildTreeExt(layer, DefaultLeafHasher, DefaultNodeHasher)
		if err != nil {
			t.Fatalf("buildTreeExt(%d): %v", i, err)
		}
		trees[i] = tree
	}

	for _, s := range []int{2, 5} {
		q, err := openQueryExt(s, layers, trees, len(layers))
		if err != nil {
			t.Fatalf("openQueryExt(%d): %v", s, err)
		}
		for j, layer := range layers {
			got := q.Layers[j]
			row := s >> j
			lo, hi := siblingRows(row)
			if got.Field != field.Ext {
				t.Fatalf("s=%d layer=%d: field = %s, want ext", s, j, got.Field)
			}
			if got.Row != row {
				t.Fatalf("s=%d layer=%d: row = %d, want %d", s, j, got.Row, row)
			}
			if got.PathP.LeafIdx != lo {
				t.Fatalf("s=%d layer=%d: PathP row = %d, want %d", s, j, got.PathP.LeafIdx, lo)
			}
			if got.PathQ.LeafIdx != hi {
				t.Fatalf("s=%d layer=%d: PathQ row = %d, want %d", s, j, got.PathQ.LeafIdx, hi)
			}
			if !got.LeafPExt.Equal(&layer[lo]) {
				t.Fatalf("s=%d layer=%d: LeafP mismatch", s, j)
			}
			if !got.LeafQExt.Equal(&layer[hi]) {
				t.Fatalf("s=%d layer=%d: LeafQ mismatch", s, j)
			}
		}
	}
}

func testBaseLayer(n int, offset uint64) []koalabear.Element {
	layer := make([]koalabear.Element, n)
	for i := range layer {
		layer[i].SetUint64(offset + uint64(i))
	}
	return layer
}

func testExtLayer(n int, offset uint64) []ext.E6 {
	layer := make([]ext.E6, n)
	for i := range layer {
		layer[i].B0.A0.SetUint64(offset + uint64(i))
		layer[i].B1.A1.SetUint64(offset + uint64(i) + 1)
		layer[i].B2.A0.SetUint64(offset + uint64(i) + 2)
	}
	return layer
}
