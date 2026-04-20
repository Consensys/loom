package board_test

import (
	"testing"

	"github.com/consensys/loom/board"
)

// TestCompileEmptyModule demonstrates that board.Compile panics when a module
// has no relations. expr.Fold is called unconditionally on m.Relations and
// indexes into the slice at position 0 without a length check.
func TestCompileEmptyModule(t *testing.T) {
	builder := board.NewBuilder()

	m := board.NewModule()
	m.N = 4
	builder.AddModule("empty", m)

	_, err := board.Compile(&builder)
	if err != nil {
		t.Fatal(err)
	}
}
