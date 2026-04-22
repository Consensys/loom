package prover

import (
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/internal/commitment"
	"github.com/consensys/loom/internal/merkle"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/trace"
)

type PublicKey = merkle.Tree

func Setup(t trace.Trace, program board.Program) (*PublicKey, error) {

	maxN := 0
	for _, m := range program.Modules {
		if m.N > maxN {
			maxN = m.N
		}
	}
	committer := commitment.NewRSCommit(uint64(maxN), commitment.LeafHash, commitment.NodeHash)

	polys := make([]poly.Polynomial, len(program.PublicColumns))
	for i, name := range program.PublicColumns {
		polys[i] = t[name]
	}
	tree, err := committer.Commit(polys, &committer.Encoder)
	if err != nil {
		return nil, err
	}

	return tree, nil
}
