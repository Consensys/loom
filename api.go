package loom

import (
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/constraint"
	"github.com/consensys/loom/internal/commitment"
	"github.com/consensys/loom/internal/prover"
	"github.com/consensys/loom/internal/verifier"
	"github.com/consensys/loom/proof"
	"github.com/consensys/loom/trace"
)

// Setup commits to all columns in publicColumns
func Setup(cp constraint.Program, trace trace.Trace) error {

	polyToCommit := make([][]koalabear.Element, len(cp.PublicColumnsCommitment.Columns))
	var ok bool
	for i, name := range cp.PublicColumnsCommitment.Columns {
		polyToCommit[i], ok = trace[name]
		if !ok {
			return fmt.Errorf("setup: column %s not found in the trace", name)
		}
	}
	digest, err := commitment.Commit(polyToCommit)
	if err != nil {
		return err
	}
	cp.PublicColumnsCommitment.Digest = digest

	return nil
}

func Prove(cp constraint.Program, trace trace.Trace, publicInputs proof.PublicInputs, nbWorkers int) (proof.Proof, error) {

	_prover := prover.NewProver(cp, trace, publicInputs)

	return _prover.Prove(nbWorkers)
}

func Verify(cp constraint.Program, p *proof.Proof, publicInputs proof.PublicInputs, nbWorkers int) error {
	verifierRunTime := verifier.NewRunTime(cp, publicInputs)
	return verifierRunTime.Verify(p, nbWorkers)
}
