package loom

import (
	"github.com/consensys/loom/constraint"
	"github.com/consensys/loom/internal/prover"
	"github.com/consensys/loom/internal/verifier"
	"github.com/consensys/loom/proof"
	"github.com/consensys/loom/trace"
)

func Prove(cp constraint.Program, trace trace.Trace, publicInputs proof.PublicInputs, nbWorkers int) (proof.ProofBatched, error) {

	knownColumns := make(map[string]bool)
	for k := range trace {
		if _, ok := knownColumns[k]; !ok {
			knownColumns[k] = true
		}
	}

	_prover := prover.NewProver(cp, trace, publicInputs)

	return _prover.Prove(knownColumns, nbWorkers)
}

func Verify(cp constraint.Program, p *proof.ProofBatched, publicInputs proof.PublicInputs, nbWorkers int) error {
	verifierRunTime := verifier.NewRunTime(cp, publicInputs)
	return verifierRunTime.Verify(p, nbWorkers)
}
