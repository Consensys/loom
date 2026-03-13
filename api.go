package loom

import (
	"github.com/consensys/loom/constraint"
	"github.com/consensys/loom/internal/prover"
	"github.com/consensys/loom/internal/verifier"
	"github.com/consensys/loom/proof"
	"github.com/consensys/loom/trace"
)

func Prove(cciop constraint.Program, trace trace.Trace, publicInputs proof.PublicInputs, nbWorkers int) (proof.Proof, error) {

	knownColumns := make(map[string]bool)
	for k := range trace {
		if _, ok := knownColumns[k]; !ok {
			knownColumns[k] = true
		}
	}

	_prover := prover.NewProver(cciop, trace, publicInputs)

	return _prover.Prove(knownColumns, nbWorkers)
}

func Verify(cciop constraint.Program, p *proof.Proof, publicInputs proof.PublicInputs, nbWorkers int) error {
	verifierRunTime := verifier.NewRunTime(cciop, publicInputs)
	return verifierRunTime.Verify(p, nbWorkers)
}
