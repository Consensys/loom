package loom

import (
	"github.com/consensys/loom/constraint"
	"github.com/consensys/loom/internal/prover"
	"github.com/consensys/loom/proof"
	"github.com/consensys/loom/trace"
	"github.com/consensys/loom/internal/verifier"
)

func Prove(cciop constraint.Program, trace trace.Trace, nbWorkers int) (proof.Proof, error) {

	knownColumns := make(map[string]bool)
	for k, _ := range trace {
		if _, ok := knownColumns[k]; !ok {
			knownColumns[k] = true
		}
	}

	_prover := prover.NewProver(cciop, trace)

	return _prover.Prove(knownColumns, nbWorkers)
}

func Verify(cciop constraint.Program, p *proof.Proof, nbWorkers int) error {
	verifierRunTime := verifier.NewRunTime(cciop)
	return verifierRunTime.Verify(p, nbWorkers)
}
