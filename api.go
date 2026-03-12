package giop

import (
	"github.com/consensys/giop/constraint"
	"github.com/consensys/giop/proof"
	"github.com/consensys/giop/prover"
	"github.com/consensys/giop/trace"
	"github.com/consensys/giop/verifier"
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
