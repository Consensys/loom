package std

import (
	"github.com/consensys/iop/pas/sym"
	"github.com/consensys/iop/protocol"
	"github.com/consensys/iop/system"
)

// DegreeReductionIOP from C, a constraint of high degree, generated a list of constraints C' of degree
// targetDegree, such that
// C(Trace) = 0 <=> for all c in C', c(Trace') = 0 (Trace' is Trace, with the additionnal columns created in the process)
//
// The constraints in C' are folded with a challenge from the verifier.
// The IOP is:
// 1. prover Flatten C, generates columns in the process
// Send commitments to all new columns and all columns appearing in C to the verifier
// 2. Verifier sends a challenge \alpha based on all those commitments
// 3. prover folds all generated constraints in C' with \alpha
func DegreeReductionIOP(prot *protocol.Protocol, C system.Constraint, targetDegree int, alpha string, opts ...system.IOPOption) error {

	var config system.Config
	for _, opt := range opts {
		err := opt(&config)
		if err != nil {
			return err
		}
	}

	// fold the constraints
	Cprime, err := system.Flatten(&prot.S, C, targetDegree)
	if err != nil {
		return err
	}

	// IDs to commit
	IDtoCommit := sym.RemoveDuplicates(C.Vars())
	if _, err := prot.SendMeAChallenge(IDtoCommit, alpha); err != nil {
		return err
	}

	// create a constraint C := \Sum_i challenge.Nameⁱ * Ci
	CprimeFolded := Cprime[0]
	for i := 1; i < len(Cprime); i++ {
		CprimeFolded = CprimeFolded.Add(Cprime[i].Mul(sym.NewChallenge(alpha).Pow(uint32(i))))
	}

	// record the constraint
	if config.CacheMe {
		prot.S.CachedConstraints = append(prot.S.CachedConstraints, CprimeFolded)
	} else {
		prot.S.Constraints = append(prot.S.Constraints, CprimeFolded)
	}

	return nil
}
