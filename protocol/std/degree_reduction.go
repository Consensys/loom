package std

import (
	"github.com/consensys/iop/pas/sym"
	"github.com/consensys/iop/protocol"
	"github.com/consensys/iop/system"
)

// DegreeReductionIOP proves C(Trace) = 0 mod X^N−1 for a high-degree constraint C by flattening it
// into a set of constraints C' = {C_0, …, C_m} each of degree ≤ targetDegree, introducing one
// auxiliary column per extracted sub-expression.  The auxiliary constraints are folded into a single
// polynomial identity with a Fiat-Shamir challenge α.
//
// It models the following Σ protocol (example: C = P0^4 − P1^2, targetDegree = 2):
//
//	|-------------------------------–-----------------------------------------------|
//	| [prover]                      |              [verifier]                       |
//	|-------------------------------–-----------------------------------------------|
//	| Flatten C:                    |                                               |
//	|   extract Q₁ := P1^2         |                                               |
//	|   extract Q₂ := P0·P0        |                                               |
//	|   C_reduced = Q₂^2 − Q₁      |                                               |
//	|   (degree ≤ targetDegree)     |                                               |
//	|                               |                                               |
//	| Commit(auxiliary cols         |                                               |
//	|   appearing in C_reduced)     |                                               |
//	|   e.g. Commit(Q₁, Q₂) -----→ | [Com(Q₁), Com(Q₂)]                           | ROUND 1
//	|-------------------------------–-----------------------------------------------|
//	|                               ←-----  Sample random α (alpha)                |
//	|                               |       (α = Fiat-Shamir(Com(Q₁), Com(Q₂)))    | ROUND 2
//	|-------------------------------–-----------------------------------------------|
//	| Fold C' with α:               |                                               |
//	|   C_f = C_0                   |                                               |
//	|       + α   · C_1             |                                               |
//	|       + α²  · C_2             |                                               |
//	|       + …                     |                                               |
//	| e.g. C_f = (P1^2 − Q₁)       |                                               |
//	|          + α · (P0^2 − Q₂)   |                                               |
//	|          + α²· (Q₂^2 − Q₁)   |                                               |
//	|-------------------------------–-----------------------------------------------|
//	|       (done via Finalize + Verify)                                            |
//	| Records one constraint:                                                       |
//	|   C_f = 0  mod X^N−1                                                         |
//	|   (equivalent to C = 0 with high probability for random α)                   |
//	|-------------------------------–-----------------------------------------------|
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
