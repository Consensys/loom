package cs

import (
	"github.com/consensys/giop/pas/dag"
	"github.com/consensys/giop/pas/sym"
)

// func reduceDegree(system *System, targetDegree int) error {

// var config system.Config
// for _, opt := range opts {
// 	err := opt(&config)
// 	if err != nil {
// 		return err
// 	}
// }

// // fold the constraints
// Cprime, err := system.Flatten(&prot.S, C, targetDegree)
// if err != nil {
// 	return err
// }

// // IDs to commit
// IDtoCommit := sym.RemoveDuplicates(C.CommittedColumns())
// if _, err := prot.SendMeAChallenge(IDtoCommit, alpha); err != nil {
// 	return err
// }

// // create a constraint C := \Sum_i challenge.Nameⁱ * Ci
// CprimeFolded := Cprime[0]
// for i := 1; i < len(Cprime); i++ {
// 	CprimeFolded = CprimeFolded.Add(Cprime[i].Mul(sym.NewChallenge(alpha).Pow(uint32(i))))
// }

// // record the constraint
// if config.CacheMe {
// 	prot.S.CachedConstraints = append(prot.S.CachedConstraints, CprimeFolded)
// } else {
// 	prot.S.Constraints = append(prot.S.Constraints, CprimeFolded)
// }

// 	return nil
// }

// reduceDegree Computes a set of constraints equivalent to constraint, but of dergee <= targetDegree.
// The auxiliary constraints are folded into a single polynomial identity with a Fiat-Shamir challenge α.
// It is a trade off between number of columns <-> fft domain size
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
func reduceDegree(system *System, targetDegree int) {

	// seenExpr records already seen folded expressions (the AST doesn't common substrings). The key is a unique ID
	// characterising a sym.Expr, derived from building its corresponding DAG. The value is the name of the reduced expression.
	// ex: for computing P0^4 and targetDegree=2, we compute P0' = P0^2 only once, and then compute P0 = P0'^2
	seenExpr := make(map[string]string)

	for i, constraint := range system.Constraints {
		// stores the intermediate low degree expressions pruned form the current constraint
		// being reduced
		for constraint.Degree() > targetDegree {

			// prune expressions, low degree expressions at a time
			lowDegreeExpr := constraint.Prune(targetDegree)

			// check if the expression was already pruned before, using a unique ID, got from the DAG
			// representation of the expression (the AST doesn't ensure canonical representation).
			// If the expression has already been seen, replace the expression with its folded counterpart
			daglowDegreeExpr := dag.ExprToDAG(lowDegreeExpr)
			if seen, ok := seenExpr[daglowDegreeExpr.Root.Key()]; ok {
				cc := sym.NewCommittedColumn(seen)
				constraint.ReplaceLeafByExpression(lowDegreeExpr.String(), cc)
				continue
			}

			// register the creation of an auxiliary column C := lowDegreeExpr(trace)
			// The ID of C is lowDegreeExpr.String()
			newConstraint := BuildCorrectConstructionConstraint(lowDegreeExpr, lowDegreeExpr.String())
			system.RegisterConstraint(newConstraint)

			// register the prover action of creating the column C := lowDegreeExpr(trace)
			system.RegisterProverAction([]sym.Expr{lowDegreeExpr}, []string{lowDegreeExpr.String()}, ComputeColumn)

			// register the lowDegreeExpr
			seenExpr[daglowDegreeExpr.Root.Key()] = lowDegreeExpr.String()

		}

		// replace the high degree constraint in place by the latest low degree constraint pruned
		system.Constraints[i] = constraint

	}
}
