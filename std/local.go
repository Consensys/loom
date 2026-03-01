package std

import (
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/iop/cs"
	"github.com/consensys/iop/pas/sym"
)

// Adds a the constrait that the column whose ID is ID is equal to value at i-th entry
func LocalConstraint(system *cs.System, ID string, i int, value koalabear.Element) {

	// 1. register the symbolic constraint in the system
	lagrangeID := cs.GetLagrangeID(0, system.N)
	GPIsOneAtFirstEntry := sym.NewComputableColumn(lagrangeID).
		Mul(sym.NewCommittedColumn(ID).Sub(sym.NewConst(koalabear.One())))
	system.RegisterConstraint(GPIsOneAtFirstEntry)

	// 2. register the prover action: creation of the column i-th-Lagrange
	system.RegisterithLagrangeColumn(i) // <- syntactic sugar to add a prover action for creating the i-th lagrange column
}
