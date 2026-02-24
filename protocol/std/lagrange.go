package std

import (
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/iop/protocol"
	"github.com/consensys/iop/system"
)

// NewLagrangeConstraint wrapper around system.NewLagrangeConstraint. Syntactic sugar to make the method available form std
// Ensures P[ID][entry]=value. No challenge involved in this scheme
func NewLagrangeConstraint(prot *protocol.Protocol, ID string, entry int, value koalabear.Element, opts ...system.Option) error {
	return system.NewLagrangeConstraint(&prot.S, ID, entry, value, opts...)
}
