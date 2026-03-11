// This package is mostly intended to be an example on how to handle a trace with
// a set of constraints.
// Here we deal with a plonk trace, and we use 4 iops:
// * vanishing constraints -> QL*L + QR*R + QM*L*R + QO*O + QK
// * folding IOP
// * permutation iOP
// * Lagrange IOP ("local constraints" in the wizard language)

package plonk_example
