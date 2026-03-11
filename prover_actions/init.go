package proveractions

const (
	GRAND_SUM PAIdentifier = iota
	GRAND_PRODUCT
	LAGRANGE
	COMPUTE_COL
	MULTIPLICITY
	FITLERED_ACC_POLY
	FIAT_SHAMIR
	PERMUTATION_GEN
	REGISTER_COL
)

func init() {
	PARegister = make(map[PAIdentifier]Action)
	PARegister[GRAND_PRODUCT] = ComputeGrandProduct
	PARegister[GRAND_SUM] = ComputeGrandSum
	PARegister[LAGRANGE] = ComputeLagrangeColumn
	PARegister[COMPUTE_COL] = ComputeColumn
	PARegister[MULTIPLICITY] = ComputeMultiplicity
	PARegister[FITLERED_ACC_POLY] = ComputeFilteredAccPolynomial
	PARegister[FIAT_SHAMIR] = ComputeChallenge
	PARegister[PERMUTATION_GEN] = ComputePermutationColumns
	PARegister[REGISTER_COL] = RegisterColumn
}
