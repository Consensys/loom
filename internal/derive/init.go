package derive

const (
	GRAND_SUM StepKind = iota
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
	StepRegistry = make(map[StepKind]Step)
	StepRegistry[GRAND_PRODUCT] = ComputeGrandProduct
	StepRegistry[GRAND_SUM] = ComputeGrandSum
	StepRegistry[LAGRANGE] = ComputeLagrangeColumn
	StepRegistry[COMPUTE_COL] = ComputeColumn
	StepRegistry[MULTIPLICITY] = ComputeMultiplicity
	StepRegistry[FITLERED_ACC_POLY] = ComputeFilteredAccPolynomial
	StepRegistry[FIAT_SHAMIR] = ComputeChallenge
	StepRegistry[PERMUTATION_GEN] = ComputePermutationColumns
	StepRegistry[REGISTER_COL] = RegisterColumn
}
