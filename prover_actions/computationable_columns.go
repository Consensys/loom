package proveractions

// GetComputationableColumn atm there is only one type of computableColumns, but when there will be more
// we need to switch on the id to know which type is it, and return the correct colum
func GetComputationableColumn(id string) (ComputableColumn, error) {

	// TODO when there is more than one type of computable column, switch on id to know which type is it
	// atm there only one type, LagrangeColumn
	return NewLagrangeColumn(id)
}
