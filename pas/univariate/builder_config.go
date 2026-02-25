package univariate

// Config holds configuration options for ComputeSym and ComputeQuotient
type BuilderConfig struct {
	OutputLayout Layout
	OutputBasis  Basis
	OutputName   string
	// DomainSize int

	// InputBasis
	InputBasis Basis
}

// Option is a functional option type for configuring ComputeSym and ComputeQuotient
type BuilderOption func(*BuilderConfig) error

// WithOutputLayout sets the layout of the resulting polynomial (Normal or BitReversed)
func WithOutputLayout(layout Layout) BuilderOption {
	return func(c *BuilderConfig) error {
		c.OutputLayout = layout
		return nil
	}
}

// WithOutputLayout sets the layout of the resulting polynomial (Normal or BitReversed)
func WithOutputBasis(basis Basis) BuilderOption {
	return func(c *BuilderConfig) error {
		c.OutputBasis = basis
		return nil
	}
}

// WithInputBasis sets the layout of the inputs polynomial (Normal or BitReversed)
func WithInputBasis(basis Basis) BuilderOption {
	return func(c *BuilderConfig) error {
		c.InputBasis = basis
		return nil
	}
}

func NewBuilderConfig() BuilderConfig {
	return BuilderConfig{
		OutputName:  "Output",
		InputBasis:  Lagrange,
		OutputBasis: Lagrange,
	}
}
