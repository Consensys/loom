package univariate

// Config holds configuration options for ComputeSym and ComputeQuotient
type BuilderConfig struct {
	OutputLayout Layout
	OutputBasis  Basis
	OutputName   string
	// DomainSize, when > 0, pins the evaluation domain size and skips the automatic
	// degree-based inflation. Useful when computing mod X^N-1 (e.g., in Flatten).
	DomainSize int

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

// WithDomainSize pins the evaluation domain size for ComputeSym, bypassing the
// automatic degree-based inflation. Use this when computing polynomials mod X^N-1
// where all values should stay on the original N-point domain.
func WithDomainSize(n int) BuilderOption {
	return func(c *BuilderConfig) error {
		c.DomainSize = n
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
