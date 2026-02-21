package univariate

// Config holds configuration options for ComputeSym and ComputeQuotient
type BuilderConfig struct {
	ResultLayout Layout
	ResultBasis  Basis
	OutputName   string
	// DomainSize, when > 0, pins the evaluation domain size and skips the automatic
	// degree-based inflation. Useful when computing mod X^N-1 (e.g., in Flatten).
	DomainSize int
}

// Option is a functional option type for configuring ComputeSym and ComputeQuotient
type BuilderOption func(*BuilderConfig) error

// WithResultLayout sets the layout of the resulting polynomial (Normal or BitReversed)
func WithResultLayout(layout Layout) BuilderOption {
	return func(c *BuilderConfig) error {
		c.ResultLayout = layout
		return nil
	}
}

// WithResultLayout sets the layout of the resulting polynomial (Normal or BitReversed)
func WithResultBasis(basis Basis) BuilderOption {
	return func(c *BuilderConfig) error {
		c.ResultBasis = basis
		return nil
	}
}

func WithOutputName(name string) BuilderOption {
	return func(s *BuilderConfig) error {
		s.OutputName = name
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
		OutputName: "Output",
	}
}
