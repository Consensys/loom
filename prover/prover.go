package prover

import (
	"crypto/sha256"
	"fmt"
	"sync"

	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/gnark-crypto/utils"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/commitment"
	"github.com/consensys/loom/internal/commitment/fri"
	"github.com/consensys/loom/internal/constants"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/proof"
	"github.com/consensys/loom/trace"
)

type Config struct {
	EmulateFS bool
	// FRIGrindingBits is the number of leading zero bits the proof-of-work
	// nonce inside the FRI commitment must satisfy. 0 disables grinding.
	// The verifier must be configured with the same value to accept the proof.
	FRIGrindingBits int
}

type Option func(c *Config) error

func EmulateFS() Option {
	return func(c *Config) error {
		c.EmulateFS = true
		return nil
	}
}

// WithFRIGrindingBits sets the proof-of-work bit count for the FRI
// commitment scheme. The verifier must be invoked with the matching
// verifier.WithFRIGrindingBits option.
func WithFRIGrindingBits(n int) Option {
	return func(c *Config) error {
		c.FRIGrindingBits = n
		return nil
	}
}

type proverRuntime struct {
	Committer    fri.Committer
	Proof        proof.Proof
	config       Config
	t            trace.Trace
	publicInputs proof.PublicInputs
	program      board.Program
	zeta         koalabear.Element
	mu           sync.Mutex
	fs           *fiatshamir.Transcript
}

func newProverRuntime(t trace.Trace, publicInputs proof.PublicInputs, program board.Program, config Config) proverRuntime {

	res := proverRuntime{
		Proof:        proof.NewProof(),
		config:       config,
		t:            t,
		publicInputs: publicInputs,
		program:      program,
		mu:           sync.Mutex{}, // mutex to protect the trace when reading/writing (in case of parallelisation)
	}

	// initialize FS transcript and pre-register all challenges (challenge@loom_0..n-1 and zeta)
	res.fs = fiatshamir.NewTranscript(sha256.New())

	// Compute the maximum polynomial base-domain size across all modules so that
	// every committed oracle uses the same codeword domain.
	var maxModuleN uint64
	for _, m := range program.Modules {
		if uint64(m.N) > maxModuleN {
			maxModuleN = uint64(m.N)
		}
	}
	friCfg := fri.Config{
		MaxCodewordDomainSize: fri.DefaultFRIBlowupFactor * maxModuleN,
		GrindingBits:          config.FRIGrindingBits,
	}

	// Initialize the FRI committer against the same transcript used by the rest
	// of the prover. All oracles are encoded at MaxCodewordDomainSize.
	res.Committer = fri.NewCommitter(res.fs, friCfg, commitment.LeafHash, commitment.NodeHash)

	return res
}

func (pr *proverRuntime) ExecuteSteps() error {

	// 1 - for each module in program, execute the list of Gen() functions in GenCol
	for _, m := range pr.program.Modules {
		mCopy := m
		for _, gen := range mCopy.GenCol {
			gen.Gen(pr.t, &mCopy)
		}
	}

	roundIdx := 0

	// 2 - execute the program's Steps level by level
	for _, steps := range pr.program.Steps {
		for _, s := range steps {
			_, ok := s.Ctx.(board.FSCtx)
			if ok {
				challengeName := constants.CanonicalChallengeName(roundIdx)

				// fetch all trace polynomials referred in FScolumnsDependencies[roundIdx]
				deps := pr.program.FScolumnsDependencies[roundIdx]
				polys := make(map[string]poly.Polynomial, len(deps))
				pr.mu.Lock()
				for _, name := range deps {
					polys[name] = pr.t[name]
				}
				pr.mu.Unlock()

				// commit to them using FRI
				if err := pr.Committer.Commit(challengeName, polys); err != nil {
					return err
				}

				// derive 'challengeName' using fs, or sample a random element if EmulateFS is set,
				// then store the value in the trace under challengeName as a polynomial of size 1
				var challengeVal koalabear.Element
				if pr.config.EmulateFS {
					challengeVal.MustSetRandom()
				} else {
					challengeBytes, err := pr.fs.ComputeChallenge(challengeName)
					if err != nil {
						return err
					}
					challengeVal.SetBytes(challengeBytes)
				}

				pr.mu.Lock()
				pr.t[challengeName] = []koalabear.Element{challengeVal}
				pr.mu.Unlock()

				roundIdx++

				continue
			}
			err := s.Execute(pr.t, &pr.program, &pr.Proof, &pr.mu)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (pr *proverRuntime) ComputeAIRQuotients() error {

	// 1 - Compute the AIR quotient for each module in the Program.
	// The quotient is written in canonical (coefficient) form, split into chunks
	// of size n, and stored as Lagrange-normal polynomials in a dedicated trace.
	// We also keep a map from chunk name to its domain for later evaluation at zeta.
	airTrace := make(trace.Trace)
	chunkDomains := make(map[string]*fft.Domain)

	for moduleName, module := range pr.program.Modules {
		// compute quotient: VanishingRelation / (X^n - 1), returned in coset-Lagrange form
		quotient, err := poly.ComputeQuotient(pr.t, *module.VanishingRelation, module.N)
		if err != nil {
			return err
		}

		// convert from coset-Lagrange to standard Lagrange Normal form
		// TODO add a method to convert the quotient to canonical directly
		poly.CosetLagrangeToLagrangeNormal(quotient)

		// convert from Lagrange Normal to canonical (coefficient) form via IFFT
		bigSize := len(quotient)
		bigD := fft.NewDomain(uint64(bigSize))
		bigD.FFTInverse(quotient, fft.DIF)
		utils.BitReverse(quotient) // quotient[k] = k-th coefficient of H

		// split into chunks of size N; convert each chunk back to Lagrange Normal for commitment
		N := module.N
		numChunks := bigSize / N
		for i := range numChunks {
			chunk := make(poly.Polynomial, N)
			copy(chunk, quotient[i*N:(i+1)*N])
			module.D.FFT(chunk, fft.DIF)
			utils.BitReverse(chunk)
			chunkName := fmt.Sprintf("%s_%d", moduleName, i)
			airTrace[chunkName] = chunk
			chunkDomains[chunkName] = module.D
		}
	}

	// 2 - commit to the AIR quotient trace
	polysToCommit := make(map[string]poly.Polynomial, len(airTrace))
	for name, p := range airTrace {
		polysToCommit[name] = p
	}
	if err := pr.Committer.Commit(constants.FINAL_EVALUATION_POINT, polysToCommit); err != nil {
		return err
	}

	// 3 - derive zeta using FS (or emulate) after the quotient commitment has
	// already been bound by the FRI committer.
	var zetaVal koalabear.Element
	if pr.config.EmulateFS {
		zetaVal.MustSetRandom()
	} else {
		zetaBytes, err := pr.fs.ComputeChallenge(constants.FINAL_EVALUATION_POINT)
		if err != nil {
			return err
		}
		zetaVal.SetBytes(zetaBytes)
	}
	pr.zeta = zetaVal

	// evaluate each quotient chunk at zeta and store in ValuesAtZeta
	for chunkName, chunkPoly := range airTrace {
		pr.Proof.ValuesAtZeta[chunkName] = poly.Evaluate(chunkPoly, chunkDomains[chunkName], pr.zeta)
	}

	return nil
}

// ComputeEvaluationsAtZeta computes the evaluations at zeta of every polynomial
// appearing in every vanishing relation of every module.
func (pr *proverRuntime) ComputeEvaluationsAtZeta() error {

	// only CommittedColumn and RotatedColumn leaves need to be opened
	config := expr.NewConfig(expr.WithoutLagrangeColumns(), expr.WithoutChallenges(), expr.WithoutPublicColumns())

	for _, module := range pr.program.Modules {
		leaves := module.VanishingRelation.LeavesFull(config)
		for _, leaf := range leaves {
			// compute the evaluation point: zeta for committed columns,
			// omega^shift * zeta for rotated columns
			evalPoint := pr.zeta
			if leaf.Type == expr.RotatedColumn {
				shift := ((leaf.Shift % module.N) + module.N) % module.N
				var omegaPow koalabear.Element
				omegaPow.SetOne()
				for range shift {
					omegaPow.Mul(&omegaPow, &module.D.Generator)
				}
				evalPoint.Mul(&evalPoint, &omegaPow)
			}

			// fetch the polynomial from the trace using the leaf's bare name
			p, ok := pr.t[leaf.Name]
			if !ok {
				return fmt.Errorf("ComputeEvaluationsAtZeta: column %q not found in trace", leaf.Name)
			}

			// evaluate using poly.Evaluate (Lagrange interpolation on module.D)
			val := poly.Evaluate(p, module.D, evalPoint)

			// store result using leaf.String() as key
			pr.Proof.ValuesAtZeta[leaf.String()] = val
		}
	}
	return nil
}

func Prove(t trace.Trace, publicInputs proof.PublicInputs, program board.Program, opts ...Option) (proof.Proof, error) {

	var config Config
	for _, opt := range opts {
		err := opt(&config)
		if err != nil {
			return proof.Proof{}, err
		}
	}

	pr := newProverRuntime(t, publicInputs, program, config)

	// run ExecuteSteps
	if err := pr.ExecuteSteps(); err != nil {
		return proof.Proof{}, err
	}

	// run ComputeAIRQuotients
	if err := pr.ComputeAIRQuotients(); err != nil {
		return proof.Proof{}, err
	}

	// run ComputeEvaluationsAtZeta
	if err := pr.ComputeEvaluationsAtZeta(); err != nil {
		return proof.Proof{}, err
	}

	openingProof, err := pr.Committer.Prove()
	if err != nil {
		return proof.Proof{}, err
	}
	pr.Proof.CommitmentOpenings = openingProof

	return pr.Proof, nil
}
