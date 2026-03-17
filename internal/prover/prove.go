package prover

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"sync"

	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/constraint"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/commitment"
	"github.com/consensys/loom/internal/constants"
	derive "github.com/consensys/loom/internal/derive"
	"github.com/consensys/loom/internal/parallel"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/trace"
)

// Prover contains the data needed to run the Program to generate the proof.
type Prover struct {
	Program      constraint.Program
	Trace        trace.Trace
	PublicInputs derive.PublicInputs
	Mu           sync.Mutex
}

func NewProver(cp constraint.Program, trace trace.Trace, publicInputs derive.PublicInputs) Prover {
	res := Prover{
		Program:      cp,
		Trace:        trace,
		PublicInputs: publicInputs,
	}
	if res.PublicInputs == nil {
		res.PublicInputs = make(derive.PublicInputs)
	}
	return res
}

// commitAndDeriveChallenge commits the polynomials listed in Program.Batches[batchIdx],
// records the batch in proof, and derives a Fiat-Shamir challenge whose name is
// challengeName.  The FS transcript binds the batch digest followed by all previously
// derived challenge values, matching the verifier's replay order.
func (runtime *Prover) commitAndDeriveChallenge(batchIdx int, proof *derive.Proof) error {
	colNames := runtime.Program.Batches[batchIdx]

	// 1. Build polynomial list, zeroing public-input positions before committing.
	polys := make([]poly.Polynomial, len(colNames))
	for i, name := range colNames {
		p, ok := runtime.Trace[name]
		if !ok {
			return fmt.Errorf("polynomial %s not found in the trace", name)
		}
		if publicInfo, ok := runtime.PublicInputs[name]; ok {
			buf := make([]koalabear.Element, proof.N)
			copy(buf, p)
			for _, idx := range publicInfo.Idx {
				buf[idx].SetZero()
			}
			polys[i] = buf
		} else {
			polys[i] = p
		}
	}

	// 2. Batch-commit.
	batch, err := commitment.CommitBatch(polys)
	if err != nil {
		return err
	}
	proof.Batch = append(proof.Batch, batch)
	proof.BatchColumns = append(proof.BatchColumns, colNames)

	// 3. Build FS transcript: bind batch digest + previously derived challenge.
	challengeName := constants.CanonicalChallengeName(batchIdx)
	// Order matches the verifier's DeriveChallenge: batch first, then prev challenge in order.
	fs := fiatshamir.NewTranscript(sha256.New())
	if err := fs.NewChallenge(challengeName); err != nil {
		return err
	}
	if len(runtime.Program.Batches[batchIdx]) > 0 {
		if err := fs.Bind(challengeName, batch.Marshal()); err != nil {
			return err
		}
	}
	if batchIdx > 0 {
		prevChallengeName := constants.CanonicalChallengeName(batchIdx - 1)
		prevChallenge, ok := runtime.Trace[prevChallengeName]
		if !ok {
			return fmt.Errorf("challenge %s not found in the trace", prevChallengeName)
		}
		if err := fs.Bind(challengeName, prevChallenge[0].Marshal()); err != nil {
			return err
		}
	}

	// 4. Derive and store challenge.
	bc, err := fs.ComputeChallenge(challengeName)
	if err != nil {
		return err
	}
	var c koalabear.Element
	c.SetBytes(bc)
	return derive.NewColumn(runtime.Trace, challengeName, []koalabear.Element{c}, &runtime.Mu)
}

// DeriveFinalFoldingChallenge commits the columns in Program.Batches[last], derives
// the folding challenge, and stores it in the trace.
// It returns the committed column names.
func (runtime *Prover) DeriveFinalFoldingChallenge(proof *derive.Proof) ([]string, error) {
	lastBatchIdx := len(runtime.Program.Batches) - 1
	colNames := runtime.Program.Batches[lastBatchIdx]
	return colNames, runtime.commitAndDeriveChallenge(lastBatchIdx, proof)
}

// ComputeQuotient computes H := VanishingRelation / (X^N - 1), commits to it as a
// 1-element batch, and stores it in the trace for later opening.
func (runtime *Prover) ComputeQuotient(proof *derive.Proof) error {

	H, err := poly.ComputeQuotient(runtime.Trace, runtime.Program.VanishingRelation, runtime.Program.N)
	if err != nil {
		return fmt.Errorf("ComputeQuotient: %w", err)
	}
	poly.CosetLagrangeToLagrangeNormal(H)

	batch, err := commitment.CommitBatch([]poly.Polynomial{H})
	if err != nil {
		return err
	}
	proof.Batch = append(proof.Batch, batch)
	proof.BatchColumns = append(proof.BatchColumns, []string{constants.FINAL_QUOTIENT})

	runtime.Trace[constants.FINAL_QUOTIENT] = H
	return nil
}

// DeriveOpeningChallenge derives zeta from the quotient batch commitment and all
// previously derived challenge values.
func (runtime *Prover) DeriveOpeningChallenge(proof *derive.Proof) (koalabear.Element, error) {

	lastBatchIdx := len(proof.Batch) - 1

	challengeName := constants.CanonicalChallengeName(len(proof.BatchColumns) - 1)

	fs := fiatshamir.NewTranscript(sha256.New())
	if err := fs.NewChallenge(challengeName); err != nil {
		return koalabear.Element{}, err
	}
	// Bind quotient batch (always non-empty).
	if err := fs.Bind(challengeName, proof.Batch[lastBatchIdx].Marshal()); err != nil {
		return koalabear.Element{}, err
	}
	// Bind only the immediately preceding challenge (the final folding challenge).
	if nRounds := len(proof.BatchColumns) - 1; nRounds > 0 {
		prevName := constants.CanonicalChallengeName(nRounds - 1)
		c, ok := runtime.Trace[prevName]
		if !ok {
			return koalabear.Element{}, fmt.Errorf("challenge %s not found in the trace", prevName)
		}
		if err := fs.Bind(challengeName, c[0].Marshal()); err != nil {
			return koalabear.Element{}, err
		}
	}

	bzeta, err := fs.ComputeChallenge(challengeName)
	if err != nil {
		return koalabear.Element{}, err
	}
	var zeta koalabear.Element
	zeta.SetBytes(bzeta)

	if err := derive.NewColumn(runtime.Trace, challengeName, []koalabear.Element{zeta}, &runtime.Mu); err != nil {
		return koalabear.Element{}, err
	}
	return zeta, nil
}

// OpenCommitments opens every batch at zeta (and at ω^shift · zeta for rotated columns).
func (runtime *Prover) OpenCommitments(proof *derive.Proof, zeta koalabear.Element) error {

	// Build a map: base column name → set of shifts needed (always includes 0).
	shiftsNeeded := make(map[string]map[int]bool)
	for _, cols := range proof.BatchColumns {
		for _, col := range cols {
			if _, ok := shiftsNeeded[col]; !ok {
				shiftsNeeded[col] = map[int]bool{0: true}
			}
		}
	}
	// Add rotated shifts from VanishingRelation.
	for _, leafFull := range runtime.Program.VanishingRelation.LeavesFull(expr.NewConfig(expr.OnlyRotatedColumns...)) {
		if leafFull.Shift != 0 {
			if _, ok := shiftsNeeded[leafFull.Name]; ok {
				shiftsNeeded[leafFull.Name][leafFull.Shift] = true
			}
		}
	}

	proof.OpeningProofs = make([]commitment.BatchProofOpening, 0, len(proof.Batch))
	for batchIdx, colNames := range proof.BatchColumns {
		polys := make([]poly.Polynomial, len(colNames))
		shifts := make([][]int, len(colNames))
		for polyIdx, colName := range colNames {
			p, ok := runtime.Trace[colName]
			if !ok {
				return fmt.Errorf("column %s not found in the trace", colName)
			}
			// Open the polynomial so the verifier receives the true evaluation
			// needed to check the vanishing relation. Careful to zeroing the public inputs
			if info, ok := runtime.PublicInputs[colName]; ok {
				buf := make([]koalabear.Element, len(p))
				copy(buf, p)
				for _, idx := range info.Idx {
					buf[idx].SetZero()
				}
				p = buf
			}
			polys[polyIdx] = p
			for s := range shiftsNeeded[colName] {
				shifts[polyIdx] = append(shifts[polyIdx], s)
			}
			sort.Ints(shifts[polyIdx])
		}
		op, err := commitment.OpenBatch(proof.Batch[batchIdx], polys, zeta, shifts)
		if err != nil {
			return err
		}
		proof.OpeningProofs = append(proof.OpeningProofs, op)
	}
	return nil
}

// FillPublicValues fills the public values in the trace.
func (runtime *Prover) FillPublicValues() error {
	for k, info := range runtime.PublicInputs {
		p, ok := runtime.Trace[k]
		if !ok {
			return fmt.Errorf("%s not found in the trace", k)
		}
		for i, idx := range info.Idx {
			p[idx].Set(&info.Vals[i])
		}
	}
	return nil
}

func (runtime *Prover) DerivePlan(proof *derive.Proof, nbWorker int) error {

	for i, steps := range runtime.Program.DerivationPlanScheduled {
		parallel.Execute(len(steps), func(start, end int) {
			for j := start; j < end; j++ {
				if err := steps[j].Execute(runtime.Trace, proof, &runtime.Mu); err != nil {
					panic(err)
				}
			}
		}, nbWorker)

		if err := runtime.commitAndDeriveChallenge(i, proof); err != nil {
			return err
		}
	}

	return nil
}

func (runtime *Prover) Prove(nbWorkers int) (derive.Proof, error) {

	proof := derive.NewProof(runtime.Program.N)

	if err := runtime.FillPublicValues(); err != nil {
		return proof, err
	}

	if err := runtime.DerivePlan(&proof, nbWorkers); err != nil {
		return proof, err
	}

	if err := runtime.ComputeQuotient(&proof); err != nil {
		return proof, err
	}

	zeta, err := runtime.DeriveOpeningChallenge(&proof)
	if err != nil {
		return proof, err
	}

	return proof, runtime.OpenCommitments(&proof, zeta)
}
