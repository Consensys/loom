package prover

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"

	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/constraint"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/internal/commitment"
	"github.com/consensys/loom/internal/constants"
	derive "github.com/consensys/loom/internal/derive"
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

// Kahn's style scheduler for Functions (with parallel schedule)
func (runtime *Prover) Solve(knownColumns map[string]bool, proof *derive.Proof, nbWorker int) error {

	funcs := runtime.Program.DerivationPlan
	n := len(funcs)

	inDegree := make([]int32, n)
	consumers := make(map[string][]int)

	// Build dependency tracking
	for i, f := range funcs {
		leaves := derive.GetColumnsBaseId(f.Inputs)
		for _, l := range leaves {
			if !knownColumns[l] {
				inDegree[i]++
			}
			consumers[l] = append(consumers[l], i)
		}
	}

	readyQueue := make(chan int, n)
	var wg sync.WaitGroup

	// Count how many functions executed
	var executed int32

	// Worker logic
	worker := func() {
		for i := range readyQueue {
			err := funcs[i].Execute(runtime.Trace, proof, &runtime.Mu)
			if err != nil {
				panic(err)
			}

			atomic.AddInt32(&executed, 1)

			// Mark outputs known and release consumers
			for _, out := range funcs[i].Outputs {
				runtime.Mu.Lock()
				knownColumns[out] = true
				runtime.Mu.Unlock()

				for _, j := range consumers[out] {
					if atomic.AddInt32(&inDegree[j], -1) == 0 {
						wg.Add(1)
						readyQueue <- j
					}
				}
			}

			wg.Done()
		}
	}

	// Seed initial ready functions before starting workers
	for i := range funcs {
		if inDegree[i] == 0 {
			wg.Add(1)
			readyQueue <- i
		}
	}

	// Start workers
	for i := 0; i < nbWorker; i++ {
		go worker()
	}

	// Wait until all scheduled work completes
	wg.Wait()
	close(readyQueue)

	// Detect cycle / unsatisfied dependencies
	if int(executed) != n {
		return fmt.Errorf("cycle detected or missing initialization")
	}

	return nil
}

// DeriveFinalFoldingChallenge commits all columns not yet committed, derives the
// folding challenge, and stores it in the trace.
func (runtime *Prover) DeriveFinalFoldingChallenge(proof *derive.Proof) error {

	// 1. Collect all committed-column leaves in the vanishing relation that have
	//    not yet been included in any batch commitment.
	leaves := runtime.Program.VanishingRelation.Leaves(
		expr.NewConfig(expr.WithoutChallenges(), expr.WithoutVirtualumns(), expr.WithoutRotatedColumns()))

	var polys []poly.Polynomial
	var colNames []string
	seen := make(map[string]bool)
	for _, l := range leaves {
		if seen[l] || proof.IsColumnCommitted(l) {
			continue
		}
		seen[l] = true
		p, ok := runtime.Trace[l]
		if !ok {
			return fmt.Errorf("polynomial %s not found in the trace", l)
		}
		if publicInfo, ok := runtime.PublicInputs[l]; ok {
			buf := make([]koalabear.Element, proof.N)
			copy(buf, p)
			for _, idx := range publicInfo.Idx {
				buf[idx].SetZero()
			}
			polys = append(polys, buf)
		} else {
			polys = append(polys, p)
		}
		colNames = append(colNames, l)
	}

	// 2. Batch-commit.
	batch, err := commitment.CommitBatch(polys)
	if err != nil {
		return err
	}
	batchIdx := len(proof.Batch)
	proof.Batch = append(proof.Batch, batch)
	proof.BatchColumns = append(proof.BatchColumns, colNames)

	// 3. Record the transcript round.
	proof.TranscriptRounds = append(proof.TranscriptRounds, derive.TranscriptRound{
		ChallengeName:   constants.FINAL_FOLDING_CHALLENGE,
		DependencyBatch: batchIdx,
	})

	// 4. Build FS transcript: bind batch digest + all previously derived challenges.
	fs := fiatshamir.NewTranscript(sha256.New())
	if err := fs.NewChallenge(constants.FINAL_FOLDING_CHALLENGE); err != nil {
		return err
	}
	if err := fs.Bind(constants.FINAL_FOLDING_CHALLENGE, batch.Marshal()); err != nil {
		return err
	}
	for _, prevRound := range proof.TranscriptRounds[:len(proof.TranscriptRounds)-1] {
		c, ok := runtime.Trace[prevRound.ChallengeName]
		if !ok {
			return fmt.Errorf("challenge %s not found in the trace", prevRound.ChallengeName)
		}
		if err := fs.Bind(constants.FINAL_FOLDING_CHALLENGE, c[0].Marshal()); err != nil {
			return err
		}
	}

	// 5. Derive challenge.
	bc, err := fs.ComputeChallenge(constants.FINAL_FOLDING_CHALLENGE)
	if err != nil {
		return err
	}
	var c koalabear.Element
	c.SetBytes(bc)
	return derive.NewColumn(runtime.Trace, constants.FINAL_FOLDING_CHALLENGE, []koalabear.Element{c}, &runtime.Mu)
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

	proof.TranscriptRounds = append(proof.TranscriptRounds, derive.TranscriptRound{
		ChallengeName:   constants.FINAL_EVALUATION_POINT,
		DependencyBatch: lastBatchIdx,
	})

	fs := fiatshamir.NewTranscript(sha256.New())
	if err := fs.NewChallenge(constants.FINAL_EVALUATION_POINT); err != nil {
		return koalabear.Element{}, err
	}
	if err := fs.Bind(constants.FINAL_EVALUATION_POINT, proof.Batch[lastBatchIdx].Marshal()); err != nil {
		return koalabear.Element{}, err
	}
	// Bind all previously derived challenge values (all rounds except the current one).
	for _, prevRound := range proof.TranscriptRounds[:len(proof.TranscriptRounds)-1] {
		c, ok := runtime.Trace[prevRound.ChallengeName]
		if !ok {
			return koalabear.Element{}, fmt.Errorf("challenge %s not found in the trace", prevRound.ChallengeName)
		}
		if err := fs.Bind(constants.FINAL_EVALUATION_POINT, c[0].Marshal()); err != nil {
			return koalabear.Element{}, err
		}
	}

	bzeta, err := fs.ComputeChallenge(constants.FINAL_EVALUATION_POINT)
	if err != nil {
		return koalabear.Element{}, err
	}
	var zeta koalabear.Element
	zeta.SetBytes(bzeta)

	if err := derive.NewColumn(runtime.Trace, constants.FINAL_EVALUATION_POINT, []koalabear.Element{zeta}, &runtime.Mu); err != nil {
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

	proof.OpeningProofs = make([]commitment.BatchOpeningProof, 0, len(proof.Batch))
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
		op, err := commitment.BatchOpen(proof.Batch[batchIdx], polys, zeta, shifts)
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

func (runtime *Prover) Prove(knownColumns map[string]bool, nbWorkers int) (derive.Proof, error) {

	proof := derive.NewProof(runtime.Program.N)

	if err := runtime.FillPublicValues(); err != nil {
		return proof, err
	}

	if err := runtime.Solve(knownColumns, &proof, nbWorkers); err != nil {
		return proof, err
	}

	if err := runtime.DeriveFinalFoldingChallenge(&proof); err != nil {
		return proof, err
	}

	if err := runtime.ComputeQuotient(&proof); err != nil {
		return proof, err
	}

	zeta, err := runtime.DeriveOpeningChallenge(&proof)
	if err != nil {
		return proof, err
	}

	err = runtime.OpenCommitments(&proof, zeta)
	return proof, err
}
