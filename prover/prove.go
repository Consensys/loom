package prover

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"

	"github.com/consensys/giop/constants"
	"github.com/consensys/giop/crypto/dummycommitment"
	"github.com/consensys/giop/cs"
	"github.com/consensys/giop/expr"
	"github.com/consensys/giop/pas/univariate"
	proveractions "github.com/consensys/giop/prover_actions"
	"github.com/consensys/giop/trace"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/field/koalabear"
)

// Runtime contains the data needed to run the Program to generate the proof.
type Runtime struct {
	Program cs.Program
	Trace       trace.Trace
	Mu          sync.Mutex
}

func NewRuntime(cciop cs.Program, trace trace.Trace) Runtime {
	return Runtime{
		Program: cciop,
		Trace:       trace,
	}
}

// Kahn's style scheduler for Functions (with parallel schedule)
func (runtime *Runtime) Solve(knownColumns map[string]bool, proof *proveractions.Proof, nbWorker int) error {

	funcs := runtime.Program.DerivationPlan
	n := len(funcs)

	inDegree := make([]int32, n)
	consumers := make(map[string][]int)

	// Build dependency tracking
	for i, f := range funcs {
		leaves := proveractions.GetColumnsBaseId(f.Inputs)
		for _, l := range leaves {
			if !knownColumns[l] {
				inDegree[i]++
			}
			consumers[l] = append(consumers[l], i)
		}
	}

	readyQueue := make(chan int, n)
	// var mu sync.Mutex
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
						wg.Add(1) // whenever we populate teh chan, we need to add one more task to the wait group
						readyQueue <- j
					}
				}
			}

			wg.Done()
		}
	}

	// Seed initial ready functions before starting workers to avoid racing on inDegree reads
	for i := range funcs {
		if inDegree[i] == 0 {
			wg.Add(1) // whenever we populate teh chan, we need to add one more task to the wait group
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

// FinalChallenges returns the last challenges in the DAG whose nodes are
// {inputs: rounds[i].DependenciesChallenges, output: rounds[i].ChallengeName}
func FinalChallenges(rounds []proveractions.Round) []string {
	usedAsInput := make(map[string]bool)
	produced := make(map[string]bool)

	for _, f := range rounds {
		for _, in := range f.DependenciesChallenges {
			usedAsInput[in] = true
		}
		produced[f.ChallengeName] = true

	}

	finals := []string{}
	for v := range produced {
		if !usedAsInput[v] {
			finals = append(finals, v)
		}
	}

	return finals
}

// Fold all the constraints by sampling a random challenge, derived from the necessary data to ensure that this challenge
// cannot have been derived derived prior to any of the prover<->interactions and commitments
func (runtime *Runtime) DeriveFinalFoldingChallenge(proof *proveractions.Proof) error {

	// proof.VanishingRelation = runtime.Program.VanishingRelation

	// generate the folding challenge whose name is constants.FINAL_FOLDING_CHALLENGE, and which must be be bound to all the necessary
	// data to ensure it cannot have been derived prior to running all the previous IOPs and commitments

	// 1. create the dependencies of the folding challenge to all the polynomials not committed
	var round proveractions.Round
	round.ChallengeName = constants.FINAL_FOLDING_CHALLENGE
	leaves := runtime.Program.VanishingRelation.Leaves(expr.NewConfig(expr.WithoutChallenges(), expr.WithoutVirtualumns(), expr.WithoutRotatedColumns()))
	round.DependenciesCommittedColumns = make([]string, 0, len(leaves))
	for _, l := range leaves {
		if _, ok := proof.OpeningProofs[l]; !ok { // <- the column whose ID is l is not committed, we add it to bindings
			round.DependenciesCommittedColumns = append(round.DependenciesCommittedColumns, l)
		}
	}

	// 2. create the dependencies of the folding challenge to the challenges which are the outputs of the DAG whose inputs/outputs are challenges
	round.DependenciesChallenges = FinalChallenges(proof.Rounds)
	proof.Rounds = append(proof.Rounds, round)

	// Now 1. and 2. guarantee the order: now we know that teh challenge cannot have been generated prior to committing to everything and prior to running every sub protocols

	// 3. Commit to all the polynomials whose name matches round.DependenciesCommittedColumns. Record the commitments in the proof, and update FS along the way
	fs := fiatshamir.NewTranscript(sha256.New())
	err := fs.NewChallenge(constants.FINAL_FOLDING_CHALLENGE)
	if err != nil {
		return err
	}
	for _, id := range round.DependenciesCommittedColumns {
		poly, ok := runtime.Trace[id]
		if !ok {
			return fmt.Errorf("polynomial %s not found in the trace", id)
		}
		com, err := dummycommitment.Commit(poly)
		err = fs.Bind(constants.FINAL_FOLDING_CHALLENGE, com.Marshal())
		if err != nil {
			return err
		}
		proof.OpeningProofs[id] = dummycommitment.PackedProof{Digest: com}
	}

	// 4. Bind the challenge to the other challenges it depends on
	for _, id := range round.DependenciesChallenges {
		c, ok := runtime.Trace[id]
		if !ok {
			return fmt.Errorf("challenge %s not found in the trace", id)
		}
		cVal := c[0]
		err := fs.Bind(constants.FINAL_FOLDING_CHALLENGE, cVal.Marshal())
		if err != nil {
			return err
		}
	}

	// 5. Derive the challenge
	bc, err := fs.ComputeChallenge(constants.FINAL_FOLDING_CHALLENGE)
	if err != nil {
		return err
	}
	var c koalabear.Element
	c.SetBytes(bc)

	// 6. add the challenge as a constant column, since it might appear in other constraints
	return proveractions.NewColumn(runtime.Trace, constants.FINAL_FOLDING_CHALLENGE, []koalabear.Element{c}, &runtime.Mu)
}

// ComputeQuotient computes H:=runtime.Program.Relation(runtime.Trace)/X^N-1 and commit to it, and
//
//	and store it in the trace, it is needed to be opened later
func (runtime *Runtime) ComputeQuotient(proof *proveractions.Proof) error {

	H, err := univariate.ComputeQuotient(runtime.Trace, runtime.Program.VanishingRelation, runtime.Program.N)
	if err != nil {
		return fmt.Errorf("ComputeQuotient: %w", err)
	}

	// Convert from coset-Lagrange to standard Lagrange so Open can evaluate it correctly
	univariate.CosetLagrangeToLagrangeNormal(H)

	digest, err := dummycommitment.Commit(H)
	if err != nil {
		return err
	}
	proof.OpeningProofs[constants.FINAL_QUOTIENT] = dummycommitment.PackedProof{Digest: digest}

	// Store H in the trace so OpenCommitments can evaluate it at zeta later
	runtime.Trace[constants.FINAL_QUOTIENT] = H

	return nil
}

// DeriveOpeningChallenge register the final round for deriving the opening challenge, and compute it
func (runtime *Runtime) DeriveOpeningChallenge(proof *proveractions.Proof) (koalabear.Element, error) {

	// register the round in the proof
	var round proveractions.Round
	round.ChallengeName = constants.FINAL_EVALUATION_POINT
	round.DependenciesCommittedColumns = []string{constants.FINAL_QUOTIENT}
	round.DependenciesChallenges = []string{constants.FINAL_FOLDING_CHALLENGE}
	proof.Rounds = append(proof.Rounds, round)

	// derive the challenge, depending on :
	// * proof.OpeningProofs[constants.FINAL_QUOTIENT].Digest
	// * constants.FINAL_FOLDING_CHALLENGE
	// it guarantess that FINAL_FOLDING_CHALLENGE is the last derived challenge, and depends on everything that happens
	// before, since constants.FINAL_FOLDING_CHALLENGE depends on everything that happens before computing the quotient.
	fs := fiatshamir.NewTranscript(sha256.New())
	fs.NewChallenge(constants.FINAL_EVALUATION_POINT)

	// bind the quotient
	if _, ok := proof.OpeningProofs[constants.FINAL_QUOTIENT]; !ok {
		return koalabear.Element{}, fmt.Errorf("%s not found in the list of digests", constants.FINAL_QUOTIENT)
	}
	com := proof.OpeningProofs[constants.FINAL_QUOTIENT]
	err := fs.Bind(constants.FINAL_EVALUATION_POINT, com.Digest.Marshal())
	if err != nil {
		return koalabear.Element{}, err
	}

	// bind the folding challenge
	c, ok := runtime.Trace[constants.FINAL_FOLDING_CHALLENGE]
	if !ok {
		return koalabear.Element{}, fmt.Errorf("challenge %s not found in the trace", constants.FINAL_FOLDING_CHALLENGE)
	}
	cVal := c[0]
	err = fs.Bind(constants.FINAL_EVALUATION_POINT, cVal.Marshal())
	if err != nil {
		return koalabear.Element{}, err
	}

	// compute the challegne
	bzeta, err := fs.ComputeChallenge(constants.FINAL_EVALUATION_POINT)
	if err != nil {
		return koalabear.Element{}, err
	}
	var zeta koalabear.Element
	zeta.SetBytes(bzeta)

	// register zeta in the trace
	err = proveractions.NewColumn(runtime.Trace, constants.FINAL_EVALUATION_POINT, []koalabear.Element{zeta}, &runtime.Mu)
	if err != nil {
		return koalabear.Element{}, err
	}

	return zeta, nil
}

func (runtime *Runtime) OpenCommitments(proof *proveractions.Proof, zeta koalabear.Element) error {

	err := runtime.OpenNonShiftedCommitments(proof, zeta)
	if err != nil {
		return err
	}

	return runtime.OpenShiftedCommitments(proof, zeta)
}

// OpenCommitments open all columns at zeta
func (runtime *Runtime) OpenNonShiftedCommitments(proof *proveractions.Proof, zeta koalabear.Element) error {
	var err error
	for k, com := range proof.OpeningProofs {
		poly, ok := runtime.Trace[k]
		if !ok {
			return fmt.Errorf("column %s not found in the trace", k)
		}
		com.OpeningProof = make([]dummycommitment.OpeningProof, 1)
		com.OpeningProof[0], err = dummycommitment.Open(poly, zeta)
		if err != nil {
			return err
		}
		proof.OpeningProofs[k] = com
	}

	return nil
}

// OpenCommitments open all columns at zeta
func (runtime *Runtime) OpenShiftedCommitments(proof *proveractions.Proof, zeta koalabear.Element) error {

	// query the leaves corresponding to RotatedColumns
	leavesShifted := runtime.Program.VanishingRelation.Leaves(
		expr.NewConfig(expr.WithoutChallenges(), expr.WithoutVirtualumns(), expr.WithoutCommittedColumns()))
	leavesShifted = expr.RemoveDuplicates(leavesShifted)

	// open the RotatedColumns
	w, err := koalabear.Generator(uint64(proof.N))
	if err != nil {
		return err
	}
	for _, l := range leavesShifted {
		name, shift, err := constants.SplitShiftedName(l)
		if err != nil {
			return err
		}
		poly, ok := runtime.Trace[name]
		if !ok {
			return fmt.Errorf("column %s (shifted opening) not found in the trace", name)
		}
		com, ok := proof.OpeningProofs[name]
		if !ok {
			return fmt.Errorf("OpeningProofs %s (base of shifted opening) not found in the proof", name)
		}
		var zetaShifted koalabear.Element
		zetaShifted.Set(&w)
		absShift := shift
		if absShift < 0 {
			zetaShifted.Inverse(&zetaShifted)
			absShift = -absShift
		}
		zetaShifted.Exp(zetaShifted, big.NewInt(int64(absShift)))
		zetaShifted.Mul(&zeta, &zetaShifted) // w^shift·ζ
		openingProof, err := dummycommitment.Open(poly, zetaShifted)
		if err != nil {
			return err
		}
		openingProof.Shift = shift // preserve original signed shift
		com.OpeningProof = append(com.OpeningProof, openingProof)
		proof.OpeningProofs[name] = com
	}

	return nil
}

func (runtime *Runtime) Prove(knownColumns map[string]bool, nbWorkers int) (proveractions.Proof, error) {

	proof := proveractions.NewProof(runtime.Program.N)

	// 1. Solve
	err := runtime.Solve(knownColumns, &proof, nbWorkers)
	if err != nil {
		return proof, err
	}

	// 2. Derive folding challenge
	err = runtime.DeriveFinalFoldingChallenge(&proof)
	if err != nil {
		return proof, err
	}

	// 3. compute quotient, and store it in the trace
	err = runtime.ComputeQuotient(&proof)
	if err != nil {
		return proof, err
	}

	// 4. derive opening challenge
	zeta, err := runtime.DeriveOpeningChallenge(&proof)
	if err != nil {
		return proof, err
	}

	// 5. compute opening proof
	err = runtime.OpenCommitments(&proof, zeta)

	return proof, err
}
