package verifier

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"

	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/iop/constants"
	"github.com/consensys/iop/crypto/dummycommitment"
	"github.com/consensys/iop/cs"
	"github.com/consensys/iop/pas/sym"
)

// Runtime stores the variables to plug in the final relation to check.
type Runtime struct {
	Varindex sym.VarIndex
	Vars     []koalabear.Element // variables appearing in the vanishing relation
	Zeta     koalabear.Element   // final opening point
}

// NewRunTime creates the NewRunTime and knownColumns, which are the committedColumns
func NewRunTime(proof *cs.Proof) Runtime {
	var res Runtime
	res.Varindex = make(sym.VarIndex)
	allLeaves := proof.VanishingRelation.Leaves(sym.NewConfig())
	allLeaves = sym.RemoveDuplicates(allLeaves)
	res.Vars = make([]koalabear.Element, len(allLeaves))
	for i, l := range allLeaves {
		fmt.Println(i)
		res.Varindex[l] = i
	}

	return res
}

// DeriveChallenge derive the challenge of corresponding to proof.Rounds[i]
func (runtime *Runtime) DeriveChallenge(proof *cs.Proof, i int) error {

	fs := fiatshamir.NewTranscript(sha256.New())

	// create the challenge
	err := fs.NewChallenge(proof.Rounds[i].ChallengeName)
	if err != nil {
		return err
	}

	// bind the challenge to its commitments dependencies
	for _, l := range proof.Rounds[i].DependenciesCommittedColumns {
		com, ok := proof.OpeningProofs[l]
		if !ok {
			return fmt.Errorf("commitment %s not registered in the proof", l)
		}
		fs.Bind(proof.Rounds[i].ChallengeName, com.Digest.Marshal())
	}

	// bind the challenge to its other challenges dependencies
	for _, l := range proof.Rounds[i].DependenciesChallenges {
		idx, ok := runtime.Varindex[l]
		if !ok {
			return fmt.Errorf("challenge %s not registered in varindex", l)
		}
		challenge := runtime.Vars[idx]
		fs.Bind(proof.Rounds[i].ChallengeName, challenge.Marshal())
	}

	// compute the challenge and store it in runtime.Vars
	bc, err := fs.ComputeChallenge(proof.Rounds[i].ChallengeName)
	if err != nil {
		return err
	}
	var c koalabear.Element
	c.SetBytes(bc)
	runtime.Vars[runtime.Varindex[proof.Rounds[i].ChallengeName]] = c

	return nil
}

// ComputeOpeningPoint compute the opening, depending on H, the quotient
func (runtime *Runtime) ComputeOpeningPoint(proof *cs.Proof) error {
	fs := fiatshamir.NewTranscript(sha256.New())
	fs.NewChallenge(constants.FINAL_EVALUATION_POINT)
	com, ok := proof.OpeningProofs[constants.FINAL_QUOTIENT]
	if !ok {
		return fmt.Errorf("%s not found in the list of commitments", constants.FINAL_QUOTIENT)
	}
	fs.Bind(constants.FINAL_EVALUATION_POINT, com.Digest.Marshal())
	bzeta, err := fs.ComputeChallenge(constants.FINAL_EVALUATION_POINT)
	if err != nil {
		return err
	}
	runtime.Zeta.SetBytes(bzeta)
	return nil
}

// ComputeChallenges compute challenges using Kahn's style scheduler.
// *The nodes are proof.Rounds
// * node input are DependenciesChallenges
// * node output is ChallengeName
func (runtime *Runtime) ComputeChallenges(proof *cs.Proof, nbWorkers int) error {

	// nodes which do not depend on other challenges have inDegree 0 by construction, these are the nodes which do not
	// depend on other challenges.
	known := make(map[string]bool)

	nodes := proof.Rounds
	n := len(nodes)

	inDegree := make([]int32, n)
	consumers := make(map[string][]int)

	// Build dependency tracking
	for i, node := range nodes {
		for _, l := range node.DependenciesChallenges { // no need to check node.DependenciesCommittedColumns because they are by default set to true
			if !known[l] {
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
			err := runtime.DeriveChallenge(proof, i)
			if err != nil {
				panic(err)
			}

			atomic.AddInt32(&executed, 1)

			// Mark outputs known and release consumers
			out := nodes[i].ChallengeName
			known[nodes[i].ChallengeName] = true
			for _, j := range consumers[out] {
				if atomic.AddInt32(&inDegree[j], -1) == 0 {
					wg.Add(1) // whenever we populate teh chan, we need to add one more task to the wait group
					readyQueue <- j
				}
			}

			wg.Done()
		}
	}

	// Start workers
	for i := 0; i < nbWorkers; i++ {
		go worker()
	}

	// Seed initial ready functions
	for i := range nodes {
		if inDegree[i] == 0 {
			wg.Add(1) // whenever we populate teh chan, we need to add one more task to the wait group
			readyQueue <- i
		}
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

// EvaluateComputableColumns evaluates the computable columns at zeta and populates the list of vars
// corresponding to those columns
func (runtime *Runtime) EvaluateComputableColumns(proof *cs.Proof) error {

	ccLeaves := proof.VanishingRelation.Leaves(sym.NewConfig(sym.WithoutChallenges(), sym.WithoutCommittedColumns()))
	ccLeaves = sym.RemoveDuplicates(ccLeaves)

	for _, l := range ccLeaves {
		cc, err := cs.GetComputationableColumn(l)
		if err != nil {
			return err
		}
		val := cc.F(runtime.Zeta)
		_, ok := runtime.Varindex[l]
		if !ok {
			return fmt.Errorf("%s does not appear in the verifier var index", l)
		}
		runtime.Vars[runtime.Varindex[l]] = val
	}

	return nil
}

// FillClaimedValues fill runtime.Vars with the claimed values from the prover
func (runtime *Runtime) FillClaimedValues(proof *cs.Proof) error {

	ccLeaves := proof.VanishingRelation.Leaves(sym.NewConfig(sym.WithoutChallenges(), sym.WithoutComputableColumns()))
	ccLeaves = sym.RemoveDuplicates(ccLeaves)

	for _, l := range ccLeaves {
		com, ok := proof.OpeningProofs[l]
		if !ok {
			return fmt.Errorf("Opening proof for column %s not found in proof", l)
		}
		runtime.Vars[runtime.Varindex[l]] = com.OpeningProof.ClaimedValue
	}

	return nil
}

// CheckRelation checks the final relation: proof.VanishingRelation(zeta)=H(zeta)(zeta^N-1)
func (runtime *Runtime) CheckRelation(proof *cs.Proof) error {

	zeta := runtime.Zeta

	comh, ok := proof.OpeningProofs[constants.FINAL_QUOTIENT]
	if !ok {
		return fmt.Errorf("%s does not appear in teh list of commitments", constants.FINAL_QUOTIENT)
	}
	hzeta := comh.OpeningProof.ClaimedValue

	var zetaNMinusOne koalabear.Element
	one := koalabear.One()
	zetaNMinusOne.Set(&zeta).Exp(zetaNMinusOne, big.NewInt(int64(proof.N))).Sub(&zetaNMinusOne, &one)

	Q := sym.ToHorner(sym.Convert(proof.VanishingRelation, runtime.Varindex, len(runtime.Varindex)))
	vanishingConstraintAtZeta := Q.Eval(runtime.Vars)

	hzeta.Mul(&zetaNMinusOne, &hzeta)
	if !vanishingConstraintAtZeta.Equal(&hzeta) {
		return fmt.Errorf("algebraic relation does not hold")
	}

	return nil
}

func (runtime *Runtime) VerifyOpeningProofs(proof *cs.Proof) error {
	_, ok := runtime.Varindex[constants.FINAL_EVALUATION_POINT]
	if !ok {
		return fmt.Errorf("%s does not appear in the verifier var index", constants.FINAL_EVALUATION_POINT)
	}
	zeta := runtime.Vars[runtime.Varindex[constants.FINAL_EVALUATION_POINT]]
	for _, op := range proof.OpeningProofs {
		err := dummycommitment.Verify(op.Digest, op.OpeningProof, zeta)
		if err != nil {
			return err
		}
	}
	return nil
}

func (runtime *Runtime) Verify(proof *cs.Proof) error {

	err := runtime.ComputeChallenges(proof, 1)
	if err != nil {
		return err
	}

	err = runtime.ComputeOpeningPoint(proof)
	if err != nil {
		return err
	}

	err = runtime.EvaluateComputableColumns(proof)
	if err != nil {
		return err
	}

	err = runtime.FillClaimedValues(proof)
	if err != nil {
		return err
	}

	err = runtime.CheckRelation(proof)
	if err != nil {
		return err
	}

	err = runtime.VerifyOpeningProofs(proof)

	return err
}
