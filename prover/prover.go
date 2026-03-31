package prover

import (
	"fmt"
	"sync"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/internal/constants"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/proof"
	"github.com/consensys/loom/trace"
)

type Config struct {
	EmulateFS bool
}

type Option func(c *Config) error

func EmulateFS() Option {
	return func(c *Config) error {
		c.EmulateFS = true
		return nil
	}
}

func Prove(t trace.Trace, program board.Program, opts ...Option) proof.Proof {

	var res proof.Proof
	res.CrossModulesLogupBus = make([]proof.CrossModulesLogupBus, len(program.CrossModulesLogupBus))
	copy(res.CrossModulesLogupBus, program.CrossModulesLogupBus)

	// 1. execute all the GenCol function of every module
	for _, module := range program.Modules {
		m := module
		for _, gen := range m.GenCol {
			gen.Gen(t, &m)
		}
	}

	mu := &sync.Mutex{}

	// defaultN is used as a fallback for steps (e.g. CountMultiplicity) that have no
	// module field; it is the N of an arbitrary module.
	defaultN := 0
	for _, m := range program.Modules {
		defaultN = m.N
		break
	}

	// 2. execute the CountMultiplicity, GrandProduct and Logup steps of each level,
	// using the api in internal/poly/iop_utils. Register the produced columns in the
	// trace, by the name given by the "output" field. Between each level, add a
	// constant column named "loom@challenge_<i>", with a random value, to emulate
	// FiatShamir.
	nSlots := max(len(program.CountMultiplicity), len(program.GrandProduct), len(program.Logup))
	for k := range nSlots {

		// CountMultiplicity steps for slot k
		if k < len(program.CountMultiplicity) {
			for _, cm := range program.CountMultiplicity[k] {
				res, err := poly.BuildMultiplicityPolynomial(t, cm.S, cm.T, cm.Sel, mu)
				if err != nil {
					panic(fmt.Sprintf("CountMultiplicity slot %d: %v", k, err))
				}
				if err := trace.RegisterColumn(t, cm.Output, res); err != nil {
					panic(fmt.Sprintf("register multiplicity column %s: %v", cm.Output, err))
				}
			}
		}

		// GrandProduct steps for slot k
		if k < len(program.GrandProduct) {
			for _, gp := range program.GrandProduct[k] {
				gpN := defaultN
				if m, ok := program.Modules[gp.Module]; ok {
					gpN = m.N
				}
				res, err := poly.BuildGrandProduct(t, gp.N, gp.D, gpN, mu)
				if err != nil {
					panic(fmt.Sprintf("GrandProduct slot %d, module %s: %v", k, gp.Module, err))
				}
				if err := trace.RegisterColumn(t, gp.Output, res); err != nil {
					panic(fmt.Sprintf("register grand product column %s: %v", gp.Output, err))
				}
			}
		}

		// Logup steps for slot k
		if k < len(program.Logup) {
			for _, lu := range program.Logup[k] {
				luN := defaultN
				if m, ok := program.Modules[lu.Module]; ok {
					luN = m.N
				}
				res, err := poly.BuildLogup(t, lu.E, lu.M, luN, mu)
				if err != nil {
					panic(fmt.Sprintf("Logup slot %d, module %s: %v", k, lu.Module, err))
				}
				if err := trace.RegisterColumn(t, lu.Output, res); err != nil {
					panic(fmt.Sprintf("register logup column %s: %v", lu.Output, err))
				}
			}
		}

		// emulate Fiat-Shamir: add a random constant column for challenge k
		var challengeVal koalabear.Element
		challengeVal.SetRandom()
		challengeCol := poly.Polynomial{challengeVal}
		challengeName := constants.CanonicalChallengeName(k)
		// ignore error: column may already exist if caller pre-seeded it
		_ = trace.RegisterColumn(t, challengeName, challengeCol)
	}

	// fill the buses
	for i, crossModulesLogupBus := range res.CrossModulesLogupBus {
		for j := 0; j < len(crossModulesLogupBus.Positive); j++ {
			m := program.Modules[crossModulesLogupBus.Positive[j].Module]
			n := m.N
			c := t[crossModulesLogupBus.Positive[j].Column]
			res.CrossModulesLogupBus[i].Positive[j].Value.Set(&c[n-1])
		}
		for j := 0; j < len(res.CrossModulesLogupBus[i].Negative); j++ {
			m := program.Modules[crossModulesLogupBus.Negative[j].Module]
			n := m.N
			c := t[crossModulesLogupBus.Negative[j].Column]
			res.CrossModulesLogupBus[i].Negative[j].Value.Set(&c[n-1])
		}
	}

	return res
}
