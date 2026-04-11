package prover

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

// func Prove(t trace.Trace, program board.Program, opts ...Option) (proof.Proof, error) {

// 	var res proof.Proof
// 	res.LogupBus = make([]proof.LogupBus, len(program.LogupBus))
// 	copy(res.LogupBus, program.LogupBus)

// 	// 1. execute all the GenCol function of every module
// 	for _, module := range program.Modules {
// 		m := module
// 		for _, gen := range m.GenCol {
// 			gen.Gen(t, &m)
// 		}
// 	}

// 	mu := &sync.Mutex{}

// 	// 2. execute the CountMultiplicity, GrandProduct and Logup steps of each level,
// 	// using the api in internal/poly/iop_utils. Register the produced columns in the
// 	// trace, by the name given by the "output" field. Between each level, add a
// 	// constant column named "loom@challenge_<i>", with a random value, to emulate
// 	// FiatShamir.
// 	// nSlots := max(len(program.CountMultiplicity), len(program.GrandProduct), len(program.Logup))
// 	nSlots := len(program.Steps)
// 	for k := range nSlots {

// 		for _, s := range program.Steps[k] {
// 			if err := s.Execute(t, &res, &program, mu, s.Ctx); err != nil {
// 				return res, err
// 			}
// 		}

// 		// emulate Fiat-Shamir: add a random constant column for challenge k
// 		var challengeVal koalabear.Element
// 		challengeVal.SetRandom()
// 		challengeCol := poly.Polynomial{challengeVal}
// 		challengeName := constants.CanonicalChallengeName(k)
// 		// ignore error: column may already exist if caller pre-seeded it
// 		_ = trace.RegisterColumn(t, challengeName, challengeCol)
// 	}

// 	// 3. fill the buses
// 	// for i, crossModulesLogupBus := range res.LogupBus {
// 	// 	for j := 0; j < len(crossModulesLogupBus.Positive); j++ {
// 	// 		m := program.Modules[crossModulesLogupBus.Positive[j].Module]
// 	// 		n := m.N
// 	// 		c := t[crossModulesLogupBus.Positive[j].Column]
// 	// 		res.LogupBus[i].Positive[j].CumulatedSum.Set(&c[n-1])
// 	// 	}
// 	// 	for j := 0; j < len(res.LogupBus[i].Negative); j++ {
// 	// 		m := program.Modules[crossModulesLogupBus.Negative[j].Module]
// 	// 		n := m.N
// 	// 		c := t[crossModulesLogupBus.Negative[j].Column]
// 	// 		res.LogupBus[i].Negative[j].CumulatedSum.Set(&c[n-1])
// 	// 	}
// 	// }

// 	// 4. Compute the quotients
// 	// for _, m := range program.Modules {

// 	// }

// 	return res, nil
// }
