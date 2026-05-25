// Copyright Consensys Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// Package recursion builds Loom proofs whose constraints check the algebraic
// core of another Loom verifier invocation.
//
// The current wrapper is specialized to a concrete inner proof rather than a
// universal proof-bytes verifier. It arithmetizes public-column reconstruction,
// Lagrange values, logup bus checks, AIR quotient identities, the
// DEEP-quotient-to-FRI bridge, FRI folding arithmetic, Poseidon2 transcript
// reconstruction, and Poseidon2 Merkle paths for that proof. ProveNextLayer
// still native-verifies the full inner proof before producing the recursive
// wrapper.
package recursion

import (
	"fmt"
	"math/big"
	"sort"

	"github.com/consensys/gnark-crypto/field/koalabear"
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/loom/board"
	"github.com/consensys/loom/expr"
	"github.com/consensys/loom/field"
	"github.com/consensys/loom/internal/commitment"
	"github.com/consensys/loom/internal/constants"
	"github.com/consensys/loom/internal/dag"
	fiatshamir "github.com/consensys/loom/internal/fiat-shamir"
	"github.com/consensys/loom/internal/fri"
	"github.com/consensys/loom/internal/hash"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/proof"
	"github.com/consensys/loom/prover"
	"github.com/consensys/loom/public"
	"github.com/consensys/loom/setup"
	"github.com/consensys/loom/trace"
	"github.com/consensys/loom/verifier"
)

const verifierCoreModule = "loom_recursion_core"

// RecursionInput is the proof and verifier context for one recursion step.
type RecursionInput struct {
	Program      board.Program
	Setup        setup.VerificationKey
	PublicInputs public.Inputs
	Proof        proof.Proof
}

// RecursionOutput is the next-layer Loom proof and the specialized verifier
// program it proves.
type RecursionOutput struct {
	Program board.Program
	Proof   proof.Proof
}

// AggregationInput holds the two proofs folded into one recursive wrapper.
type AggregationInput struct {
	Left  RecursionInput
	Right RecursionInput
}

type Config struct {
	verifyInner          bool
	innerVerifierOpts    []verifier.Option
	outerProverOpts      []prover.Option
	outerVerifierOpts    []verifier.Option
	hashBackend          commitment.HashBackend
	forceSkipInnerFRI    bool
	forceSkipOuterFRI    bool
	forceSkipOuterCheck  bool
	arithmetizePoseidon2 bool
}

// Option configures ProveNextLayer.
type Option func(*Config)

// WithoutInnerVerification skips the native verifier precheck.
//
// This is useful for testing that the generated outer Loom program rejects
// bad algebraic verifier-core equations. It should not be used by callers that
// want a recursive wrapper for a complete Loom proof.
func WithoutInnerVerification() Option {
	return func(c *Config) {
		c.verifyInner = false
	}
}

// SkipInnerFRI verifies only the inner verifier's algebraic core before
// producing the next layer.
func SkipInnerFRI() Option {
	return func(c *Config) {
		c.forceSkipInnerFRI = true
		c.innerVerifierOpts = append(c.innerVerifierOpts, verifier.SkipFRI())
	}
}

// SkipOuterFRI proves the recursive wrapper without the outer FRI phase.
func SkipOuterFRI() Option {
	return func(c *Config) {
		c.forceSkipOuterFRI = true
		c.outerProverOpts = append(c.outerProverOpts, prover.SkipFRI())
		c.outerVerifierOpts = append(c.outerVerifierOpts, verifier.SkipFRI())
	}
}

// UsePoseidon2 explicitly selects Loom's Poseidon2 hash backend for the inner
// verifier precheck, recursive wrapper proof, and verifier-core transcript
// reconstruction. Poseidon2 is Loom's default backend on current main, so this
// option is mostly kept for recursion callers that want an explicit setting.
func UsePoseidon2() Option {
	return func(c *Config) {
		backend := commitment.Poseidon2HashBackend()
		c.arithmetizePoseidon2 = true
		c.hashBackend = backend
		c.innerVerifierOpts = append(c.innerVerifierOpts, verifier.WithHashBackend(backend))
		c.outerProverOpts = append(c.outerProverOpts, prover.WithHashBackend(backend))
		c.outerVerifierOpts = append(c.outerVerifierOpts, verifier.WithHashBackend(backend))
	}
}

func defaultConfig() Config {
	return Config{verifyInner: true, arithmetizePoseidon2: true}
}

// ProveNextLayer native-verifies input.Proof and then proves, with Loom, that
// the inner verifier's algebraic core is satisfied.
func ProveNextLayer(input RecursionInput, opts ...Option) (RecursionOutput, error) {
	config := defaultConfig()
	for _, opt := range opts {
		opt(&config)
	}

	if config.verifyInner {
		if err := verifier.Verify(input.PublicInputs, input.Setup, input.Program, input.Proof, config.innerVerifierOpts...); err != nil {
			return RecursionOutput{}, fmt.Errorf("recursion: inner proof rejected: %w", err)
		}
	}

	program, tr, err := buildVerifierCore(input, config)
	if err != nil {
		return RecursionOutput{}, err
	}

	prf, err := prover.Prove(tr, setup.ProvingKey{}, nil, program, config.outerProverOpts...)
	if err != nil {
		return RecursionOutput{}, fmt.Errorf("recursion: prove next layer: %w", err)
	}

	if !config.forceSkipOuterCheck {
		if err := verifier.Verify(nil, setup.VerificationKey{}, program, prf, config.outerVerifierOpts...); err != nil {
			return RecursionOutput{}, fmt.Errorf("recursion: generated outer proof rejected: %w", err)
		}
	}

	return RecursionOutput{Program: program, Proof: prf}, nil
}

// VerifyOutput verifies a recursive wrapper proof.
func VerifyOutput(output RecursionOutput, opts ...verifier.Option) error {
	return verifier.Verify(nil, setup.VerificationKey{}, output.Program, output.Proof, opts...)
}

// ProveAggregationLayer creates one Loom proof whose verifier-core constraints
// check both input proofs.
func ProveAggregationLayer(input AggregationInput, opts ...Option) (RecursionOutput, error) {
	config := defaultConfig()
	for _, opt := range opts {
		opt(&config)
	}

	if config.verifyInner {
		if err := verifier.Verify(input.Left.PublicInputs, input.Left.Setup, input.Left.Program, input.Left.Proof, config.innerVerifierOpts...); err != nil {
			return RecursionOutput{}, fmt.Errorf("recursion: left inner proof rejected: %w", err)
		}
		if err := verifier.Verify(input.Right.PublicInputs, input.Right.Setup, input.Right.Program, input.Right.Proof, config.innerVerifierOpts...); err != nil {
			return RecursionOutput{}, fmt.Errorf("recursion: right inner proof rejected: %w", err)
		}
	}

	program, tr, err := buildAggregationCore(input, config)
	if err != nil {
		return RecursionOutput{}, err
	}

	prf, err := prover.Prove(tr, setup.ProvingKey{}, nil, program, config.outerProverOpts...)
	if err != nil {
		return RecursionOutput{}, fmt.Errorf("recursion: prove aggregation layer: %w", err)
	}

	if !config.forceSkipOuterCheck {
		if err := verifier.Verify(nil, setup.VerificationKey{}, program, prf, config.outerVerifierOpts...); err != nil {
			return RecursionOutput{}, fmt.Errorf("recursion: generated aggregation proof rejected: %w", err)
		}
	}

	return RecursionOutput{Program: program, Proof: prf}, nil
}

// BuildVerifierCore returns a specialized Loom program and trace whose witness
// columns satisfy the inner verifier's algebraic core for input.
func BuildVerifierCore(input RecursionInput, opts ...Option) (board.Program, trace.Trace, error) {
	config := defaultConfig()
	for _, opt := range opts {
		opt(&config)
	}
	return buildVerifierCore(input, config)
}

func buildVerifierCore(input RecursionInput, config Config) (board.Program, trace.Trace, error) {
	state, err := deriveVerifierState(input, config)
	if err != nil {
		return board.Program{}, trace.Trace{}, err
	}

	builder := board.NewBuilder()
	module := board.NewModule(verifierCoreModule)
	module.N = 2
	cb := newCoreBuilder(&module, state)
	cb.namespace = "single"

	if err := cb.addExposedColumnConstraints(input.Program, input.Proof); err != nil {
		return board.Program{}, trace.Trace{}, err
	}
	if err := cb.addPublicInputColumnConstraints(input.Program, input.PublicInputs); err != nil {
		return board.Program{}, trace.Trace{}, err
	}
	if err := cb.addProgramLagrangeConstraints(input.Program); err != nil {
		return board.Program{}, trace.Trace{}, err
	}
	if err := cb.addLogupBusConstraints(input.Program, input.Proof); err != nil {
		return board.Program{}, trace.Trace{}, err
	}
	if err := cb.addAIRConstraints(input.Program); err != nil {
		return board.Program{}, trace.Trace{}, err
	}
	if !config.forceSkipInnerFRI {
		if err := cb.addFRIBridgeConstraints(input); err != nil {
			return board.Program{}, trace.Trace{}, err
		}
		if err := cb.addFRIFoldConstraints(input.Proof); err != nil {
			return board.Program{}, trace.Trace{}, err
		}
	}

	builder.AddModule(module)
	if !config.forceSkipInnerFRI && config.arithmetizePoseidon2 {
		p2Module, p2Trace, err := buildPoseidon2VerifierModule(
			verifierCoreModule+"_poseidon2",
			[]poseidon2MerkleTarget{{Namespace: "single", Input: input}},
		)
		if err != nil {
			return board.Program{}, trace.Trace{}, err
		}
		builder.AddModule(p2Module)
		if err := mergeTrace(cb.trace, p2Trace); err != nil {
			return board.Program{}, trace.Trace{}, err
		}
	}

	program, err := board.Compile(&builder)
	if err != nil {
		return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: compile verifier core: %w", err)
	}

	return program, cb.trace, nil
}

func buildAggregationCore(input AggregationInput, config Config) (board.Program, trace.Trace, error) {
	leftState, err := deriveVerifierState(input.Left, config)
	if err != nil {
		return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: derive left verifier state: %w", err)
	}
	rightState, err := deriveVerifierState(input.Right, config)
	if err != nil {
		return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: derive right verifier state: %w", err)
	}

	builder := board.NewBuilder()
	module := board.NewModule(verifierCoreModule)
	module.N = 2
	cb := newCoreBuilder(&module, verifierState{})

	cb.state = leftState
	cb.namespace = "left"
	if err := cb.addExposedColumnConstraints(input.Left.Program, input.Left.Proof); err != nil {
		return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: left exposed columns: %w", err)
	}
	if err := cb.addPublicInputColumnConstraints(input.Left.Program, input.Left.PublicInputs); err != nil {
		return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: left public inputs: %w", err)
	}
	if err := cb.addProgramLagrangeConstraints(input.Left.Program); err != nil {
		return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: left lagranges: %w", err)
	}
	if err := cb.addLogupBusConstraints(input.Left.Program, input.Left.Proof); err != nil {
		return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: left logup: %w", err)
	}
	if err := cb.addAIRConstraints(input.Left.Program); err != nil {
		return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: left AIR: %w", err)
	}
	if !config.forceSkipInnerFRI {
		if err := cb.addFRIBridgeConstraints(input.Left); err != nil {
			return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: left FRI bridge: %w", err)
		}
		if err := cb.addFRIFoldConstraints(input.Left.Proof); err != nil {
			return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: left FRI folds: %w", err)
		}
	}

	cb.state = rightState
	cb.namespace = "right"
	if err := cb.addExposedColumnConstraints(input.Right.Program, input.Right.Proof); err != nil {
		return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: right exposed columns: %w", err)
	}
	if err := cb.addPublicInputColumnConstraints(input.Right.Program, input.Right.PublicInputs); err != nil {
		return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: right public inputs: %w", err)
	}
	if err := cb.addProgramLagrangeConstraints(input.Right.Program); err != nil {
		return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: right lagranges: %w", err)
	}
	if err := cb.addLogupBusConstraints(input.Right.Program, input.Right.Proof); err != nil {
		return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: right logup: %w", err)
	}
	if err := cb.addAIRConstraints(input.Right.Program); err != nil {
		return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: right AIR: %w", err)
	}
	if !config.forceSkipInnerFRI {
		if err := cb.addFRIBridgeConstraints(input.Right); err != nil {
			return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: right FRI bridge: %w", err)
		}
		if err := cb.addFRIFoldConstraints(input.Right.Proof); err != nil {
			return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: right FRI folds: %w", err)
		}
	}

	builder.AddModule(module)
	if !config.forceSkipInnerFRI && config.arithmetizePoseidon2 {
		p2Module, p2Trace, err := buildPoseidon2VerifierModule(
			verifierCoreModule+"_poseidon2",
			[]poseidon2MerkleTarget{
				{Namespace: "left", Input: input.Left},
				{Namespace: "right", Input: input.Right},
			},
		)
		if err != nil {
			return board.Program{}, trace.Trace{}, err
		}
		builder.AddModule(p2Module)
		if err := mergeTrace(cb.trace, p2Trace); err != nil {
			return board.Program{}, trace.Trace{}, err
		}
	}

	program, err := board.Compile(&builder)
	if err != nil {
		return board.Program{}, trace.Trace{}, fmt.Errorf("recursion: compile aggregation core: %w", err)
	}

	return program, cb.trace, nil
}

type verifierState struct {
	values map[string]ext.E4
	zeta   ext.E4
	alpha  ext.E4
	fri    friVerifierState
}

type friVerifierState struct {
	maxN         int
	numRounds    int
	levelAtRound map[int]int
	foldAlphas   []ext.E4
	levelGammas  map[int]ext.E4
	queryIndices []int
}

type coreBuilder struct {
	module    *board.Module
	trace     trace.Trace
	state     verifierState
	namespace string
	lagranges map[string]struct{}
}

func newCoreBuilder(module *board.Module, state verifierState) *coreBuilder {
	return &coreBuilder{
		module:    module,
		trace:     trace.New(),
		state:     state,
		namespace: "inner",
		lagranges: make(map[string]struct{}),
	}
}

func (cb *coreBuilder) scopedName(kind, key string) string {
	return fmt.Sprintf("rec.%s.%s.%s", cb.namespace, kind, key)
}

func (cb *coreBuilder) setExtColumn(name string, value ext.E4) (expr.Expr, error) {
	if existing, ok := cb.trace.Ext[name]; ok {
		if len(existing) != cb.module.N {
			return nil, fmt.Errorf("recursion: extension column %q has length %d, want %d", name, len(existing), cb.module.N)
		}
		for i := range existing {
			if !existing[i].Equal(&value) {
				return nil, fmt.Errorf("recursion: extension column %q reused with different value at row %d", name, i)
			}
		}
		return expr.ExtCol(name), nil
	}

	col := make(trace.ExtPolynomial, cb.module.N)
	for i := range col {
		col[i].Set(&value)
	}
	cb.trace.SetExt(name, col)
	return expr.ExtCol(name), nil
}

func (cb *coreBuilder) valueExpr(key string) (expr.Expr, error) {
	value, ok := cb.state.values[key]
	if !ok {
		return nil, fmt.Errorf("recursion: verifier value %q not found", key)
	}
	return cb.setExtColumn(cb.scopedName("value", key), value)
}

func (cb *coreBuilder) zetaExpr() (expr.Expr, error) {
	return cb.setExtColumn(cb.scopedName("challenge", constants.FINAL_EVALUATION_POINT), cb.state.zeta)
}

func (cb *coreBuilder) alphaExpr() (expr.Expr, error) {
	return cb.setExtColumn(cb.scopedName("challenge", constants.DEEP_ALPHA), cb.state.alpha)
}

func (cb *coreBuilder) friFoldAlphaExpr(round int) (expr.Expr, error) {
	if round < 0 || round >= len(cb.state.fri.foldAlphas) {
		return nil, fmt.Errorf("recursion: FRI fold alpha round %d out of range", round)
	}
	return cb.setExtColumn(cb.scopedName("challenge", friFoldName(round)), cb.state.fri.foldAlphas[round])
}

func (cb *coreBuilder) friLevelGammaExpr(level int) (expr.Expr, error) {
	gamma, ok := cb.state.fri.levelGammas[level]
	if !ok {
		return nil, fmt.Errorf("recursion: FRI gamma for level %d not found", level)
	}
	return cb.setExtColumn(cb.scopedName("challenge", friLevelGammaName(level)), gamma)
}

func (cb *coreBuilder) literalExpr(key string, value ext.E4) (expr.Expr, error) {
	return cb.setExtColumn(cb.scopedName("literal", key), value)
}

func (cb *coreBuilder) setVerifierValue(key string, value ext.E4) {
	if cb.state.values == nil {
		cb.state.values = make(map[string]ext.E4)
	}
	cb.state.values[key] = value
}

func (cb *coreBuilder) addExposedColumnConstraints(program board.Program, prf proof.Proof) error {
	moduleNames := sortedModuleNames(program.Modules)
	for _, moduleName := range moduleNames {
		innerModule := program.Modules[moduleName]
		names := innerModule.VanishingRelation.Leaves(expr.NewConfig(expr.OnlyExposedColumns...))
		sort.Strings(names)
		for _, name := range names {
			pi, ok := prf.ExposedValues[name]
			if !ok {
				return fmt.Errorf("recursion: exposed column %q not found in proof.ExposedValues", name)
			}
			eval, err := cb.valueExpr(name)
			if err != nil {
				return fmt.Errorf("recursion: exposed column %q evaluation: %w", name, err)
			}

			sum := zeroExpr()
			for entryIndex, pe := range pi.Entries {
				idx, err := normalizeIndex(pe.Idx, innerModule.N)
				if err != nil {
					return fmt.Errorf("recursion: exposed column %q entry %d: %w", name, entryIndex, err)
				}

				lagKey := fmt.Sprintf("exposed.%s.%s.%d.%d.%d", moduleName, name, innerModule.N, idx, entryIndex)
				if _, ok := cb.state.values[lagKey]; !ok {
					cb.setVerifierValue(lagKey, poly.LagrangeAtZetaExt(cb.state.zeta, innerModule.N, idx))
				}
				lag, err := cb.valueExpr(lagKey)
				if err != nil {
					return err
				}
				if err := cb.addLagrangeConstraint(lagKey, innerModule.N, idx); err != nil {
					return fmt.Errorf("recursion: exposed column %q entry %d lagrange: %w", name, entryIndex, err)
				}

				value, err := cb.exposedEntryExpr(name, entryIndex, pe)
				if err != nil {
					return fmt.Errorf("recursion: exposed column %q entry %d value: %w", name, entryIndex, err)
				}
				sum = sum.Add(value.Mul(lag))
			}

			cb.module.AssertZero(eval.Sub(sum))
		}
	}
	return nil
}

func (cb *coreBuilder) addPublicInputColumnConstraints(program board.Program, inputs public.Inputs) error {
	moduleNames := sortedModuleNames(program.Modules)
	for _, moduleName := range moduleNames {
		innerModule := program.Modules[moduleName]
		names := innerModule.VanishingRelation.Leaves(expr.NewConfig(expr.OnlyPublicColumns...))
		sort.Strings(names)
		for _, name := range names {
			pi, ok := inputs[name]
			if !ok {
				return fmt.Errorf("recursion: public input column %q not found", name)
			}
			if pi.Module != moduleName {
				return fmt.Errorf("recursion: public input column %q belongs to module %q, used from module %q", name, pi.Module, moduleName)
			}
			eval, err := cb.valueExpr(name)
			if err != nil {
				return fmt.Errorf("recursion: public input column %q evaluation: %w", name, err)
			}

			sum := zeroExpr()
			for entryIndex, pe := range pi.Entries {
				if pe.Idx < 0 || pe.Idx >= innerModule.N {
					return fmt.Errorf("recursion: public input column %q entry %d index %d out of bounds for module %q of size %d", name, entryIndex, pe.Idx, moduleName, innerModule.N)
				}

				lagKey := fmt.Sprintf("public_input.%s.%s.%d.%d.%d", moduleName, name, innerModule.N, pe.Idx, entryIndex)
				if _, ok := cb.state.values[lagKey]; !ok {
					cb.setVerifierValue(lagKey, poly.LagrangeAtZetaExt(cb.state.zeta, innerModule.N, pe.Idx))
				}
				lag, err := cb.valueExpr(lagKey)
				if err != nil {
					return err
				}
				if err := cb.addLagrangeConstraint(lagKey, innerModule.N, pe.Idx); err != nil {
					return fmt.Errorf("recursion: public input column %q entry %d lagrange: %w", name, entryIndex, err)
				}

				value, err := cb.publicInputEntryExpr(name, entryIndex, pe)
				if err != nil {
					return fmt.Errorf("recursion: public input column %q entry %d value: %w", name, entryIndex, err)
				}
				sum = sum.Add(value.Mul(lag))
			}

			cb.module.AssertZero(eval.Sub(sum))
		}
	}
	return nil
}

func (cb *coreBuilder) publicInputEntryExpr(name string, entryIndex int, pe public.Entry) (expr.Expr, error) {
	return cb.literalExpr(fmt.Sprintf("public_input.%s.%d", name, entryIndex), pe.ExtValue())
}

func (cb *coreBuilder) exposedEntryExpr(name string, entryIndex int, pe proof.ExposedEntry) (expr.Expr, error) {
	return cb.literalExpr(fmt.Sprintf("exposed.%s.%d", name, entryIndex), pe.ExtValue())
}

func (cb *coreBuilder) addProgramLagrangeConstraints(program board.Program) error {
	config := expr.OnlyLagranges
	moduleNames := sortedModuleNames(program.Modules)
	for _, moduleName := range moduleNames {
		innerModule := program.Modules[moduleName]
		lags := innerModule.VanishingRelation.Leaves(expr.NewConfig(config...))
		sort.Strings(lags)
		for _, lag := range lags {
			idx := constants.ParseLagrangeName(lag)
			if idx < 0 {
				idx = innerModule.N + idx
			}
			if err := cb.addLagrangeConstraint(lag, innerModule.N, idx); err != nil {
				return err
			}
		}
	}
	return nil
}

func (cb *coreBuilder) addLagrangeConstraint(name string, n, idx int) error {
	idx, err := normalizeIndex(idx, n)
	if err != nil {
		return err
	}
	if uint64(n) > uint64(^uint32(0)) {
		return fmt.Errorf("recursion: lagrange domain size %d exceeds expression exponent limit", n)
	}

	lagrangeKey := cb.scopedName("lagrange", fmt.Sprintf("%s.%d.%d", name, n, idx))
	if _, ok := cb.lagranges[lagrangeKey]; ok {
		return nil
	}
	cb.lagranges[lagrangeKey] = struct{}{}

	lag, err := cb.valueExpr(name)
	if err != nil {
		return err
	}
	zeta, err := cb.zetaExpr()
	if err != nil {
		return err
	}

	omegaI, err := koalabear.Generator(uint64(n))
	if err != nil {
		return err
	}
	omegaI.Exp(omegaI, big.NewInt(int64(idx)))

	left := lag.Mul(zeta.Sub(expr.Const(omegaI))).Mul(uintConst(uint64(n)))
	right := zeta.Pow(uint32(n)).Sub(oneExpr()).Mul(expr.Const(omegaI))
	cb.module.AssertZero(left.Sub(right))
	return nil
}

func (cb *coreBuilder) addLogupBusConstraints(program board.Program, prf proof.Proof) error {
	for busIndex, bus := range program.LogupBus {
		sum := zeroExpr()
		for _, pos := range bus.Positive {
			value, err := cb.logupPublicEntryExpr(prf, pos)
			if err != nil {
				return fmt.Errorf("recursion: logup bus %d positive %q: %w", busIndex, pos, err)
			}
			sum = sum.Add(value)
		}
		for _, neg := range bus.Negative {
			value, err := cb.logupPublicEntryExpr(prf, neg)
			if err != nil {
				return fmt.Errorf("recursion: logup bus %d negative %q: %w", busIndex, neg, err)
			}
			sum = sum.Sub(value)
		}
		cb.module.AssertZero(sum)
	}
	return nil
}

func (cb *coreBuilder) logupPublicEntryExpr(prf proof.Proof, name string) (expr.Expr, error) {
	pi, ok := prf.ExposedValues[name]
	if !ok {
		return nil, fmt.Errorf("exposed column not found")
	}
	if len(pi.Entries) != 1 {
		return nil, fmt.Errorf("has %d entries, want 1", len(pi.Entries))
	}
	return cb.literalExpr("logup."+name, pi.Entries[0].ExtValue())
}

func (cb *coreBuilder) addAIRConstraints(program board.Program) error {
	moduleNames := sortedModuleNames(program.Modules)
	for _, moduleName := range moduleNames {
		innerModule := program.Modules[moduleName]
		zeta, err := cb.zetaExpr()
		if err != nil {
			return err
		}
		if uint64(innerModule.N) > uint64(^uint32(0)) {
			return fmt.Errorf("recursion: module %q size %d exceeds expression exponent limit", moduleName, innerModule.N)
		}

		qZeta := zeroExpr()
		zetaPowIN := oneExpr()
		zetaN := zeta.Pow(uint32(innerModule.N))
		for i := 0; ; i++ {
			chunkName := constants.QuotientChunkName(moduleName, i)
			if _, ok := cb.state.values[chunkName]; !ok {
				break
			}
			chunk, err := cb.valueExpr(chunkName)
			if err != nil {
				return err
			}
			qZeta = qZeta.Add(zetaPowIN.Mul(chunk))
			zetaPowIN = zetaPowIN.Mul(zetaN)
		}

		vZeta, err := cb.translateDAG(innerModule.VanishingRelation.Root)
		if err != nil {
			return fmt.Errorf("recursion: translate AIR relation for module %q: %w", moduleName, err)
		}
		cb.module.AssertZero(vZeta.Sub(zetaN.Sub(oneExpr()).Mul(qZeta)))
	}
	return nil
}

func (cb *coreBuilder) translateDAG(node *dag.DAGNode) (expr.Expr, error) {
	switch node.Kind {
	case dag.KindLeaf:
		if node.IsConst {
			return expr.Const(node.ConstVal), nil
		}
		if node.Leaf == nil {
			return nil, fmt.Errorf("leaf node has nil leaf")
		}
		return cb.valueExpr(node.Leaf.String())

	case dag.KindAdd:
		return cb.translateFold(node.Children, func(left, right expr.Expr) expr.Expr {
			return left.Add(right)
		})

	case dag.KindSub:
		if len(node.Children) != 2 {
			return nil, fmt.Errorf("sub node has %d children, want 2", len(node.Children))
		}
		left, err := cb.translateDAG(node.Children[0])
		if err != nil {
			return nil, err
		}
		right, err := cb.translateDAG(node.Children[1])
		if err != nil {
			return nil, err
		}
		return left.Sub(right), nil

	case dag.KindMul:
		return cb.translateFold(node.Children, func(left, right expr.Expr) expr.Expr {
			return left.Mul(right)
		})

	case dag.KindPow:
		if len(node.Children) != 1 {
			return nil, fmt.Errorf("pow node has %d children, want 1", len(node.Children))
		}
		base, err := cb.translateDAG(node.Children[0])
		if err != nil {
			return nil, err
		}
		return base.Pow(node.Exp), nil

	default:
		return nil, fmt.Errorf("unknown DAG node kind %d", node.Kind)
	}
}

func (cb *coreBuilder) translateFold(children []*dag.DAGNode, op func(expr.Expr, expr.Expr) expr.Expr) (expr.Expr, error) {
	if len(children) == 0 {
		return zeroExpr(), nil
	}
	acc, err := cb.translateDAG(children[0])
	if err != nil {
		return nil, err
	}
	for _, child := range children[1:] {
		next, err := cb.translateDAG(child)
		if err != nil {
			return nil, err
		}
		acc = op(acc, next)
	}
	return acc, nil
}

func (cb *coreBuilder) addFRIBridgeConstraints(input RecursionInput) error {
	prf := input.Proof
	if len(prf.DeepQuotientFriProof.FRIQueries) != constants.NUM_QUERIES {
		return fmt.Errorf("recursion: FRI bridge has %d FRI queries, want %d", len(prf.DeepQuotientFriProof.FRIQueries), constants.NUM_QUERIES)
	}

	layout := prover.BuildLayout(input.Program, len(input.Setup.Roots))
	dqLayout := prover.BuildDeepQuotientLayout(input.Program)
	if len(dqLayout.Sizes) > 1 && len(prf.DeepQuotientFriProof.LevelQueries) < len(dqLayout.Sizes)-1 {
		return fmt.Errorf("recursion: FRI bridge has %d level query sets, want at least %d", len(prf.DeepQuotientFriProof.LevelQueries), len(dqLayout.Sizes)-1)
	}

	zeta, err := cb.zetaExpr()
	if err != nil {
		return err
	}
	alpha, err := cb.alphaExpr()
	if err != nil {
		return err
	}

	for q := 0; q < constants.NUM_QUERIES; q++ {
		query := prf.DeepQuotientFriProof.FRIQueries[q]
		if len(query.Layers) == 0 {
			return fmt.Errorf("recursion: FRI query %d has no layers", q)
		}
		sFull := query.Layers[0].Path.LeafIdx

		for level, n := range dqLayout.Sizes {
			domainSize := constants.RATE * n
			halfDomain := domainSize / 2
			if halfDomain <= 0 {
				return fmt.Errorf("recursion: invalid FRI bridge domain size %d for N=%d", domainSize, n)
			}
			sLocal := sFull % halfDomain

			xBase, negXBase, err := bridgeSamplePoints(domainSize, sLocal)
			if err != nil {
				return err
			}
			x := liftBaseToExt(xBase)
			negX := liftBaseToExt(negXBase)

			domainGenerator, err := koalabear.Generator(uint64(n))
			if err != nil {
				return err
			}

			deepAtX := zeroExpr()
			deepAtNegX := zeroExpr()
			var alphaAcc ext.E4
			alphaAcc.SetOne()
			alphaAccExpr := oneExpr()

			for shiftIdx, shift := range dqLayout.Shifts[level] {
				var omegaShift koalabear.Element
				omegaShift.Exp(domainGenerator, big.NewInt(int64(shift)))
				zetaAtShift := cb.state.zeta
				zetaAtShift.MulByElement(&zetaAtShift, &omegaShift)
				zetaAtShiftExpr := zeta.Mul(expr.Const(omegaShift))

				vAtZeta := zeroExpr()
				cAtX := zeroExpr()
				cAtNegX := zeroExpr()
				var vAtZetaVal, cAtXVal, cAtNegXVal ext.E4

				names := dqLayout.Names[level][shiftIdx]
				keys := dqLayout.Keys[level][shiftIdx]
				for k := range names {
					evalAtZetaVal, ok := cb.state.values[keys[k]]
					if !ok {
						return fmt.Errorf("recursion: FRI bridge value %q not found", keys[k])
					}
					evalAtZeta, err := cb.valueExpr(keys[k])
					if err != nil {
						return err
					}
					slot, ok := layout.ColSlot[names[k]]
					if !ok {
						return fmt.Errorf("recursion: FRI bridge column %q not found in layout", names[k])
					}
					leafX, leafNegX, leafXVal, leafNegXVal, err := cb.bridgeSamplePair(prf, slot, q, fmt.Sprintf("q%d.l%d.s%d.c%d", q, level, shiftIdx, k))
					if err != nil {
						return err
					}

					vAtZeta = vAtZeta.Add(evalAtZeta.Mul(alphaAccExpr))
					cAtX = cAtX.Add(leafX.Mul(alphaAccExpr))
					cAtNegX = cAtNegX.Add(leafNegX.Mul(alphaAccExpr))
					addWeightedExt(&vAtZetaVal, evalAtZetaVal, alphaAcc)
					addWeightedExt(&cAtXVal, leafXVal, alphaAcc)
					addWeightedExt(&cAtNegXVal, leafNegXVal, alphaAcc)

					alphaAcc.Mul(&alphaAcc, &cb.state.alpha)
					alphaAccExpr = alphaAccExpr.Mul(alpha)
				}

				numXVal := subExt(vAtZetaVal, cAtXVal)
				denomXVal := subExt(zetaAtShift, x)
				quotXVal := divExt(numXVal, denomXVal)
				quotX, err := cb.addBridgeFraction(
					fmt.Sprintf("q%d.l%d.s%d.p", q, level, shiftIdx),
					vAtZeta.Sub(cAtX),
					zetaAtShiftExpr.Sub(expr.Const(xBase)),
					quotXVal,
				)
				if err != nil {
					return err
				}
				deepAtX = deepAtX.Add(quotX)

				numNegXVal := subExt(vAtZetaVal, cAtNegXVal)
				denomNegXVal := subExt(zetaAtShift, negX)
				quotNegXVal := divExt(numNegXVal, denomNegXVal)
				quotNegX, err := cb.addBridgeFraction(
					fmt.Sprintf("q%d.l%d.s%d.q", q, level, shiftIdx),
					vAtZeta.Sub(cAtNegX),
					zetaAtShiftExpr.Sub(expr.Const(negXBase)),
					quotNegXVal,
				)
				if err != nil {
					return err
				}
				deepAtNegX = deepAtNegX.Add(quotNegX)
			}

			if len(dqLayout.AIRChunks[level]) > 0 {
				vAtZeta := zeroExpr()
				cAtX := zeroExpr()
				cAtNegX := zeroExpr()
				var vAtZetaVal, cAtXVal, cAtNegXVal ext.E4

				for chunkIdx, chunkName := range dqLayout.AIRChunks[level] {
					evalAtZetaVal, ok := cb.state.values[chunkName]
					if !ok {
						return fmt.Errorf("recursion: FRI bridge AIR chunk %q not found", chunkName)
					}
					evalAtZeta, err := cb.valueExpr(chunkName)
					if err != nil {
						return err
					}
					slot, ok := layout.AIRChunkSlot[chunkName]
					if !ok {
						return fmt.Errorf("recursion: FRI bridge AIR chunk %q not found in layout", chunkName)
					}
					leafX, leafNegX, leafXVal, leafNegXVal, err := cb.bridgeSamplePair(prf, slot, q, fmt.Sprintf("q%d.l%d.air%d", q, level, chunkIdx))
					if err != nil {
						return err
					}

					vAtZeta = vAtZeta.Add(evalAtZeta.Mul(alphaAccExpr))
					cAtX = cAtX.Add(leafX.Mul(alphaAccExpr))
					cAtNegX = cAtNegX.Add(leafNegX.Mul(alphaAccExpr))
					addWeightedExt(&vAtZetaVal, evalAtZetaVal, alphaAcc)
					addWeightedExt(&cAtXVal, leafXVal, alphaAcc)
					addWeightedExt(&cAtNegXVal, leafNegXVal, alphaAcc)

					alphaAcc.Mul(&alphaAcc, &cb.state.alpha)
					alphaAccExpr = alphaAccExpr.Mul(alpha)
				}

				numXVal := subExt(vAtZetaVal, cAtXVal)
				denomXVal := subExt(cb.state.zeta, x)
				quotXVal := divExt(numXVal, denomXVal)
				quotX, err := cb.addBridgeFraction(
					fmt.Sprintf("q%d.l%d.air.p", q, level),
					vAtZeta.Sub(cAtX),
					zeta.Sub(expr.Const(xBase)),
					quotXVal,
				)
				if err != nil {
					return err
				}
				deepAtX = deepAtX.Add(quotX)

				numNegXVal := subExt(vAtZetaVal, cAtNegXVal)
				denomNegXVal := subExt(cb.state.zeta, negX)
				quotNegXVal := divExt(numNegXVal, denomNegXVal)
				quotNegX, err := cb.addBridgeFraction(
					fmt.Sprintf("q%d.l%d.air.q", q, level),
					vAtZeta.Sub(cAtNegX),
					zeta.Sub(expr.Const(negXBase)),
					quotNegXVal,
				)
				if err != nil {
					return err
				}
				deepAtNegX = deepAtNegX.Add(quotNegX)
			}

			actualX, actualNegX, err := cb.bridgeActualPair(prf, q, level)
			if err != nil {
				return err
			}
			cb.module.AssertZero(deepAtX.Sub(actualX))
			cb.module.AssertZero(deepAtNegX.Sub(actualNegX))
		}
	}

	return nil
}

func (cb *coreBuilder) bridgeSamplePair(prf proof.Proof, slot prover.Slot, q int, label string) (expr.Expr, expr.Expr, ext.E4, ext.E4, error) {
	if q >= len(prf.PointSamplings) {
		return nil, nil, ext.E4{}, ext.E4{}, fmt.Errorf("point sampling query %d out of range", q)
	}
	if slot.TreeIdx >= len(prf.PointSamplings[q]) {
		return nil, nil, ext.E4{}, ext.E4{}, fmt.Errorf("point sampling query %d tree index %d out of range", q, slot.TreeIdx)
	}
	wp := prf.PointSamplings[q][slot.TreeIdx]

	var xVal, negXVal ext.E4
	if slot.Field == field.Ext {
		if slot.PolyIdx >= len(wp.RawLeafExt) {
			return nil, nil, ext.E4{}, ext.E4{}, fmt.Errorf("point sampling ext leaf index %d out of range for slot %+v", slot.PolyIdx, slot)
		}
		xVal = wp.RawLeafExt[slot.PolyIdx][0]
		negXVal = wp.RawLeafExt[slot.PolyIdx][1]
	} else {
		if slot.PolyIdx >= len(wp.RawLeafBase) {
			return nil, nil, ext.E4{}, ext.E4{}, fmt.Errorf("point sampling base leaf index %d out of range for slot %+v", slot.PolyIdx, slot)
		}
		xVal = liftBaseToExt(wp.RawLeafBase[slot.PolyIdx][0])
		negXVal = liftBaseToExt(wp.RawLeafBase[slot.PolyIdx][1])
	}

	x, err := cb.literalExpr("bridge.sample."+label+".p", xVal)
	if err != nil {
		return nil, nil, ext.E4{}, ext.E4{}, err
	}
	negX, err := cb.literalExpr("bridge.sample."+label+".q", negXVal)
	if err != nil {
		return nil, nil, ext.E4{}, ext.E4{}, err
	}
	return x, negX, xVal, negXVal, nil
}

func (cb *coreBuilder) bridgeActualPair(prf proof.Proof, q, level int) (expr.Expr, expr.Expr, error) {
	var layerField field.Kind
	var xVal, negXVal ext.E4
	if level == 0 {
		if q >= len(prf.DeepQuotientFriProof.FRIQueries) {
			return nil, nil, fmt.Errorf("FRI query %d out of range", q)
		}
		if len(prf.DeepQuotientFriProof.FRIQueries[q].Layers) == 0 {
			return nil, nil, fmt.Errorf("FRI query %d has no layers", q)
		}
		layer := prf.DeepQuotientFriProof.FRIQueries[q].Layers[0]
		layerField = layer.Field
		xVal = layer.LeafPExt
		negXVal = layer.LeafQExt
	} else {
		if level-1 >= len(prf.DeepQuotientFriProof.LevelQueries) {
			return nil, nil, fmt.Errorf("FRI level query set %d out of range", level-1)
		}
		if q >= len(prf.DeepQuotientFriProof.LevelQueries[level-1]) {
			return nil, nil, fmt.Errorf("FRI level %d query %d out of range", level, q)
		}
		layer := prf.DeepQuotientFriProof.LevelQueries[level-1][q]
		layerField = layer.Field
		xVal = layer.LeafPExt
		negXVal = layer.LeafQExt
	}
	if layerField != field.Ext {
		return nil, nil, fmt.Errorf("expected extension FRI query layer, got %s", layerField)
	}

	x, err := cb.literalExpr(fmt.Sprintf("bridge.actual.q%d.l%d.p", q, level), xVal)
	if err != nil {
		return nil, nil, err
	}
	negX, err := cb.literalExpr(fmt.Sprintf("bridge.actual.q%d.l%d.q", q, level), negXVal)
	if err != nil {
		return nil, nil, err
	}
	return x, negX, nil
}

func (cb *coreBuilder) addBridgeFraction(label string, numerator, denominator expr.Expr, quotientValue ext.E4) (expr.Expr, error) {
	quotient, err := cb.literalExpr("bridge.quot."+label, quotientValue)
	if err != nil {
		return nil, err
	}
	cb.module.AssertZero(quotient.Mul(denominator).Sub(numerator))
	return quotient, nil
}

func (cb *coreBuilder) addFRIFoldConstraints(prf proof.Proof) error {
	state := cb.state.fri
	if state.numRounds == 0 {
		return nil
	}
	friProof := prf.DeepQuotientFriProof
	if friProof.FinalField != field.Ext {
		return fmt.Errorf("recursion: FRI folds expected extension final polynomial, got %s", friProof.FinalField)
	}
	if len(friProof.FinalPolyExt) == 0 {
		return fmt.Errorf("recursion: FRI folds final extension polynomial is empty")
	}
	if len(friProof.FRIQueries) != constants.NUM_QUERIES {
		return fmt.Errorf("recursion: FRI folds have %d queries, want %d", len(friProof.FRIQueries), constants.NUM_QUERIES)
	}
	if len(state.queryIndices) != constants.NUM_QUERIES {
		return fmt.Errorf("recursion: FRI fold state has %d query indices, want %d", len(state.queryIndices), constants.NUM_QUERIES)
	}

	var two, invTwo koalabear.Element
	two.SetUint64(2)
	invTwo.Inverse(&two)
	invTwoExpr := expr.Const(invTwo)

	for q := 0; q < constants.NUM_QUERIES; q++ {
		query := friProof.FRIQueries[q]
		if len(query.Layers) != state.numRounds {
			return fmt.Errorf("recursion: FRI query %d has %d layers, want %d", q, len(query.Layers), state.numRounds)
		}
		s := state.queryIndices[q]

		for round := 0; round < state.numRounds; round++ {
			nRound := constants.RATE * state.maxN >> round
			if nRound <= 1 {
				return fmt.Errorf("recursion: invalid FRI round %d domain size %d", round, nRound)
			}
			base := s % (nRound / 2)
			layer := query.Layers[round]
			if layer.Path.LeafIdx != base {
				return fmt.Errorf("recursion: FRI query %d round %d opens leaf %d, want %d", q, round, layer.Path.LeafIdx, base)
			}

			leafP, leafQ, err := cb.friLayerPairExpr(fmt.Sprintf("q%d.r%d", q, round), layer)
			if err != nil {
				return err
			}
			alpha, err := cb.friFoldAlphaExpr(round)
			if err != nil {
				return err
			}

			generator, err := koalabear.Generator(uint64(nRound))
			if err != nil {
				return err
			}
			var xInv koalabear.Element
			xInv.Exp(generator, big.NewInt(int64(nRound-base)))

			expected := leafP.Add(leafQ).Mul(invTwoExpr).
				Add(leafP.Sub(leafQ).Mul(invTwoExpr).Mul(expr.Const(xInv)).Mul(alpha))

			if round < state.numRounds-1 {
				nextRoundSize := nRound / 2
				nextLayer := query.Layers[round+1]
				nextBase := s % (nextRoundSize / 2)
				if nextLayer.Path.LeafIdx != nextBase {
					return fmt.Errorf("recursion: FRI query %d round %d opens leaf %d, want %d", q, round+1, nextLayer.Path.LeafIdx, nextBase)
				}
				nextLeafP, nextLeafQ, err := cb.friLayerPairExpr(fmt.Sprintf("q%d.r%d", q, round+1), nextLayer)
				if err != nil {
					return err
				}

				isLeafP := base < nextRoundSize/2
				if level, ok := state.levelAtRound[round+1]; ok {
					levelLeaf, err := cb.friLevelContributionExpr(prf, q, level, isLeafP)
					if err != nil {
						return err
					}
					gamma, err := cb.friLevelGammaExpr(level)
					if err != nil {
						return err
					}
					expected = expected.Add(levelLeaf.Mul(gamma))
				}

				if isLeafP {
					cb.module.AssertZero(expected.Sub(nextLeafP))
				} else {
					cb.module.AssertZero(expected.Sub(nextLeafQ))
				}
				continue
			}

			finalVal := friProof.FinalPolyExt[s%len(friProof.FinalPolyExt)]
			finalExpr, err := cb.literalExpr(fmt.Sprintf("fri.final.q%d", q), finalVal)
			if err != nil {
				return err
			}
			cb.module.AssertZero(expected.Sub(finalExpr))
		}
	}

	return nil
}

func (cb *coreBuilder) friLayerPairExpr(label string, layer fri.QueryLayer) (expr.Expr, expr.Expr, error) {
	if layer.Field != field.Ext {
		return nil, nil, fmt.Errorf("recursion: FRI layer %s has field %s, want %s", label, layer.Field, field.Ext)
	}
	leafP, err := cb.literalExpr("fri.layer."+label+".p", layer.LeafPExt)
	if err != nil {
		return nil, nil, err
	}
	leafQ, err := cb.literalExpr("fri.layer."+label+".q", layer.LeafQExt)
	if err != nil {
		return nil, nil, err
	}
	return leafP, leafQ, nil
}

func (cb *coreBuilder) friLevelContributionExpr(prf proof.Proof, query, level int, useP bool) (expr.Expr, error) {
	if level <= 0 || level-1 >= len(prf.DeepQuotientFriProof.LevelQueries) {
		return nil, fmt.Errorf("recursion: FRI extra level %d out of range", level)
	}
	if query >= len(prf.DeepQuotientFriProof.LevelQueries[level-1]) {
		return nil, fmt.Errorf("recursion: FRI extra level %d query %d out of range", level, query)
	}
	layer := prf.DeepQuotientFriProof.LevelQueries[level-1][query]
	if layer.Field != field.Ext {
		return nil, fmt.Errorf("recursion: FRI extra level %d query %d has field %s, want %s", level, query, layer.Field, field.Ext)
	}
	nLevel := constants.RATE * cb.state.fri.maxN >> cb.friRoundForLevel(level)
	base := cb.state.fri.queryIndices[query] % (nLevel / 2)
	if layer.Path.LeafIdx != base {
		return nil, fmt.Errorf("recursion: FRI extra level %d query %d opens leaf %d, want %d", level, query, layer.Path.LeafIdx, base)
	}
	if useP {
		return cb.literalExpr(fmt.Sprintf("fri.level.q%d.l%d.p", query, level), layer.LeafPExt)
	}
	return cb.literalExpr(fmt.Sprintf("fri.level.q%d.l%d.q", query, level), layer.LeafQExt)
}

func (cb *coreBuilder) friRoundForLevel(level int) int {
	for round, candidate := range cb.state.fri.levelAtRound {
		if candidate == level {
			return round
		}
	}
	return 0
}

func resolveRecursionHashBackend(input RecursionInput, config Config) (commitment.HashBackend, error) {
	keyID := input.Setup.HashBackendID
	if keyID == "" {
		keyID = input.Proof.HashBackendID
	}
	hashBackend, err := commitment.ResolveHashBackend(config.hashBackend, keyID)
	if err != nil {
		return commitment.HashBackend{}, err
	}
	if input.Setup.HashBackendID != "" && commitment.NormalizeHashBackendID(input.Setup.HashBackendID) != hashBackend.ID {
		return commitment.HashBackend{}, fmt.Errorf("recursion: setup hash backend %q does not match verifier backend %q", input.Setup.HashBackendID, hashBackend.ID)
	}
	if input.Proof.HashBackendID != "" && commitment.NormalizeHashBackendID(input.Proof.HashBackendID) != hashBackend.ID {
		return commitment.HashBackend{}, fmt.Errorf("recursion: proof hash backend %q does not match verifier backend %q", input.Proof.HashBackendID, hashBackend.ID)
	}
	return hashBackend, nil
}

func deriveVerifierState(input RecursionInput, config Config) (verifierState, error) {
	layout := prover.BuildLayout(input.Program, len(input.Setup.Roots))
	wantCommitments := layout.NumTrees - layout.SetupEnd
	if len(input.Proof.Commitments) != wantCommitments {
		return verifierState{}, fmt.Errorf("recursion: proof has %d commitments, layout expects %d", len(input.Proof.Commitments), wantCommitments)
	}

	if len(input.Setup.Roots) != layout.SetupEnd-layout.SetupBegin {
		return verifierState{}, fmt.Errorf("recursion: setup has %d trees, layout expects %d", len(input.Setup.Roots), layout.SetupEnd-layout.SetupBegin)
	}

	hashBackend, err := resolveRecursionHashBackend(input, config)
	if err != nil {
		return verifierState{}, err
	}

	roots := make([]hash.Digest, layout.NumTrees)
	for i, root := range input.Setup.Roots {
		roots[layout.SetupBegin+i] = root
	}
	for i, root := range input.Proof.Commitments {
		roots[layout.SetupEnd+i] = root
	}

	fs := fiatshamir.NewTranscript(hashBackend.NewTranscriptHasher())
	numRounds := len(input.Program.FScolumnsDependencies)
	for i := 0; i < numRounds; i++ {
		if err := fs.NewChallenge(constants.CanonicalChallengeName(i)); err != nil {
			return verifierState{}, err
		}
	}
	if err := fs.NewChallenge(constants.FINAL_EVALUATION_POINT); err != nil {
		return verifierState{}, err
	}
	if err := fs.NewChallenge(constants.DEEP_ALPHA); err != nil {
		return verifierState{}, err
	}

	initialChallenge := constants.InitialChallengeName(numRounds)
	if err := fs.Bind(initialChallenge, hash.StringToElements(constants.HASH_BACKEND_DOMAIN_TAG, hashBackend.ID)); err != nil {
		return verifierState{}, err
	}
	for _, root := range input.Setup.Roots {
		if err := fs.Bind(initialChallenge, root[:]); err != nil {
			return verifierState{}, err
		}
	}
	if len(input.PublicInputs) > 0 {
		if err := fs.Bind(initialChallenge, input.PublicInputs.TranscriptElements()); err != nil {
			return verifierState{}, err
		}
	}

	values := input.Proof.ExtValuesAtZeta()
	for r := 0; r < numRounds; r++ {
		challengeName := constants.CanonicalChallengeName(r)
		for i := layout.TraceBegin[r]; i < layout.TraceEnd[r]; i++ {
			if err := fs.Bind(challengeName, roots[i][:]); err != nil {
				return verifierState{}, err
			}
		}
		challenge, err := fs.ComputeChallenge(challengeName)
		if err != nil {
			return verifierState{}, err
		}
		values[challengeName] = hash.OutputToExt(challenge)
	}

	for i := layout.AIRBegin; i < layout.AIREnd; i++ {
		if err := fs.Bind(constants.FINAL_EVALUATION_POINT, roots[i][:]); err != nil {
			return verifierState{}, err
		}
	}
	zetaDigest, err := fs.ComputeChallenge(constants.FINAL_EVALUATION_POINT)
	if err != nil {
		return verifierState{}, err
	}
	zeta := hash.OutputToExt(zetaDigest)

	if err := computeExposedColumns(values, zeta, input.Program, input.Proof); err != nil {
		return verifierState{}, err
	}
	if err := computePublicInputColumns(values, zeta, input.Program, input.PublicInputs); err != nil {
		return verifierState{}, err
	}
	if err := computeLagranges(values, zeta, input.Program); err != nil {
		return verifierState{}, err
	}

	var alpha ext.E4
	var friState friVerifierState
	if !config.forceSkipInnerFRI {
		dqLayout := prover.BuildDeepQuotientLayout(input.Program)
		if err := prover.BindDeepEvaluationClaims(fs, input.Proof, dqLayout); err != nil {
			return verifierState{}, err
		}
		alphaDigest, err := fs.ComputeChallenge(constants.DEEP_ALPHA)
		if err != nil {
			return verifierState{}, err
		}
		alpha = hash.OutputToExt(alphaDigest)
		friState, err = deriveFRIVerifierState(fs, input, dqLayout)
		if err != nil {
			return verifierState{}, err
		}
	}

	return verifierState{values: values, zeta: zeta, alpha: alpha, fri: friState}, nil
}

func computeExposedColumns(values map[string]ext.E4, zeta ext.E4, program board.Program, prf proof.Proof) error {
	moduleNames := sortedModuleNames(program.Modules)
	for _, moduleName := range moduleNames {
		innerModule := program.Modules[moduleName]
		names := innerModule.VanishingRelation.Leaves(expr.NewConfig(expr.OnlyExposedColumns...))
		sort.Strings(names)
		for _, name := range names {
			pi, ok := prf.ExposedValues[name]
			if !ok {
				return fmt.Errorf("recursion: exposed column %q not found in proof.ExposedValues", name)
			}
			var lag ext.E4
			for _, pe := range pi.Entries {
				idx, err := normalizeIndex(pe.Idx, innerModule.N)
				if err != nil {
					return fmt.Errorf("recursion: exposed column %q entry: %w", name, err)
				}
				tmp := poly.LagrangeAtZetaExt(zeta, innerModule.N, idx)
				value := pe.ExtValue()
				tmp.Mul(&tmp, &value)
				lag.Add(&lag, &tmp)
			}
			values[name] = lag
		}
	}
	return nil
}

func computePublicInputColumns(values map[string]ext.E4, zeta ext.E4, program board.Program, inputs public.Inputs) error {
	moduleNames := sortedModuleNames(program.Modules)
	for _, moduleName := range moduleNames {
		innerModule := program.Modules[moduleName]
		names := innerModule.VanishingRelation.Leaves(expr.NewConfig(expr.OnlyPublicColumns...))
		sort.Strings(names)
		for _, name := range names {
			pi, ok := inputs[name]
			if !ok {
				return fmt.Errorf("recursion: public input column %q not found", name)
			}
			if pi.Module != moduleName {
				return fmt.Errorf("recursion: public input column %q belongs to module %q, used from module %q", name, pi.Module, moduleName)
			}
			var lag ext.E4
			for entryIndex, pe := range pi.Entries {
				if pe.Idx < 0 || pe.Idx >= innerModule.N {
					return fmt.Errorf("recursion: public input column %q entry %d index %d out of bounds for module %q of size %d", name, entryIndex, pe.Idx, moduleName, innerModule.N)
				}
				tmp := poly.LagrangeAtZetaExt(zeta, innerModule.N, pe.Idx)
				value := pe.ExtValue()
				tmp.Mul(&tmp, &value)
				lag.Add(&lag, &tmp)
			}
			values[name] = lag
		}
	}
	return nil
}

func computeLagranges(values map[string]ext.E4, zeta ext.E4, program board.Program) error {
	config := expr.OnlyLagranges
	for _, m := range program.Modules {
		lags := m.VanishingRelation.Leaves(expr.NewConfig(config...))
		for _, lag := range lags {
			if _, ok := values[lag]; ok {
				continue
			}
			i := constants.ParseLagrangeName(lag)
			if i < 0 {
				i = m.N + i
			}
			if i < 0 || i >= m.N {
				return fmt.Errorf("recursion: lagrange %q resolves to row %d outside module size %d", lag, i, m.N)
			}
			values[lag] = poly.LagrangeAtZetaExt(zeta, m.N, i)
		}
	}
	return nil
}

func deriveFRIVerifierState(fs *fiatshamir.Transcript, input RecursionInput, dqLayout prover.DEEPquotientLayout) (friVerifierState, error) {
	maxN, err := maxModuleSize(input.Program)
	if err != nil {
		return friVerifierState{}, err
	}
	if maxN <= 1 {
		return friVerifierState{}, nil
	}
	numRounds, err := log2Exact(maxN)
	if err != nil {
		return friVerifierState{}, err
	}

	levelDs := dqLayout.Sizes
	if len(levelDs) == 0 {
		return friVerifierState{}, fmt.Errorf("recursion: FRI has no DEEP quotient levels")
	}
	if levelDs[0] != maxN {
		return friVerifierState{}, fmt.Errorf("recursion: FRI first level D=%d, want max module size %d", levelDs[0], maxN)
	}
	if len(input.Proof.DeepQuotientCommitment) != len(levelDs) {
		return friVerifierState{}, fmt.Errorf("recursion: FRI has %d DEEP quotient commitments, want %d", len(input.Proof.DeepQuotientCommitment), len(levelDs))
	}

	wantFRIRoots := numRounds - 1
	if numRounds <= 1 {
		wantFRIRoots = 0
	}
	if len(input.Proof.DeepQuotientFriProof.FRIRoots) != wantFRIRoots {
		return friVerifierState{}, fmt.Errorf("recursion: FRI has %d running roots, want %d", len(input.Proof.DeepQuotientFriProof.FRIRoots), wantFRIRoots)
	}

	levelAtRound := make(map[int]int, len(levelDs)-1)
	for level := 1; level < len(levelDs); level++ {
		levelD := levelDs[level]
		if levelD <= 0 || levelD&(levelD-1) != 0 {
			return friVerifierState{}, fmt.Errorf("recursion: FRI level %d D=%d is not a positive power of two", level, levelD)
		}
		ratio := maxN / levelD
		if ratio <= 0 || ratio*levelD != maxN || ratio&(ratio-1) != 0 {
			return friVerifierState{}, fmt.Errorf("recursion: FRI level %d D=%d does not divide max D=%d by a power-of-two ratio", level, levelD, maxN)
		}
		round, err := log2Exact(ratio)
		if err != nil {
			return friVerifierState{}, err
		}
		if round < 1 || round >= numRounds {
			return friVerifierState{}, fmt.Errorf("recursion: FRI level %d introduction round %d outside 1..%d", level, round, numRounds-1)
		}
		if _, ok := levelAtRound[round]; ok {
			return friVerifierState{}, fmt.Errorf("recursion: FRI duplicate level introduction round %d", round)
		}
		levelAtRound[round] = level
	}

	if err := friRegisterChallenges(fs, numRounds, levelAtRound); err != nil {
		return friVerifierState{}, err
	}

	roots := make([]hash.Digest, numRounds)
	roots[0] = input.Proof.DeepQuotientCommitment[0]
	for round := 1; round < numRounds; round++ {
		roots[round] = input.Proof.DeepQuotientFriProof.FRIRoots[round-1]
	}

	foldAlphas := make([]ext.E4, numRounds)
	levelGammas := make(map[int]ext.E4, len(levelAtRound))
	for round := 0; round < numRounds; round++ {
		if round > 0 {
			if level, ok := levelAtRound[round]; ok {
				gammaName := friLevelGammaName(level)
				if err := fs.Bind(gammaName, input.Proof.DeepQuotientCommitment[level][:]); err != nil {
					return friVerifierState{}, err
				}
				challenge, err := fs.ComputeChallenge(gammaName)
				if err != nil {
					return friVerifierState{}, err
				}
				levelGammas[level] = hash.OutputToExt(challenge)
			}
		}

		foldName := friFoldName(round)
		if err := fs.Bind(foldName, roots[round][:]); err != nil {
			return friVerifierState{}, err
		}
		challenge, err := fs.ComputeChallenge(foldName)
		if err != nil {
			return friVerifierState{}, err
		}
		foldAlphas[round] = hash.OutputToExt(challenge)
	}

	if input.Proof.DeepQuotientFriProof.FinalField != field.Ext {
		return friVerifierState{}, fmt.Errorf("recursion: FRI final field is %s, want %s", input.Proof.DeepQuotientFriProof.FinalField, field.Ext)
	}
	if len(input.Proof.DeepQuotientFriProof.FinalPolyExt) == 0 {
		return friVerifierState{}, fmt.Errorf("recursion: FRI final extension polynomial is empty")
	}
	if err := fs.Bind(friQueryName(0), friTranscriptExtPoly(input.Proof.DeepQuotientFriProof.FinalPolyExt)); err != nil {
		return friVerifierState{}, err
	}

	queryIndices := make([]int, constants.NUM_QUERIES)
	queryModulus := constants.RATE * maxN / 2
	for query := 0; query < constants.NUM_QUERIES; query++ {
		challenge, err := fs.ComputeChallenge(friQueryName(query))
		if err != nil {
			return friVerifierState{}, err
		}
		queryIndices[query] = friQueryIndex(challenge, queryModulus)
		if query < constants.NUM_QUERIES-1 {
			if err := fs.Bind(friQueryName(query+1), challenge[:]); err != nil {
				return friVerifierState{}, err
			}
		}
	}

	return friVerifierState{
		maxN:         maxN,
		numRounds:    numRounds,
		levelAtRound: levelAtRound,
		foldAlphas:   foldAlphas,
		levelGammas:  levelGammas,
		queryIndices: queryIndices,
	}, nil
}

func friRegisterChallenges(fs *fiatshamir.Transcript, numRounds int, levelAtRound map[int]int) error {
	if err := fs.NewChallenge(friFoldName(0)); err != nil {
		return err
	}
	for round := 1; round < numRounds; round++ {
		if level, ok := levelAtRound[round]; ok {
			if err := fs.NewChallenge(friLevelGammaName(level)); err != nil {
				return err
			}
		}
		if err := fs.NewChallenge(friFoldName(round)); err != nil {
			return err
		}
	}
	for query := 0; query < constants.NUM_QUERIES; query++ {
		if err := fs.NewChallenge(friQueryName(query)); err != nil {
			return err
		}
	}
	return nil
}

func friLevelGammaName(level int) string {
	return fmt.Sprintf("fri_level_%d_gamma", level)
}

func friFoldName(round int) string {
	return fmt.Sprintf("fri_fold_%d", round)
}

func friQueryName(query int) string {
	return fmt.Sprintf("fri_query_%d", query)
}

func friTranscriptExtPoly(poly []ext.E4) []koalabear.Element {
	res := make([]koalabear.Element, 0, 2+4*len(poly))
	res = append(res, hash.NewElement(0x45585450), hash.NewElement(uint64(len(poly)))) // "EXTP"
	for _, v := range poly {
		res = append(res, v.B0.A0, v.B0.A1, v.B1.A0, v.B1.A1)
	}
	return res
}

func friQueryIndex(challenge hash.Digest, modulus int) int {
	if modulus <= 0 {
		return 0
	}
	v := (challenge[0].Uint64() << 31) ^ challenge[1].Uint64()
	return int(v % uint64(modulus))
}

func sortedModuleNames(modules map[string]board.CompiledModule) []string {
	names := make([]string, 0, len(modules))
	for name := range modules {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func normalizeIndex(idx, n int) (int, error) {
	if n <= 0 {
		return 0, fmt.Errorf("domain size must be positive, got %d", n)
	}
	if idx < 0 {
		idx = n + idx
	}
	if idx < 0 || idx >= n {
		return 0, fmt.Errorf("row %d outside domain size %d", idx, n)
	}
	return idx, nil
}

func maxModuleSize(program board.Program) (int, error) {
	maxN := 0
	for name, module := range program.Modules {
		if module.N <= 0 {
			return 0, fmt.Errorf("recursion: module %q has invalid size %d", name, module.N)
		}
		if module.N > maxN {
			maxN = module.N
		}
	}
	if maxN == 0 {
		return 0, fmt.Errorf("recursion: program has no modules")
	}
	return maxN, nil
}

func log2Exact(n int) (int, error) {
	if n <= 0 || n&(n-1) != 0 {
		return 0, fmt.Errorf("recursion: %d is not a positive power of two", n)
	}
	res := 0
	for n > 1 {
		n >>= 1
		res++
	}
	return res, nil
}

func bridgeSamplePoints(domainSize, idx int) (koalabear.Element, koalabear.Element, error) {
	generator, err := koalabear.Generator(uint64(domainSize))
	if err != nil {
		return koalabear.Element{}, koalabear.Element{}, err
	}
	var x, negX koalabear.Element
	x.Exp(generator, big.NewInt(int64(idx)))
	negX.Neg(&x)
	return x, negX, nil
}

func addWeightedExt(acc *ext.E4, value, weight ext.E4) {
	var term ext.E4
	term.Mul(&value, &weight)
	acc.Add(acc, &term)
}

func subExt(left, right ext.E4) ext.E4 {
	var res ext.E4
	res.Sub(&left, &right)
	return res
}

func divExt(numerator, denominator ext.E4) ext.E4 {
	var inv, res ext.E4
	inv.Inverse(&denominator)
	res.Mul(&numerator, &inv)
	return res
}

func liftBaseToExt(value koalabear.Element) ext.E4 {
	var res ext.E4
	res.Lift(&value)
	return res
}

func zeroExpr() expr.Expr {
	var z koalabear.Element
	return expr.Const(z)
}

func oneExpr() expr.Expr {
	return expr.Const(koalabear.One())
}

func uintConst(v uint64) expr.Expr {
	var z koalabear.Element
	z.SetUint64(v)
	return expr.Const(z)
}
