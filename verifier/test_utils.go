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

package verifier

import (
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark-crypto/field/koalabear/fft"
	"github.com/consensys/gnark-crypto/field/koalabear/iop"
	gnark_plonk "github.com/consensys/gnark/backend/plonk/koalabear"
	gnark_cs "github.com/consensys/gnark/constraint/koalabear"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/loom/internal/poly"
	"github.com/consensys/loom/trace"
)

const (
	ID_L  string = "L"
	ID_R  string = "R"
	ID_O  string = "O"
	ID_Z  string = "Z"
	ID_ZS string = "ZS"
	ID_Ql string = "QL"
	ID_Qr string = "QR"
	ID_Qm string = "QM"
	ID_Qo string = "QO"
	ID_Qk string = "QK"
)

func ithInstance(id string, num int) string {
	return fmt.Sprintf("%d-%s", num, id)
}

// gnarkCryptoPolyToUnivariatePoly converts *iop.Polynomial to poly.Polynomial
// (i.e., []koalabear.Element in Lagrange Normal form).
func gnarkCryptoPolyToUnivariatePoly(p *iop.Polynomial) (poly.Polynomial, error) {
	c := p.Coefficients()
	coeffs := make([]koalabear.Element, len(c))
	copy(coeffs, c)

	n := uint64(len(coeffs))
	d := fft.NewDomain(n)

	switch p.Basis {
	case iop.Lagrange:
		if p.Layout == iop.BitReverse {
			fft.BitReverse(coeffs)
		}
		// Lagrange Normal: already in the desired form
	case iop.Canonical:
		if p.Layout == iop.BitReverse {
			fft.BitReverse(coeffs) // canonical BitReversed → canonical Normal
		}
		d.FFT(coeffs, fft.DIF) // canonical Normal → Lagrange BitReversed
		fft.BitReverse(coeffs) // → Lagrange Normal
	case iop.LagrangeCoset:
		if p.Layout == iop.BitReverse {
			fft.BitReverse(coeffs)
		}
		poly.CosetLagrangeToLagrangeNormal(coeffs)
	default:
		return nil, fmt.Errorf("unsupported polynomial basis")
	}

	return coeffs, nil
}

// buildTrace from a plonk trace ([ql, qr, qm, qo, qk, l, r, o], permutation), returns
// a trace.
//
// nbPublicInputs must equal len(spr.Public) (i.e. spr.GetNbPublicVariables()).
// gnark's NewTrace leaves Qk[i]=0 for i < nbPublicInputs (public-input placeholder rows
// where Ql[i]=-1), with the explicit note "to be completed by the prover". The prover
// must set Qk[i]=L[i] so that the vanishing relation Ql[i]*L[i]+Qk[i] = -L[i]+L[i] = 0
// holds on those rows.
func buildTrace(plonkTrace *gnark_plonk.Trace, plonkSolution *gnark_cs.SparseR1CSSolution, nbPublicInputs int, i int) (trace.Trace, error) {

	nbColumns := 16
	T := make(trace.Trace, nbColumns)
	var err error

	T[Ith(ID_Ql, i)], err = gnarkCryptoPolyToUnivariatePoly(plonkTrace.Ql)
	if err != nil {
		return T, err
	}
	T[Ith(ID_Qr, i)], err = gnarkCryptoPolyToUnivariatePoly(plonkTrace.Qr)
	if err != nil {
		return T, err
	}
	T[Ith(ID_Qm, i)], err = gnarkCryptoPolyToUnivariatePoly(plonkTrace.Qm)
	if err != nil {
		return T, err
	}
	T[Ith(ID_Qo, i)], err = gnarkCryptoPolyToUnivariatePoly(plonkTrace.Qo)
	if err != nil {
		return T, err
	}
	T[Ith(ID_Qk, i)], err = gnarkCryptoPolyToUnivariatePoly(plonkTrace.Qk)
	if err != nil {
		return T, err
	}

	// Solution columns: L, R, O are already in Lagrange Normal form
	lCoeffs := make([]koalabear.Element, len(plonkSolution.L))
	copy(lCoeffs, plonkSolution.L)
	T[Ith(ID_L, i)] = lCoeffs

	// Complete Qk for the public-input placeholder rows.
	for k := 0; k < nbPublicInputs; k++ {
		T[Ith(ID_Qk, i)][k] = T[Ith(ID_L, i)][k]
	}

	rCoeffs := make([]koalabear.Element, len(plonkSolution.R))
	copy(rCoeffs, plonkSolution.R)
	T[Ith(ID_R, i)] = rCoeffs

	oCoeffs := make([]koalabear.Element, len(plonkSolution.O))
	copy(oCoeffs, plonkSolution.O)
	T[Ith(ID_O, i)] = oCoeffs

	return T, nil
}

// plonk circuit
type Circuit struct {
	A, B, C frontend.Variable
	D       frontend.Variable
	N       int
}

func (c *Circuit) Define(api frontend.API) error {

	a := api.Mul(c.A, c.B)
	a = api.Add(a, c.C)

	for i := 0; i < c.N; i++ {
		a = api.Mul(a, a)
	}

	api.AssertIsDifferent(a, c.D)

	return nil
}

func Ith(s string, i int) string {
	return fmt.Sprintf("%s_%d", s, i)
}

func getIthPlonkTrace(N int, i int) (trace.Trace, []int64, int, error) {

	assignment := Circuit{
		A: 3,
		B: 4,
		C: 5,
		D: 6,
		N: N,
	}
	witness, err := frontend.NewWitness(&assignment, koalabear.Modulus())
	if err != nil {
		return nil, nil, 0, err
	}

	var circuit Circuit

	ccs, err := frontend.CompileU32(koalabear.Modulus(), scs.NewBuilder, &circuit)
	if err != nil {
		return nil, nil, 0, err
	}
	spr, ok := ccs.(*gnark_cs.SparseR1CS)
	if !ok {
		return nil, nil, 0, fmt.Errorf("cannot cast ccs to *gnark_constraint.SparseR1CS")
	}

	nbPublic := ccs.GetNbPublicVariables()
	nbRelations := ccs.GetNbConstraints()
	size := poly.NextPowerOfTwo(nbRelations + nbPublic)
	d := fft.NewDomain(uint64(size))

	publicTrace := gnark_plonk.NewTrace(spr, d)

	isolution, err := spr.Solve(witness)
	if err != nil {
		return nil, nil, size, err
	}
	solution, ok := isolution.(*gnark_cs.SparseR1CSSolution)
	if !ok {
		return nil, nil, size, fmt.Errorf("cannot cast isolution to *gnark_constraint.SparseR1CSSolution")
	}

	T, err := buildTrace(publicTrace, solution, nbPublic, i)
	if err != nil {
		return nil, nil, size, err
	}

	return T, publicTrace.S, size, nil
}
