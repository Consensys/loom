package proveractions

import (
	"fmt"
	"sync"

	"github.com/consensys/giop/pas/sym"
	"github.com/consensys/giop/trace"
)

var PARegister map[PAIdentifier]Action

type PAIdentifier int

const (
	GRAND_SUM PAIdentifier = iota
	GRAND_PRODUCT
	LAGRANGE
	COMPUTE_COL
	MULTIPLICITY
	FITLERED_ACC_POLY
	FIAT_SHAMIR
)

func init() {
	PARegister = make(map[PAIdentifier]Action)
	PARegister[GRAND_PRODUCT] = ComputeGrandProduct
	PARegister[GRAND_SUM] = ComputeGrandSum
	PARegister[LAGRANGE] = ComputeLagrangeColumn
	PARegister[COMPUTE_COL] = ComputeColumn
	PARegister[MULTIPLICITY] = ComputeMultiplicity
	PARegister[FITLERED_ACC_POLY] = ComputeFilteredAccPolynomial
	PARegister[FIAT_SHAMIR] = ComputeChallenge
}

type Action = func(trace.Trace, *Proof, *sync.Mutex, []sym.Expr, []string, Ctx) error

type Ctx interface {
	String() string
	GetID() PAIdentifier
}

// simple type of context, an identifier
type IDCtx struct {
	ID PAIdentifier
}

func (ctx IDCtx) GetID() PAIdentifier {
	return ctx.ID
}

func (ctx IDCtx) String() string {
	switch ctx.ID {
	case GRAND_PRODUCT:
		return "grand_product"
	case GRAND_SUM:
		return "grand_sum"
	case LAGRANGE:
		return "lagrange"
	case COMPUTE_COL:
		return "comCol"
	case MULTIPLICITY:
		return "multiplicity"
	case FITLERED_ACC_POLY:
		return "filtered acc poly"
	case FIAT_SHAMIR:
		return "fiat shamir"
	}
	return "not found"
}

func NewIDCtx(id PAIdentifier) IDCtx {
	return IDCtx{ID: id}
}

// ProverAction functions telling how to solve for intermediate columns in a list of constraints
type ProverAction struct {
	Inputs  []sym.Expr
	Outputs []string
	Ctx     Ctx // additional context needed in certain case (e.g. building columns representing a permutation)
}

func (pa ProverAction) Execute(trace trace.Trace, proof *Proof, mu *sync.Mutex) error {
	if _, ok := PARegister[pa.Ctx.GetID()]; !ok {
		return fmt.Errorf("prover action not found")
	}
	F := PARegister[pa.Ctx.GetID()]
	return F(trace, proof, mu, pa.Inputs, pa.Outputs, pa.Ctx)
}

// List of functions needed for solving all the columns in FinalVanishingRelation
type ProverActions = []ProverAction
