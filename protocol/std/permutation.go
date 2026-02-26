package std

import (
	"fmt"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/iop/pas/sym"
	"github.com/consensys/iop/protocol"
	"github.com/consensys/iop/system"
)

// EqualityUpToPermutation proves that the multiset { ID1[j][i] } equals { ID2[j][i] }.
// Concretely, for every i, j there is k, l such that ID1[i][j] = ID2[k][l].
//
// It models the following Σ protocol (N = domain size, P_j := ID1[j], Q_j := ID2[j]):
//
//	|-------------------------------–-----------------------------------------------|
//	| [prover]                      |              [verifier]                       |
//	|-------------------------------–-----------------------------------------------|
//	| Commit(P_0,..,P_k,            |                                               |
//	|        Q_0,..,Q_l)    -----→  | [Com(P_0),..,Com(P_k),Com(Q_0),..,Com(Q_l)] | ROUND 1
//	|-------------------------------–-----------------------------------------------|
//	|                               ←-----  Sample random γ (challengeName)         |
//	|                               |       (γ = Fiat-Shamir(Com(P_j), Com(Q_j)))   | ROUND 2
//	|-------------------------------–-----------------------------------------------|
//	| Compute Z s.t.                |                                               |
//	|   Z[0]   = 1                  |                                               |
//	|   Z[i+1] = Z[i] ·            |                                               |
//	|     ∏_j(P_j[i] - γ)          |                                               |
//	|    ─────────────────          |                                               |
//	|     ∏_j(Q_j[i] - γ)          |                                               |
//	| Commit(Z, Z_shifted)  -----→  | [Com(Z), Com(Z_shifted)]                     | ROUND 3
//	|-------------------------------–-----------------------------------------------|
//	|       (done via FoldConstraints + Finalize + Verify)                          |
//	| Records two constraints:                                                      |
//	|   C1: ∏_j(Q_j-γ)·Z_shifted - ∏_j(P_j-γ)·Z = 0 mod X^N-1                   |
//	|   C2: (Z-1)·L_0 = 0  (enforces Z[0]=1)                                      |
//	|-------------------------------–-----------------------------------------------|
func EqualityUpToPermutationIOP(prot *protocol.Protocol, ID1, ID2 []string, IDGrandProduct string, challengeName string, opts ...system.Option) error {

	E1 := make([]sym.Expr, len(ID1))
	for i, id := range ID1 {
		if expr, ok := prot.S.VirtualColumns[id]; ok {
			E1[i] = expr
		} else {
			E1[i] = sym.NewVar(id)
		}
	}
	E2 := make([]sym.Expr, len(ID2))
	for i, id := range ID2 {
		if expr, ok := prot.S.VirtualColumns[id]; ok {
			E2[i] = expr
		} else {
			E2[i] = sym.NewVar(id)
		}
	}

	// collect the physical column IDs (leaves of the expressions, excluding placeholders)
	// to derive the challenge via Fiat-Shamir
	var physicalIDs []string
	for _, e := range E1 {
		physicalIDs = append(physicalIDs, e.Vars()...)
	}
	for _, e := range E2 {
		physicalIDs = append(physicalIDs, e.Vars()...)
	}
	physicalIDs = sym.RemoveDuplicates(physicalIDs)

	_, err := prot.SendMeAChallenge(physicalIDs, challengeName) // <- the challenge column is allocated here, we can refer to it by name from now
	if err != nil {
		return err
	}

	if err := system.BuildGrandProductAndRegisterConstraints(&prot.S, E1, E2, IDGrandProduct, challengeName, opts...); err != nil {
		return err
	}

	// enforce R[0] = 1 (Lagrange constraint at entry 0)
	var one koalabear.Element
	one.SetOne()
	return prot.NewLagrangeConstraint(IDGrandProduct, 0, one, opts...)
}

// MultiSetEqualityUpToPermutation proves that the multiset of tuples { (ID1[i][0][j], ID1[i][1][j], ..) }
// equals the multiset of tuples { (ID2[i][0][j], ID2[i][1][j], ..) }.
// Tuples are first compressed into scalars with α, then EqualityUpToPermutation is applied on the scalars.
//
// It models the following Σ protocol (N = domain size, P_s := ID1[s], Q_s := ID2[s]):
//
//	|-------------------------------–-----------------------------------------------|
//	| [prover]                      |              [verifier]                       |
//	|-------------------------------–-----------------------------------------------|
//	| Commit(P_s[0],..,P_s[d],      |                                               |
//	|        Q_s[0],..,Q_s[d])      |                                               |
//	|   for all subsets s   -----→  | [Com(P_s[k]), Com(Q_s[k])]  ∀ s, k           | ROUND 1
//	|-------------------------------–-----------------------------------------------|
//	|                               ←-----  Sample random α (alpha)                 |
//	|                               |       (α = Fiat-Shamir(Com(P_s[k]),Com(Q_s[k])))| ROUND 2
//	|-------------------------------–-----------------------------------------------|
//	| Fold each subset into a scalar column:                                        |
//	|   F1_s[i] = Σ_k α^k · P_s[k][i]                                             |
//	|   F2_s[i] = Σ_k α^k · Q_s[k][i]                                             |
//	| (reduces tuple equality to scalar equality)                                   |
//	|-------------------------------–-----------------------------------------------|
//	|                               ←-----  Sample random γ (gamma)                 |
//	|                               |       (γ = Fiat-Shamir(Com(P_s[k]),Com(Q_s[k])))| ROUND 3
//	|-------------------------------–-----------------------------------------------|
//	| Compute Z s.t.                |                                               |
//	|   Z[0]   = 1                  |                                               |
//	|   Z[i+1] = Z[i] ·            |                                               |
//	|     ∏_s(F1_s[i] - γ)         |                                               |
//	|    ─────────────────          |                                               |
//	|     ∏_s(F2_s[i] - γ)         |                                               |
//	| Commit(Z, Z_shifted)  -----→  | [Com(Z), Com(Z_shifted)]                     | ROUND 4
//	|-------------------------------–-----------------------------------------------|
//	|       (done via FoldConstraints + Finalize + Verify)                          |
//	| Records two constraints:                                                      |
//	|   C1: ∏_s(F2_s-γ)·Z_shifted - ∏_s(F1_s-γ)·Z = 0 mod X^N-1                 |
//	|   C2: (Z-1)·L_0 = 0  (enforces Z[0]=1)                                      |
//	|-------------------------------–-----------------------------------------------|
func MultiSetEqualityUpToPermutationIOP(
	prot *protocol.Protocol,
	ID1, ID2 [][]string,
	IDGrandProduct string,
	alpha, gamma string,
	opts ...system.Option) error {

	// step 1: collect all physical column IDs and sample alpha.
	// SendMeAChallenge commits every physical column and derives alpha via Fiat-Shamir.
	var allIDs []string
	for _, subset := range ID1 {
		allIDs = append(allIDs, subset...)
	}
	for _, subset := range ID2 {
		allIDs = append(allIDs, subset...)
	}
	allIDs = sym.RemoveDuplicates(allIDs)
	if _, err := prot.SendMeAChallenge(allIDs, alpha); err != nil {
		return err
	}

	// step 2: fold each subset into a single expression and register it as a virtual column.
	// F1[i] = ID1[i][0] + alpha * ID1[i][1] + alpha^2 * ID1[i][2] + ...
	E1 := make([]sym.Expr, len(ID1))
	VID1 := make([]string, len(ID1))
	for i, subset := range ID1 {
		E1[i] = system.GetFoldingExpression(subset, alpha)
		VID1[i] = fmt.Sprintf("F1_%d", i)
		if err := system.NewVirtualColumn(&prot.S, VID1[i], E1[i]); err != nil {
			return err
		}
	}
	E2 := make([]sym.Expr, len(ID2))
	VID2 := make([]string, len(ID2))
	for i, subset := range ID2 {
		E2[i] = system.GetFoldingExpression(subset, alpha)
		VID2[i] = fmt.Sprintf("F2_%d", i)
		if err := system.NewVirtualColumn(&prot.S, VID2[i], E2[i]); err != nil {
			return err
		}
	}

	// step 3: build the grand product constraint over the folded virtual columns.
	// EqualityUpToPermutation looks up VID1/VID2 in VirtualColumns, collects the physical
	// column IDs from their leaves, samples gamma, and also enforces R[0]=1.
	return EqualityUpToPermutationIOP(prot, VID1, VID2, IDGrandProduct, gamma, opts...)
}
