package fri

import (
	ext "github.com/consensys/gnark-crypto/field/koalabear/extensions"
)

type OpeningProof struct {
	FriProof      Proof
	ClaimedValues []ext.E6

	// PointSamplings[q][i] is the opening at FRI query position q of the i-th
	// committed tree
	PointSamplings [][]WMerkleProof
}

// batches are polynomials of in lagrange basis, not bit reversed
// alpha is the challenge used to fold the DEEP quotients per size (sum_i \alpha^i(P_i(\omega^shift*zeta)-P(X))/(\omega^shift*zeta-X)
// zeta base point of evaluation
// shifts[i]
// func computeDeepQuotient(batches []Batch, alpha, zeta ext.E6, shifts [][]int, evaluations [][]ext.E6) map[int]poly.ExtPolynomial {

// 	// group all polynomials of the same size accross batches
// 	// for each size, group polynomials per shift in increasing shift order

// 	// for each size, compute the corresponding DEEP quotient:
// 	// (sum_i1<n1 \alpha^i1(P_i1(\omega^shift1*zeta)-P_i1(X))/(\omega^shift1*zeta-X) +
// 	// (sum_i2<n2 \alpha^i1(P_i2(\omega^shift2*zeta)-P_i2(X))/(\omega^shift2*zeta-X) +
// 	// ..

// }

// func Open(batches []Batch, fs *fiatshamir.Transcript) OpeningProof {

// 	// step

// }
