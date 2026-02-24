package system

// flatten lows the degree of a constraint.
//
// To compute C(P)/X^n-1, if the degree of C(P) is too big, we can't use FFT because the domain might not be
// big enough.
//
// To avoid this issue the strategy we compute intermediate expressions of low degree step by step.
//
// Example: if C(P1,P2) = P1⁵ - P2³ and WithMaxDegree(2), we build new intermediate polynomials of degree N (size of the original polynomials in P):
// * Q1, that satisfies the constraint C1: Q1-P1² = 0 mod X^n-1
// * Q2, that satisfies the constraint C2: Q2-Q1² = 0 mod X^n-1
// * Q3, that satisfies the constraint C3: Q3-Q2*Q = 0 mod X^n-1 <- so Q3 - P1⁵ = 0 mod X^n-1, and for each intermediate relations we can compute the quotient by X^n-1
// * R1, that satisfies the constraint C4: R1-P2² = 0 mod X^n-1
// * R2, that satisfies the constraint C5: R2 - P2*R1 = 0 mod X^n-1 <- so R2 - P2³ = 0 mod X^n-1, and for each intermediate relations we can compute the quotient by X^n-1
// Proving that C(P1, P2) = 0 mod X^n-1 is equivalent (with high probability for a random α) to proving that
// (Q1-P1²)+α(Q2-Q1²)+α²(Q3-Q2*Q)+α³(R1-P2²)+α⁴(R2 - P2*R1) = 0 mod X^n-1
// Now (Q1-P1²)+α(Q2-Q1²)+α²(Q3-Q2*Q)+α³(R1-P2²)+α⁴(R2 - P2*R1) is if low degree, so we can compute
// [ (Q1-P1²)+α(Q2-Q1²)+α²(Q3-Q2*Q)+α³(R1-P2²)+α⁴(R2 - P2*R1) ] / X^n-1 without an fft domain which is too big.
//
// Flatten returns all the simple IOP created in the process of pruning C, low-degree expressions at a time
func Flatten(S *System, C Constraint, targetDegree int) error {

	CLowRecord := make(map[string]struct{})

	for C.Degree() > targetDegree {

		CLow := C.Prune(targetDegree)

		// make sure CLow is not already recorded (might happen if the same expression appears at multiple leaves)
		// Prune already replaced the occurrence in CReduced with NewVar(CLow.String()), so we've made
		// progress regardless; we just skip creating a duplicate intermediate polynomial.
		if _, ok := CLowRecord[CLow.String()]; ok {
			continue
		}
		CLowRecord[CLow.String()] = struct{}{}

		err := BuildColumn(S, CLow, CLow.String())
		if err != nil {
			return err
		}

	}
	return nil
}
