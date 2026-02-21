package cs

import (
	"testing"
)

func TestVanishing(t *testing.T) {

	// trivial circuit: quotient=0
	{
		// get simple system, test it
		P, C, N := GetTrivialVanishingConstraint(t)

		S := System{Trace: P, Constraint: C, N: N}
		if err := BruteForceChecker(S); err != nil {
			t.Fatalf("[BruteForceChecker] Trace does not satisfy the constraint: %v", err)
		}
		if err := QuotientChecker(S); err != nil {
			t.Fatalf("[QuotientChecker] Trace does not satisfy the constraint: %v", err)
		}

		// call ProveVanishingConstraint to populate the proof
		_, T, err := NewVanishingProtocol(P, C)
		if err != nil {
			t.Fatalf("ProveVanishingConstraint failed: %v", err)
		}

		// call VerifyVanishingConstraint, check that there is no error
		if err := Verify(&T); err != nil {
			t.Fatalf("VerifyVanishingConstraint failed: %v", err)
		}
	}

	// non trivial circuit: quotient != 0
	{
		// get simple system, test it
		P, C, N := GetNonTrivialVanishingConstraint(t)

		S := System{Trace: P, Constraint: C, N: N}
		if err := BruteForceChecker(S); err != nil {
			t.Fatalf("[BruteForceChecker] Trace does not satisfy the constraint: %v", err)
		}
		if err := QuotientChecker(S); err != nil {
			t.Fatalf("[QuotientChecker] Trace does not satisfy the constraint: %v", err)
		}

		// call ProveVanishingConstraint to populate the proof
		_, T, err := NewVanishingProtocol(P, C)
		if err != nil {
			t.Fatalf("ProveVanishingConstraint failed: %v", err)
		}

		// call VerifyVanishingConstraint, check that there is no error
		if err := Verify(&T); err != nil {
			t.Fatalf("VerifyVanishingConstraint failed: %v", err)
		}
	}

	// high degree circuit
	{
		T, C, N := GetHighDegreeVanishingConstraint(t)

		S := System{Trace: T, Constraint: C, N: N}
		if err := BruteForceChecker(S); err != nil {
			t.Fatalf("[BruteForceChecker] Trace does not satisfy the constraint: %v", err)
		}

		if err := QuotientChecker(S); err != nil {
			t.Fatalf("[QuotientChecker] Trace does not satisfy the constraint: %v", err)
		}

		// 1. Without degree reducing
		{
			// call ProveVanishingConstraint to populate the proof
			S, P, err := NewVanishingProtocol(T, C)
			if err != nil {
				t.Fatalf("ProveVanishingConstraint failed: %v", err)
			}

			// recheck S - NewVanishingProtocol should not modify S at all
			if err := BruteForceChecker(S); err != nil {
				t.Fatalf("[BruteForceChecker] Trace does not satisfy the constraint: %v", err)
			}

			if err := QuotientChecker(S); err != nil {
				t.Fatalf("[QuotientChecker] Trace does not satisfy the constraint: %v", err)
			}

			// call VerifyVanishingConstraint, check that there is no error
			if err := Verify(&P); err != nil {
				t.Fatalf("VerifyVanishingConstraint failed: %v", err)
			}
		}

		// 2. With degree reducing
		{
			// call ProveVanishingConstraint to populate the proof
			S, P, err := NewVanishingProtocol(T, C, WithMaxDegree(3))
			if err != nil {
				t.Fatalf("ProveVanishingConstraint failed: %v", err)
			}
			if P.Constraint.Degree() > 3 {
				t.Fatalf("max degree should be 3, got %d", S.Constraint.Degree())
			}

			if err := BruteForceChecker(S); err != nil {
				t.Fatalf("[BruteForceChecker] Trace does not satisfy the constraint: %v", err)
			}
			if err := QuotientChecker(S); err != nil {
				t.Fatalf("[QuotientChecker] Trace does not satisfy the constraint: %v", err)
			}

			// call VerifyVanishingConstraint, check that there is no error
			if err := Verify(&P); err != nil {
				t.Fatalf("VerifyVanishingConstraint failed: %v", err)
			}
		}
	}

}
