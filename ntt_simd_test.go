// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package fhe

import (
	"testing"
)

// NTT-friendly primes where Q ≡ 1 (mod 2*N)
var nttTestCases = []struct {
	name string
	N    uint32
	Q    uint64
}{
	{"N1024_Q27", 1024, 0x7fff801},      // PN10QP27
	{"N2048_Q54", 2048, 0x3FFFFFFFFED001}, // PN11QP54 (fixed prime)
}

func TestNewNTTEngine(t *testing.T) {
	for _, tc := range nttTestCases {
		t.Run(tc.name, func(t *testing.T) {
			eng, err := NewNTTEngine(tc.N, tc.Q)
			if err != nil {
				t.Fatalf("NewNTTEngine(%d, %d): %v", tc.N, tc.Q, err)
			}
			if eng.N != tc.N {
				t.Errorf("N = %d, want %d", eng.N, tc.N)
			}
			if eng.Q != tc.Q {
				t.Errorf("Q = %d, want %d", eng.Q, tc.Q)
			}
		})
	}
}

func TestPrimeFactors(t *testing.T) {
	tests := []struct {
		n    uint64
		want []uint64
	}{
		{12, []uint64{2, 3}},
		{60, []uint64{2, 3, 5}},
		{1024, []uint64{2}},
		{4096, []uint64{2}},
		{97, []uint64{97}},           // prime
		{2 * 3 * 5 * 7, []uint64{2, 3, 5, 7}},
	}
	for _, tc := range tests {
		got := primeFactors(tc.n)
		if len(got) != len(tc.want) {
			t.Errorf("primeFactors(%d) = %v, want %v", tc.n, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("primeFactors(%d)[%d] = %d, want %d", tc.n, i, got[i], tc.want[i])
			}
		}
	}
}

func TestNTTRoundtrip(t *testing.T) {
	for _, tc := range nttTestCases {
		t.Run(tc.name, func(t *testing.T) {
			eng, err := NewNTTEngine(tc.N, tc.Q)
			if err != nil {
				t.Fatalf("NewNTTEngine: %v", err)
			}

			N := int(tc.N)
			orig := make([]uint64, N)
			coeffs := make([]uint64, N)
			for i := 0; i < N; i++ {
				orig[i] = uint64(i) % tc.Q
				coeffs[i] = orig[i]
			}

			eng.NTTInPlace(coeffs)

			// After NTT, coeffs should differ from original (for non-trivial input)
			allSame := true
			for i := 0; i < N; i++ {
				if coeffs[i] != orig[i] {
					allSame = false
					break
				}
			}
			if allSame {
				t.Error("NTT did not transform coefficients")
			}

			eng.INTTInPlace(coeffs)

			// After INTT, should recover original
			for i := 0; i < N; i++ {
				if coeffs[i] != orig[i] {
					t.Errorf("roundtrip mismatch at [%d]: got %d, want %d", i, coeffs[i], orig[i])
					if i > 5 {
						t.Fatal("too many mismatches, stopping")
					}
				}
			}
		})
	}
}

func TestPN11QP54Prime(t *testing.T) {
	// Verify PN11QP54 modulus is NTT-friendly: prime and Q ≡ 1 (mod 2*N)
	Q := PN11QP54.QLWE
	N := uint64(1) << PN11QP54.LogNLWE // 2048

	if (Q-1)%(2*N) != 0 {
		t.Errorf("Q-1 (%d) not divisible by 2N (%d)", Q-1, 2*N)
	}

	// Verify NTT engine can be created (requires Q to be usable for NTT)
	eng, err := NewNTTEngine(uint32(N), Q)
	if err != nil {
		t.Fatalf("NewNTTEngine with PN11QP54: %v", err)
	}

	// Verify primitive root properties
	omega, err := eng.findPrimitiveRoot()
	if err != nil {
		t.Fatalf("findPrimitiveRoot: %v", err)
	}

	// omega^(2N) must equal 1
	if eng.powMod(omega, 2*N) != 1 {
		t.Error("omega^(2N) != 1")
	}

	// omega^N must equal Q-1 (i.e., -1 mod Q)
	if eng.powMod(omega, N) != Q-1 {
		t.Errorf("omega^N = %d, want %d (Q-1)", eng.powMod(omega, N), Q-1)
	}

	// omega^k != 1 for 0 < k < 2N
	if eng.powMod(omega, N) == 1 {
		t.Error("omega has order <= N, not a primitive 2N-th root")
	}
}

func TestFindPrimitiveRootAllFactors(t *testing.T) {
	// Verify findPrimitiveRoot checks ALL prime factors of Q-1, not just 2.
	// With N=1024, Q=0x7fff801: Q-1 = 134215680 = 2^14 * 3 * 5 * 547
	// If only factor 2 were checked, g=2 would falsely pass as a generator.
	// With all factors checked, the first generator is found correctly.
	Q := uint64(0x7fff801)
	eng, err := NewNTTEngine(1024, Q)
	if err != nil {
		t.Fatal(err)
	}

	omega, err := eng.findPrimitiveRoot()
	if err != nil {
		t.Fatal(err)
	}

	// Verify omega is a proper 2048-th root of unity
	N := uint64(1024)
	if eng.powMod(omega, 2*N) != 1 {
		t.Error("omega^(2N) != 1")
	}
	if eng.powMod(omega, N) == 1 {
		t.Error("omega has order dividing N, not a primitive 2N-th root")
	}
	// omega^N must be -1 (mod Q) for a primitive 2N-th root
	if eng.powMod(omega, N) != Q-1 {
		t.Errorf("omega^N = %d, want Q-1 = %d", eng.powMod(omega, N), Q-1)
	}
}
