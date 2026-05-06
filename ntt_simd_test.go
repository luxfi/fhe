// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package fhe

import (
	"testing"
)

// NTT-friendly primes where Q ≡ 1 (mod 2*N).
var nttTestCases = []struct {
	name string
	N    uint32
	Q    uint64
}{
	{"N1024_Q27", 1024, 0x7fff801},        // PN10QP27
	{"N2048_Q54", 2048, 0x3FFFFFFFFED001}, // PN11QP54
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

// TestNTTRoundtrip verifies INTT(NTT(x)) == x. The intermediate byte
// representation is negacyclic (Montgomery form) per the unified Lux
// NTT substrate; only round-trip equivalence is asserted here.
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

			// After NTT, coeffs should differ from the input (non-trivial transform).
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

// TestNTTRoundtripSIMD exercises the SIMD-named entry points; on the
// unified substrate they delegate to the same body as the scalar path.
func TestNTTRoundtripSIMD(t *testing.T) {
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

			eng.NTTInPlaceSIMD(coeffs)
			eng.INTTInPlaceSIMD(coeffs)

			for i := 0; i < N; i++ {
				if coeffs[i] != orig[i] {
					t.Errorf("SIMD roundtrip mismatch at [%d]: got %d, want %d", i, coeffs[i], orig[i])
					if i > 5 {
						t.Fatal("too many mismatches, stopping")
					}
				}
			}
		})
	}
}

// TestPN11QP54Prime verifies the PN11QP54 modulus is NTT-friendly and the
// engine constructs successfully (the substrate validates primality and
// Q ≡ 1 (mod 2N) inside GenerateNTTConstants).
func TestPN11QP54Prime(t *testing.T) {
	Q := PN11QP54.QLWE
	N := uint64(1) << PN11QP54.LogNLWE

	if (Q-1)%(2*N) != 0 {
		t.Errorf("Q-1 (%d) not divisible by 2N (%d)", Q-1, 2*N)
	}

	if _, err := NewNTTEngine(uint32(N), Q); err != nil {
		t.Fatalf("NewNTTEngine with PN11QP54: %v", err)
	}
}
