//go:build ntt_experimental
// +build ntt_experimental

// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

// This file contains experimental NTT optimization tests.
// To run: go test -tags ntt_experimental ./...

package tfhe

import (
	"math/rand"
	"testing"
)

// Test parameters for NTT
// Note: Q must satisfy (Q-1) % 2N == 0 for NTT to work
// For TFHE, the lattice library handles this internally with proper moduli
const (
	testN = 1024
	// Q must have (Q-1) divisible by 2N = 2048
	// 2048 = 2^11, so we need Q ≡ 1 (mod 2048)
	// Example: 12289 = 6*2048 + 1 (used in many NTT implementations)
	// Or: 132120577 = 64512*2048 + 1 (larger prime)
	testQ = 132120577 // Prime with 2N | Q-1
)

func TestNTTEngineCreation(t *testing.T) {
	t.Skip("Skipping experimental NTT optimization tests")
	engine := NewNTTEngine(testN, testQ)

	if engine.N != testN {
		t.Errorf("expected N=%d, got %d", testN, engine.N)
	}
	if engine.Q != testQ {
		t.Errorf("expected Q=%d, got %d", testQ, engine.Q)
	}

	// Verify twiddle factors are populated
	if len(engine.twiddleFactors) != testN {
		t.Errorf("expected %d twiddle factors, got %d", testN, len(engine.twiddleFactors))
	}

	// Verify nInv * N = 1 mod Q
	prod := engine.mulMod(engine.nInv, uint64(engine.N))
	if prod != 1 {
		t.Errorf("N^(-1) * N != 1 mod Q: got %d", prod)
	}
}

func TestNTTRoundTrip(t *testing.T) {
	t.Skip("Skipping experimental NTT optimization tests")
	engine := NewNTTEngine(testN, testQ)

	// Create random polynomial
	original := make([]uint64, testN)
	for i := range original {
		original[i] = uint64(rand.Int63n(int64(testQ)))
	}

	// Copy for NTT
	coeffs := make([]uint64, testN)
	copy(coeffs, original)

	// Forward NTT
	engine.NTTInPlace(coeffs)

	// Verify it changed (should be different for random input)
	same := true
	for i := range coeffs {
		if coeffs[i] != original[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("NTT did not change coefficients")
	}

	// Inverse NTT
	engine.INTTInPlace(coeffs)

	// Verify round-trip
	for i := range coeffs {
		if coeffs[i] != original[i] {
			t.Errorf("round-trip mismatch at index %d: expected %d, got %d",
				i, original[i], coeffs[i])
		}
	}
}

func TestNTTZeroPolynomial(t *testing.T) {
	engine := NewNTTEngine(testN, testQ)

	coeffs := make([]uint64, testN)

	engine.NTTInPlace(coeffs)

	// NTT of zero should be zero
	for i, c := range coeffs {
		if c != 0 {
			t.Errorf("NTT of zero polynomial has non-zero at %d: %d", i, c)
		}
	}
}

func TestNTTConstantPolynomial(t *testing.T) {
	engine := NewNTTEngine(testN, testQ)

	// f(x) = c (constant polynomial)
	c := uint64(12345)
	coeffs := make([]uint64, testN)
	coeffs[0] = c

	original := make([]uint64, testN)
	copy(original, coeffs)

	engine.NTTInPlace(coeffs)

	// NTT(c) should have c at all evaluation points (since f(omega^i) = c)
	for i, val := range coeffs {
		if val != c {
			t.Errorf("NTT of constant at index %d: expected %d, got %d", i, c, val)
		}
	}

	engine.INTTInPlace(coeffs)

	// Verify round-trip
	for i := range coeffs {
		if coeffs[i] != original[i] {
			t.Errorf("round-trip of constant polynomial mismatch at %d", i)
		}
	}
}

func TestNTTConvolution(t *testing.T) {
	engine := NewNTTEngine(testN, testQ)

	// Test that multiplication in NTT domain = convolution in coefficient domain
	// For negacyclic convolution: (a * b)(x) = a(x) * b(x) mod (x^N + 1)

	// Simple test: a = [1, 2, 0, 0, ...], b = [3, 4, 0, 0, ...]
	// a * b = [3, 10, 8, 0, ...] mod Q

	a := make([]uint64, testN)
	b := make([]uint64, testN)
	a[0], a[1] = 1, 2
	b[0], b[1] = 3, 4

	aCopy := make([]uint64, testN)
	bCopy := make([]uint64, testN)
	copy(aCopy, a)
	copy(bCopy, b)

	// NTT both
	engine.NTTInPlace(a)
	engine.NTTInPlace(b)

	// Point-wise multiply
	result := make([]uint64, testN)
	engine.PolyMulNTT(a, b, result)

	// INTT
	engine.INTTInPlace(result)

	// Check first few coefficients
	expected := []uint64{3, 10, 8}
	for i, exp := range expected {
		if result[i] != exp {
			t.Errorf("convolution result[%d]: expected %d, got %d", i, exp, result[i])
		}
	}

	// Rest should be zero
	for i := 3; i < testN; i++ {
		if result[i] != 0 {
			t.Errorf("convolution result[%d] should be 0, got %d", i, result[i])
		}
	}
}

func TestNTTNegacyclicWrap(t *testing.T) {
	engine := NewNTTEngine(testN, testQ)

	// Test negacyclic property: x^N = -1 mod (x^N + 1)
	// So multiplying by x^N should negate the polynomial

	// a = [1, 0, 0, ..., 0]
	// b = [0, 0, ..., 0, 1] (x^(N-1))
	// a * b = [0, 1, 0, ..., 0] = x
	// a * b * b = [0, 0, 1, 0, ..., 0] = x^2
	// After N multiplications by b, we should get -a due to negacyclic wrap

	a := make([]uint64, testN)
	b := make([]uint64, testN)
	a[0] = 1
	b[1] = 1 // x

	engine.NTTInPlace(a)
	engine.NTTInPlace(b)

	result := make([]uint64, testN)
	engine.PolyMulNTT(a, b, result)

	engine.INTTInPlace(result)

	// result should be x, i.e., [0, 1, 0, ...]
	if result[0] != 0 || result[1] != 1 {
		t.Errorf("multiplication by x failed: got [%d, %d, ...]", result[0], result[1])
	}
	for i := 2; i < testN; i++ {
		if result[i] != 0 {
			t.Errorf("result[%d] should be 0, got %d", i, result[i])
		}
	}
}

func TestPolyAdd(t *testing.T) {
	engine := NewNTTEngine(testN, testQ)

	a := make([]uint64, testN)
	b := make([]uint64, testN)
	result := make([]uint64, testN)

	for i := range a {
		a[i] = uint64(rand.Int63n(int64(testQ)))
		b[i] = uint64(rand.Int63n(int64(testQ)))
	}

	engine.PolyAdd(a, b, result)

	for i := range result {
		expected := (a[i] + b[i]) % testQ
		if result[i] != expected {
			t.Errorf("PolyAdd[%d]: expected %d, got %d", i, expected, result[i])
		}
	}
}

func TestPolySub(t *testing.T) {
	engine := NewNTTEngine(testN, testQ)

	a := make([]uint64, testN)
	b := make([]uint64, testN)
	result := make([]uint64, testN)

	for i := range a {
		a[i] = uint64(rand.Int63n(int64(testQ)))
		b[i] = uint64(rand.Int63n(int64(testQ)))
	}

	engine.PolySub(a, b, result)

	for i := range result {
		var expected uint64
		if a[i] >= b[i] {
			expected = a[i] - b[i]
		} else {
			expected = testQ - b[i] + a[i]
		}
		if result[i] != expected {
			t.Errorf("PolySub[%d]: expected %d, got %d", i, expected, result[i])
		}
	}
}

func TestPolyNeg(t *testing.T) {
	engine := NewNTTEngine(testN, testQ)

	a := make([]uint64, testN)
	result := make([]uint64, testN)

	for i := range a {
		a[i] = uint64(rand.Int63n(int64(testQ)))
	}

	engine.PolyNeg(a, result)

	for i := range result {
		var expected uint64
		if a[i] == 0 {
			expected = 0
		} else {
			expected = testQ - a[i]
		}
		if result[i] != expected {
			t.Errorf("PolyNeg[%d]: expected %d, got %d", i, expected, result[i])
		}
	}
}

func TestPolyMulScalar(t *testing.T) {
	engine := NewNTTEngine(testN, testQ)

	a := make([]uint64, testN)
	result := make([]uint64, testN)
	scalar := uint64(12345)

	for i := range a {
		a[i] = uint64(rand.Int63n(int64(testQ)))
	}

	engine.PolyMulScalar(a, scalar, result)

	for i := range result {
		expected := engine.mulMod(a[i], scalar)
		if result[i] != expected {
			t.Errorf("PolyMulScalar[%d]: expected %d, got %d", i, expected, result[i])
		}
	}
}

func TestNTTBatch(t *testing.T) {
	engine := NewNTTEngine(testN, testQ)
	batchSize := 16

	// Create batch of random polynomials
	polys := make([][]uint64, batchSize)
	originals := make([][]uint64, batchSize)

	for i := range polys {
		polys[i] = make([]uint64, testN)
		originals[i] = make([]uint64, testN)
		for j := range polys[i] {
			polys[i][j] = uint64(rand.Int63n(int64(testQ)))
			originals[i][j] = polys[i][j]
		}
	}

	// Batch NTT
	engine.NTTBatch(polys)

	// Batch INTT
	engine.INTTBatch(polys)

	// Verify round-trip
	for i := range polys {
		for j := range polys[i] {
			if polys[i][j] != originals[i][j] {
				t.Errorf("batch round-trip mismatch at poly %d, coeff %d", i, j)
			}
		}
	}
}

func TestBarrettReduction(t *testing.T) {
	engine := NewNTTEngine(testN, testQ)

	// Test cases
	cases := []struct {
		a, b uint64
	}{
		{0, 0},
		{1, 1},
		{testQ - 1, testQ - 1},
		{testQ / 2, testQ / 2},
		{12345, 67890},
	}

	for _, tc := range cases {
		expected := engine.mulMod(tc.a, tc.b)
		got := engine.mulModBarrett(tc.a, tc.b)

		if got != expected {
			t.Errorf("Barrett(%d * %d): expected %d, got %d", tc.a, tc.b, expected, got)
		}
	}

	// Random cases
	for i := 0; i < 1000; i++ {
		a := uint64(rand.Int63n(int64(testQ)))
		b := uint64(rand.Int63n(int64(testQ)))

		expected := engine.mulMod(a, b)
		got := engine.mulModBarrett(a, b)

		if got != expected {
			t.Errorf("Barrett(%d * %d): expected %d, got %d", a, b, expected, got)
		}
	}
}

// ========== Edge Case Tests ==========

func TestNTTEdgeCases(t *testing.T) {
	engine := NewNTTEngine(testN, testQ)

	t.Run("all_ones", func(t *testing.T) {
		coeffs := make([]uint64, testN)
		for i := range coeffs {
			coeffs[i] = 1
		}
		original := make([]uint64, testN)
		copy(original, coeffs)

		engine.NTTInPlace(coeffs)
		engine.INTTInPlace(coeffs)

		for i := range coeffs {
			if coeffs[i] != original[i] {
				t.Errorf("all_ones: mismatch at %d", i)
			}
		}
	})

	t.Run("max_values", func(t *testing.T) {
		coeffs := make([]uint64, testN)
		for i := range coeffs {
			coeffs[i] = testQ - 1
		}
		original := make([]uint64, testN)
		copy(original, coeffs)

		engine.NTTInPlace(coeffs)
		engine.INTTInPlace(coeffs)

		for i := range coeffs {
			if coeffs[i] != original[i] {
				t.Errorf("max_values: mismatch at %d", i)
			}
		}
	})

	t.Run("alternating", func(t *testing.T) {
		coeffs := make([]uint64, testN)
		for i := range coeffs {
			if i%2 == 0 {
				coeffs[i] = 0
			} else {
				coeffs[i] = testQ - 1
			}
		}
		original := make([]uint64, testN)
		copy(original, coeffs)

		engine.NTTInPlace(coeffs)
		engine.INTTInPlace(coeffs)

		for i := range coeffs {
			if coeffs[i] != original[i] {
				t.Errorf("alternating: mismatch at %d", i)
			}
		}
	})

	t.Run("single_nonzero", func(t *testing.T) {
		for pos := 0; pos < 10; pos++ {
			coeffs := make([]uint64, testN)
			coeffs[pos] = 12345
			original := make([]uint64, testN)
			copy(original, coeffs)

			engine.NTTInPlace(coeffs)
			engine.INTTInPlace(coeffs)

			for i := range coeffs {
				if coeffs[i] != original[i] {
					t.Errorf("single_nonzero at %d: mismatch at %d", pos, i)
				}
			}
		}
	})
}

// ========== Benchmarks ==========

func BenchmarkNTT(b *testing.B) {
	engine := NewNTTEngine(testN, testQ)
	coeffs := make([]uint64, testN)
	for i := range coeffs {
		coeffs[i] = uint64(rand.Int63n(int64(testQ)))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.NTTInPlace(coeffs)
	}
}

func BenchmarkINTT(b *testing.B) {
	engine := NewNTTEngine(testN, testQ)
	coeffs := make([]uint64, testN)
	for i := range coeffs {
		coeffs[i] = uint64(rand.Int63n(int64(testQ)))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.INTTInPlace(coeffs)
	}
}

func BenchmarkNTTRoundTrip(b *testing.B) {
	engine := NewNTTEngine(testN, testQ)
	coeffs := make([]uint64, testN)
	for i := range coeffs {
		coeffs[i] = uint64(rand.Int63n(int64(testQ)))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.NTTInPlace(coeffs)
		engine.INTTInPlace(coeffs)
	}
}

func BenchmarkPolyMulNTT(b *testing.B) {
	engine := NewNTTEngine(testN, testQ)
	a := make([]uint64, testN)
	bb := make([]uint64, testN)
	result := make([]uint64, testN)

	for i := range a {
		a[i] = uint64(rand.Int63n(int64(testQ)))
		bb[i] = uint64(rand.Int63n(int64(testQ)))
	}

	engine.NTTInPlace(a)
	engine.NTTInPlace(bb)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.PolyMulNTT(a, bb, result)
	}
}

func BenchmarkBarrettMul(b *testing.B) {
	engine := NewNTTEngine(testN, testQ)
	a := uint64(rand.Int63n(int64(testQ)))
	bb := uint64(rand.Int63n(int64(testQ)))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.mulModBarrett(a, bb)
	}
}

func BenchmarkNTTBatch(b *testing.B) {
	engine := NewNTTEngine(testN, testQ)
	batchSize := 16

	polys := make([][]uint64, batchSize)
	for i := range polys {
		polys[i] = make([]uint64, testN)
		for j := range polys[i] {
			polys[i][j] = uint64(rand.Int63n(int64(testQ)))
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.NTTBatch(polys)
	}
}
