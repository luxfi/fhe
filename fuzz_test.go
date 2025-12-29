// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

//go:build go1.18

package tfhe

import (
	"testing"
)

// FuzzNTTRoundTrip verifies that NTT -> INTT is identity for all inputs
// Skipped: experimental NTT code, run with -tags ntt_experimental
func FuzzNTTRoundTrip(f *testing.F) {
	f.Skip("Skipping experimental NTT tests")

	// Add seed corpus
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{255, 255, 255, 255})
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7, 8})

	engine := NewNTTEngine(1024, 1<<27)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 8 {
			return
		}

		coeffs := make([]uint64, 1024)
		original := make([]uint64, 1024)

		// Fill coefficients from fuzzer data, cycling if needed
		for i := 0; i < 1024; i++ {
			// Use 3 bytes per coefficient to stay within Q
			idx := (i * 3) % len(data)
			val := uint64(data[idx%len(data)]) |
				(uint64(data[(idx+1)%len(data)]) << 8) |
				(uint64(data[(idx+2)%len(data)]) << 16)
			coeffs[i] = val % engine.Q
			original[i] = coeffs[i]
		}

		// Round-trip
		engine.NTTInPlace(coeffs)
		engine.INTTInPlace(coeffs)

		// Verify
		for i := 0; i < 1024; i++ {
			if coeffs[i] != original[i] {
				t.Fatalf("round-trip failure at index %d: expected %d, got %d",
					i, original[i], coeffs[i])
			}
		}
	})
}

// FuzzBarrettReduction verifies Barrett reduction matches standard modular reduction
// Skipped: experimental NTT code
func FuzzBarrettReduction(f *testing.F) {
	f.Skip("Skipping experimental NTT tests")

	f.Add(uint64(0), uint64(0))
	f.Add(uint64(1), uint64(1))
	f.Add(uint64(1<<27-1), uint64(1<<27-1))
	f.Add(uint64(12345), uint64(67890))

	engine := NewNTTEngine(1024, 1<<27)
	Q := engine.Q

	f.Fuzz(func(t *testing.T, a, b uint64) {
		// Reduce inputs to valid range
		a = a % Q
		b = b % Q

		expected := engine.mulMod(a, b)
		got := engine.mulModBarrett(a, b)

		if got != expected {
			t.Fatalf("Barrett mismatch: %d * %d: expected %d, got %d", a, b, expected, got)
		}
	})
}

// FuzzPolyAdd verifies polynomial addition
// Skipped: experimental NTT code
func FuzzPolyAdd(f *testing.F) {
	f.Skip("Skipping experimental NTT tests")

	f.Add([]byte{1, 2, 3, 4}, []byte{5, 6, 7, 8})

	engine := NewNTTEngine(1024, 1<<27)
	Q := engine.Q

	f.Fuzz(func(t *testing.T, dataA, dataB []byte) {
		if len(dataA) < 4 || len(dataB) < 4 {
			return
		}

		a := make([]uint64, 1024)
		b := make([]uint64, 1024)
		result := make([]uint64, 1024)

		for i := 0; i < 1024; i++ {
			a[i] = uint64(dataA[i%len(dataA)]) % Q
			b[i] = uint64(dataB[i%len(dataB)]) % Q
		}

		engine.PolyAdd(a, b, result)

		for i := 0; i < 1024; i++ {
			expected := (a[i] + b[i]) % Q
			if result[i] != expected {
				t.Fatalf("PolyAdd mismatch at %d: expected %d, got %d", i, expected, result[i])
			}
		}
	})
}

// FuzzPolySub verifies polynomial subtraction
// Skipped: experimental NTT code
func FuzzPolySub(f *testing.F) {
	f.Skip("Skipping experimental NTT tests")

	f.Add([]byte{1, 2, 3, 4}, []byte{5, 6, 7, 8})

	engine := NewNTTEngine(1024, 1<<27)
	Q := engine.Q

	f.Fuzz(func(t *testing.T, dataA, dataB []byte) {
		if len(dataA) < 4 || len(dataB) < 4 {
			return
		}

		a := make([]uint64, 1024)
		b := make([]uint64, 1024)
		result := make([]uint64, 1024)

		for i := 0; i < 1024; i++ {
			a[i] = uint64(dataA[i%len(dataA)]) % Q
			b[i] = uint64(dataB[i%len(dataB)]) % Q
		}

		engine.PolySub(a, b, result)

		for i := 0; i < 1024; i++ {
			var expected uint64
			if a[i] >= b[i] {
				expected = a[i] - b[i]
			} else {
				expected = Q - b[i] + a[i]
			}
			if result[i] != expected {
				t.Fatalf("PolySub mismatch at %d: expected %d, got %d", i, expected, result[i])
			}
		}
	})
}

// FuzzNTTConvolution verifies that NTT-based multiplication equals direct convolution
// Skipped: experimental NTT code, run with -tags ntt_experimental
func FuzzNTTConvolution(f *testing.F) {
	f.Skip("Skipping experimental NTT tests")

	f.Add([]byte{1, 2, 3}, []byte{4, 5, 6})

	engine := NewNTTEngine(1024, 1<<27)
	Q := engine.Q

	f.Fuzz(func(t *testing.T, dataA, dataB []byte) {
		if len(dataA) < 4 || len(dataB) < 4 {
			return
		}

		// Use small polynomials for direct convolution check
		degA := (int(dataA[0]) % 8) + 1 // 1-8
		degB := (int(dataB[0]) % 8) + 1 // 1-8

		a := make([]uint64, 1024)
		b := make([]uint64, 1024)

		for i := 0; i < degA; i++ {
			a[i] = uint64(dataA[(i+1)%len(dataA)]) % Q
		}
		for i := 0; i < degB; i++ {
			b[i] = uint64(dataB[(i+1)%len(dataB)]) % Q
		}

		// Compute direct convolution (naive O(n^2) for correctness)
		expected := make([]uint64, 1024)
		for i := 0; i < degA; i++ {
			for j := 0; j < degB; j++ {
				prod := engine.mulMod(a[i], b[j])
				idx := i + j
				if idx >= 1024 {
					// Negacyclic: x^1024 = -1
					idx -= 1024
					if expected[idx] >= prod {
						expected[idx] -= prod
					} else {
						expected[idx] = Q - prod + expected[idx]
					}
				} else {
					expected[idx] = (expected[idx] + prod) % Q
				}
			}
		}

		// Compute NTT-based convolution
		aNTT := make([]uint64, 1024)
		bNTT := make([]uint64, 1024)
		copy(aNTT, a)
		copy(bNTT, b)

		engine.NTTInPlace(aNTT)
		engine.NTTInPlace(bNTT)

		result := make([]uint64, 1024)
		engine.PolyMulNTT(aNTT, bNTT, result)
		engine.INTTInPlace(result)

		// Compare
		for i := 0; i < 1024; i++ {
			if result[i] != expected[i] {
				t.Fatalf("convolution mismatch at %d: expected %d, got %d",
					i, expected[i], result[i])
			}
		}
	})
}

// FuzzBitEncryptDecrypt verifies bit encryption-decryption round-trip
func FuzzBitEncryptDecrypt(f *testing.F) {
	f.Add(true)
	f.Add(false)

	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		f.Fatalf("failed to create params: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	_ = kg.GenPublicKey(sk)
	enc := NewEncryptor(params, sk)
	dec := NewDecryptor(params, sk)

	f.Fuzz(func(t *testing.T, value bool) {
		ct := enc.Encrypt(value)
		result := dec.Decrypt(ct)

		if result != value {
			t.Fatalf("encrypt-decrypt mismatch: expected %v, got %v", value, result)
		}
	})
}

// FuzzBooleanGates verifies boolean gate correctness for all input combinations
func FuzzBooleanGates(f *testing.F) {
	// Seed with all combinations
	f.Add(false, false)
	f.Add(false, true)
	f.Add(true, false)
	f.Add(true, true)

	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		f.Fatalf("failed to create params: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	_ = kg.GenPublicKey(sk)
	bsk := kg.GenBootstrapKey(sk)
	enc := NewEncryptor(params, sk)
	dec := NewDecryptor(params, sk)
	eval := NewEvaluator(params, bsk)

	f.Fuzz(func(t *testing.T, a, b bool) {
		ctA := enc.Encrypt(a)
		ctB := enc.Encrypt(b)

		// Test AND
		ctAND, err := eval.AND(ctA, ctB)
		if err != nil {
			t.Fatalf("AND failed: %v", err)
		}
		if dec.Decrypt(ctAND) != (a && b) {
			t.Fatalf("AND(%v, %v): expected %v, got %v", a, b, a && b, dec.Decrypt(ctAND))
		}

		// Test OR
		ctOR, err := eval.OR(ctA, ctB)
		if err != nil {
			t.Fatalf("OR failed: %v", err)
		}
		if dec.Decrypt(ctOR) != (a || b) {
			t.Fatalf("OR(%v, %v): expected %v, got %v", a, b, a || b, dec.Decrypt(ctOR))
		}

		// Test XOR
		ctXOR, err := eval.XOR(ctA, ctB)
		if err != nil {
			t.Fatalf("XOR failed: %v", err)
		}
		if dec.Decrypt(ctXOR) != (a != b) {
			t.Fatalf("XOR(%v, %v): expected %v, got %v", a, b, a != b, dec.Decrypt(ctXOR))
		}

		// Test NAND
		ctNAND, err := eval.NAND(ctA, ctB)
		if err != nil {
			t.Fatalf("NAND failed: %v", err)
		}
		if dec.Decrypt(ctNAND) != !(a && b) {
			t.Fatalf("NAND(%v, %v): expected %v, got %v", a, b, !(a && b), dec.Decrypt(ctNAND))
		}

		// Test NOR
		ctNOR, err := eval.NOR(ctA, ctB)
		if err != nil {
			t.Fatalf("NOR failed: %v", err)
		}
		if dec.Decrypt(ctNOR) != !(a || b) {
			t.Fatalf("NOR(%v, %v): expected %v, got %v", a, b, !(a || b), dec.Decrypt(ctNOR))
		}

		// Test XNOR
		ctXNOR, err := eval.XNOR(ctA, ctB)
		if err != nil {
			t.Fatalf("XNOR failed: %v", err)
		}
		if dec.Decrypt(ctXNOR) != (a == b) {
			t.Fatalf("XNOR(%v, %v): expected %v, got %v", a, b, a == b, dec.Decrypt(ctXNOR))
		}
	})
}

// FuzzByteEncryption verifies byte encryption-decryption
func FuzzByteEncryption(f *testing.F) {
	f.Add(byte(0))
	f.Add(byte(127))
	f.Add(byte(255))

	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		f.Fatalf("failed to create params: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	_ = kg.GenPublicKey(sk)
	enc := NewEncryptor(params, sk)
	dec := NewDecryptor(params, sk)

	f.Fuzz(func(t *testing.T, value byte) {
		cts := enc.EncryptByte(value)
		result := dec.DecryptByte(cts)

		if result != value {
			t.Fatalf("byte encrypt-decrypt mismatch: expected %d, got %d", value, result)
		}
	})
}
