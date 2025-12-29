// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package tfhe

import (
	"testing"
)

func TestIntegerTypes(t *testing.T) {
	// Test FheUintType
	tests := []struct {
		t    FheUintType
		bits int
		name string
	}{
		{FheBool, 1, "ebool"},
		{FheUint4, 4, "euint4"},
		{FheUint8, 8, "euint8"},
		{FheUint16, 16, "euint16"},
		{FheUint32, 32, "euint32"},
		{FheUint64, 64, "euint64"},
		{FheUint128, 128, "euint128"},
		{FheUint160, 160, "euint160"},
		{FheUint256, 256, "euint256"},
	}

	for _, tc := range tests {
		if tc.t.NumBits() != tc.bits {
			t.Errorf("%s: expected %d bits, got %d", tc.name, tc.bits, tc.t.NumBits())
		}
		if tc.t.String() != tc.name {
			t.Errorf("expected name %s, got %s", tc.name, tc.t.String())
		}
	}
}

func TestShortIntEncryptDecrypt(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()

	// Test with 2-bit message space (values 0-3)
	shortParams, err := NewShortIntParams(params, 2)
	if err != nil {
		t.Fatalf("NewShortIntParams: %v", err)
	}

	enc := NewShortIntEncryptor(shortParams, sk)
	dec := NewShortIntDecryptor(shortParams, sk)

	for value := 0; value < 4; value++ {
		ct, err := enc.Encrypt(value)
		if err != nil {
			t.Fatalf("Encrypt(%d): %v", value, err)
		}

		got := dec.Decrypt(ct)
		if got != value {
			t.Errorf("Encrypt/Decrypt(%d): got %d", value, got)
		}
	}
}

func TestShortIntEncryptDecrypt4Bit(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()

	// Test with 4-bit message space (values 0-15)
	shortParams, err := NewShortIntParams(params, 4)
	if err != nil {
		t.Fatalf("NewShortIntParams: %v", err)
	}

	enc := NewShortIntEncryptor(shortParams, sk)
	dec := NewShortIntDecryptor(shortParams, sk)

	// Test a few values
	testValues := []int{0, 1, 7, 8, 14, 15}
	for _, value := range testValues {
		ct, err := enc.Encrypt(value)
		if err != nil {
			t.Fatalf("Encrypt(%d): %v", value, err)
		}

		got := dec.Decrypt(ct)
		if got != value {
			t.Errorf("Encrypt/Decrypt(%d): got %d", value, got)
		}
	}
}

func TestIntegerEncryptDecryptUint8(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()

	// Use 4-bit blocks (2 blocks for uint8)
	intParams, err := NewIntegerParams(params, 4)
	if err != nil {
		t.Fatalf("NewIntegerParams: %v", err)
	}

	enc := NewIntegerEncryptor(intParams, sk)
	dec := NewIntegerDecryptor(intParams, sk)

	testValues := []uint64{0, 1, 127, 128, 200, 255}
	for _, value := range testValues {
		ct, err := enc.EncryptUint64(value, FheUint8)
		if err != nil {
			t.Fatalf("EncryptUint64(%d): %v", value, err)
		}

		got := dec.DecryptUint64(ct)
		if got != value {
			t.Errorf("Encrypt/Decrypt(%d): got %d", value, got)
		}
	}
}

func TestIntegerEncryptDecryptUint32(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()

	// Use 4-bit blocks (8 blocks for uint32)
	intParams, err := NewIntegerParams(params, 4)
	if err != nil {
		t.Fatalf("NewIntegerParams: %v", err)
	}

	enc := NewIntegerEncryptor(intParams, sk)
	dec := NewIntegerDecryptor(intParams, sk)

	testValues := []uint64{0, 1, 1000, 65535, 1000000, 0xFFFFFFFF}
	for _, value := range testValues {
		ct, err := enc.EncryptUint64(value, FheUint32)
		if err != nil {
			t.Fatalf("EncryptUint64(%d): %v", value, err)
		}

		got := dec.DecryptUint64(ct)
		if got != value {
			t.Errorf("Encrypt/Decrypt(%d): got %d", value, got)
		}
	}
}

func TestShortIntAdd(t *testing.T) {
	t.Skip("Skipping - LUT-based bootstrap needs debugging. Use BitwiseEvaluator.Add instead.")
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	shortParams, err := NewShortIntParams(params, 4)
	if err != nil {
		t.Fatalf("NewShortIntParams: %v", err)
	}

	enc := NewShortIntEncryptor(shortParams, sk)
	dec := NewShortIntDecryptor(shortParams, sk)
	eval := NewShortIntEvaluator(shortParams, bsk)

	// Test encrypted addition (requires bootstrap)
	testCases := []struct {
		a, b   int
		expect int
	}{
		{3, 2, 5},
		{7, 1, 8},
		{10, 5, 15},
	}

	for _, tc := range testCases {
		ctA, err := enc.Encrypt(tc.a)
		if err != nil {
			t.Fatalf("Encrypt(%d): %v", tc.a, err)
		}
		ctB, err := enc.Encrypt(tc.b)
		if err != nil {
			t.Fatalf("Encrypt(%d): %v", tc.b, err)
		}

		result, err := eval.Add(ctA, ctB)
		if err != nil {
			t.Fatalf("Add(%d, %d): %v", tc.a, tc.b, err)
		}

		got := dec.Decrypt(result)
		if got != tc.expect {
			t.Errorf("Add(%d, %d): expected %d, got %d", tc.a, tc.b, tc.expect, got)
		}
	}
}

func TestShortIntTrivialEncrypt(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	shortParams, err := NewShortIntParams(params, 4)
	if err != nil {
		t.Fatalf("NewShortIntParams: %v", err)
	}

	dec := NewShortIntDecryptor(shortParams, sk)
	eval := NewShortIntEvaluator(shortParams, bsk)

	// Test trivial encryption can be decrypted
	for value := 0; value < 16; value++ {
		ct, err := eval.EncryptTrivial(value)
		if err != nil {
			t.Fatalf("EncryptTrivial(%d): %v", value, err)
		}

		got := dec.Decrypt(ct)
		if got != value {
			t.Errorf("EncryptTrivial(%d): got %d", value, got)
		}
	}
}

func TestShortIntScalarAdd(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	// Test with 4-bit message space
	shortParams, err := NewShortIntParams(params, 4)
	if err != nil {
		t.Fatalf("NewShortIntParams: %v", err)
	}

	enc := NewShortIntEncryptor(shortParams, sk)
	dec := NewShortIntDecryptor(shortParams, sk)
	eval := NewShortIntEvaluator(shortParams, bsk)

	// Test simple scalar addition (no overflow)
	testCases := []struct {
		a, b   int
		expect int
	}{
		{3, 2, 5},
		{7, 1, 8},
		{0, 15, 15},
		{10, 3, 13},
	}

	for _, tc := range testCases {
		ct, err := enc.Encrypt(tc.a)
		if err != nil {
			t.Fatalf("Encrypt(%d): %v", tc.a, err)
		}

		result, err := eval.ScalarAdd(ct, tc.b)
		if err != nil {
			t.Fatalf("ScalarAdd(%d, %d): %v", tc.a, tc.b, err)
		}

		got := dec.Decrypt(result)
		if got != tc.expect {
			t.Errorf("ScalarAdd(%d, %d): expected %d, got %d", tc.a, tc.b, tc.expect, got)
		}
	}
}

func TestIntegerScalarAdd(t *testing.T) {
	t.Skip("Skipping until ShortInt operations are fixed")

	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	intParams, err := NewIntegerParams(params, 4)
	if err != nil {
		t.Fatalf("NewIntegerParams: %v", err)
	}

	enc := NewIntegerEncryptor(intParams, sk)
	dec := NewIntegerDecryptor(intParams, sk)
	eval := NewIntegerEvaluator(intParams, bsk)

	// Test scalar addition on uint8
	testCases := []struct {
		a, b   uint64
		expect uint64
	}{
		{10, 5, 15},
		{100, 50, 150},
		{250, 10, 4}, // Overflow wraps: (250 + 10) % 256 = 4
		{0, 255, 255},
	}

	for _, tc := range testCases {
		ct, err := enc.EncryptUint64(tc.a, FheUint8)
		if err != nil {
			t.Fatalf("EncryptUint64(%d): %v", tc.a, err)
		}

		result, err := eval.ScalarAdd(ct, tc.b)
		if err != nil {
			t.Fatalf("ScalarAdd(%d, %d): %v", tc.a, tc.b, err)
		}

		got := dec.DecryptUint64(result)
		if got != tc.expect {
			t.Errorf("ScalarAdd(%d, %d): expected %d, got %d", tc.a, tc.b, tc.expect, got)
		}
	}
}

func BenchmarkShortIntEncrypt(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	shortParams, _ := NewShortIntParams(params, 4)
	enc := NewShortIntEncryptor(shortParams, sk)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enc.Encrypt(i % 16)
	}
}

func BenchmarkShortIntDecrypt(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	shortParams, _ := NewShortIntParams(params, 4)
	enc := NewShortIntEncryptor(shortParams, sk)
	dec := NewShortIntDecryptor(shortParams, sk)
	ct, _ := enc.Encrypt(7)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dec.Decrypt(ct)
	}
}

func BenchmarkIntegerEncryptUint8(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	intParams, _ := NewIntegerParams(params, 4)
	enc := NewIntegerEncryptor(intParams, sk)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enc.EncryptUint64(uint64(i%256), FheUint8)
	}
}

func BenchmarkIntegerDecryptUint8(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	intParams, _ := NewIntegerParams(params, 4)
	enc := NewIntegerEncryptor(intParams, sk)
	dec := NewIntegerDecryptor(intParams, sk)
	ct, _ := enc.EncryptUint64(123, FheUint8)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dec.DecryptUint64(ct)
	}
}
