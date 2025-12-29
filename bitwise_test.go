// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package tfhe

import (
	"testing"
)

func TestBitwiseEncryptDecrypt(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()

	enc := NewBitwiseEncryptor(params, sk)
	dec := NewBitwiseDecryptor(params, sk)

	testCases := []struct {
		value uint64
		ftype FheUintType
	}{
		{0, FheUint8},
		{1, FheUint8},
		{127, FheUint8},
		{255, FheUint8},
		{0, FheUint4},
		{15, FheUint4},
	}

	for _, tc := range testCases {
		ct := enc.EncryptUint64(tc.value, tc.ftype)
		got := dec.DecryptUint64(ct)
		if got != tc.value {
			t.Errorf("Encrypt/Decrypt(%d, %s): got %d", tc.value, tc.ftype, got)
		}
	}
}

func TestBitwiseAdd(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	enc := NewBitwiseEncryptor(params, sk)
	dec := NewBitwiseDecryptor(params, sk)
	eval := NewBitwiseEvaluator(params, bsk, sk)

	// Test with 4-bit integers (faster than 8-bit for testing)
	testCases := []struct {
		a, b   uint64
		expect uint64
	}{
		{3, 2, 5},
		{7, 1, 8},
		{10, 5, 15},
		{15, 1, 0}, // Overflow: 15 + 1 = 0 mod 16
	}

	for _, tc := range testCases {
		ctA := enc.EncryptUint64(tc.a, FheUint4)
		ctB := enc.EncryptUint64(tc.b, FheUint4)

		result, err := eval.Add(ctA, ctB)
		if err != nil {
			t.Fatalf("Add(%d, %d): %v", tc.a, tc.b, err)
		}

		got := dec.DecryptUint64(result)
		if got != tc.expect {
			t.Errorf("Add(%d, %d): expected %d, got %d", tc.a, tc.b, tc.expect, got)
		}
	}
}

func TestBitwiseScalarAdd(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	enc := NewBitwiseEncryptor(params, sk)
	dec := NewBitwiseDecryptor(params, sk)
	eval := NewBitwiseEvaluator(params, bsk, sk)

	testCases := []struct {
		a, b   uint64
		expect uint64
	}{
		{3, 2, 5},
		{7, 1, 8},
		{10, 5, 15},
		{14, 3, 1}, // Overflow: 14 + 3 = 17 mod 16 = 1
	}

	for _, tc := range testCases {
		ct := enc.EncryptUint64(tc.a, FheUint4)

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

func TestBitwiseEq(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	enc := NewBitwiseEncryptor(params, sk)
	decBool := NewDecryptor(params, sk)
	eval := NewBitwiseEvaluator(params, bsk, sk)

	testCases := []struct {
		a, b   uint64
		expect bool
	}{
		{5, 5, true},
		{5, 6, false},
		{0, 0, true},
		{15, 0, false},
	}

	for _, tc := range testCases {
		ctA := enc.EncryptUint64(tc.a, FheUint4)
		ctB := enc.EncryptUint64(tc.b, FheUint4)

		result, err := eval.Eq(ctA, ctB)
		if err != nil {
			t.Fatalf("Eq(%d, %d): %v", tc.a, tc.b, err)
		}

		got := decBool.Decrypt(result)
		if got != tc.expect {
			t.Errorf("Eq(%d, %d): expected %v, got %v", tc.a, tc.b, tc.expect, got)
		}
	}
}

func TestBitwiseLt(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	enc := NewBitwiseEncryptor(params, sk)
	decBool := NewDecryptor(params, sk)
	eval := NewBitwiseEvaluator(params, bsk, sk)

	testCases := []struct {
		a, b   uint64
		expect bool
	}{
		{3, 5, true},
		{5, 3, false},
		{5, 5, false},
		{0, 15, true},
		{15, 0, false},
	}

	for _, tc := range testCases {
		ctA := enc.EncryptUint64(tc.a, FheUint4)
		ctB := enc.EncryptUint64(tc.b, FheUint4)

		result, err := eval.Lt(ctA, ctB)
		if err != nil {
			t.Fatalf("Lt(%d, %d): %v", tc.a, tc.b, err)
		}

		got := decBool.Decrypt(result)
		if got != tc.expect {
			t.Errorf("Lt(%d, %d): expected %v, got %v", tc.a, tc.b, tc.expect, got)
		}
	}
}

func TestBitwiseSub(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	enc := NewBitwiseEncryptor(params, sk)
	dec := NewBitwiseDecryptor(params, sk)
	eval := NewBitwiseEvaluator(params, bsk, sk)

	testCases := []struct {
		a, b   uint64
		expect uint64
	}{
		{5, 3, 2},
		{10, 5, 5},
		{15, 0, 15},
		{0, 1, 15}, // Underflow: 0 - 1 = 15 mod 16
	}

	for _, tc := range testCases {
		ctA := enc.EncryptUint64(tc.a, FheUint4)
		ctB := enc.EncryptUint64(tc.b, FheUint4)

		result, err := eval.Sub(ctA, ctB)
		if err != nil {
			t.Fatalf("Sub(%d, %d): %v", tc.a, tc.b, err)
		}

		got := dec.DecryptUint64(result)
		if got != tc.expect {
			t.Errorf("Sub(%d, %d): expected %d, got %d", tc.a, tc.b, tc.expect, got)
		}
	}
}

func TestBitwiseBitOps(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	enc := NewBitwiseEncryptor(params, sk)
	dec := NewBitwiseDecryptor(params, sk)
	eval := NewBitwiseEvaluator(params, bsk, sk)

	// Test AND: 0b1100 & 0b1010 = 0b1000 = 8
	ctA := enc.EncryptUint64(12, FheUint4)
	ctB := enc.EncryptUint64(10, FheUint4)

	result, err := eval.And(ctA, ctB)
	if err != nil {
		t.Fatalf("And: %v", err)
	}
	if got := dec.DecryptUint64(result); got != 8 {
		t.Errorf("And(12, 10): expected 8, got %d", got)
	}

	// Test OR: 0b1100 | 0b1010 = 0b1110 = 14
	result, err = eval.Or(ctA, ctB)
	if err != nil {
		t.Fatalf("Or: %v", err)
	}
	if got := dec.DecryptUint64(result); got != 14 {
		t.Errorf("Or(12, 10): expected 14, got %d", got)
	}

	// Test XOR: 0b1100 ^ 0b1010 = 0b0110 = 6
	result, err = eval.Xor(ctA, ctB)
	if err != nil {
		t.Fatalf("Xor: %v", err)
	}
	if got := dec.DecryptUint64(result); got != 6 {
		t.Errorf("Xor(12, 10): expected 6, got %d", got)
	}

	// Test NOT: ~0b1100 = 0b0011 = 3
	result = eval.Not(ctA)
	if got := dec.DecryptUint64(result); got != 3 {
		t.Errorf("Not(12): expected 3, got %d", got)
	}
}

func TestBitwiseShift(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	enc := NewBitwiseEncryptor(params, sk)
	dec := NewBitwiseDecryptor(params, sk)
	eval := NewBitwiseEvaluator(params, bsk, sk)

	// Test left shift: 3 << 2 = 12
	ct := enc.EncryptUint64(3, FheUint4)
	result := eval.Shl(ct, 2)
	if got := dec.DecryptUint64(result); got != 12 {
		t.Errorf("Shl(3, 2): expected 12, got %d", got)
	}

	// Test right shift: 12 >> 2 = 3
	ct = enc.EncryptUint64(12, FheUint4)
	result = eval.Shr(ct, 2)
	if got := dec.DecryptUint64(result); got != 3 {
		t.Errorf("Shr(12, 2): expected 3, got %d", got)
	}
}

func TestBitwiseCastTo(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	enc := NewBitwiseEncryptor(params, sk)
	dec := NewBitwiseDecryptor(params, sk)
	eval := NewBitwiseEvaluator(params, bsk, sk)

	// Test widening: 4-bit to 8-bit
	ct4 := enc.EncryptUint64(10, FheUint4)
	ct8 := eval.CastTo(ct4, FheUint8)

	if ct8.NumBits() != 8 {
		t.Errorf("CastTo 8-bit: expected 8 bits, got %d", ct8.NumBits())
	}
	if got := dec.DecryptUint64(ct8); got != 10 {
		t.Errorf("CastTo 8-bit: expected 10, got %d", got)
	}

	// Test narrowing: 8-bit to 4-bit
	ct8 = enc.EncryptUint64(250, FheUint8) // 250 = 0xFA
	ct4 = eval.CastTo(ct8, FheUint4)       // Truncate to 0xA = 10

	if ct4.NumBits() != 4 {
		t.Errorf("CastTo 4-bit: expected 4 bits, got %d", ct4.NumBits())
	}
	if got := dec.DecryptUint64(ct4); got != 10 {
		t.Errorf("CastTo 4-bit: expected 10, got %d", got)
	}
}

func TestCiphertextSerialization(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()

	enc := NewBitwiseEncryptor(params, sk)
	dec := NewBitwiseDecryptor(params, sk)

	// Test BitCiphertext serialization
	original := enc.EncryptUint64(42, FheUint8)

	data, err := original.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	restored := new(BitCiphertext)
	if err := restored.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}

	// Verify restored ciphertext decrypts correctly
	if got := dec.DecryptUint64(restored); got != 42 {
		t.Errorf("Serialization roundtrip: expected 42, got %d", got)
	}
}

func TestSecretKeySerialization(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()

	// Serialize
	data, err := sk.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	// Deserialize
	restored := new(SecretKey)
	if err := restored.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}

	// Verify by encrypting/decrypting with restored key
	enc := NewEncryptor(params, restored)
	dec := NewDecryptor(params, restored)

	ct := enc.Encrypt(true)
	if !dec.Decrypt(ct) {
		t.Error("Secret key serialization: decryption with restored key failed")
	}
}

func TestPublicKeyEncryption(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk, pk := kg.GenKeyPair()

	// Encrypt using public key
	pubEnc := NewBitwisePublicEncryptor(params, pk)
	// Decrypt using secret key
	dec := NewBitwiseDecryptor(params, sk)

	// Test single bit encryption
	t.Run("SingleBit", func(t *testing.T) {
		ctTrue, err := pubEnc.Encrypt(true)
		if err != nil {
			t.Fatal(err)
		}
		ctFalse, err := pubEnc.Encrypt(false)
		if err != nil {
			t.Fatal(err)
		}

		if !dec.dec.Decrypt(ctTrue) {
			t.Error("Public key encrypt(true) decrypted to false")
		}
		if dec.dec.Decrypt(ctFalse) {
			t.Error("Public key encrypt(false) decrypted to true")
		}
	})

	// Test integer encryption
	t.Run("Integer", func(t *testing.T) {
		testCases := []struct {
			value uint64
			ftype FheUintType
		}{
			{0, FheUint8},
			{1, FheUint8},
			{127, FheUint8},
			{255, FheUint8},
			{0, FheUint4},
			{15, FheUint4},
		}

		for _, tc := range testCases {
			ct, err := pubEnc.EncryptUint64(tc.value, tc.ftype)
			if err != nil {
				t.Fatalf("EncryptUint64: %v", err)
			}
			got := dec.DecryptUint64(ct)
			if got != tc.value {
				t.Errorf("PublicKey Encrypt/Decrypt(%d, %s): got %d", tc.value, tc.ftype, got)
			}
		}
	})
}

func TestPublicKeyWithOperations(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk, pk := kg.GenKeyPair()
	bsk := kg.GenBootstrapKey(sk)

	// Encrypt using public key (simulates user input)
	pubEnc := NewBitwisePublicEncryptor(params, pk)
	dec := NewBitwiseDecryptor(params, sk)
	eval := NewBitwiseEvaluator(params, bsk, sk)

	// Encrypt two values with public key
	ctA, err := pubEnc.EncryptUint64(5, FheUint4)
	if err != nil {
		t.Fatalf("EncryptUint64: %v", err)
	}
	ctB, err := pubEnc.EncryptUint64(3, FheUint4)
	if err != nil {
		t.Fatalf("EncryptUint64: %v", err)
	}

	// Perform operation using evaluator
	ctSum, err := eval.Add(ctA, ctB)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Decrypt and verify
	got := dec.DecryptUint64(ctSum)
	if got != 8 {
		t.Errorf("PublicKey Add(5, 3): expected 8, got %d", got)
	}
}

func TestPublicKeySerialization(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk, pk := kg.GenKeyPair()

	// Serialize public key
	data, err := pk.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	// Deserialize public key
	restored := new(PublicKey)
	if err := restored.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}

	// Verify by encrypting with restored key and decrypting with original secret key
	pubEnc := NewBitwisePublicEncryptor(params, restored)
	dec := NewBitwiseDecryptor(params, sk)

	ct, err := pubEnc.EncryptUint64(42, FheUint8)
	if err != nil {
		t.Fatalf("EncryptUint64: %v", err)
	}
	got := dec.DecryptUint64(ct)
	if got != 42 {
		t.Errorf("PublicKey serialization: expected 42, got %d", got)
	}
}

func TestFheRNG(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	dec := NewBitwiseDecryptor(params, sk)

	seed := []byte("test seed for deterministic RNG")
	rng := NewFheRNG(params, sk, seed)

	t.Run("RandomBit", func(t *testing.T) {
		// Generate 100 random bits and verify they decrypt
		zeros, ones := 0, 0
		for i := 0; i < 100; i++ {
			ct := rng.RandomBit()
			if dec.dec.Decrypt(ct) {
				ones++
			} else {
				zeros++
			}
		}
		// With 100 bits, both should appear (probability of all same is 2^-99)
		if zeros == 0 || ones == 0 {
			t.Errorf("RandomBit: unexpected distribution zeros=%d, ones=%d", zeros, ones)
		}
	})

	t.Run("RandomUint", func(t *testing.T) {
		// Generate random 4-bit values
		values := make(map[uint64]int)
		for i := 0; i < 50; i++ {
			ct := rng.RandomUint(FheUint4)
			v := dec.DecryptUint64(ct)
			values[v]++
			if v > 15 {
				t.Errorf("RandomUint(FheUint4): got value %d > 15", v)
			}
		}
		// With 50 samples over 16 possible values, we should see at least 5 distinct values
		if len(values) < 5 {
			t.Errorf("RandomUint: low diversity, only %d distinct values in 50 samples", len(values))
		}
	})

	t.Run("Deterministic", func(t *testing.T) {
		// Same seed should produce same sequence
		rng1 := NewFheRNG(params, sk, seed)
		rng2 := NewFheRNG(params, sk, seed)

		for i := 0; i < 10; i++ {
			ct1 := rng1.RandomUint(FheUint8)
			ct2 := rng2.RandomUint(FheUint8)
			v1 := dec.DecryptUint64(ct1)
			v2 := dec.DecryptUint64(ct2)
			if v1 != v2 {
				t.Errorf("Deterministic: iteration %d: rng1=%d, rng2=%d", i, v1, v2)
			}
		}
	})

	t.Run("DifferentSeeds", func(t *testing.T) {
		seed1 := []byte("seed 1")
		seed2 := []byte("seed 2")
		rng1 := NewFheRNG(params, sk, seed1)
		rng2 := NewFheRNG(params, sk, seed2)

		// Generate values and check they're different
		same := 0
		for i := 0; i < 10; i++ {
			ct1 := rng1.RandomUint(FheUint8)
			ct2 := rng2.RandomUint(FheUint8)
			v1 := dec.DecryptUint64(ct1)
			v2 := dec.DecryptUint64(ct2)
			if v1 == v2 {
				same++
			}
		}
		// Different seeds should produce different sequences (allowing for some collision)
		if same > 5 {
			t.Errorf("DifferentSeeds: too many matches (%d/10)", same)
		}
	})

	t.Run("Reseed", func(t *testing.T) {
		rng1 := NewFheRNG(params, sk, seed)

		// Generate some values
		rng1.RandomUint(FheUint8)
		rng1.RandomUint(FheUint8)

		// Reseed with same seed
		rng1.Reseed(seed)

		// Should match fresh RNG with same seed
		rng2 := NewFheRNG(params, sk, seed)

		ct1 := rng1.RandomUint(FheUint8)
		ct2 := rng2.RandomUint(FheUint8)
		v1 := dec.DecryptUint64(ct1)
		v2 := dec.DecryptUint64(ct2)
		if v1 != v2 {
			t.Errorf("Reseed: expected %d, got %d", v2, v1)
		}
	})
}

func TestFheRNGPublic(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk, pk := kg.GenKeyPair()
	dec := NewBitwiseDecryptor(params, sk)

	seed := []byte("test seed for public RNG")
	rng := NewFheRNGPublic(params, pk, seed)

	t.Run("RandomUint", func(t *testing.T) {
		// Generate random values and verify they decrypt
		for i := 0; i < 10; i++ {
			ct, err := rng.RandomUint(FheUint8)
			if err != nil {
				t.Fatal(err)
			}
			v := dec.DecryptUint64(ct)
			if v > 255 {
				t.Errorf("RandomUint(FheUint8): got value %d > 255", v)
			}
		}
	})

	t.Run("Deterministic", func(t *testing.T) {
		// Same seed should produce same values
		rng1 := NewFheRNGPublic(params, pk, seed)
		rng2 := NewFheRNGPublic(params, pk, seed)

		for i := 0; i < 10; i++ {
			ct1, err := rng1.RandomUint(FheUint4)
			if err != nil {
				t.Fatal(err)
			}
			ct2, err := rng2.RandomUint(FheUint4)
			if err != nil {
				t.Fatal(err)
			}
			v1 := dec.DecryptUint64(ct1)
			v2 := dec.DecryptUint64(ct2)
			if v1 != v2 {
				t.Errorf("Deterministic: iteration %d: rng1=%d, rng2=%d", i, v1, v2)
			}
		}
	})
}

func BenchmarkBitwiseAdd4Bit(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	enc := NewBitwiseEncryptor(params, sk)
	eval := NewBitwiseEvaluator(params, bsk, sk)

	ctA := enc.EncryptUint64(5, FheUint4)
	ctB := enc.EncryptUint64(3, FheUint4)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eval.Add(ctA, ctB)
	}
}

// ========== Mul, Div, Rem Tests ==========

func TestBitwiseMul(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	enc := NewBitwiseEncryptor(params, sk)
	dec := NewBitwiseDecryptor(params, sk)
	eval := NewBitwiseEvaluator(params, bsk, sk)

	// Test with 4-bit integers
	testCases := []struct {
		a, b   uint64
		expect uint64
	}{
		{2, 3, 6},
		{3, 4, 12},
		{5, 3, 15},
		{4, 4, 0}, // Overflow: 16 mod 16 = 0
		{7, 2, 14},
		{0, 15, 0},
		{1, 1, 1},
	}

	for _, tc := range testCases {
		ctA := enc.EncryptUint64(tc.a, FheUint4)
		ctB := enc.EncryptUint64(tc.b, FheUint4)

		result, err := eval.Mul(ctA, ctB)
		if err != nil {
			t.Fatalf("Mul(%d, %d): %v", tc.a, tc.b, err)
		}

		got := dec.DecryptUint64(result)
		if got != tc.expect {
			t.Errorf("Mul(%d, %d): expected %d, got %d", tc.a, tc.b, tc.expect, got)
		}
	}
}

func TestBitwiseScalarMul(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	enc := NewBitwiseEncryptor(params, sk)
	dec := NewBitwiseDecryptor(params, sk)
	eval := NewBitwiseEvaluator(params, bsk, sk)

	testCases := []struct {
		a, b   uint64
		expect uint64
	}{
		{3, 2, 6},
		{5, 3, 15},
		{7, 0, 0},
		{1, 15, 15},
		{2, 8, 0}, // Overflow: 16 mod 16 = 0
	}

	for _, tc := range testCases {
		ct := enc.EncryptUint64(tc.a, FheUint4)

		result, err := eval.ScalarMul(ct, tc.b)
		if err != nil {
			t.Fatalf("ScalarMul(%d, %d): %v", tc.a, tc.b, err)
		}

		got := dec.DecryptUint64(result)
		if got != tc.expect {
			t.Errorf("ScalarMul(%d, %d): expected %d, got %d", tc.a, tc.b, tc.expect, got)
		}
	}
}

func TestBitwiseDiv(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	enc := NewBitwiseEncryptor(params, sk)
	dec := NewBitwiseDecryptor(params, sk)
	eval := NewBitwiseEvaluator(params, bsk, sk)

	// Test with 4-bit integers
	testCases := []struct {
		a, b   uint64
		expect uint64
	}{
		{6, 2, 3},
		{15, 3, 5},
		{10, 2, 5},
		{7, 2, 3},
		{1, 1, 1},
		{0, 5, 0},
		{5, 0, 15}, // Division by zero returns max value
	}

	for _, tc := range testCases {
		ctA := enc.EncryptUint64(tc.a, FheUint4)
		ctB := enc.EncryptUint64(tc.b, FheUint4)

		result, err := eval.Div(ctA, ctB)
		if err != nil {
			t.Fatalf("Div(%d, %d): %v", tc.a, tc.b, err)
		}

		got := dec.DecryptUint64(result)
		if got != tc.expect {
			t.Errorf("Div(%d, %d): expected %d, got %d", tc.a, tc.b, tc.expect, got)
		}
	}
}

func TestBitwiseRem(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	enc := NewBitwiseEncryptor(params, sk)
	dec := NewBitwiseDecryptor(params, sk)
	eval := NewBitwiseEvaluator(params, bsk, sk)

	// Test with 4-bit integers
	testCases := []struct {
		a, b   uint64
		expect uint64
	}{
		{7, 3, 1},  // 7 % 3 = 1
		{15, 4, 3}, // 15 % 4 = 3
		{10, 3, 1}, // 10 % 3 = 1
		{8, 2, 0},  // 8 % 2 = 0
		{5, 5, 0},  // 5 % 5 = 0
		{3, 7, 3},  // 3 % 7 = 3 (when a < b)
		{5, 0, 5},  // Remainder by zero returns dividend
	}

	for _, tc := range testCases {
		ctA := enc.EncryptUint64(tc.a, FheUint4)
		ctB := enc.EncryptUint64(tc.b, FheUint4)

		result, err := eval.Rem(ctA, ctB)
		if err != nil {
			t.Fatalf("Rem(%d, %d): %v", tc.a, tc.b, err)
		}

		got := dec.DecryptUint64(result)
		if got != tc.expect {
			t.Errorf("Rem(%d, %d): expected %d, got %d", tc.a, tc.b, tc.expect, got)
		}
	}
}

func TestBitwiseNeg(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	enc := NewBitwiseEncryptor(params, sk)
	dec := NewBitwiseDecryptor(params, sk)
	eval := NewBitwiseEvaluator(params, bsk, sk)

	// Two's complement negation in 4 bits: -a = 16 - a
	testCases := []struct {
		a      uint64
		expect uint64
	}{
		{0, 0},  // -0 = 0
		{1, 15}, // -1 = 15 (0xF)
		{5, 11}, // -5 = 11 (0xB)
		{8, 8},  // -8 = 8 (special case in 4-bit)
		{15, 1}, // -15 = 1
	}

	for _, tc := range testCases {
		ct := enc.EncryptUint64(tc.a, FheUint4)

		result, err := eval.Neg(ct)
		if err != nil {
			t.Fatalf("Neg(%d): %v", tc.a, err)
		}

		got := dec.DecryptUint64(result)
		if got != tc.expect {
			t.Errorf("Neg(%d): expected %d, got %d", tc.a, tc.expect, got)
		}
	}
}

func TestBitwiseIsZero(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	enc := NewBitwiseEncryptor(params, sk)
	decBool := NewDecryptor(params, sk)
	eval := NewBitwiseEvaluator(params, bsk, sk)

	testCases := []struct {
		a      uint64
		expect bool
	}{
		{0, true},
		{1, false},
		{15, false},
		{8, false},
	}

	for _, tc := range testCases {
		ct := enc.EncryptUint64(tc.a, FheUint4)

		result, err := eval.IsZero(ct)
		if err != nil {
			t.Fatalf("IsZero(%d): %v", tc.a, err)
		}

		got := decBool.Decrypt(result)
		if got != tc.expect {
			t.Errorf("IsZero(%d): expected %v, got %v", tc.a, tc.expect, got)
		}
	}
}

func TestBitwiseZeroAndOne(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	dec := NewBitwiseDecryptor(params, sk)
	eval := NewBitwiseEvaluator(params, bsk, sk)

	// Test Zero
	zero := eval.Zero(FheUint4)
	if got := dec.DecryptUint64(zero); got != 0 {
		t.Errorf("Zero(FheUint4): expected 0, got %d", got)
	}

	// Test One
	one := eval.One(FheUint4)
	if got := dec.DecryptUint64(one); got != 1 {
		t.Errorf("One(FheUint4): expected 1, got %d", got)
	}

	// Test MaxValue
	maxVal := eval.MaxValue(FheUint4)
	if got := dec.DecryptUint64(maxVal); got != 15 {
		t.Errorf("MaxValue(FheUint4): expected 15, got %d", got)
	}
}

func BenchmarkBitwiseMul4Bit(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	enc := NewBitwiseEncryptor(params, sk)
	eval := NewBitwiseEvaluator(params, bsk, sk)

	ctA := enc.EncryptUint64(5, FheUint4)
	ctB := enc.EncryptUint64(3, FheUint4)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eval.Mul(ctA, ctB)
	}
}

func BenchmarkBitwiseDiv4Bit(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	enc := NewBitwiseEncryptor(params, sk)
	eval := NewBitwiseEvaluator(params, bsk, sk)

	ctA := enc.EncryptUint64(12, FheUint4)
	ctB := enc.EncryptUint64(3, FheUint4)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eval.Div(ctA, ctB)
	}
}

func BenchmarkBitwiseRem4Bit(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	enc := NewBitwiseEncryptor(params, sk)
	eval := NewBitwiseEvaluator(params, bsk, sk)

	ctA := enc.EncryptUint64(11, FheUint4)
	ctB := enc.EncryptUint64(3, FheUint4)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eval.Rem(ctA, ctB)
	}
}
