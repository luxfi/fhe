//go:build cgo
// +build cgo

// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

// This file tests CGO-enabled mode with potential GPU acceleration

package fhe

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCGOMode verifies FHE works with CGO enabled
func TestCGOMode(t *testing.T) {
	t.Log("Running in CGO mode (CGO_ENABLED=1)")

	tc := newTestContext(t)

	t.Run("BooleanEncryptDecrypt", func(t *testing.T) {
		testBooleanEncryptDecrypt(t, tc)
	})

	t.Run("BooleanGates", func(t *testing.T) {
		testBooleanGates(t, tc)
	})

	t.Run("BooleanMUX", func(t *testing.T) {
		// MUX test is CGO-specific (additional gate)
		enc := NewEncryptor(tc.params, tc.sk)
		dec := NewDecryptor(tc.params, tc.sk)
		eval := NewEvaluator(tc.params, tc.bsk)

		sel := enc.Encrypt(true)
		ctTrue := enc.Encrypt(true)
		ctFalse := enc.Encrypt(false)
		result, err := eval.MUX(sel, ctTrue, ctFalse)
		require.NoError(t, err)
		require.True(t, dec.Decrypt(result), "MUX(true, true, false)")
	})

	t.Run("IntegerEncryptDecrypt", func(t *testing.T) {
		// CGO mode tests more types
		testIntegerEncryptDecrypt(t, tc, []FheUintType{FheUint4, FheUint8, FheUint16})
	})

	t.Run("IntegerArithmetic", func(t *testing.T) {
		testIntegerArithmetic(t, tc, 10, 5, FheUint8)

		// Additional Mul test for CGO
		enc := NewBitwiseEncryptor(tc.params, tc.sk)
		dec := NewBitwiseDecryptor(tc.params, tc.sk)
		eval := NewBitwiseEvaluator(tc.params, tc.bsk, tc.sk)

		ctC := enc.EncryptUint64(3, FheUint4)
		ctD := enc.EncryptUint64(4, FheUint4)
		result, err := eval.Mul(ctC, ctD)
		require.NoError(t, err)
		require.Equal(t, uint64(12), dec.DecryptUint64(result), "Mul(3, 4)")
	})

	t.Run("BigIntTypes", func(t *testing.T) {
		// Test uint128
		val128 := new(big.Int).SetUint64(0xFFFFFFFFFFFFFFFF)
		testBigIntRoundtrip(t, tc, val128, FheUint128)

		// Test uint160 (Ethereum address)
		val160 := new(big.Int)
		val160.SetString("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", 16)
		testBigIntRoundtrip(t, tc, val160, FheUint160)

		// Test uint256 max
		val256 := new(big.Int).Sub(
			new(big.Int).Lsh(big.NewInt(1), 256),
			big.NewInt(1),
		)
		testBigIntRoundtrip(t, tc, val256, FheUint256)
	})
}

// TestCGOSerialization tests serialization with CGO enabled
func TestCGOSerialization(t *testing.T) {
	tc := newTestContext(t)

	t.Run("SecretKey", func(t *testing.T) {
		testKeySerialization(t, tc)
	})

	t.Run("PublicKey", func(t *testing.T) {
		t.Skip("TODO(fhe#2): PublicKey serialization has noise issues")
		_, pk := tc.kg.GenKeyPair()

		data, err := pk.MarshalBinary()
		require.NoError(t, err)

		restored := new(PublicKey)
		err = restored.UnmarshalBinary(data)
		require.NoError(t, err)

		pubEnc := NewBitwisePublicEncryptor(tc.params, restored)
		dec := NewBitwiseDecryptor(tc.params, tc.sk)

		ct, err := pubEnc.EncryptUint64(42, FheUint8)
		require.NoError(t, err)
		require.Equal(t, uint64(42), dec.DecryptUint64(ct))
	})

	t.Run("BootstrapKey", func(t *testing.T) {
		t.Skip("TODO(fhe#2): BootstrapKey gob interface deserialization bug")
		data, err := tc.bsk.MarshalBinary()
		require.NoError(t, err)

		restored := new(BootstrapKey)
		err = restored.UnmarshalBinary(data)
		require.NoError(t, err)

		enc := NewEncryptor(tc.params, tc.sk)
		dec := NewDecryptor(tc.params, tc.sk)
		eval := NewEvaluator(tc.params, restored)

		ct1 := enc.Encrypt(true)
		ct2 := enc.Encrypt(true)
		result, err := eval.AND(ct1, ct2)
		require.NoError(t, err)
		require.True(t, dec.Decrypt(result))
	})
}

// TestCGORNG tests RNG with CGO enabled
func TestCGORNG(t *testing.T) {
	tc := newTestContext(t)

	t.Run("SecretKeyRNG", func(t *testing.T) {
		testRNG(t, tc, FheUint8)
	})

	t.Run("PublicKeyRNG", func(t *testing.T) {
		_, pk := tc.kg.GenKeyPair()
		dec := NewBitwiseDecryptor(tc.params, tc.sk)

		seed := []byte("cgo public rng test seed")
		rng := NewFheRNGPublic(tc.params, pk, seed)

		for i := 0; i < 10; i++ {
			ct, err := rng.RandomUint(FheUint4)
			require.NoError(t, err)
			val := dec.DecryptUint64(ct)
			require.True(t, val <= 15, "random value in range: %d", val)
		}
	})
}

func BenchmarkCGOOperations(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)
	enc := NewBitwiseEncryptor(params, sk)
	eval := NewBitwiseEvaluator(params, bsk, sk)

	ct4A := enc.EncryptUint64(5, FheUint4)
	ct4B := enc.EncryptUint64(3, FheUint4)
	ct8A := enc.EncryptUint64(100, FheUint8)
	ct8B := enc.EncryptUint64(50, FheUint8)

	b.Run("CGO_Add4", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			eval.Add(ct4A, ct4B)
		}
	})

	b.Run("CGO_Add8", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			eval.Add(ct8A, ct8B)
		}
	})

	b.Run("CGO_Mul4", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			eval.Mul(ct4A, ct4B)
		}
	})

	b.Run("CGO_Mul8", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			eval.Mul(ct8A, ct8B)
		}
	})
}
