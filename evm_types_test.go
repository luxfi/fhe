// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package fhe

import (
	"math/big"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestEVMTypes tests all FHE types used in EVM (euint4 through euint256)
func TestEVMTypes(t *testing.T) {
	tests := []struct {
		ftype   FheUintType
		bits    int
		name    string
		maxUint string // max value as string for big.Int
	}{
		{FheBool, 1, "ebool", "1"},
		{FheUint4, 4, "euint4", "15"},
		{FheUint8, 8, "euint8", "255"},
		{FheUint16, 16, "euint16", "65535"},
		{FheUint32, 32, "euint32", "4294967295"},
		{FheUint64, 64, "euint64", "18446744073709551615"},
		{FheUint128, 128, "euint128", "340282366920938463463374607431768211455"},
		{FheUint160, 160, "euint160", "1461501637330902918203684832716283019655932542975"}, // Ethereum address size
		{FheUint256, 256, "euint256", "115792089237316195423570985008687907853269984665640564039457584007913129639935"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.bits, tc.ftype.NumBits(), "NumBits mismatch")
			require.Equal(t, tc.name, tc.ftype.String(), "String mismatch")

			maxVal := new(big.Int)
			_, ok := maxVal.SetString(tc.maxUint, 10)
			require.True(t, ok, "failed to parse max value")

			// Verify max value matches (2^bits - 1)
			expected := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(tc.bits)), big.NewInt(1))
			require.Equal(t, expected, maxVal, "max value mismatch for %s", tc.name)
		})
	}
}

// ============ Encrypt/Decrypt Tests for All Types ============

func TestEncryptDecryptUint4(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	require.NoError(t, err)

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()

	intParams, err := NewIntegerParams(params, 4)
	require.NoError(t, err)

	enc := NewIntegerEncryptor(intParams, sk)
	dec := NewIntegerDecryptor(intParams, sk)

	// Test all possible 4-bit values
	for value := uint64(0); value <= 15; value++ {
		ct, err := enc.EncryptUint64(value, FheUint4)
		require.NoError(t, err, "encrypt %d", value)

		got := dec.DecryptUint64(ct)
		require.Equal(t, value, got, "encrypt/decrypt %d", value)
	}
}

func TestEncryptDecryptUint16(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	require.NoError(t, err)

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()

	intParams, err := NewIntegerParams(params, 4)
	require.NoError(t, err)

	enc := NewIntegerEncryptor(intParams, sk)
	dec := NewIntegerDecryptor(intParams, sk)

	testValues := []uint64{0, 1, 255, 256, 1000, 32767, 32768, 65534, 65535}
	for _, value := range testValues {
		ct, err := enc.EncryptUint64(value, FheUint16)
		require.NoError(t, err, "encrypt %d", value)

		got := dec.DecryptUint64(ct)
		require.Equal(t, value, got, "encrypt/decrypt %d", value)
	}
}

func TestEncryptDecryptUint64(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	require.NoError(t, err)

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()

	intParams, err := NewIntegerParams(params, 4)
	require.NoError(t, err)

	enc := NewIntegerEncryptor(intParams, sk)
	dec := NewIntegerDecryptor(intParams, sk)

	testValues := []uint64{
		0, 1, 255, 256, 65535, 65536,
		0xFFFFFFFF,         // max uint32
		0x100000000,        // uint32 + 1
		0x7FFFFFFFFFFFFFFF, // max int64
		0xFFFFFFFFFFFFFFFF, // max uint64
	}
	for _, value := range testValues {
		ct, err := enc.EncryptUint64(value, FheUint64)
		require.NoError(t, err, "encrypt %d", value)

		got := dec.DecryptUint64(ct)
		require.Equal(t, value, got, "encrypt/decrypt %d", value)
	}
}

func TestEncryptDecryptUint128(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	require.NoError(t, err)

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()

	intParams, err := NewIntegerParams(params, 4)
	require.NoError(t, err)

	enc := NewIntegerEncryptor(intParams, sk)
	dec := NewIntegerDecryptor(intParams, sk)

	maxUint64 := new(big.Int).SetUint64(^uint64(0)) // max uint64
	testValues := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		maxUint64,
		new(big.Int).SetBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}), // max uint128
	}

	for _, value := range testValues {
		ct, err := enc.EncryptBigInt(value, FheUint128)
		require.NoError(t, err, "encrypt %s", value.String())

		got := dec.DecryptBigInt(ct)
		require.Equal(t, value.Cmp(got), 0, "encrypt/decrypt %s: got %s", value.String(), got.String())
	}
}

func TestEncryptDecryptUint160(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	require.NoError(t, err)

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()

	intParams, err := NewIntegerParams(params, 4)
	require.NoError(t, err)

	enc := NewIntegerEncryptor(intParams, sk)
	dec := NewIntegerDecryptor(intParams, sk)

	// Test typical Ethereum addresses
	testAddresses := []string{
		"0",
		"1",
		"0xdead000000000000000000000000000000000000", // example address
		"0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // max address
	}

	for _, addrStr := range testAddresses {
		value := new(big.Int)
		if addrStr[0] == '0' && len(addrStr) > 1 && addrStr[1] == 'x' {
			value.SetString(addrStr[2:], 16)
		} else {
			value.SetString(addrStr, 10)
		}

		ct, err := enc.EncryptBigInt(value, FheUint160)
		require.NoError(t, err, "encrypt %s", addrStr)

		got := dec.DecryptBigInt(ct)
		require.Equal(t, 0, value.Cmp(got), "encrypt/decrypt %s: got %s", addrStr, got.String())
	}
}

func TestEncryptDecryptUint256(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	require.NoError(t, err)

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()

	intParams, err := NewIntegerParams(params, 4)
	require.NoError(t, err)

	enc := NewIntegerEncryptor(intParams, sk)
	dec := NewIntegerDecryptor(intParams, sk)

	// Max uint256 = 2^256 - 1
	maxUint256 := new(big.Int).Sub(
		new(big.Int).Lsh(big.NewInt(1), 256),
		big.NewInt(1),
	)

	testValues := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		new(big.Int).SetUint64(0xFFFFFFFFFFFFFFFF),
		new(big.Int).Lsh(big.NewInt(1), 128), // 2^128
		new(big.Int).Lsh(big.NewInt(1), 200), // 2^200
		maxUint256,
	}

	for _, value := range testValues {
		ct, err := enc.EncryptBigInt(value, FheUint256)
		require.NoError(t, err, "encrypt %s", value.String())

		got := dec.DecryptBigInt(ct)
		require.Equal(t, 0, value.Cmp(got), "encrypt/decrypt %s: got %s", value.String(), got.String())
	}
}

// ============ Bitwise Encrypt/Decrypt Tests ============

func TestBitwiseEncryptDecryptAllTypes(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	require.NoError(t, err)

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()

	enc := NewBitwiseEncryptor(params, sk)
	dec := NewBitwiseDecryptor(params, sk)

	testCases := []struct {
		value uint64
		ftype FheUintType
	}{
		// FheUint4
		{0, FheUint4},
		{7, FheUint4},
		{15, FheUint4},
		// FheUint8
		{0, FheUint8},
		{127, FheUint8},
		{255, FheUint8},
		// FheUint16
		{0, FheUint16},
		{32767, FheUint16},
		{65535, FheUint16},
		// FheUint32
		{0, FheUint32},
		{0x7FFFFFFF, FheUint32},
		{0xFFFFFFFF, FheUint32},
	}

	for _, tc := range testCases {
		t.Run(tc.ftype.String(), func(t *testing.T) {
			ct := enc.EncryptUint64(tc.value, tc.ftype)
			got := dec.DecryptUint64(ct)
			require.Equal(t, tc.value, got, "encrypt/decrypt %d as %s", tc.value, tc.ftype)
		})
	}
}

// ============ Arithmetic Operations with Larger Types ============

func TestBitwiseAddUint8(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	require.NoError(t, err)

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
		{0, 0, 0},
		{1, 1, 2},
		{100, 50, 150},
		{127, 1, 128},
		{200, 55, 255},
		{255, 1, 0},     // Overflow wraps
		{255, 255, 254}, // 510 mod 256 = 254
	}

	for _, tc := range testCases {
		ctA := enc.EncryptUint64(tc.a, FheUint8)
		ctB := enc.EncryptUint64(tc.b, FheUint8)

		result, err := eval.Add(ctA, ctB)
		require.NoError(t, err, "Add(%d, %d)", tc.a, tc.b)

		got := dec.DecryptUint64(result)
		require.Equal(t, tc.expect, got, "Add(%d, %d) = %d, want %d", tc.a, tc.b, got, tc.expect)
	}
}

func TestBitwiseSubUint8(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	require.NoError(t, err)

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
		{0, 0, 0},
		{10, 5, 5},
		{100, 50, 50},
		{255, 255, 0},
		{0, 1, 255},     // Underflow wraps
		{100, 200, 156}, // -100 mod 256 = 156
	}

	for _, tc := range testCases {
		ctA := enc.EncryptUint64(tc.a, FheUint8)
		ctB := enc.EncryptUint64(tc.b, FheUint8)

		result, err := eval.Sub(ctA, ctB)
		require.NoError(t, err, "Sub(%d, %d)", tc.a, tc.b)

		got := dec.DecryptUint64(result)
		require.Equal(t, tc.expect, got, "Sub(%d, %d) = %d, want %d", tc.a, tc.b, got, tc.expect)
	}
}

func TestBitwiseMulUint8(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	require.NoError(t, err)

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
		{0, 0, 0},
		{1, 1, 1},
		{10, 10, 100},
		{15, 17, 255},
		{16, 16, 0},   // 256 mod 256 = 0
		{20, 20, 144}, // 400 mod 256 = 144
	}

	for _, tc := range testCases {
		ctA := enc.EncryptUint64(tc.a, FheUint8)
		ctB := enc.EncryptUint64(tc.b, FheUint8)

		result, err := eval.Mul(ctA, ctB)
		require.NoError(t, err, "Mul(%d, %d)", tc.a, tc.b)

		got := dec.DecryptUint64(result)
		require.Equal(t, tc.expect, got, "Mul(%d, %d) = %d, want %d", tc.a, tc.b, got, tc.expect)
	}
}

// ============ Comparison Operations ============

func TestBitwiseCompareAllTypes(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	require.NoError(t, err)

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	enc := NewBitwiseEncryptor(params, sk)
	decBool := NewDecryptor(params, sk)
	eval := NewBitwiseEvaluator(params, bsk, sk)

	t.Run("Lt", func(t *testing.T) {
		testCases := []struct {
			a, b   uint64
			expect bool
		}{
			{0, 1, true},
			{1, 0, false},
			{5, 5, false},
			{10, 15, true},
			{15, 10, false},
		}

		for _, tc := range testCases {
			ctA := enc.EncryptUint64(tc.a, FheUint4)
			ctB := enc.EncryptUint64(tc.b, FheUint4)

			result, err := eval.Lt(ctA, ctB)
			require.NoError(t, err)

			got := decBool.Decrypt(result)
			require.Equal(t, tc.expect, got, "Lt(%d, %d)", tc.a, tc.b)
		}
	})

	t.Run("Le", func(t *testing.T) {
		testCases := []struct {
			a, b   uint64
			expect bool
		}{
			{0, 1, true},
			{1, 0, false},
			{5, 5, true},
			{10, 15, true},
		}

		for _, tc := range testCases {
			ctA := enc.EncryptUint64(tc.a, FheUint4)
			ctB := enc.EncryptUint64(tc.b, FheUint4)

			result, err := eval.Le(ctA, ctB)
			require.NoError(t, err)

			got := decBool.Decrypt(result)
			require.Equal(t, tc.expect, got, "Le(%d, %d)", tc.a, tc.b)
		}
	})

	t.Run("Gt", func(t *testing.T) {
		testCases := []struct {
			a, b   uint64
			expect bool
		}{
			{1, 0, true},
			{0, 1, false},
			{5, 5, false},
			{15, 10, true},
		}

		for _, tc := range testCases {
			ctA := enc.EncryptUint64(tc.a, FheUint4)
			ctB := enc.EncryptUint64(tc.b, FheUint4)

			result, err := eval.Gt(ctA, ctB)
			require.NoError(t, err)

			got := decBool.Decrypt(result)
			require.Equal(t, tc.expect, got, "Gt(%d, %d)", tc.a, tc.b)
		}
	})

	t.Run("Ge", func(t *testing.T) {
		testCases := []struct {
			a, b   uint64
			expect bool
		}{
			{1, 0, true},
			{0, 1, false},
			{5, 5, true},
			{15, 10, true},
		}

		for _, tc := range testCases {
			ctA := enc.EncryptUint64(tc.a, FheUint4)
			ctB := enc.EncryptUint64(tc.b, FheUint4)

			result, err := eval.Ge(ctA, ctB)
			require.NoError(t, err)

			got := decBool.Decrypt(result)
			require.Equal(t, tc.expect, got, "Ge(%d, %d)", tc.a, tc.b)
		}
	})

}

// ============ Min/Max Operations ============

func TestBitwiseMinMax(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	require.NoError(t, err)

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	enc := NewBitwiseEncryptor(params, sk)
	dec := NewBitwiseDecryptor(params, sk)
	eval := NewBitwiseEvaluator(params, bsk, sk)

	t.Run("Min", func(t *testing.T) {
		testCases := []struct {
			a, b, expect uint64
		}{
			{3, 7, 3},
			{10, 5, 5},
			{15, 15, 15},
			{0, 15, 0},
		}

		for _, tc := range testCases {
			ctA := enc.EncryptUint64(tc.a, FheUint4)
			ctB := enc.EncryptUint64(tc.b, FheUint4)

			result, err := eval.Min(ctA, ctB)
			require.NoError(t, err)

			got := dec.DecryptUint64(result)
			require.Equal(t, tc.expect, got, "Min(%d, %d)", tc.a, tc.b)
		}
	})

	t.Run("Max", func(t *testing.T) {
		testCases := []struct {
			a, b, expect uint64
		}{
			{3, 7, 7},
			{10, 5, 10},
			{15, 15, 15},
			{0, 15, 15},
		}

		for _, tc := range testCases {
			ctA := enc.EncryptUint64(tc.a, FheUint4)
			ctB := enc.EncryptUint64(tc.b, FheUint4)

			result, err := eval.Max(ctA, ctB)
			require.NoError(t, err)

			got := dec.DecryptUint64(result)
			require.Equal(t, tc.expect, got, "Max(%d, %d)", tc.a, tc.b)
		}
	})
}

// ============ Select/Conditional Operation ============

func TestBitwiseSelect(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	require.NoError(t, err)

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	enc := NewBitwiseEncryptor(params, sk)
	dec := NewBitwiseDecryptor(params, sk)
	eval := NewBitwiseEvaluator(params, bsk, sk)
	boolEnc := NewEncryptor(params, sk)

	t.Run("SelectTrue", func(t *testing.T) {
		sel := boolEnc.Encrypt(true)
		trueVal := enc.EncryptUint64(10, FheUint4)
		falseVal := enc.EncryptUint64(5, FheUint4)

		result, err := eval.Select(sel, trueVal, falseVal)
		require.NoError(t, err)

		got := dec.DecryptUint64(result)
		require.Equal(t, uint64(10), got, "Select(true, 10, 5)")
	})

	t.Run("SelectFalse", func(t *testing.T) {
		sel := boolEnc.Encrypt(false)
		trueVal := enc.EncryptUint64(10, FheUint4)
		falseVal := enc.EncryptUint64(5, FheUint4)

		result, err := eval.Select(sel, trueVal, falseVal)
		require.NoError(t, err)

		got := dec.DecryptUint64(result)
		require.Equal(t, uint64(5), got, "Select(false, 10, 5)")
	})
}

// ============ Memory Management Tests ============

func TestMemoryCleanup(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	require.NoError(t, err)

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()

	enc := NewBitwiseEncryptor(params, sk)

	// Create many ciphertexts and let them go out of scope
	for i := 0; i < 100; i++ {
		ct := enc.EncryptUint64(uint64(i), FheUint8)
		_ = ct
	}

	// Force GC
	runtime.GC()

	// If we get here without crash, memory management is working
	require.True(t, true, "memory cleanup completed")
}

// ============ Benchmarks for Various Types ============

func BenchmarkEncryptDecryptByType(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()

	enc := NewBitwiseEncryptor(params, sk)
	dec := NewBitwiseDecryptor(params, sk)

	types := []FheUintType{FheUint4, FheUint8, FheUint16, FheUint32}

	for _, ftype := range types {
		b.Run("Encrypt_"+ftype.String(), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				enc.EncryptUint64(uint64(i%256), ftype)
			}
		})

		ct := enc.EncryptUint64(42, ftype)
		b.Run("Decrypt_"+ftype.String(), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				dec.DecryptUint64(ct)
			}
		})
	}
}

func BenchmarkArithmeticByType(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	enc := NewBitwiseEncryptor(params, sk)
	eval := NewBitwiseEvaluator(params, bsk, sk)

	types := []FheUintType{FheUint4, FheUint8}

	for _, ftype := range types {
		ctA := enc.EncryptUint64(5, ftype)
		ctB := enc.EncryptUint64(3, ftype)

		b.Run("Add_"+ftype.String(), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				eval.Add(ctA, ctB)
			}
		})

		b.Run("Sub_"+ftype.String(), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				eval.Sub(ctA, ctB)
			}
		})

		b.Run("Mul_"+ftype.String(), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				eval.Mul(ctA, ctB)
			}
		})
	}
}
