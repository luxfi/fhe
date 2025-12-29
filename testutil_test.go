// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package fhe

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// testContext holds common test fixtures for FHE tests.
type testContext struct {
	params Parameters
	kg     *KeyGenerator
	sk     *SecretKey
	bsk    *BootstrapKey
}

// newTestContext creates a test context with standard parameters.
func newTestContext(t testing.TB) *testContext {
	t.Helper()
	params, err := NewParametersFromLiteral(PN10QP27)
	require.NoError(t, err, "create parameters")

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	return &testContext{
		params: params,
		kg:     kg,
		sk:     sk,
		bsk:    bsk,
	}
}

// testBooleanEncryptDecrypt tests boolean encrypt/decrypt roundtrip.
func testBooleanEncryptDecrypt(t *testing.T, tc *testContext) {
	t.Helper()
	enc := NewEncryptor(tc.params, tc.sk)
	dec := NewDecryptor(tc.params, tc.sk)

	ct := enc.Encrypt(true)
	require.True(t, dec.Decrypt(ct), "encrypt/decrypt true")

	ct = enc.Encrypt(false)
	require.False(t, dec.Decrypt(ct), "encrypt/decrypt false")
}

// testBooleanGates tests boolean gate operations.
func testBooleanGates(t *testing.T, tc *testContext) {
	t.Helper()
	enc := NewEncryptor(tc.params, tc.sk)
	dec := NewDecryptor(tc.params, tc.sk)
	eval := NewEvaluator(tc.params, tc.bsk)

	ct1 := enc.Encrypt(true)
	ct2 := enc.Encrypt(false)

	// AND
	result, err := eval.AND(ct1, ct2)
	require.NoError(t, err)
	require.False(t, dec.Decrypt(result), "AND(true, false)")

	// OR
	result, err = eval.OR(ct1, ct2)
	require.NoError(t, err)
	require.True(t, dec.Decrypt(result), "OR(true, false)")

	// XOR
	result, err = eval.XOR(ct1, ct2)
	require.NoError(t, err)
	require.True(t, dec.Decrypt(result), "XOR(true, false)")
}

// testIntegerEncryptDecrypt tests integer encrypt/decrypt for given types.
func testIntegerEncryptDecrypt(t *testing.T, tc *testContext, types []FheUintType) {
	t.Helper()
	enc := NewBitwiseEncryptor(tc.params, tc.sk)
	dec := NewBitwiseDecryptor(tc.params, tc.sk)

	for _, ftype := range types {
		maxVal := uint64((1 << ftype.NumBits()) - 1)
		for _, val := range []uint64{0, 1, maxVal / 2, maxVal} {
			ct := enc.EncryptUint64(val, ftype)
			got := dec.DecryptUint64(ct)
			require.Equal(t, val, got, "encrypt/decrypt %d as %s", val, ftype)
		}
	}
}

// testIntegerArithmetic tests basic integer arithmetic.
func testIntegerArithmetic(t *testing.T, tc *testContext, a, b uint64, ftype FheUintType) {
	t.Helper()
	enc := NewBitwiseEncryptor(tc.params, tc.sk)
	dec := NewBitwiseDecryptor(tc.params, tc.sk)
	eval := NewBitwiseEvaluator(tc.params, tc.bsk, tc.sk)

	ctA := enc.EncryptUint64(a, ftype)
	ctB := enc.EncryptUint64(b, ftype)

	// Add
	result, err := eval.Add(ctA, ctB)
	require.NoError(t, err)
	expected := (a + b) & ((1 << ftype.NumBits()) - 1)
	require.Equal(t, expected, dec.DecryptUint64(result), "Add(%d, %d)", a, b)

	// Sub (only if a >= b to avoid underflow complexity)
	if a >= b {
		result, err = eval.Sub(ctA, ctB)
		require.NoError(t, err)
		require.Equal(t, a-b, dec.DecryptUint64(result), "Sub(%d, %d)", a, b)
	}
}

// testBigIntRoundtrip tests big integer encryption roundtrip.
func testBigIntRoundtrip(t *testing.T, tc *testContext, val *big.Int, ftype FheUintType) {
	t.Helper()
	intParams, err := NewIntegerParams(tc.params, 4)
	require.NoError(t, err)

	enc := NewIntegerEncryptor(intParams, tc.sk)
	dec := NewIntegerDecryptor(intParams, tc.sk)

	ct, err := enc.EncryptBigInt(val, ftype)
	require.NoError(t, err)
	got := dec.DecryptBigInt(ct)
	require.Equal(t, 0, val.Cmp(got), "%s roundtrip", ftype)
}

// testKeySerialization tests key serialization roundtrip.
func testKeySerialization(t *testing.T, tc *testContext) {
	t.Helper()
	data, err := tc.sk.MarshalBinary()
	require.NoError(t, err, "marshal secret key")

	restored := new(SecretKey)
	err = restored.UnmarshalBinary(data)
	require.NoError(t, err, "unmarshal secret key")

	// Verify restored key works
	enc := NewEncryptor(tc.params, restored)
	dec := NewDecryptor(tc.params, restored)
	ct := enc.Encrypt(true)
	require.True(t, dec.Decrypt(ct), "restored key works")
}

// testRNG tests FHE random number generation.
func testRNG(t *testing.T, tc *testContext, ftype FheUintType) {
	t.Helper()
	dec := NewBitwiseDecryptor(tc.params, tc.sk)

	seed := []byte("test rng seed")
	rng := NewFheRNG(tc.params, tc.sk, seed)

	maxVal := uint64((1 << ftype.NumBits()) - 1)
	for i := 0; i < 10; i++ {
		ct := rng.RandomUint(ftype)
		val := dec.DecryptUint64(ct)
		require.True(t, val <= maxVal, "random value in range: %d", val)
	}
}
