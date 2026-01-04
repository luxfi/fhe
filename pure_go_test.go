//go:build !cgo
// +build !cgo

// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

// This file tests pure Go mode (CGO_ENABLED=0)

package fhe

import (
	"math/big"
	"testing"
)

// TestPureGoMode verifies FHE works without CGO
func TestPureGoMode(t *testing.T) {
	t.Log("Running in Pure Go mode (CGO_ENABLED=0)")

	tc := newTestContext(t)

	t.Run("BooleanEncryptDecrypt", func(t *testing.T) {
		testBooleanEncryptDecrypt(t, tc)
	})

	t.Run("BooleanGates", func(t *testing.T) {
		testBooleanGates(t, tc)
	})

	t.Run("IntegerEncryptDecrypt", func(t *testing.T) {
		testIntegerEncryptDecrypt(t, tc, []FheUintType{FheUint4, FheUint8})
	})

	t.Run("IntegerArithmetic", func(t *testing.T) {
		testIntegerArithmetic(t, tc, 5, 3, FheUint4)
	})

	t.Run("BigIntTypes", func(t *testing.T) {
		// Test uint128
		val128 := new(big.Int).SetUint64(0xFFFFFFFFFFFFFFFF)
		testBigIntRoundtrip(t, tc, val128, FheUint128)

		// Test uint256
		val256 := new(big.Int).Lsh(big.NewInt(1), 200) // 2^200
		testBigIntRoundtrip(t, tc, val256, FheUint256)
	})
}

// TestPureGoSerialization tests serialization in pure Go mode
func TestPureGoSerialization(t *testing.T) {
	tc := newTestContext(t)
	testKeySerialization(t, tc)
}

// TestPureGoRNG tests RNG in pure Go mode
func TestPureGoRNG(t *testing.T) {
	tc := newTestContext(t)
	testRNG(t, tc, FheUint4)
}

func BenchmarkPureGoOperations(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)
	enc := NewBitwiseEncryptor(params, sk)
	eval := NewBitwiseEvaluator(params, bsk, sk)

	ctA := enc.EncryptUint64(5, FheUint4)
	ctB := enc.EncryptUint64(3, FheUint4)

	b.Run("PureGo_Add4", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			eval.Add(ctA, ctB)
		}
	})

	b.Run("PureGo_Mul4", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			eval.Mul(ctA, ctB)
		}
	})
}
