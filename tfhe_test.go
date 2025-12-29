// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package tfhe

import (
	"testing"
)

func TestTFHE(t *testing.T) {
	// Use fast parameters for testing
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("failed to create parameters: %v", err)
	}

	// Generate keys
	kgen := NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	bsk := kgen.GenBootstrapKey(sk)

	// Create encryptor, decryptor, evaluator
	enc := NewEncryptor(params, sk)
	dec := NewDecryptor(params, sk)
	eval := NewEvaluator(params, bsk)

	t.Run("EncryptDecrypt", func(t *testing.T) {
		ct0 := enc.Encrypt(false)
		ct1 := enc.Encrypt(true)

		if dec.Decrypt(ct0) != false {
			t.Error("expected false, got true")
		}
		if dec.Decrypt(ct1) != true {
			t.Error("expected true, got false")
		}
	})

	t.Run("NOT", func(t *testing.T) {
		ct0 := enc.Encrypt(false)
		ct1 := enc.Encrypt(true)

		not0 := eval.NOT(ct0)
		not1 := eval.NOT(ct1)

		if dec.Decrypt(not0) != true {
			t.Error("NOT(0) should be 1")
		}
		if dec.Decrypt(not1) != false {
			t.Error("NOT(1) should be 0")
		}
	})
}

func TestAND(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("failed to create parameters: %v", err)
	}

	kgen := NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	bsk := kgen.GenBootstrapKey(sk)

	enc := NewEncryptor(params, sk)
	dec := NewDecryptor(params, sk)
	eval := NewEvaluator(params, bsk)

	testCases := []struct {
		a, b, want bool
	}{
		{false, false, false},
		{false, true, false},
		{true, false, false},
		{true, true, true},
	}

	for _, tc := range testCases {
		ctA := enc.Encrypt(tc.a)
		ctB := enc.Encrypt(tc.b)

		result, err := eval.AND(ctA, ctB)
		if err != nil {
			t.Fatalf("AND error: %v", err)
		}

		got := dec.Decrypt(result)
		if got != tc.want {
			t.Errorf("AND(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestOR(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("failed to create parameters: %v", err)
	}

	kgen := NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	bsk := kgen.GenBootstrapKey(sk)

	enc := NewEncryptor(params, sk)
	dec := NewDecryptor(params, sk)
	eval := NewEvaluator(params, bsk)

	testCases := []struct {
		a, b, want bool
	}{
		{false, false, false},
		{false, true, true},
		{true, false, true},
		{true, true, true},
	}

	for _, tc := range testCases {
		ctA := enc.Encrypt(tc.a)
		ctB := enc.Encrypt(tc.b)

		result, err := eval.OR(ctA, ctB)
		if err != nil {
			t.Fatalf("OR error: %v", err)
		}

		got := dec.Decrypt(result)
		if got != tc.want {
			t.Errorf("OR(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestXOR(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("failed to create parameters: %v", err)
	}

	kgen := NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	bsk := kgen.GenBootstrapKey(sk)

	enc := NewEncryptor(params, sk)
	dec := NewDecryptor(params, sk)
	eval := NewEvaluator(params, bsk)

	testCases := []struct {
		a, b, want bool
	}{
		{false, false, false},
		{false, true, true},
		{true, false, true},
		{true, true, false},
	}

	for _, tc := range testCases {
		ctA := enc.Encrypt(tc.a)
		ctB := enc.Encrypt(tc.b)

		result, err := eval.XOR(ctA, ctB)
		if err != nil {
			t.Fatalf("XOR error: %v", err)
		}

		got := dec.Decrypt(result)
		if got != tc.want {
			t.Errorf("XOR(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestNAND(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("failed to create parameters: %v", err)
	}

	kgen := NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	bsk := kgen.GenBootstrapKey(sk)

	enc := NewEncryptor(params, sk)
	dec := NewDecryptor(params, sk)
	eval := NewEvaluator(params, bsk)

	testCases := []struct {
		a, b, want bool
	}{
		{false, false, true},
		{false, true, true},
		{true, false, true},
		{true, true, false},
	}

	for _, tc := range testCases {
		ctA := enc.Encrypt(tc.a)
		ctB := enc.Encrypt(tc.b)

		result, err := eval.NAND(ctA, ctB)
		if err != nil {
			t.Fatalf("NAND error: %v", err)
		}

		got := dec.Decrypt(result)
		if got != tc.want {
			t.Errorf("NAND(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestMUX(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("failed to create parameters: %v", err)
	}

	kgen := NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	bsk := kgen.GenBootstrapKey(sk)

	enc := NewEncryptor(params, sk)
	dec := NewDecryptor(params, sk)
	eval := NewEvaluator(params, bsk)

	testCases := []struct {
		sel, a, b, want bool
	}{
		{false, false, false, false},
		{false, false, true, true},
		{false, true, false, false},
		{false, true, true, true},
		{true, false, false, false},
		{true, false, true, false},
		{true, true, false, true},
		{true, true, true, true},
	}

	for _, tc := range testCases {
		ctSel := enc.Encrypt(tc.sel)
		ctA := enc.Encrypt(tc.a)
		ctB := enc.Encrypt(tc.b)

		result, err := eval.MUX(ctSel, ctA, ctB)
		if err != nil {
			t.Fatalf("MUX error: %v", err)
		}

		got := dec.Decrypt(result)
		if got != tc.want {
			t.Errorf("MUX(%v, %v, %v) = %v, want %v", tc.sel, tc.a, tc.b, got, tc.want)
		}
	}
}

func TestNOR(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("failed to create parameters: %v", err)
	}

	kgen := NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	bsk := kgen.GenBootstrapKey(sk)

	enc := NewEncryptor(params, sk)
	dec := NewDecryptor(params, sk)
	eval := NewEvaluator(params, bsk)

	testCases := []struct {
		a, b, want bool
	}{
		{false, false, true},
		{false, true, false},
		{true, false, false},
		{true, true, false},
	}

	for _, tc := range testCases {
		ctA := enc.Encrypt(tc.a)
		ctB := enc.Encrypt(tc.b)

		result, err := eval.NOR(ctA, ctB)
		if err != nil {
			t.Fatalf("NOR error: %v", err)
		}

		got := dec.Decrypt(result)
		if got != tc.want {
			t.Errorf("NOR(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestXNOR(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("failed to create parameters: %v", err)
	}

	kgen := NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	bsk := kgen.GenBootstrapKey(sk)

	enc := NewEncryptor(params, sk)
	dec := NewDecryptor(params, sk)
	eval := NewEvaluator(params, bsk)

	testCases := []struct {
		a, b, want bool
	}{
		{false, false, true},
		{false, true, false},
		{true, false, false},
		{true, true, true},
	}

	for _, tc := range testCases {
		ctA := enc.Encrypt(tc.a)
		ctB := enc.Encrypt(tc.b)

		result, err := eval.XNOR(ctA, ctB)
		if err != nil {
			t.Fatalf("XNOR error: %v", err)
		}

		got := dec.Decrypt(result)
		if got != tc.want {
			t.Errorf("XNOR(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

// Benchmarks
func BenchmarkKeyGen(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	kgen := NewKeyGenerator(params)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sk := kgen.GenSecretKey()
		_ = kgen.GenBootstrapKey(sk)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	kgen := NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	enc := NewEncryptor(params, sk)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = enc.Encrypt(true)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	kgen := NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	enc := NewEncryptor(params, sk)
	dec := NewDecryptor(params, sk)
	ct := enc.Encrypt(true)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = dec.Decrypt(ct)
	}
}

func BenchmarkAND(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	kgen := NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	bsk := kgen.GenBootstrapKey(sk)
	enc := NewEncryptor(params, sk)
	eval := NewEvaluator(params, bsk)

	ct1 := enc.Encrypt(true)
	ct2 := enc.Encrypt(false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = eval.AND(ct1, ct2)
	}
}

func BenchmarkOR(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	kgen := NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	bsk := kgen.GenBootstrapKey(sk)
	enc := NewEncryptor(params, sk)
	eval := NewEvaluator(params, bsk)

	ct1 := enc.Encrypt(true)
	ct2 := enc.Encrypt(false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = eval.OR(ct1, ct2)
	}
}

func BenchmarkXOR(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	kgen := NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	bsk := kgen.GenBootstrapKey(sk)
	enc := NewEncryptor(params, sk)
	eval := NewEvaluator(params, bsk)

	ct1 := enc.Encrypt(true)
	ct2 := enc.Encrypt(false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = eval.XOR(ct1, ct2)
	}
}

func BenchmarkMUX(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	kgen := NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	bsk := kgen.GenBootstrapKey(sk)
	enc := NewEncryptor(params, sk)
	eval := NewEvaluator(params, bsk)

	sel := enc.Encrypt(true)
	ctTrue := enc.Encrypt(true)
	ctFalse := enc.Encrypt(false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = eval.MUX(sel, ctTrue, ctFalse)
	}
}

// ========== Multi-Input Gate Tests ==========

func TestAND3(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("failed to create parameters: %v", err)
	}

	kgen := NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	bsk := kgen.GenBootstrapKey(sk)

	enc := NewEncryptor(params, sk)
	dec := NewDecryptor(params, sk)
	eval := NewEvaluator(params, bsk)

	// AND3: all 8 combinations
	testCases := []struct {
		a, b, c, want bool
	}{
		{false, false, false, false},
		{false, false, true, false},
		{false, true, false, false},
		{false, true, true, false},
		{true, false, false, false},
		{true, false, true, false},
		{true, true, false, false},
		{true, true, true, true}, // only case where AND3 = true
	}

	for _, tc := range testCases {
		ctA := enc.Encrypt(tc.a)
		ctB := enc.Encrypt(tc.b)
		ctC := enc.Encrypt(tc.c)

		result, err := eval.AND3(ctA, ctB, ctC)
		if err != nil {
			t.Fatalf("AND3 error: %v", err)
		}

		got := dec.Decrypt(result)
		if got != tc.want {
			t.Errorf("AND3(%v, %v, %v) = %v, want %v", tc.a, tc.b, tc.c, got, tc.want)
		}
	}
}

func TestOR3(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("failed to create parameters: %v", err)
	}

	kgen := NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	bsk := kgen.GenBootstrapKey(sk)

	enc := NewEncryptor(params, sk)
	dec := NewDecryptor(params, sk)
	eval := NewEvaluator(params, bsk)

	// OR3: all 8 combinations
	testCases := []struct {
		a, b, c, want bool
	}{
		{false, false, false, false}, // only case where OR3 = false
		{false, false, true, true},
		{false, true, false, true},
		{false, true, true, true},
		{true, false, false, true},
		{true, false, true, true},
		{true, true, false, true},
		{true, true, true, true},
	}

	for _, tc := range testCases {
		ctA := enc.Encrypt(tc.a)
		ctB := enc.Encrypt(tc.b)
		ctC := enc.Encrypt(tc.c)

		result, err := eval.OR3(ctA, ctB, ctC)
		if err != nil {
			t.Fatalf("OR3 error: %v", err)
		}

		got := dec.Decrypt(result)
		if got != tc.want {
			t.Errorf("OR3(%v, %v, %v) = %v, want %v", tc.a, tc.b, tc.c, got, tc.want)
		}
	}
}

func TestMAJORITY(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("failed to create parameters: %v", err)
	}

	kgen := NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	bsk := kgen.GenBootstrapKey(sk)

	enc := NewEncryptor(params, sk)
	dec := NewDecryptor(params, sk)
	eval := NewEvaluator(params, bsk)

	// MAJORITY: true when 2+ of 3 are true
	testCases := []struct {
		a, b, c, want bool
	}{
		{false, false, false, false}, // 0 true
		{false, false, true, false},  // 1 true
		{false, true, false, false},  // 1 true
		{false, true, true, true},    // 2 true
		{true, false, false, false},  // 1 true
		{true, false, true, true},    // 2 true
		{true, true, false, true},    // 2 true
		{true, true, true, true},     // 3 true
	}

	for _, tc := range testCases {
		ctA := enc.Encrypt(tc.a)
		ctB := enc.Encrypt(tc.b)
		ctC := enc.Encrypt(tc.c)

		result, err := eval.MAJORITY(ctA, ctB, ctC)
		if err != nil {
			t.Fatalf("MAJORITY error: %v", err)
		}

		got := dec.Decrypt(result)
		if got != tc.want {
			t.Errorf("MAJORITY(%v, %v, %v) = %v, want %v", tc.a, tc.b, tc.c, got, tc.want)
		}
	}
}

// ========== Multi-Input Gate Benchmarks ==========

func BenchmarkAND3(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	kgen := NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	bsk := kgen.GenBootstrapKey(sk)
	enc := NewEncryptor(params, sk)
	eval := NewEvaluator(params, bsk)

	ct1 := enc.Encrypt(true)
	ct2 := enc.Encrypt(true)
	ct3 := enc.Encrypt(false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = eval.AND3(ct1, ct2, ct3)
	}
}

func BenchmarkOR3(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	kgen := NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	bsk := kgen.GenBootstrapKey(sk)
	enc := NewEncryptor(params, sk)
	eval := NewEvaluator(params, bsk)

	ct1 := enc.Encrypt(true)
	ct2 := enc.Encrypt(false)
	ct3 := enc.Encrypt(false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = eval.OR3(ct1, ct2, ct3)
	}
}

func BenchmarkMAJORITY(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	kgen := NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	bsk := kgen.GenBootstrapKey(sk)
	enc := NewEncryptor(params, sk)
	eval := NewEvaluator(params, bsk)

	ct1 := enc.Encrypt(true)
	ct2 := enc.Encrypt(true)
	ct3 := enc.Encrypt(false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = eval.MAJORITY(ct1, ct2, ct3)
	}
}
