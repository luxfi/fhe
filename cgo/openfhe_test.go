// Copyright (c) 2024 The Lux Authors
// Use of this source code is governed by a BSD 3-Clause
// license that can be found in the LICENSE file.

//go:build cgo && openfhe

package cgo

import (
	"bytes"
	"testing"
)

func TestContextCreation(t *testing.T) {
	ctx, err := NewContext(SecuritySTD128, MethodGINX)
	if err != nil {
		t.Fatalf("failed to create context: %v", err)
	}
	defer ctx.Free()
}

func TestKeyGeneration(t *testing.T) {
	ctx, err := NewContext(SecuritySTD128, MethodGINX)
	if err != nil {
		t.Fatalf("failed to create context: %v", err)
	}
	defer ctx.Free()

	sk, err := ctx.GenerateSecretKey()
	if err != nil {
		t.Fatalf("failed to generate secret key: %v", err)
	}
	defer sk.Free()

	err = ctx.GenerateBootstrapKey(sk)
	if err != nil {
		t.Fatalf("failed to generate bootstrap key: %v", err)
	}
}

func TestPublicKeyGeneration(t *testing.T) {
	ctx, err := NewContext(SecuritySTD128, MethodGINX)
	if err != nil {
		t.Fatalf("failed to create context: %v", err)
	}
	defer ctx.Free()

	sk, err := ctx.GenerateSecretKey()
	if err != nil {
		t.Fatalf("failed to generate secret key: %v", err)
	}
	defer sk.Free()

	pk, err := ctx.GeneratePublicKey(sk)
	if err != nil {
		t.Fatalf("failed to generate public key: %v", err)
	}
	defer pk.Free()
}

func TestBitEncryption(t *testing.T) {
	ctx, err := NewContext(SecuritySTD128, MethodGINX)
	if err != nil {
		t.Fatalf("failed to create context: %v", err)
	}
	defer ctx.Free()

	sk, err := ctx.GenerateSecretKey()
	if err != nil {
		t.Fatalf("failed to generate secret key: %v", err)
	}
	defer sk.Free()

	// Test encryption/decryption of true
	ctTrue, err := ctx.EncryptBit(sk, true)
	if err != nil {
		t.Fatalf("failed to encrypt true: %v", err)
	}
	defer ctTrue.Free()

	result, err := ctx.DecryptBit(sk, ctTrue)
	if err != nil {
		t.Fatalf("failed to decrypt: %v", err)
	}
	if result != true {
		t.Error("expected true, got false")
	}

	// Test encryption/decryption of false
	ctFalse, err := ctx.EncryptBit(sk, false)
	if err != nil {
		t.Fatalf("failed to encrypt false: %v", err)
	}
	defer ctFalse.Free()

	result, err = ctx.DecryptBit(sk, ctFalse)
	if err != nil {
		t.Fatalf("failed to decrypt: %v", err)
	}
	if result != false {
		t.Error("expected false, got true")
	}
}

func TestBooleanGates(t *testing.T) {
	ctx, err := NewContext(SecuritySTD128, MethodGINX)
	if err != nil {
		t.Fatalf("failed to create context: %v", err)
	}
	defer ctx.Free()

	sk, err := ctx.GenerateSecretKey()
	if err != nil {
		t.Fatalf("failed to generate secret key: %v", err)
	}
	defer sk.Free()

	err = ctx.GenerateBootstrapKey(sk)
	if err != nil {
		t.Fatalf("failed to generate bootstrap key: %v", err)
	}

	tests := []struct {
		name string
		a, b bool
		op   func(*Ciphertext, *Ciphertext) (*Ciphertext, error)
		want bool
	}{
		{"AND true true", true, true, func(a, b *Ciphertext) (*Ciphertext, error) { return ctx.And(a, b) }, true},
		{"AND true false", true, false, func(a, b *Ciphertext) (*Ciphertext, error) { return ctx.And(a, b) }, false},
		{"AND false true", false, true, func(a, b *Ciphertext) (*Ciphertext, error) { return ctx.And(a, b) }, false},
		{"AND false false", false, false, func(a, b *Ciphertext) (*Ciphertext, error) { return ctx.And(a, b) }, false},
		{"OR true true", true, true, func(a, b *Ciphertext) (*Ciphertext, error) { return ctx.Or(a, b) }, true},
		{"OR true false", true, false, func(a, b *Ciphertext) (*Ciphertext, error) { return ctx.Or(a, b) }, true},
		{"OR false true", false, true, func(a, b *Ciphertext) (*Ciphertext, error) { return ctx.Or(a, b) }, true},
		{"OR false false", false, false, func(a, b *Ciphertext) (*Ciphertext, error) { return ctx.Or(a, b) }, false},
		{"XOR true true", true, true, func(a, b *Ciphertext) (*Ciphertext, error) { return ctx.Xor(a, b) }, false},
		{"XOR true false", true, false, func(a, b *Ciphertext) (*Ciphertext, error) { return ctx.Xor(a, b) }, true},
		{"XOR false true", false, true, func(a, b *Ciphertext) (*Ciphertext, error) { return ctx.Xor(a, b) }, true},
		{"XOR false false", false, false, func(a, b *Ciphertext) (*Ciphertext, error) { return ctx.Xor(a, b) }, false},
		{"NAND true true", true, true, func(a, b *Ciphertext) (*Ciphertext, error) { return ctx.Nand(a, b) }, false},
		{"NAND true false", true, false, func(a, b *Ciphertext) (*Ciphertext, error) { return ctx.Nand(a, b) }, true},
		{"NOR true true", true, true, func(a, b *Ciphertext) (*Ciphertext, error) { return ctx.Nor(a, b) }, false},
		{"NOR false false", false, false, func(a, b *Ciphertext) (*Ciphertext, error) { return ctx.Nor(a, b) }, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctA, _ := ctx.EncryptBit(sk, tt.a)
			defer ctA.Free()
			ctB, _ := ctx.EncryptBit(sk, tt.b)
			defer ctB.Free()

			result, err := tt.op(ctA, ctB)
			if err != nil {
				t.Fatalf("operation failed: %v", err)
			}
			defer result.Free()

			got, err := ctx.DecryptBit(sk, result)
			if err != nil {
				t.Fatalf("decrypt failed: %v", err)
			}

			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNOT(t *testing.T) {
	ctx, err := NewContext(SecuritySTD128, MethodGINX)
	if err != nil {
		t.Fatalf("failed to create context: %v", err)
	}
	defer ctx.Free()

	sk, err := ctx.GenerateSecretKey()
	if err != nil {
		t.Fatalf("failed to generate secret key: %v", err)
	}
	defer sk.Free()

	err = ctx.GenerateBootstrapKey(sk)
	if err != nil {
		t.Fatalf("failed to generate bootstrap key: %v", err)
	}

	// NOT true = false
	ctTrue, _ := ctx.EncryptBit(sk, true)
	defer ctTrue.Free()

	notTrue, err := ctx.Not(ctTrue)
	if err != nil {
		t.Fatalf("NOT failed: %v", err)
	}
	defer notTrue.Free()

	result, _ := ctx.DecryptBit(sk, notTrue)
	if result != false {
		t.Errorf("NOT true: got %v, want false", result)
	}

	// NOT false = true
	ctFalse, _ := ctx.EncryptBit(sk, false)
	defer ctFalse.Free()

	notFalse, err := ctx.Not(ctFalse)
	if err != nil {
		t.Fatalf("NOT failed: %v", err)
	}
	defer notFalse.Free()

	result, _ = ctx.DecryptBit(sk, notFalse)
	if result != true {
		t.Errorf("NOT false: got %v, want true", result)
	}
}

func TestMUX(t *testing.T) {
	ctx, err := NewContext(SecuritySTD128, MethodGINX)
	if err != nil {
		t.Fatalf("failed to create context: %v", err)
	}
	defer ctx.Free()

	sk, err := ctx.GenerateSecretKey()
	if err != nil {
		t.Fatalf("failed to generate secret key: %v", err)
	}
	defer sk.Free()

	err = ctx.GenerateBootstrapKey(sk)
	if err != nil {
		t.Fatalf("failed to generate bootstrap key: %v", err)
	}

	// MUX(sel=true, a=true, b=false) = true
	selTrue, _ := ctx.EncryptBit(sk, true)
	defer selTrue.Free()
	selFalse, _ := ctx.EncryptBit(sk, false)
	defer selFalse.Free()
	ctTrue, _ := ctx.EncryptBit(sk, true)
	defer ctTrue.Free()
	ctFalse, _ := ctx.EncryptBit(sk, false)
	defer ctFalse.Free()

	// sel=true -> select first
	result1, err := ctx.Mux(selTrue, ctTrue, ctFalse)
	if err != nil {
		t.Fatalf("MUX failed: %v", err)
	}
	defer result1.Free()

	got, _ := ctx.DecryptBit(sk, result1)
	if got != true {
		t.Errorf("MUX(true, true, false): got %v, want true", got)
	}

	// sel=false -> select second
	result2, err := ctx.Mux(selFalse, ctTrue, ctFalse)
	if err != nil {
		t.Fatalf("MUX failed: %v", err)
	}
	defer result2.Free()

	got, _ = ctx.DecryptBit(sk, result2)
	if got != false {
		t.Errorf("MUX(false, true, false): got %v, want false", got)
	}
}

func TestIntegerEncryption(t *testing.T) {
	ctx, err := NewContext(SecuritySTD128, MethodGINX)
	if err != nil {
		t.Fatalf("failed to create context: %v", err)
	}
	defer ctx.Free()

	sk, err := ctx.GenerateSecretKey()
	if err != nil {
		t.Fatalf("failed to generate secret key: %v", err)
	}
	defer sk.Free()

	err = ctx.GenerateBootstrapKey(sk)
	if err != nil {
		t.Fatalf("failed to generate bootstrap key: %v", err)
	}

	tests := []struct {
		value  int64
		bitLen int
	}{
		{0, 8},
		{42, 8},
		{255, 8},
		{0, 16},
		{1000, 16},
		{65535, 16},
		{0, 32},
		{123456, 32},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			ct, err := ctx.EncryptInteger(sk, tt.value, tt.bitLen)
			if err != nil {
				t.Fatalf("failed to encrypt %d: %v", tt.value, err)
			}
			defer ct.Free()

			got, err := ctx.DecryptInteger(sk, ct)
			if err != nil {
				t.Fatalf("failed to decrypt: %v", err)
			}

			if got != tt.value {
				t.Errorf("got %d, want %d", got, tt.value)
			}
		})
	}
}

func TestIntegerAdd(t *testing.T) {
	ctx, err := NewContext(SecuritySTD128, MethodGINX)
	if err != nil {
		t.Fatalf("failed to create context: %v", err)
	}
	defer ctx.Free()

	sk, err := ctx.GenerateSecretKey()
	if err != nil {
		t.Fatalf("failed to generate secret key: %v", err)
	}
	defer sk.Free()

	err = ctx.GenerateBootstrapKey(sk)
	if err != nil {
		t.Fatalf("failed to generate bootstrap key: %v", err)
	}

	tests := []struct {
		a, b, want int64
		bitLen     int
	}{
		{10, 20, 30, 8},
		{100, 50, 150, 8},
		{1000, 2000, 3000, 16},
	}

	for _, tt := range tests {
		ctA, _ := ctx.EncryptInteger(sk, tt.a, tt.bitLen)
		defer ctA.Free()
		ctB, _ := ctx.EncryptInteger(sk, tt.b, tt.bitLen)
		defer ctB.Free()

		result, err := ctx.Add(ctA, ctB)
		if err != nil {
			t.Fatalf("Add failed: %v", err)
		}
		defer result.Free()

		got, _ := ctx.DecryptInteger(sk, result)
		if got != tt.want {
			t.Errorf("%d + %d: got %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestIntegerSub(t *testing.T) {
	ctx, err := NewContext(SecuritySTD128, MethodGINX)
	if err != nil {
		t.Fatalf("failed to create context: %v", err)
	}
	defer ctx.Free()

	sk, err := ctx.GenerateSecretKey()
	if err != nil {
		t.Fatalf("failed to generate secret key: %v", err)
	}
	defer sk.Free()

	err = ctx.GenerateBootstrapKey(sk)
	if err != nil {
		t.Fatalf("failed to generate bootstrap key: %v", err)
	}

	tests := []struct {
		a, b, want int64
		bitLen     int
	}{
		{30, 10, 20, 8},
		{200, 50, 150, 8},
		{5000, 2000, 3000, 16},
	}

	for _, tt := range tests {
		ctA, _ := ctx.EncryptInteger(sk, tt.a, tt.bitLen)
		defer ctA.Free()
		ctB, _ := ctx.EncryptInteger(sk, tt.b, tt.bitLen)
		defer ctB.Free()

		result, err := ctx.Sub(ctA, ctB)
		if err != nil {
			t.Fatalf("Sub failed: %v", err)
		}
		defer result.Free()

		got, _ := ctx.DecryptInteger(sk, result)
		if got != tt.want {
			t.Errorf("%d - %d: got %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestIntegerComparisons(t *testing.T) {
	ctx, err := NewContext(SecuritySTD128, MethodGINX)
	if err != nil {
		t.Fatalf("failed to create context: %v", err)
	}
	defer ctx.Free()

	sk, err := ctx.GenerateSecretKey()
	if err != nil {
		t.Fatalf("failed to generate secret key: %v", err)
	}
	defer sk.Free()

	err = ctx.GenerateBootstrapKey(sk)
	if err != nil {
		t.Fatalf("failed to generate bootstrap key: %v", err)
	}

	tests := []struct {
		name   string
		a, b   int64
		op     func(a, b *Integer) (*Ciphertext, error)
		want   bool
		bitLen int
	}{
		{"10 == 10", 10, 10, func(a, b *Integer) (*Ciphertext, error) { return ctx.Eq(a, b) }, true, 8},
		{"10 == 20", 10, 20, func(a, b *Integer) (*Ciphertext, error) { return ctx.Eq(a, b) }, false, 8},
		{"10 != 20", 10, 20, func(a, b *Integer) (*Ciphertext, error) { return ctx.Ne(a, b) }, true, 8},
		{"10 < 20", 10, 20, func(a, b *Integer) (*Ciphertext, error) { return ctx.Lt(a, b) }, true, 8},
		{"20 < 10", 20, 10, func(a, b *Integer) (*Ciphertext, error) { return ctx.Lt(a, b) }, false, 8},
		{"10 <= 10", 10, 10, func(a, b *Integer) (*Ciphertext, error) { return ctx.Le(a, b) }, true, 8},
		{"10 <= 20", 10, 20, func(a, b *Integer) (*Ciphertext, error) { return ctx.Le(a, b) }, true, 8},
		{"20 > 10", 20, 10, func(a, b *Integer) (*Ciphertext, error) { return ctx.Gt(a, b) }, true, 8},
		{"10 >= 10", 10, 10, func(a, b *Integer) (*Ciphertext, error) { return ctx.Ge(a, b) }, true, 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctA, _ := ctx.EncryptInteger(sk, tt.a, tt.bitLen)
			defer ctA.Free()
			ctB, _ := ctx.EncryptInteger(sk, tt.b, tt.bitLen)
			defer ctB.Free()

			result, err := tt.op(ctA, ctB)
			if err != nil {
				t.Fatalf("comparison failed: %v", err)
			}
			defer result.Free()

			got, _ := ctx.DecryptBit(sk, result)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBitwiseOperations(t *testing.T) {
	ctx, err := NewContext(SecuritySTD128, MethodGINX)
	if err != nil {
		t.Fatalf("failed to create context: %v", err)
	}
	defer ctx.Free()

	sk, err := ctx.GenerateSecretKey()
	if err != nil {
		t.Fatalf("failed to generate secret key: %v", err)
	}
	defer sk.Free()

	err = ctx.GenerateBootstrapKey(sk)
	if err != nil {
		t.Fatalf("failed to generate bootstrap key: %v", err)
	}

	// AND
	ctA, _ := ctx.EncryptInteger(sk, 0xFF, 8)
	defer ctA.Free()
	ctB, _ := ctx.EncryptInteger(sk, 0x0F, 8)
	defer ctB.Free()

	andResult, err := ctx.BitwiseAnd(ctA, ctB)
	if err != nil {
		t.Fatalf("BitwiseAnd failed: %v", err)
	}
	defer andResult.Free()

	got, _ := ctx.DecryptInteger(sk, andResult)
	if got != 0x0F {
		t.Errorf("0xFF AND 0x0F: got %d, want %d", got, 0x0F)
	}

	// OR
	ctC, _ := ctx.EncryptInteger(sk, 0xF0, 8)
	defer ctC.Free()
	ctD, _ := ctx.EncryptInteger(sk, 0x0F, 8)
	defer ctD.Free()

	orResult, err := ctx.BitwiseOr(ctC, ctD)
	if err != nil {
		t.Fatalf("BitwiseOr failed: %v", err)
	}
	defer orResult.Free()

	got, _ = ctx.DecryptInteger(sk, orResult)
	if got != 0xFF {
		t.Errorf("0xF0 OR 0x0F: got %d, want %d", got, 0xFF)
	}

	// XOR
	ctE, _ := ctx.EncryptInteger(sk, 0xFF, 8)
	defer ctE.Free()
	ctF, _ := ctx.EncryptInteger(sk, 0x55, 8)
	defer ctF.Free()

	xorResult, err := ctx.BitwiseXor(ctE, ctF)
	if err != nil {
		t.Fatalf("BitwiseXor failed: %v", err)
	}
	defer xorResult.Free()

	got, _ = ctx.DecryptInteger(sk, xorResult)
	if got != 0xAA {
		t.Errorf("0xFF XOR 0x55: got %d, want %d", got, 0xAA)
	}
}

func TestShift(t *testing.T) {
	ctx, err := NewContext(SecuritySTD128, MethodGINX)
	if err != nil {
		t.Fatalf("failed to create context: %v", err)
	}
	defer ctx.Free()

	sk, err := ctx.GenerateSecretKey()
	if err != nil {
		t.Fatalf("failed to generate secret key: %v", err)
	}
	defer sk.Free()

	err = ctx.GenerateBootstrapKey(sk)
	if err != nil {
		t.Fatalf("failed to generate bootstrap key: %v", err)
	}

	// Left shift
	ct1, _ := ctx.EncryptInteger(sk, 0x0F, 8)
	defer ct1.Free()

	shlResult, err := ctx.Shl(ct1, 4)
	if err != nil {
		t.Fatalf("Shl failed: %v", err)
	}
	defer shlResult.Free()

	got, _ := ctx.DecryptInteger(sk, shlResult)
	if got != 0xF0 {
		t.Errorf("0x0F << 4: got %d, want %d", got, 0xF0)
	}

	// Right shift
	ct2, _ := ctx.EncryptInteger(sk, 0xF0, 8)
	defer ct2.Free()

	shrResult, err := ctx.Shr(ct2, 4)
	if err != nil {
		t.Fatalf("Shr failed: %v", err)
	}
	defer shrResult.Free()

	got, _ = ctx.DecryptInteger(sk, shrResult)
	if got != 0x0F {
		t.Errorf("0xF0 >> 4: got %d, want %d", got, 0x0F)
	}
}

func TestPublicKeyEncryption(t *testing.T) {
	ctx, err := NewContext(SecuritySTD128, MethodGINX)
	if err != nil {
		t.Fatalf("failed to create context: %v", err)
	}
	defer ctx.Free()

	sk, err := ctx.GenerateSecretKey()
	if err != nil {
		t.Fatalf("failed to generate secret key: %v", err)
	}
	defer sk.Free()

	pk, err := ctx.GeneratePublicKey(sk)
	if err != nil {
		t.Fatalf("failed to generate public key: %v", err)
	}
	defer pk.Free()

	err = ctx.GenerateBootstrapKey(sk)
	if err != nil {
		t.Fatalf("failed to generate bootstrap key: %v", err)
	}

	// Encrypt with public key
	ct, err := ctx.EncryptBitPublic(pk, true)
	if err != nil {
		t.Fatalf("failed to encrypt with public key: %v", err)
	}
	defer ct.Free()

	// Decrypt with secret key
	result, err := ctx.DecryptBit(sk, ct)
	if err != nil {
		t.Fatalf("failed to decrypt: %v", err)
	}

	if result != true {
		t.Error("expected true, got false")
	}

	// Test integer encryption with public key
	ctInt, err := ctx.EncryptIntegerPublic(pk, 42, 8)
	if err != nil {
		t.Fatalf("failed to encrypt integer with public key: %v", err)
	}
	defer ctInt.Free()

	got, err := ctx.DecryptInteger(sk, ctInt)
	if err != nil {
		t.Fatalf("failed to decrypt integer: %v", err)
	}

	if got != 42 {
		t.Errorf("got %d, want 42", got)
	}
}

func TestSerialization(t *testing.T) {
	ctx, err := NewContext(SecuritySTD128, MethodGINX)
	if err != nil {
		t.Fatalf("failed to create context: %v", err)
	}
	defer ctx.Free()

	sk, err := ctx.GenerateSecretKey()
	if err != nil {
		t.Fatalf("failed to generate secret key: %v", err)
	}
	defer sk.Free()

	err = ctx.GenerateBootstrapKey(sk)
	if err != nil {
		t.Fatalf("failed to generate bootstrap key: %v", err)
	}

	// Test ciphertext serialization
	ct, _ := ctx.EncryptBit(sk, true)
	defer ct.Free()

	data, err := ctx.SerializeCiphertext(ct)
	if err != nil {
		t.Fatalf("failed to serialize ciphertext: %v", err)
	}

	ct2, err := ctx.DeserializeCiphertext(data)
	if err != nil {
		t.Fatalf("failed to deserialize ciphertext: %v", err)
	}
	defer ct2.Free()

	result, _ := ctx.DecryptBit(sk, ct2)
	if result != true {
		t.Error("deserialized ciphertext decrypts to wrong value")
	}

	// Test integer serialization
	ctInt, _ := ctx.EncryptInteger(sk, 12345, 16)
	defer ctInt.Free()

	intData, err := ctx.SerializeInteger(ctInt)
	if err != nil {
		t.Fatalf("failed to serialize integer: %v", err)
	}

	ctInt2, err := ctx.DeserializeInteger(intData, 16)
	if err != nil {
		t.Fatalf("failed to deserialize integer: %v", err)
	}
	defer ctInt2.Free()

	got, _ := ctx.DecryptInteger(sk, ctInt2)
	if got != 12345 {
		t.Errorf("deserialized integer: got %d, want 12345", got)
	}
}

func TestSecretKeySerialization(t *testing.T) {
	ctx, err := NewContext(SecuritySTD128, MethodGINX)
	if err != nil {
		t.Fatalf("failed to create context: %v", err)
	}
	defer ctx.Free()

	sk, err := ctx.GenerateSecretKey()
	if err != nil {
		t.Fatalf("failed to generate secret key: %v", err)
	}
	defer sk.Free()

	// Serialize
	data, err := ctx.SerializeSecretKey(sk)
	if err != nil {
		t.Fatalf("failed to serialize secret key: %v", err)
	}

	if len(data) == 0 {
		t.Error("serialized key is empty")
	}

	// Deserialize
	sk2, err := ctx.DeserializeSecretKey(data)
	if err != nil {
		t.Fatalf("failed to deserialize secret key: %v", err)
	}
	defer sk2.Free()

	// Verify by encrypting with original and decrypting with deserialized
	err = ctx.GenerateBootstrapKey(sk)
	if err != nil {
		t.Fatalf("failed to generate bootstrap key: %v", err)
	}

	ct, _ := ctx.EncryptBit(sk, true)
	defer ct.Free()

	result, _ := ctx.DecryptBit(sk2, ct)
	if result != true {
		t.Error("deserialized key produces wrong decryption")
	}
}

func TestClone(t *testing.T) {
	ctx, err := NewContext(SecuritySTD128, MethodGINX)
	if err != nil {
		t.Fatalf("failed to create context: %v", err)
	}
	defer ctx.Free()

	sk, err := ctx.GenerateSecretKey()
	if err != nil {
		t.Fatalf("failed to generate secret key: %v", err)
	}
	defer sk.Free()

	err = ctx.GenerateBootstrapKey(sk)
	if err != nil {
		t.Fatalf("failed to generate bootstrap key: %v", err)
	}

	// Clone ciphertext
	ct, _ := ctx.EncryptBit(sk, true)
	defer ct.Free()

	ct2, err := ct.Clone()
	if err != nil {
		t.Fatalf("failed to clone ciphertext: %v", err)
	}
	defer ct2.Free()

	result, _ := ctx.DecryptBit(sk, ct2)
	if result != true {
		t.Error("cloned ciphertext has wrong value")
	}

	// Clone integer
	ctInt, _ := ctx.EncryptInteger(sk, 42, 8)
	defer ctInt.Free()

	ctInt2, err := ctInt.Clone()
	if err != nil {
		t.Fatalf("failed to clone integer: %v", err)
	}
	defer ctInt2.Free()

	got, _ := ctx.DecryptInteger(sk, ctInt2)
	if got != 42 {
		t.Errorf("cloned integer: got %d, want 42", got)
	}
}

func TestMinMax(t *testing.T) {
	ctx, err := NewContext(SecuritySTD128, MethodGINX)
	if err != nil {
		t.Fatalf("failed to create context: %v", err)
	}
	defer ctx.Free()

	sk, err := ctx.GenerateSecretKey()
	if err != nil {
		t.Fatalf("failed to generate secret key: %v", err)
	}
	defer sk.Free()

	err = ctx.GenerateBootstrapKey(sk)
	if err != nil {
		t.Fatalf("failed to generate bootstrap key: %v", err)
	}

	ctA, _ := ctx.EncryptInteger(sk, 10, 8)
	defer ctA.Free()
	ctB, _ := ctx.EncryptInteger(sk, 20, 8)
	defer ctB.Free()

	// Min
	minResult, err := ctx.Min(ctA, ctB)
	if err != nil {
		t.Fatalf("Min failed: %v", err)
	}
	defer minResult.Free()

	got, _ := ctx.DecryptInteger(sk, minResult)
	if got != 10 {
		t.Errorf("min(10, 20): got %d, want 10", got)
	}

	// Max
	maxResult, err := ctx.Max(ctA, ctB)
	if err != nil {
		t.Fatalf("Max failed: %v", err)
	}
	defer maxResult.Free()

	got, _ = ctx.DecryptInteger(sk, maxResult)
	if got != 20 {
		t.Errorf("max(10, 20): got %d, want 20", got)
	}
}

func TestSelect(t *testing.T) {
	ctx, err := NewContext(SecuritySTD128, MethodGINX)
	if err != nil {
		t.Fatalf("failed to create context: %v", err)
	}
	defer ctx.Free()

	sk, err := ctx.GenerateSecretKey()
	if err != nil {
		t.Fatalf("failed to generate secret key: %v", err)
	}
	defer sk.Free()

	err = ctx.GenerateBootstrapKey(sk)
	if err != nil {
		t.Fatalf("failed to generate bootstrap key: %v", err)
	}

	condTrue, _ := ctx.EncryptBit(sk, true)
	defer condTrue.Free()
	condFalse, _ := ctx.EncryptBit(sk, false)
	defer condFalse.Free()
	ctA, _ := ctx.EncryptInteger(sk, 10, 8)
	defer ctA.Free()
	ctB, _ := ctx.EncryptInteger(sk, 20, 8)
	defer ctB.Free()

	// Select true -> A
	result1, err := ctx.Select(condTrue, ctA, ctB)
	if err != nil {
		t.Fatalf("Select failed: %v", err)
	}
	defer result1.Free()

	got, _ := ctx.DecryptInteger(sk, result1)
	if got != 10 {
		t.Errorf("select(true, 10, 20): got %d, want 10", got)
	}

	// Select false -> B
	result2, err := ctx.Select(condFalse, ctA, ctB)
	if err != nil {
		t.Fatalf("Select failed: %v", err)
	}
	defer result2.Free()

	got, _ = ctx.DecryptInteger(sk, result2)
	if got != 20 {
		t.Errorf("select(false, 10, 20): got %d, want 20", got)
	}
}

func TestCastTo(t *testing.T) {
	ctx, err := NewContext(SecuritySTD128, MethodGINX)
	if err != nil {
		t.Fatalf("failed to create context: %v", err)
	}
	defer ctx.Free()

	sk, err := ctx.GenerateSecretKey()
	if err != nil {
		t.Fatalf("failed to generate secret key: %v", err)
	}
	defer sk.Free()

	err = ctx.GenerateBootstrapKey(sk)
	if err != nil {
		t.Fatalf("failed to generate bootstrap key: %v", err)
	}

	// Cast 8-bit to 16-bit
	ct8, _ := ctx.EncryptInteger(sk, 42, 8)
	defer ct8.Free()

	ct16, err := ctx.CastTo(ct8, 16)
	if err != nil {
		t.Fatalf("CastTo failed: %v", err)
	}
	defer ct16.Free()

	got, _ := ctx.DecryptInteger(sk, ct16)
	if got != 42 {
		t.Errorf("cast 8->16: got %d, want 42", got)
	}

	if ct16.BitLen() != 16 {
		t.Errorf("cast 8->16: bitLen got %d, want 16", ct16.BitLen())
	}
}

// Benchmarks

func BenchmarkCGOEncryptBit(b *testing.B) {
	ctx, _ := NewContext(SecuritySTD128, MethodGINX)
	defer ctx.Free()
	sk, _ := ctx.GenerateSecretKey()
	defer sk.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ct, _ := ctx.EncryptBit(sk, true)
		ct.Free()
	}
}

func BenchmarkCGODecryptBit(b *testing.B) {
	ctx, _ := NewContext(SecuritySTD128, MethodGINX)
	defer ctx.Free()
	sk, _ := ctx.GenerateSecretKey()
	defer sk.Free()
	ct, _ := ctx.EncryptBit(sk, true)
	defer ct.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ctx.DecryptBit(sk, ct)
	}
}

func BenchmarkCGOAND(b *testing.B) {
	ctx, _ := NewContext(SecuritySTD128, MethodGINX)
	defer ctx.Free()
	sk, _ := ctx.GenerateSecretKey()
	defer sk.Free()
	_ = ctx.GenerateBootstrapKey(sk)
	ct1, _ := ctx.EncryptBit(sk, true)
	defer ct1.Free()
	ct2, _ := ctx.EncryptBit(sk, false)
	defer ct2.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, _ := ctx.And(ct1, ct2)
		result.Free()
	}
}

func BenchmarkCGOAdd8(b *testing.B) {
	ctx, _ := NewContext(SecuritySTD128, MethodGINX)
	defer ctx.Free()
	sk, _ := ctx.GenerateSecretKey()
	defer sk.Free()
	_ = ctx.GenerateBootstrapKey(sk)
	a, _ := ctx.EncryptInteger(sk, 10, 8)
	defer a.Free()
	c, _ := ctx.EncryptInteger(sk, 20, 8)
	defer c.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, _ := ctx.Add(a, c)
		result.Free()
	}
}

func BenchmarkCGOAdd16(b *testing.B) {
	ctx, _ := NewContext(SecuritySTD128, MethodGINX)
	defer ctx.Free()
	sk, _ := ctx.GenerateSecretKey()
	defer sk.Free()
	_ = ctx.GenerateBootstrapKey(sk)
	a, _ := ctx.EncryptInteger(sk, 1000, 16)
	defer a.Free()
	c, _ := ctx.EncryptInteger(sk, 2000, 16)
	defer c.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, _ := ctx.Add(a, c)
		result.Free()
	}
}

func BenchmarkCGOSerialize(b *testing.B) {
	ctx, _ := NewContext(SecuritySTD128, MethodGINX)
	defer ctx.Free()
	sk, _ := ctx.GenerateSecretKey()
	defer sk.Free()
	ct, _ := ctx.EncryptBit(sk, true)
	defer ct.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		data, _ := ctx.SerializeCiphertext(ct)
		_ = data
	}
}

func BenchmarkCGODeserialize(b *testing.B) {
	ctx, _ := NewContext(SecuritySTD128, MethodGINX)
	defer ctx.Free()
	sk, _ := ctx.GenerateSecretKey()
	defer sk.Free()
	ct, _ := ctx.EncryptBit(sk, true)
	defer ct.Free()
	data, _ := ctx.SerializeCiphertext(ct)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ct2, _ := ctx.DeserializeCiphertext(data)
		ct2.Free()
	}
}

func BenchmarkCGOKeyGen(b *testing.B) {
	ctx, _ := NewContext(SecuritySTD128, MethodGINX)
	defer ctx.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sk, _ := ctx.GenerateSecretKey()
		sk.Free()
	}
}

func BenchmarkCGOBootstrapKeyGen(b *testing.B) {
	ctx, _ := NewContext(SecuritySTD128, MethodGINX)
	defer ctx.Free()
	sk, _ := ctx.GenerateSecretKey()
	defer sk.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ctx.GenerateBootstrapKey(sk)
	}
}

func BenchmarkCGOPublicKeyGen(b *testing.B) {
	ctx, _ := NewContext(SecuritySTD128, MethodGINX)
	defer ctx.Free()
	sk, _ := ctx.GenerateSecretKey()
	defer sk.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pk, _ := ctx.GeneratePublicKey(sk)
		pk.Free()
	}
}

// Helper to avoid "imported but not used" errors
var _ = bytes.Buffer{}
