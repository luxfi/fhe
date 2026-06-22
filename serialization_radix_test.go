// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package fhe

import (
	"bytes"
	"testing"
)

// TestRadixCiphertext_MarshalRoundTrip proves a RadixCiphertext survives a
// MarshalBinary/UnmarshalBinary round trip and still decrypts to the original
// plaintext.
func TestRadixCiphertext_MarshalRoundTrip(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()

	intParams, err := NewIntegerParams(params, 2)
	if err != nil {
		t.Fatalf("integer params: %v", err)
	}
	enc := NewIntegerEncryptor(intParams, sk)
	dec := NewIntegerDecryptor(intParams, sk)

	const want uint64 = 0xA5
	ct, err := enc.EncryptUint64(want, FheUint8)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	data, err := ct.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	got := new(RadixCiphertext)
	if err := got.UnmarshalBinary(data); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.fheType != ct.fheType {
		t.Fatalf("fheType: got %d want %d", got.fheType, ct.fheType)
	}
	if got.blockBits != ct.blockBits || got.numBlocks != ct.numBlocks {
		t.Fatalf("shape: got (%d,%d) want (%d,%d)",
			got.blockBits, got.numBlocks, ct.blockBits, ct.numBlocks)
	}

	if dv := dec.DecryptUint64(got); dv != want {
		t.Fatalf("decrypt after round trip: got %#x want %#x", dv, want)
	}
}

// TestRadixCiphertext_MarshalLossless proves the wire format is lossless and
// byte-stable: re-marshaling an unmarshaled ciphertext yields identical bytes,
// and every block decrypts to its original value across several sizes. This
// pins the serialization contract only — it deliberately does not re-assert the
// IntegerEvaluator's homomorphic arithmetic, which is owned by its own tests.
func TestRadixCiphertext_MarshalLossless(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()

	intParams, err := NewIntegerParams(params, 2)
	if err != nil {
		t.Fatalf("integer params: %v", err)
	}
	enc := NewIntegerEncryptor(intParams, sk)
	dec := NewIntegerDecryptor(intParams, sk)

	cases := []struct {
		name  string
		value uint64
		typ   FheUintType
	}{
		{"u8", 0xA5, FheUint8},
		{"u16", 0xBEEF, FheUint16},
		{"u32", 0xDEADBEEF, FheUint32},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ct, err := enc.EncryptUint64(tc.value, tc.typ)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}

			b1, err := ct.MarshalBinary()
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}

			out := new(RadixCiphertext)
			if err := out.UnmarshalBinary(b1); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			// Byte-stable: re-marshaling the decoded value reproduces b1 exactly.
			b2, err := out.MarshalBinary()
			if err != nil {
				t.Fatalf("re-marshal: %v", err)
			}
			if !bytes.Equal(b1, b2) {
				t.Fatalf("marshal not byte-stable: %d vs %d bytes", len(b1), len(b2))
			}

			// Lossless: the round-tripped ciphertext decrypts to the original.
			mask := uint64(1)<<uint(tc.typ.NumBits()) - 1
			if got := dec.DecryptUint64(out) & mask; got != tc.value&mask {
				t.Fatalf("decrypt after round trip: got %#x want %#x", got, tc.value&mask)
			}
		})
	}
}
