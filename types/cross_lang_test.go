// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package types

import (
	"bytes"
	"testing"
	"unsafe"

	lattice "github.com/luxfi/lattice/v7/types"
)

// TestFHECiphertextHeader_CrossLangByteImage asserts byte-identical layout
// against the C++ mirror at luxcpp/fhe/test/types/types_test.cpp
// (test_ciphertext_header_memcmp).
func TestFHECiphertextHeader_CrossLangByteImage(t *testing.T) {
	var h FHECiphertextHeader
	for i := range h.ParamsHash {
		h.ParamsHash[i] = byte(i)
	}
	for i := range h.KeyID {
		h.KeyID[i] = byte(i + 0x40)
	}
	for i := range h.CircuitID {
		h.CircuitID[i] = byte(i + 0x80)
	}
	h.Scheme = FHESchemeCKKS
	h.Level = 7
	h.N = 16384
	h.ModulusCount = 8
	h.Domain = lattice.PolyDomainNTTMontgomery

	want := make([]byte, 144)
	for i := 0; i < 32; i++ {
		want[i] = byte(i)
		want[32+i] = byte(i + 0x40)
		want[64+i] = byte(i + 0x80)
	}
	// scheme = CKKS (2)
	want[96] = 0x02
	// level = 7
	want[100] = 0x07
	// N = 16384 = 0x4000 little-endian
	want[104] = 0x00
	want[105] = 0x40
	// modulus_count = 8
	want[108] = 0x08
	// domain = NTTMontgomery (3)
	want[112] = 0x03
	// 113..119 pad zero, 120..143 reserved zero (already)

	got := unsafe.Slice((*byte)(unsafe.Pointer(&h)), unsafe.Sizeof(h))
	if !bytes.Equal(got, want) {
		t.Fatalf("FHECiphertextHeader byte image mismatch with C++ side\n  got:  %x\n  want: %x", got, want)
	}
}

// TestFHEPrecompileArtifact_CrossLangByteImage asserts byte-identical layout
// against the C++ mirror at luxcpp/fhe/test/types/types_test.cpp
// (test_artifact_memcmp).
func TestFHEPrecompileArtifact_CrossLangByteImage(t *testing.T) {
	var a FHEPrecompileArtifact
	for i := range a.ParamsHash {
		a.ParamsHash[i] = byte(i)
	}
	for i := range a.KeyRoot {
		a.KeyRoot[i] = byte(i + 1)
	}
	for i := range a.InputCiphertextRoot {
		a.InputCiphertextRoot[i] = byte(i + 2)
	}
	for i := range a.OutputCiphertextRoot {
		a.OutputCiphertextRoot[i] = byte(i + 3)
	}
	for i := range a.CircuitRoot {
		a.CircuitRoot[i] = byte(i + 4)
	}
	for i := range a.ThresholdTranscriptRoot {
		a.ThresholdTranscriptRoot[i] = byte(i + 5)
	}
	for i := range a.AttestationRoot {
		a.AttestationRoot[i] = byte(i + 6)
	}
	a.OpCount = 1024
	a.FailedCount = 0

	want := make([]byte, 232)
	for i := 0; i < 32; i++ {
		want[i] = byte(i)
		want[32+i] = byte(i + 1)
		want[64+i] = byte(i + 2)
		want[96+i] = byte(i + 3)
		want[128+i] = byte(i + 4)
		want[160+i] = byte(i + 5)
		want[192+i] = byte(i + 6)
	}
	// op_count = 1024 = 0x00000400 LE
	want[224] = 0x00
	want[225] = 0x04

	got := unsafe.Slice((*byte)(unsafe.Pointer(&a)), unsafe.Sizeof(a))
	if !bytes.Equal(got, want) {
		t.Fatalf("FHEPrecompileArtifact byte image mismatch with C++ side\n  got:  %x\n  want: %x", got, want)
	}
}
