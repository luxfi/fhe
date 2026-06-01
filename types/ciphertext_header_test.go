// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package types

import (
	"bytes"
	"testing"
	"unsafe"

	lattice "github.com/luxfi/lattice/v7/types"
)

func TestFHEScheme_StableValues(t *testing.T) {
	cases := []struct {
		s    FHEScheme
		want uint32
	}{
		{FHESchemeTFHE, 0},
		{FHESchemeFHEW, 1},
		{FHESchemeCKKS, 2},
		{FHESchemeBFV, 3},
		{FHESchemeBGV, 4},
	}
	for _, c := range cases {
		if uint32(c.s) != c.want {
			t.Errorf("FHEScheme(%s) = %d, want %d", c.s, c.s, c.want)
		}
	}
}

func TestFHEScheme_StableStrings(t *testing.T) {
	cases := []struct {
		s    FHEScheme
		want string
	}{
		{FHESchemeTFHE, "TFHE"},
		{FHESchemeFHEW, "FHEW"},
		{FHESchemeCKKS, "CKKS"},
		{FHESchemeBFV, "BFV"},
		{FHESchemeBGV, "BGV"},
		{FHEScheme(0xFF), "Unknown"},
	}
	for _, c := range cases {
		if got := c.s.String(); got != c.want {
			t.Errorf("FHEScheme(%d).String() = %q, want %q", c.s, got, c.want)
		}
	}
}

// makeHeader returns a deterministic test header.
func makeHeader() FHECiphertextHeader {
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
	h.N = 1 << 14
	h.ModulusCount = 8
	h.Domain = lattice.PolyDomainNTTMontgomery
	return h
}

// TestFHECiphertextHeader_DigestDeterministic asserts that the same field
// values always produce the same digest. Determinism is the basis for
// using the digest as a binding tag in precompile artifacts.
func TestFHECiphertextHeader_DigestDeterministic(t *testing.T) {
	h1 := makeHeader()
	h2 := makeHeader()
	d1 := h1.Digest()
	d2 := h2.Digest()
	if d1 != d2 {
		t.Errorf("two equal headers produced different digests:\n  d1=%x\n  d2=%x", d1, d2)
	}
	// Stability: re-digesting the same struct must give the same result.
	for i := 0; i < 4; i++ {
		if got := h1.Digest(); got != d1 {
			t.Errorf("re-digest %d differed: %x vs %x", i, got, d1)
		}
	}
}

// TestFHECiphertextHeader_DigestSensitiveToFields asserts that changing
// any single field changes the digest.
func TestFHECiphertextHeader_DigestSensitiveToFields(t *testing.T) {
	base := makeHeader()
	baseDigest := base.Digest()

	mutate := func(name string, mut func(*FHECiphertextHeader)) {
		t.Run(name, func(t *testing.T) {
			h := makeHeader()
			mut(&h)
			if got := h.Digest(); got == baseDigest {
				t.Errorf("mutating %s did not change digest", name)
			}
		})
	}
	mutate("ParamsHash", func(h *FHECiphertextHeader) { h.ParamsHash[0] ^= 0xFF })
	mutate("KeyID", func(h *FHECiphertextHeader) { h.KeyID[31] ^= 0xFF })
	mutate("CircuitID", func(h *FHECiphertextHeader) { h.CircuitID[15] ^= 0xFF })
	mutate("Scheme", func(h *FHECiphertextHeader) { h.Scheme = FHESchemeBGV })
	mutate("Level", func(h *FHECiphertextHeader) { h.Level++ })
	mutate("N", func(h *FHECiphertextHeader) { h.N <<= 1 })
	mutate("ModulusCount", func(h *FHECiphertextHeader) { h.ModulusCount++ })
	mutate("Domain", func(h *FHECiphertextHeader) { h.Domain = lattice.PolyDomainStandard })
	mutate("Reserved", func(h *FHECiphertextHeader) { h.Reserved[0] = 1 })
}

func TestFHECiphertextHeader_MatchesContext(t *testing.T) {
	h := makeHeader() // N=16384, Domain=NTTMontgomery
	good := &lattice.NTTContext{
		Modulus: 0xFFFFFFFFFFFFFFC5, N: 1 << 14,
		InputDomain: lattice.PolyDomainNTTMontgomery, RootDomain: lattice.PolyDomainNTTMontgomery,
		OutputDomain: lattice.PolyDomainMontgomery,
	}
	if !h.MatchesContext(good) {
		t.Errorf("matching N+Domain should match")
	}

	wrongN := &lattice.NTTContext{
		Modulus: 0xFFFFFFFFFFFFFFC5, N: 1 << 12,
		InputDomain: lattice.PolyDomainNTTMontgomery, RootDomain: lattice.PolyDomainNTTMontgomery,
		OutputDomain: lattice.PolyDomainMontgomery,
	}
	if h.MatchesContext(wrongN) {
		t.Errorf("different N should not match")
	}

	wrongDomain := &lattice.NTTContext{
		Modulus: 0xFFFFFFFFFFFFFFC5, N: 1 << 14,
		InputDomain: lattice.PolyDomainNTTStandard, RootDomain: lattice.PolyDomainNTTStandard,
		OutputDomain: lattice.PolyDomainStandard,
	}
	if h.MatchesContext(wrongDomain) {
		t.Errorf("different Domain should not match")
	}

	if h.MatchesContext(nil) {
		t.Errorf("nil ctx should not match")
	}
}

// TestFHECiphertextHeader_CanonicalEncodingDeterministic verifies the byte
// representation used by Digest() is identical for identical inputs and
// has the expected length.
func TestFHECiphertextHeader_CanonicalEncodingDeterministic(t *testing.T) {
	h1 := makeHeader()
	h2 := makeHeader()
	enc1 := h1.canonicalEncoding()
	enc2 := h2.canonicalEncoding()
	if !bytes.Equal(enc1, enc2) {
		t.Fatalf("canonical encoding not deterministic\n  e1=%x\n  e2=%x", enc1, enc2)
	}
	if len(enc1) != 144 {
		t.Errorf("canonical encoding len = %d, want 144", len(enc1))
	}
}

// TestFHECiphertextHeader_Layout pins the byte layout for cgo compatibility.
func TestFHECiphertextHeader_Layout(t *testing.T) {
	const wantSize = 144
	if got := unsafe.Sizeof(FHECiphertextHeader{}); got != wantSize {
		t.Fatalf("sizeof(FHECiphertextHeader) = %d, want %d", got, wantSize)
	}
	var h FHECiphertextHeader
	base := uintptr(unsafe.Pointer(&h))
	cases := []struct {
		name string
		off  uintptr
		want uintptr
	}{
		{"ParamsHash", uintptr(unsafe.Pointer(&h.ParamsHash)) - base, 0},
		{"KeyID", uintptr(unsafe.Pointer(&h.KeyID)) - base, 32},
		{"CircuitID", uintptr(unsafe.Pointer(&h.CircuitID)) - base, 64},
		{"Scheme", uintptr(unsafe.Pointer(&h.Scheme)) - base, 96},
		{"Level", uintptr(unsafe.Pointer(&h.Level)) - base, 100},
		{"N", uintptr(unsafe.Pointer(&h.N)) - base, 104},
		{"ModulusCount", uintptr(unsafe.Pointer(&h.ModulusCount)) - base, 108},
		{"Domain", uintptr(unsafe.Pointer(&h.Domain)) - base, 112},
		{"Reserved", uintptr(unsafe.Pointer(&h.Reserved)) - base, 120},
	}
	for _, c := range cases {
		if c.off != c.want {
			t.Errorf("offset of %s = %d, want %d", c.name, c.off, c.want)
		}
	}
}
