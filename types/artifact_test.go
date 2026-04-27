// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package types

import (
	"bytes"
	"testing"
	"unsafe"
)

func makeArtifact() FHEPrecompileArtifact {
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
	return a
}

func TestFHEPrecompileArtifact_DigestDeterministic(t *testing.T) {
	a1 := makeArtifact()
	a2 := makeArtifact()
	d1 := a1.Digest()
	d2 := a2.Digest()
	if d1 != d2 {
		t.Errorf("two equal artifacts produced different digests:\n  d1=%x\n  d2=%x", d1, d2)
	}
}

func TestFHEPrecompileArtifact_DigestSensitiveToFields(t *testing.T) {
	base := makeArtifact()
	baseDigest := base.Digest()
	mutate := func(name string, mut func(*FHEPrecompileArtifact)) {
		t.Run(name, func(t *testing.T) {
			a := makeArtifact()
			mut(&a)
			if got := a.Digest(); got == baseDigest {
				t.Errorf("mutating %s did not change digest", name)
			}
		})
	}
	mutate("ParamsHash", func(a *FHEPrecompileArtifact) { a.ParamsHash[0] ^= 0xFF })
	mutate("KeyRoot", func(a *FHEPrecompileArtifact) { a.KeyRoot[0] ^= 0xFF })
	mutate("InputCiphertextRoot", func(a *FHEPrecompileArtifact) { a.InputCiphertextRoot[0] ^= 0xFF })
	mutate("OutputCiphertextRoot", func(a *FHEPrecompileArtifact) { a.OutputCiphertextRoot[0] ^= 0xFF })
	mutate("CircuitRoot", func(a *FHEPrecompileArtifact) { a.CircuitRoot[0] ^= 0xFF })
	mutate("ThresholdTranscriptRoot", func(a *FHEPrecompileArtifact) { a.ThresholdTranscriptRoot[0] ^= 0xFF })
	mutate("AttestationRoot", func(a *FHEPrecompileArtifact) { a.AttestationRoot[0] ^= 0xFF })
	mutate("OpCount", func(a *FHEPrecompileArtifact) { a.OpCount++ })
	mutate("FailedCount", func(a *FHEPrecompileArtifact) { a.FailedCount++ })
}

func TestFHEPrecompileArtifact_IsThresholdAndIsAttested(t *testing.T) {
	var a FHEPrecompileArtifact
	if a.IsThreshold() {
		t.Errorf("zero artifact should not be threshold")
	}
	if a.IsAttested() {
		t.Errorf("zero artifact should not be attested")
	}
	a.ThresholdTranscriptRoot[0] = 1
	if !a.IsThreshold() {
		t.Errorf("non-zero ThresholdTranscriptRoot should be threshold")
	}
	a.AttestationRoot[31] = 1
	if !a.IsAttested() {
		t.Errorf("non-zero AttestationRoot should be attested")
	}
}

func TestFHEPrecompileArtifact_CanonicalEncoding(t *testing.T) {
	a := makeArtifact()
	enc := a.canonicalEncoding()
	if len(enc) != 232 {
		t.Errorf("canonical encoding len = %d, want 232", len(enc))
	}
	// determinism
	enc2 := a.canonicalEncoding()
	if !bytes.Equal(enc, enc2) {
		t.Errorf("canonical encoding not deterministic")
	}
}

func TestFHEPrecompileArtifact_Layout(t *testing.T) {
	const wantSize = 232
	if got := unsafe.Sizeof(FHEPrecompileArtifact{}); got != wantSize {
		t.Fatalf("sizeof(FHEPrecompileArtifact) = %d, want %d", got, wantSize)
	}
	var a FHEPrecompileArtifact
	base := uintptr(unsafe.Pointer(&a))
	cases := []struct {
		name string
		off  uintptr
		want uintptr
	}{
		{"ParamsHash", uintptr(unsafe.Pointer(&a.ParamsHash)) - base, 0},
		{"KeyRoot", uintptr(unsafe.Pointer(&a.KeyRoot)) - base, 32},
		{"InputCiphertextRoot", uintptr(unsafe.Pointer(&a.InputCiphertextRoot)) - base, 64},
		{"OutputCiphertextRoot", uintptr(unsafe.Pointer(&a.OutputCiphertextRoot)) - base, 96},
		{"CircuitRoot", uintptr(unsafe.Pointer(&a.CircuitRoot)) - base, 128},
		{"ThresholdTranscriptRoot", uintptr(unsafe.Pointer(&a.ThresholdTranscriptRoot)) - base, 160},
		{"AttestationRoot", uintptr(unsafe.Pointer(&a.AttestationRoot)) - base, 192},
		{"OpCount", uintptr(unsafe.Pointer(&a.OpCount)) - base, 224},
		{"FailedCount", uintptr(unsafe.Pointer(&a.FailedCount)) - base, 228},
	}
	for _, c := range cases {
		if c.off != c.want {
			t.Errorf("offset of %s = %d, want %d", c.name, c.off, c.want)
		}
	}
}
