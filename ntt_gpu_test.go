// Copyright (c) 2025-2026, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package fhe

import (
	"testing"
)

// TestNTTBatch_ByteEqualToInPlace pins the byte-equality contract: the
// batch path (whether routed to GPU or CPU subring fallback) MUST produce
// identical output to repeated NTTInPlace calls on the same inputs.
func TestNTTBatch_ByteEqualToInPlace(t *testing.T) {
	const (
		N = uint32(1024)
		Q = uint64(0x3FFFFFFFFED001) // 54-bit NTT-friendly prime (PN11QP54)
	)
	eng, err := NewNTTEngine(N, Q)
	if err != nil {
		t.Skipf("subring init failed for N=%d Q=%x: %v", N, Q, err)
	}

	batchSize := 8
	polys := make([][]uint64, batchSize)
	for i := range polys {
		p := make([]uint64, N)
		for j := range p {
			p[j] = uint64(i*1000+j+1) % Q
		}
		polys[i] = p
	}

	// Reference: per-poly in-place.
	want := make([][]uint64, batchSize)
	for i, p := range polys {
		c := make([]uint64, N)
		copy(c, p)
		eng.NTTInPlace(c)
		want[i] = c
	}

	got, err := eng.NTTBatch(polys)
	if err != nil {
		t.Fatalf("NTTBatch error: %v", err)
	}
	if len(got) != batchSize {
		t.Fatalf("NTTBatch len=%d want=%d", len(got), batchSize)
	}
	for i := 0; i < batchSize; i++ {
		for j := uint32(0); j < N; j++ {
			if got[i][j] != want[i][j] {
				t.Fatalf("NTTBatch byte mismatch at [%d][%d]: got=%d want=%d (gpu_available=%v)",
					i, j, got[i][j], want[i][j], eng.GPUNTTAvailable())
			}
		}
	}
}

// TestINTTBatch_RoundTrip pins INTT(NTT(x)) == x for the batch path.
func TestINTTBatch_RoundTrip(t *testing.T) {
	const (
		N = uint32(1024)
		Q = uint64(0x3FFFFFFFFED001)
	)
	eng, err := NewNTTEngine(N, Q)
	if err != nil {
		t.Skipf("subring init failed: %v", err)
	}

	batchSize := 4
	original := make([][]uint64, batchSize)
	for i := range original {
		p := make([]uint64, N)
		for j := range p {
			p[j] = uint64(j*7+i+1) % Q
		}
		original[i] = p
	}

	// Deep-copy because NTT/INTTBatch shouldn't mutate input but contracts vary.
	inputCopy := make([][]uint64, batchSize)
	for i, p := range original {
		inputCopy[i] = make([]uint64, N)
		copy(inputCopy[i], p)
	}

	forward, err := eng.NTTBatch(inputCopy)
	if err != nil {
		t.Fatalf("NTTBatch: %v", err)
	}
	back, err := eng.INTTBatch(forward)
	if err != nil {
		t.Fatalf("INTTBatch: %v", err)
	}

	for i := 0; i < batchSize; i++ {
		for j := uint32(0); j < N; j++ {
			if back[i][j] != original[i][j] {
				t.Fatalf("round-trip mismatch at [%d][%d]: got=%d want=%d (gpu_available=%v)",
					i, j, back[i][j], original[i][j], eng.GPUNTTAvailable())
			}
		}
	}
}
