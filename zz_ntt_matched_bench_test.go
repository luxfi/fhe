// Copyright (c) 2025-2026, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause
//
// TEMPORARY matched-workload benchmark (C++ metal_bench.mm parity).
// Same modulus Q=998244353 (119*2^23+1), same N set, same operation:
// single-polynomial forward NTT. Delete after measuring.

package fhe

import (
	"testing"
)

// Q identical to luxcpp/fhe metal_bench.mm CPU-vs-Metal reference.
const matchedQ = uint64(998244353)

var matchedNs = []uint32{1024, 2048, 4096, 8192, 16384}

// BenchmarkMatchedForwardNTT measures single-poly forward NTT (CPU subring),
// the exact operation metal_bench.mm times as its "CPU (µs)" B=1 column.
func BenchmarkMatchedForwardNTT(b *testing.B) {
	for _, N := range matchedNs {
		eng, err := NewNTTEngine(N, matchedQ)
		if err != nil {
			b.Fatalf("NewNTTEngine(N=%d, Q=%d): %v", N, matchedQ, err)
		}
		work := make([]uint64, N)
		for i := range work {
			work[i] = uint64(i+1) % matchedQ
		}
		// Match metal_bench.mm exactly: repeatedly transform the SAME
		// buffer with no per-iteration reset (values stay reduced mod Q).
		b.Run(sizeName(N), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				eng.NTTInPlace(work)
			}
		})
	}
}

func sizeName(N uint32) string {
	switch N {
	case 1024:
		return "N1024"
	case 2048:
		return "N2048"
	case 4096:
		return "N4096"
	case 8192:
		return "N8192"
	case 16384:
		return "N16384"
	}
	return "N?"
}
