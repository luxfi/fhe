// Copyright (c) 2025-2026, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package fhe

import (
	"fmt"
	"sync"

	"github.com/luxfi/lattice/v7/gpu"
)

// Batch NTT/INTT dispatch — routes to lattice/v7/gpu (Metal/CUDA) when a
// GPU device is reachable AND the engine's (N, Q) probe matches the CPU
// subring NTT byte-for-byte. Otherwise per-polynomial subring fallback.
// CGO_ENABLED gates lattice/gpu compilation; no other build tag exists.

var (
	gpuCtxMu    sync.Mutex
	gpuCtxCache = map[engineKey]*gpu.NTTContext{}
)

func fheGPUCtx(e *NTTEngine) *gpu.NTTContext {
	if !gpu.GPUAvailable() {
		return nil
	}
	gpuCtxMu.Lock()
	defer gpuCtxMu.Unlock()
	k := engineKey{N: e.N, Q: e.Q}
	if ctx, ok := gpuCtxCache[k]; ok {
		return ctx
	}
	ctx, err := gpu.NewNTTContext(e.N, e.Q)
	if err != nil {
		gpuCtxCache[k] = nil
		return nil
	}
	if !probeByteEqual(e, ctx) {
		ctx.Close()
		gpuCtxCache[k] = nil
		return nil
	}
	gpuCtxCache[k] = ctx
	return ctx
}

// probeByteEqual rejects a GPU context whose forward NTT differs from
// the CPU subring NTT on a deterministic input. Different Montgomery /
// bit-reversed / twiddle conventions would corrupt ciphertexts silently.
func probeByteEqual(e *NTTEngine, gpuCtx *gpu.NTTContext) bool {
	N := int(e.N)
	probe := make([]uint64, N)
	for i := range probe {
		probe[i] = uint64(i+1) % e.Q
	}
	cpu := make([]uint64, N)
	copy(cpu, probe)
	e.sr.NTT(cpu, cpu)
	gpuOut, err := gpuCtx.NTT([][]uint64{probe})
	if err != nil || len(gpuOut) != 1 || len(gpuOut[0]) != N {
		return false
	}
	for i := 0; i < N; i++ {
		if cpu[i] != gpuOut[0][i] {
			return false
		}
	}
	return true
}

// NTTBatch performs forward NTT on every polynomial in polys. Output is
// byte-equal to repeated NTTInPlace calls regardless of dispatch path.
func (e *NTTEngine) NTTBatch(polys [][]uint64) ([][]uint64, error) {
	if ctx := fheGPUCtx(e); ctx != nil {
		return ctx.NTT(polys)
	}
	N := int(e.N)
	out := make([][]uint64, len(polys))
	for i, p := range polys {
		if len(p) != N {
			return nil, fmt.Errorf("fhe.NTTBatch: poly %d size %d != %d", i, len(p), N)
		}
		out[i] = make([]uint64, N)
		copy(out[i], p)
		e.sr.NTT(out[i], out[i])
	}
	return out, nil
}

// INTTBatch is the inverse of NTTBatch.
func (e *NTTEngine) INTTBatch(polys [][]uint64) ([][]uint64, error) {
	if ctx := fheGPUCtx(e); ctx != nil {
		return ctx.INTT(polys)
	}
	N := int(e.N)
	out := make([][]uint64, len(polys))
	for i, p := range polys {
		if len(p) != N {
			return nil, fmt.Errorf("fhe.INTTBatch: poly %d size %d != %d", i, len(p), N)
		}
		out[i] = make([]uint64, N)
		copy(out[i], p)
		e.sr.INTT(out[i], out[i])
	}
	return out, nil
}

// GPUNTTAvailable reports whether the GPU path serves this engine's (N, Q).
// First call may run the byte-equality probe; subsequent calls are cached.
func (e *NTTEngine) GPUNTTAvailable() bool { return fheGPUCtx(e) != nil }
