// Copyright (c) 2026, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

//go:build gpu

package bench

import (
	"fmt"
	"sync"

	lgpu "github.com/luxfi/lattice/v7/gpu"
)

type gpuProbeResult struct {
	available bool
	backend   string
	reason    string
}

var probeOnce sync.Once
var probeCached gpuProbeResult

func gpuProbe() gpuProbeResult {
	probeOnce.Do(func() {
		probeCached = gpuProbeResult{
			available: lgpu.GPUAvailable(),
			backend:   lgpu.GetBackend(),
		}
		if !probeCached.available {
			probeCached.reason = "lattice_gpu_available() returned false (library built without WITH_GPU=ON)"
		}
	})
	return probeCached
}

// nttCtxCache reuses NTT contexts across iterations -- creating them
// every call would dominate the bench. Keyed by N because Q is fixed.
var (
	nttCtxMu    sync.Mutex
	nttCtxCache = map[int]*lgpu.NTTContext{}
)

func getNTTContext(n int) (*lgpu.NTTContext, error) {
	nttCtxMu.Lock()
	defer nttCtxMu.Unlock()
	if ctx, ok := nttCtxCache[n]; ok {
		return ctx, nil
	}
	ctx, err := lgpu.NewNTTContext(uint32(n), nttQ)
	if err != nil {
		return nil, fmt.Errorf("NewNTTContext(N=%d, Q=0x%x): %w", n, nttQ, err)
	}
	nttCtxCache[n] = ctx
	return ctx, nil
}

// metalNTTForwardSinglePoly dispatches one NTT(N) through the lattice
// gpu wrapper. The wrapper internally calls metal_ntt_forward in
// libluxlattice.dylib. Single-poly is the path that worked in #121
// (12x slower than Go pure-Go, see policy/PERFORMANCE.md S5).
func metalNTTForwardSinglePoly(n int, data []uint64) error {
	ctx, err := getNTTContext(n)
	if err != nil {
		return err
	}
	if len(data) != n {
		return fmt.Errorf("data length %d != N %d", len(data), n)
	}
	// gpu.NTT takes [][]uint64 and returns [][]uint64. We pre-wrap the
	// caller's slice to avoid an extra allocation per iteration.
	in := [][]uint64{data}
	_, err = ctx.NTT(in)
	return err
}

// metalNTTForwardBatch dispatches batch NTTs. The published
// luxfi/lattice/v7@v7.0.0/gpu API does not expose a single-dispatch
// BatchNTT (the underlying libluxlattice exports lattice_ntt_batch_*
// but the Go wrapper only has NTT([][]uint64) which calls
// metal_ntt_forward once per polynomial). We therefore measure the
// "B sequential single-poly NTTs through the cgo boundary" cost,
// which is what the policy/PERFORMANCE.md S5 already established as
// 12x slower than Go.
//
// When/if the lattice gpu wrapper grows BatchNTT (ETA per
// FHE-GPU FIX agent), this function will be updated to call it. For
// now, our cell labels honestly show "B sequential single-poly".
func metalNTTForwardBatch(n, batch int, data []uint64) error {
	ctx, err := getNTTContext(n)
	if err != nil {
		return err
	}
	if len(data) != n*batch {
		return fmt.Errorf("data length %d != N*batch %d*%d", len(data), n, batch)
	}
	polys := make([][]uint64, batch)
	for i := 0; i < batch; i++ {
		polys[i] = data[i*n : (i+1)*n]
	}
	_, err = ctx.NTT(polys)
	return err
}
