// Copyright (c) 2026, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

//go:build gpu

package bench

import (
	"fmt"
	"sync"

	"github.com/luxfi/lattice/v7/ring"
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
			probeCached.reason = "lattice_gpu_available() returned false (library built without WITH_GPU=ON or missing Metal probe)"
		}
	})
	return probeCached
}

// montCtxCache reuses Montgomery NTT contexts across iterations. Keyed
// by N because Q is fixed. Uses the Montgomery dispatch path which is
// byte-equal to ring.NTTStandard and supports true single-dispatch
// batch via lattice_ntt_forward(ctx, data, batch).
var (
	montCtxMu    sync.Mutex
	montCtxCache = map[int]*lgpu.MontgomeryNTTContext{}
)

func getMontgomeryNTTContext(n int) (*lgpu.MontgomeryNTTContext, error) {
	montCtxMu.Lock()
	defer montCtxMu.Unlock()
	if ctx, ok := montCtxCache[n]; ok {
		return ctx, nil
	}
	r, err := ring.NewRing(n, []uint64{nttQ})
	if err != nil {
		return nil, fmt.Errorf("ring.NewRing(N=%d, Q=0x%x): %w", n, nttQ, err)
	}
	ctx, err := lgpu.NewMontgomeryNTTContext(r.SubRings[0])
	if err != nil {
		return nil, fmt.Errorf("NewMontgomeryNTTContext(N=%d, Q=0x%x): %w", n, nttQ, err)
	}
	montCtxCache[n] = ctx
	return ctx, nil
}

// metalNTTForwardSinglePoly dispatches one NTT(N) through the
// Montgomery dispatch path. Output is byte-equal to ring.NTTStandard.
func metalNTTForwardSinglePoly(n int, data []uint64) error {
	ctx, err := getMontgomeryNTTContext(n)
	if err != nil {
		return err
	}
	if len(data) != n {
		return fmt.Errorf("data length %d != N %d", len(data), n)
	}
	return ctx.Forward(data, 1)
}

// metalNTTForwardBatch dispatches batch NTTs through the
// Montgomery batch dispatcher. After the FHE-GPU FIX
// (0507c925 + 3fd1ed7), MontgomeryNTTContext.Forward(data, batch) is
// a single-dispatch batched call -- the BatchNTT C ABI signature
// mismatch was fixed in luxcpp/lattice/src/lattice.cpp.
func metalNTTForwardBatch(n, batch int, data []uint64) error {
	ctx, err := getMontgomeryNTTContext(n)
	if err != nil {
		return err
	}
	if len(data) != n*batch {
		return fmt.Errorf("data length %d != N*batch %d*%d", len(data), n, batch)
	}
	return ctx.Forward(data, uint32(batch))
}
