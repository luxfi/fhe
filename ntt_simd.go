// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

// Package fhe NTT thin wrapper.
//
// This file is a delegating wrapper around the unified Lux NTT
// substrate at github.com/luxfi/math/ntt/subring (the Lattigo-derived
// Montgomery negacyclic NTT body, mirrored on the C++ side by
// crypto/fhe/cpp/backends/cpu/ntt_cpu.cpp via
// lux::crypto::ringtail::lattice_ring::NTTStandard).
//
// The previous standalone cyclic NTT implementation has been removed;
// there were zero production callers of NTTEngine (only ntt_simd_test.go).
// Convention is now negacyclic — same body, same byte representation,
// across Go and C++.

package fhe

import (
	"fmt"
	"sync"

	"github.com/luxfi/math/ntt/subring"
)

// NTTEngine is a thin wrapper around a cached *subring.SubRing
// keyed by (N, Q). All forward/inverse NTT operations delegate to
// the unified substrate.
type NTTEngine struct {
	N  uint32
	Q  uint64
	sr *subring.SubRing
}

// engineCache memoizes SubRing instances keyed by (N, Q) so that
// callers constructing many NTTEngine values for the same parameters
// share the (expensive) NTT constant tables.
var (
	engineCacheMu sync.RWMutex
	engineCache   = make(map[engineKey]*subring.SubRing)
)

type engineKey struct {
	N uint32
	Q uint64
}

// resolveSubRing returns or builds the cached *subring.SubRing for (N, Q).
func resolveSubRing(N uint32, Q uint64) (*subring.SubRing, error) {
	k := engineKey{N: N, Q: Q}

	engineCacheMu.RLock()
	sr, ok := engineCache[k]
	engineCacheMu.RUnlock()
	if ok {
		return sr, nil
	}

	engineCacheMu.Lock()
	defer engineCacheMu.Unlock()
	if sr, ok := engineCache[k]; ok {
		return sr, nil
	}

	sr, err := subring.NewSubRing(int(N), Q)
	if err != nil {
		return nil, fmt.Errorf("fhe: subring.NewSubRing(N=%d, Q=%d): %w", N, Q, err)
	}
	if err := sr.GenerateNTTConstants(); err != nil {
		return nil, fmt.Errorf("fhe: GenerateNTTConstants(N=%d, Q=%d): %w", N, Q, err)
	}
	engineCache[k] = sr
	return sr, nil
}

// NewNTTEngine creates an NTTEngine for the given ring degree and modulus.
// The underlying SubRing is shared across engines with identical (N, Q).
func NewNTTEngine(N uint32, Q uint64) (*NTTEngine, error) {
	sr, err := resolveSubRing(N, Q)
	if err != nil {
		return nil, err
	}
	return &NTTEngine{N: N, Q: Q, sr: sr}, nil
}

// NTTInPlace performs an in-place forward NTT (negacyclic, Montgomery form).
func (e *NTTEngine) NTTInPlace(coeffs []uint64) {
	e.sr.NTT(coeffs, coeffs)
}

// INTTInPlace performs an in-place inverse NTT (negacyclic, Montgomery form).
// INTT(NTT(x)) == x.
func (e *NTTEngine) INTTInPlace(coeffs []uint64) {
	e.sr.INTT(coeffs, coeffs)
}

// NTTInPlaceSIMD is an alias for NTTInPlace; the substrate selects the
// best available implementation (pure Go or SIMD via build tags).
func (e *NTTEngine) NTTInPlaceSIMD(coeffs []uint64) {
	e.sr.NTT(coeffs, coeffs)
}

// INTTInPlaceSIMD is an alias for INTTInPlace.
func (e *NTTEngine) INTTInPlaceSIMD(coeffs []uint64) {
	e.sr.INTT(coeffs, coeffs)
}
