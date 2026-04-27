// Copyright (c) 2026, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package bench

import (
	"fmt"

	"github.com/luxfi/lattice/v7/ring"
)

// goSubRingT is the package-local alias used by bench files so they
// can refer to the SubRing type without importing ring everywhere.
type goSubRingT = ring.SubRing

// nttQ is the NTT-friendly modulus used for the canonical ladder. It is
// the first 60-bit prime in luxfi/lattice/v7/ring.Qi60, the same one
// the gpu-side bench harness in #121 used. Picking a single Q across
// the whole ladder keeps Go-vs-Metal cells comparable even though the
// internal Montgomery constants differ between paths.
//
//	Q = 0x1fffffffffe00001 = 2305843009213317121 (60 bits)
const nttQ uint64 = 0x1fffffffffe00001

// goSubRing constructs the pure-Go SubRing for a given N. The SubRing
// holds RootsForward, RootsBackward, MRedConstant, NInv, and the rest
// of the Montgomery-domain NTT machinery.
//
// NewSubRing only sets up the metadata -- the NTT roots are generated
// by the unexported generateNTTConstants on the returned SubRing. We
// route through the parent Ring constructor instead, which guarantees
// roots are populated.
//
// Returns an error rather than panicking so the bench can mark the
// cell NotApplicable instead of failing the whole run.
func goSubRing(n int) (*ring.SubRing, error) {
	r, err := ring.NewRing(n, []uint64{nttQ})
	if err != nil {
		return nil, fmt.Errorf("ring.NewRing(N=%d, Q=0x%x): %w", n, nttQ, err)
	}
	if len(r.SubRings) == 0 || r.SubRings[0] == nil {
		return nil, fmt.Errorf("ring.NewRing returned no SubRings")
	}
	return r.SubRings[0], nil
}

// uniformPoly fills a slice with N coefficients in [0, Q). The samples
// are deterministic via a small linear congruential generator so the
// bench is reproducible without pulling in PRNG plumbing.
func uniformPoly(n int) []uint64 {
	out := make([]uint64, n)
	state := uint64(0xc0ffeefacefeed01)
	for i := range out {
		state = state*6364136223846793005 + 1442695040888963407
		out[i] = state % nttQ
	}
	return out
}
