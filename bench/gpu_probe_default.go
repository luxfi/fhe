// Copyright (c) 2026, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

//go:build !gpu

package bench

// gpuProbe attempts a runtime check of the lattice GPU wrapper. With
// the default tag the GPU package is unreachable, so the probe always
// reports unavailable.
type gpuProbeResult struct {
	available bool
	backend   string
	reason    string
}

func gpuProbe() gpuProbeResult {
	return gpuProbeResult{
		available: false,
		backend:   "CPU (pure Go)",
		reason:    "built without -tags gpu; GPU wrapper not linked",
	}
}

// metalNTTForwardSinglePoly is a stub on the no-tag build. Cells call
// it only after gpuProbe().available, but we still need a definition
// so the test files compile under both tags.
func metalNTTForwardSinglePoly(n int, _ []uint64) error {
	_ = n
	return errGPUDisabled
}

// metalNTTForwardBatch is a stub on the no-tag build. Same reason as
// metalNTTForwardSinglePoly.
func metalNTTForwardBatch(n, batch int, _ []uint64) error {
	_, _ = n, batch
	return errGPUDisabled
}
