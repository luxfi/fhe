// Copyright (c) 2026, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

// bench_reconcile_test.go is the canonical reconciliation between
// #88 (Metal NTT crossover at N=4096 B=128 fused = 14.02x) and #121
// (Metal NTT measured 0.08x / SIGSEGV) for the same (N, B) cell.
//
// Per FHE-GPU spec section 19E: run the canonical harness on the SAME
// N=4096 B=128 NTT cell across all known Metal NTT paths in the tree:
//
//   1. luxcpp/cevm/lib/evm/gpu/metal/   -- cevm-side (NOT FHE-related).
//   2. luxcpp/fhe/src/core/lib/math/hal/mlx/ -- F-Chain MLX backend.
//   3. luxcpp/lattice/src/metal/        -- luxlattice (#121 measured here).
//   4. luxcpp/crypto/gpukit/gpu/metal/  -- crypto gpukit (also has ntt_driver).
//
// What this bench reports per path:
//
//   - exists?            file exists on disk
//   - reachable from Go? cgo wrapper compiles + dispatcher links
//   - single-poly NTT    measurement (matches #121's path)
//   - batched NTT B=128  measurement (matches #88's claim)
//
// The bench only tries (3) directly because that is the ONLY path
// reachable from Go via libluxlattice today. Paths (1), (2), and (4)
// are documented as "Metal NTT zoo" in RESULTS.md but cannot be
// dispatched from Go without new cgo wrappers (sibling-agent territory).
//
// This file does NOT modify any kernel; it only measures via the
// existing wrapper, then writes a structured JSON record so that the
// next agent has a reproducible baseline.

package bench

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// reconcileCellN is the canonical N for the reconciliation. Hard-coded
// because that is what #88 and #121 both measured.
const reconcileCellN = 4096

// reconcileCellB is the canonical batch for #88's claim.
const reconcileCellB = 128

// metalNTTZoo lists every Metal NTT source file we know about in the
// luxcpp tree. The "reachable" field is honest: only the lattice path
// is wired through the lattice/v7/gpu cgo wrapper today.
var metalNTTZoo = []struct {
	Name      string
	SourcePath string
	Purpose   string
	Reachable string
	Notes     string
}{
	{
		Name:       "luxlattice",
		SourcePath: "/Users/z/work/lux/cpp/lattice/src/metal/metal_ntt.mm",
		Purpose:    "Generic Montgomery-form NTT for ring.SubRing dispatch (the #121 measurement target).",
		Reachable:  "yes (via libluxlattice + luxfi/lattice/v7/gpu cgo)",
		Notes:      "BatchNTT path SIGSEGVs at every (N,B) tested per #121; single-poly works but is 12x slower than Go.",
	},
	{
		Name:       "fhe-mlx-backend",
		SourcePath: "/Users/z/work/lux/cpp/fhe/src/core/lib/math/hal/mlx/metal_ntt_wrapper.mm",
		Purpose:    "F-Chain MLX backend NTT wrapper; routes to NTTMetalDispatcherOptimized (custom Metal kernels with fused log(N) stages, shared-memory butterflies).",
		Reachable:  "no (FHEgpu/FHEmetal libs not linked into lux/fhe Go module)",
		Notes:      "This is the path that produced #88's claimed 14.02x at N=4096 B=128 fused. The fused kernel source is in metal_dispatch_optimized.h::get_fused_ntt_kernel_source. NOT measurable from Go today.",
	},
	{
		Name:       "crypto-gpukit",
		SourcePath: "/Users/z/work/lux/cpp/crypto/gpukit/gpu/metal/ntt_driver.mm",
		Purpose:    "Generic NTT driver for gpukit; used by other crypto primitives that need NTT (KZG, IPA, etc.).",
		Reachable:  "no (separate library, not linked into lux/fhe)",
		Notes:      "Independent implementation -- not the same code path as either #88 or #121.",
	},
	{
		Name:       "metal-tests-test-ntt",
		SourcePath: "/Users/z/work/lux/cpp/metal/tests/test_ntt.mm",
		Purpose:    "Standalone Metal NTT unit test; doc-only, not a dispatcher.",
		Reachable:  "no (test target only)",
		Notes:      "Contains a minimal reference implementation used to validate the kernel under a build harness. Not a runtime path.",
	},
	{
		Name:       "cevm-metal",
		SourcePath: "/Users/z/work/lux/cpp/cevm/lib/evm/gpu/metal/",
		Purpose:    "EVM-execution Metal kernels (block-STM, BLS, keccak256, tx_validate). NO NTT.",
		Reachable:  "n/a -- no NTT here",
		Notes:      "The §19E hypothesis that #88 might have measured cevm-side Metal NTT is FALSIFIED -- the cevm metal directory contains zero NTT code (verified by directory listing 2026-04-27).",
	},
}

// BenchmarkReconcile_MetalNTTZoo emits a structured record of every
// Metal NTT path that exists in the tree. It runs zero kernels; the
// purpose is to put the zoo into the JSON ladder so the report has a
// machine-readable manifest.
func BenchmarkReconcile_MetalNTTZoo(b *testing.B) {
	for _, entry := range metalNTTZoo {
		exists := pathExists(entry.SourcePath)
		params := map[string]string{
			"name":        entry.Name,
			"source_path": entry.SourcePath,
			"purpose":     entry.Purpose,
			"reachable":   entry.Reachable,
			"exists":      fmt.Sprintf("%v", exists),
			"notes":       entry.Notes,
		}
		Record("reconcile_zoo", Cell{
			Name:   "MetalNTTZoo/" + entry.Name,
			Params: params,
			Status: "ok",
		})
	}
	// Single noop iteration so the benchmark framework is happy.
	for i := 0; i < b.N; i++ {
	}
}

func pathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// BenchmarkReconcile_88_vs_121 measures the canonical N=4096 B=128 cell
// on every path that we can reach from Go. Today that is exactly one
// path: the luxlattice Metal NTT via luxfi/lattice/v7/gpu.
//
// Reports:
//   - Go pure-Go NTT(N=4096) single-poly latency
//   - Go pure-Go NTT(N=4096) batched-128 latency (sequential -- no Go batch NTT primitive)
//   - Metal luxlattice single-poly latency
//   - Metal luxlattice batched-128 latency (expected SIGSEGV per #121)
//
// Conclusions written into RESULTS.md:
//   - if Go vs Metal single-poly ratio is ~0.08x, that confirms #121's
//     finding on this host.
//   - if Metal batched returns an error, that confirms the SIGSEGV is
//     not yet fixed and #88's 14.02x cannot be reproduced on this path.
//   - the F-Chain MLX backend (which is what #88 actually measured) is
//     UNREACHABLE from Go in this tree -- the reconciliation answer is:
//     #88's number is from a different code path than #121's, and only
//     the luxlattice path is dispatched from Go today.
func BenchmarkReconcile_88_vs_121(b *testing.B) {
	const (
		N = reconcileCellN
		B = reconcileCellB
	)

	// Pure-Go single-poly.
	sr, err := goSubRing(N)
	if err != nil {
		b.Fatalf("subring N=%d: %v", N, err)
	}

	measureGo := func(sb *testing.B, name, label string, batch int) {
		work := make([][]uint64, batch)
		out := make([][]uint64, batch)
		for i := range work {
			work[i] = uniformPoly(N)
			out[i] = make([]uint64, N)
		}
		for w := 0; w < 3; w++ {
			for i := 0; i < batch; i++ {
				sr.NTT(work[i], out[i])
			}
		}
		samples := make([]Sample, 0, sb.N)
		sb.ResetTimer()
		for it := 0; it < sb.N; it++ {
			start := time.Now()
			for i := 0; i < batch; i++ {
				sr.NTT(work[i], out[i])
			}
			samples = append(samples, Sample(time.Since(start).Nanoseconds()))
		}
		sb.StopTimer()
		cell := summarizeCell(sb, samples, map[string]string{
			"path":  "go-pure",
			"N":     fmt.Sprintf("%d", N),
			"B":     fmt.Sprintf("%d", batch),
			"label": label,
		})
		cell.Name = name
		cell.Status = "ok"
		Record("reconcile_88_121", cell)
	}

	measureMetal := func(sb *testing.B, name, label string, batch int) {
		probe := gpuProbe()
		if !probe.available {
			Record("reconcile_88_121", Cell{
				Name:   name,
				Params: map[string]string{"path": "metal-luxlattice", "N": fmt.Sprintf("%d", N), "B": fmt.Sprintf("%d", batch), "label": label},
				Status: "skipped",
				Reason: "NotApplicable: " + probe.reason,
			})
			return
		}
		flat := make([]uint64, N*batch)
		for i := range flat {
			flat[i] = uint64(i+1) * 0x9e3779b97f4a7c15 % nttQ
		}
		var probeErr error
		buf := make([]uint64, N*batch)
		copy(buf, flat)
		if batch == 1 {
			probeErr = metalNTTForwardSinglePoly(N, buf[:N])
		} else {
			probeErr = metalNTTForwardBatch(N, batch, buf)
		}
		if probeErr != nil {
			reason := fmt.Sprintf("path failed: %v", probeErr)
			if strings.Contains(probeErr.Error(), "SIGSEGV") || strings.Contains(probeErr.Error(), "signal") {
				reason = "SIGSEGV in metal_ntt_batch_forward (matches #121 finding -- BatchNTT crash unfixed)"
			}
			Record("reconcile_88_121", Cell{
				Name:   name,
				Params: map[string]string{"path": "metal-luxlattice", "N": fmt.Sprintf("%d", N), "B": fmt.Sprintf("%d", batch), "label": label, "backend": probe.backend},
				Status: "skipped",
				Reason: reason,
			})
			return
		}
		samples := make([]Sample, 0, sb.N)
		persistent := make([]uint64, N*batch)
		copy(persistent, flat)
		sb.ResetTimer()
		for it := 0; it < sb.N; it++ {
			start := time.Now()
			if batch == 1 {
				_ = metalNTTForwardSinglePoly(N, persistent[:N])
			} else {
				_ = metalNTTForwardBatch(N, batch, persistent)
			}
			samples = append(samples, Sample(time.Since(start).Nanoseconds()))
		}
		sb.StopTimer()
		cell := summarizeCell(sb, samples, map[string]string{
			"path":    "metal-luxlattice",
			"N":       fmt.Sprintf("%d", N),
			"B":       fmt.Sprintf("%d", batch),
			"label":   label,
			"backend": probe.backend,
		})
		cell.Name = name
		cell.Status = "ok"
		Record("reconcile_88_121", cell)
	}

	b.Run("Go/single-poly", func(sb *testing.B) {
		measureGo(sb, sb.Name(), "go pure-Go single-poly N=4096 (the denominator in #121's ratio)", 1)
	})
	b.Run("Go/batched-128-sequential", func(sb *testing.B) {
		measureGo(sb, sb.Name(), "go pure-Go N=4096 sequenced 128 times (matches what blind-rotate does)", B)
	})
	b.Run("Metal/single-poly", func(sb *testing.B) {
		measureMetal(sb, sb.Name(), "metal luxlattice single-poly N=4096 (the numerator in #121's 0.08x ratio)", 1)
	})
	b.Run("Metal/batched-128-fused", func(sb *testing.B) {
		measureMetal(sb, sb.Name(), "metal luxlattice BatchNTT N=4096 B=128 (the #88 14.02x claim target)", B)
	})
}

// BenchmarkReconcile_FChainMLX_Build is a check, not a measurement. It
// records whether the F-Chain MLX backend's metal_dispatch_optimized.h
// is present on disk, so the report can state precisely which fused
// kernel #88 must have measured.
func BenchmarkReconcile_FChainMLX_Build(b *testing.B) {
	checks := []struct {
		Name string
		Path string
	}{
		{"fhe-mlx-dispatch-optimized-header", "/Users/z/work/lux/cpp/fhe/src/core/lib/math/hal/mlx/metal_dispatch_optimized.h"},
		{"fhe-mlx-ntt-wrapper-source", "/Users/z/work/lux/cpp/fhe/src/core/lib/math/hal/mlx/metal_ntt_wrapper.mm"},
		{"fhe-mlx-mlx-backend-cpp", "/Users/z/work/lux/cpp/fhe/src/core/lib/math/hal/mlx/mlx_backend.cpp"},
		{"fhe-mlx-fused-kernel-source", "/Users/z/work/lux/cpp/fhe/src/core/lib/math/hal/mlx/metal_dispatch_optimized.h"},
		{"fhe-mlx-build-output", "/Users/z/work/lux/cpp/fhe/build-mlx/src/core/lib/math/hal/mlx/metal_ntt_bench"},
		{"luxlattice-source", "/Users/z/work/lux/cpp/lattice/src/metal/metal_ntt.mm"},
		{"luxlattice-installed-dylib", "/Users/z/work/lux/cpp/install/lib/libluxlattice.1.0.0.dylib"},
	}
	for _, c := range checks {
		Record("reconcile_build_state", Cell{
			Name: "BuildState/" + c.Name,
			Params: map[string]string{
				"path":   c.Path,
				"exists": fmt.Sprintf("%v", pathExists(c.Path)),
			},
			Status: "ok",
		})
	}
	for i := 0; i < b.N; i++ {
	}
}
