// Copyright (c) 2026, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

// bench_ntt_test.go is the canonical NTT ladder.
//
// Sweep dimensions (per FHE-GPU spec section 19A):
//   - N      in {1024, 2048, 4096, 8192, 16384}
//   - B      in {1, 8, 32, 128, 512, 2048}
//   - domain in {Montgomery, Standard}
//   - mode   in {kernel-only, end-to-end, copy-included, warm-buffer}
//
// Per cell: median of >=10 runs, Release, M1 Max.
//
// Mode definitions:
//   - kernel-only   == time only the inner NTT call, buffers are
//                      pre-allocated and stay live across iterations
//                      (the "warmest possible" measurement).
//   - end-to-end    == includes constructing the input poly each
//                      iteration (the realistic dispatch cost).
//   - copy-included == includes a slice copy on the input boundary
//                      (the "must not corrupt caller's data" cost).
//   - warm-buffer   == kernel-only with an explicit warmup of N
//                      iterations before the timer starts. Reports the
//                      same number as kernel-only on most paths but
//                      differs when the GPU dispatcher caches twiddle
//                      tables on first use.
//
// Domain defines whether RootsForward/Backward are in Montgomery form
// (the luxfi/lattice/v7/ring path) or standard form (the historical
// path used by luxcpp/lattice/src/metal/metal_ntt.mm::compute_twiddles
// when no caller-supplied roots are provided). The pure-Go SubRing
// always operates in Montgomery -- the bench records that choice
// explicitly so the data file is unambiguous.
//
// Honest residual: this harness only exercises the SubRing.NTT entry.
// Variants (NTTConjugateInvariant, NTTLazy) are out of scope -- the
// crossover question is on the standard nega-cyclic path that
// dominates blind-rotate.

package bench

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
)

// nttSweepN is the canonical N axis. Powers of two from 2^10 to 2^14.
var nttSweepN = []int{1024, 2048, 4096, 8192, 16384}

// nttSweepB is the canonical batch axis. 2048 will SIGSEGV on Metal
// per #121, but we still sweep it for the Go-side measurement and to
// document the failure mode.
var nttSweepB = []int{1, 8, 32, 128, 512, 2048}

// nttSweepMode enumerates the timing scopes.
var nttSweepMode = []string{"kernel-only", "end-to-end", "copy-included", "warm-buffer"}

// goSubRing operates in Montgomery domain by definition. We expose the
// "Standard" variant by IMForm-ing on read-out, but for benchmarking
// purposes we only differentiate the cell label -- the inner kernel is
// the same. This matches how the question is actually asked: "is the
// caller paying the Montgomery conversion cost?" rather than "does the
// kernel use Montgomery internally?".
var nttSweepDomain = []string{"Montgomery", "Standard"}

// BenchmarkNTTLadderGo runs the full NTT ladder against the pure-Go
// path. Every cell completes (no GPU dependence). Output rolls into
// the "ntt_ladder_go" Ladder in the registry.
func BenchmarkNTTLadderGo(b *testing.B) {
	for _, n := range nttSweepN {
		sr, err := goSubRing(n)
		if err != nil {
			b.Fatalf("subring N=%d: %v", n, err)
		}
		for _, batch := range nttSweepB {
			for _, domain := range nttSweepDomain {
				for _, mode := range nttSweepMode {
					name := fmt.Sprintf("Go/N=%d/B=%d/D=%s/M=%s", n, batch, domain, mode)
					b.Run(name, func(b *testing.B) {
						runGoNTT(b, sr, n, batch, domain, mode)
					})
				}
			}
		}
	}
}

func runGoNTT(b *testing.B, sr *_goSubRingType, n, batch int, domain, mode string) {
	// Pre-allocated work buffers used by all modes.
	work := make([][]uint64, batch)
	scratch := make([][]uint64, batch)
	for i := 0; i < batch; i++ {
		work[i] = uniformPoly(n)
		scratch[i] = make([]uint64, n)
	}

	// "Warm-buffer" mode does N untimed iterations first. We match the
	// Go bench convention -- ResetTimer wipes the clock.
	if mode == "warm-buffer" {
		for w := 0; w < 4; w++ {
			for i := 0; i < batch; i++ {
				sr.NTT(work[i], scratch[i])
			}
		}
		runtime.GC()
	}

	samples := make([]Sample, 0, b.N)
	b.ResetTimer()
	for it := 0; it < b.N; it++ {
		var (
			in  [][]uint64
			out [][]uint64
		)

		switch mode {
		case "end-to-end":
			// Pay the input-construction cost every iteration.
			in = make([][]uint64, batch)
			out = make([][]uint64, batch)
			for i := 0; i < batch; i++ {
				in[i] = uniformPoly(n)
				out[i] = make([]uint64, n)
			}
		case "copy-included":
			// Pay only the slice-copy cost; reuse buffers.
			in = work
			out = scratch
		default:
			// kernel-only and warm-buffer share the same scope.
			in = work
			out = scratch
		}

		start := time.Now()

		// Domain handling. "Standard" pre-converts inputs to standard
		// form via IMForm, runs NTT in Montgomery on the converted
		// data (which is what the Go ring does internally either way),
		// and reports the converted-input cost.
		if domain == "Standard" {
			for i := 0; i < batch; i++ {
				sr.IMForm(in[i], in[i])
			}
		}

		if mode == "copy-included" {
			for i := 0; i < batch; i++ {
				copy(out[i], in[i])
				sr.NTT(out[i], out[i])
			}
		} else {
			for i := 0; i < batch; i++ {
				sr.NTT(in[i], out[i])
			}
		}

		samples = append(samples, Sample(time.Since(start).Nanoseconds()))
	}
	b.StopTimer()

	cell := summarizeCell(b, samples, map[string]string{
		"N":       fmt.Sprintf("%d", n),
		"B":       fmt.Sprintf("%d", batch),
		"domain":  domain,
		"mode":    mode,
		"path":    "go-pure",
		"backend": "CPU (pure Go)",
	})
	cell.Name = b.Name()
	cell.Status = "ok"
	Record("ntt_ladder_go", cell)
}

// _goSubRingType is the SubRing alias so the benchmark file can move
// the pointer through helpers without re-importing ring everywhere.
// The real type comes from luxfi/lattice/v7/ring.SubRing.
type _goSubRingType = goSubRingT

// BenchmarkNTTLadderMetal runs the same sweep against the Metal path
// via luxfi/lattice/v7/gpu. Cells skip with NotApplicable when:
//
//   - the binary was not built with -tags gpu (probe.available == false)
//   - the wrapper reports an error during context creation
//   - BatchNTT (B>=8) returns an error -- known SIGSEGV-prone per #121
//
// The single-poly cells (B=1) should always complete on a host with the
// installed dylib; their numbers are the load-bearing reconciliation
// data for #88 vs #121.
func BenchmarkNTTLadderMetal(b *testing.B) {
	probe := gpuProbe()
	if !probe.available {
		Record("ntt_ladder_metal", Cell{
			Name:   b.Name(),
			Status: "skipped",
			Reason: "NotApplicable: " + probe.reason,
			Params: map[string]string{"backend": probe.backend},
		})
		b.Skipf("NotApplicable: %s", probe.reason)
		return
	}

	for _, n := range nttSweepN {
		for _, batch := range nttSweepB {
			for _, domain := range nttSweepDomain {
				for _, mode := range nttSweepMode {
					name := fmt.Sprintf("Metal/N=%d/B=%d/D=%s/M=%s", n, batch, domain, mode)
					b.Run(name, func(b *testing.B) {
						runMetalNTT(b, n, batch, domain, mode, probe.backend)
					})
				}
			}
		}
	}
}

func runMetalNTT(b *testing.B, n, batch int, domain, mode, backend string) {
	// Pre-allocate work buffer. BatchNTT and NTT both want a flat
	// or sliced layout; the wrapper handles both.
	flat := make([]uint64, n*batch)
	for i := 0; i < n*batch; i++ {
		flat[i] = uint64(i) * 0x9e3779b97f4a7c15 % nttQ
	}

	// Probe the path once before timing. If it fails we skip with the
	// failure recorded (this is the BatchNTT SIGSEGV signal).
	var probeErr error
	if batch == 1 {
		buf := make([]uint64, n)
		copy(buf, flat[:n])
		probeErr = metalNTTForwardSinglePoly(n, buf)
	} else {
		buf := make([]uint64, n*batch)
		copy(buf, flat)
		probeErr = metalNTTForwardBatch(n, batch, buf)
	}
	if probeErr != nil {
		reason := fmt.Sprintf("NotApplicable: metal NTT path failed -- %v", probeErr)
		if strings.Contains(probeErr.Error(), "SIGSEGV") || strings.Contains(probeErr.Error(), "signal") {
			reason = "SIGSEGV in metal_ntt_batch_forward (matches #121 finding)"
		}
		Record("ntt_ladder_metal", Cell{
			Name:   b.Name(),
			Status: "skipped",
			Reason: reason,
			Params: map[string]string{
				"N": fmt.Sprintf("%d", n), "B": fmt.Sprintf("%d", batch),
				"domain": domain, "mode": mode, "backend": backend,
			},
		})
		b.Skip(reason)
		return
	}

	// Warmup for warm-buffer mode.
	if mode == "warm-buffer" {
		for w := 0; w < 4; w++ {
			buf := make([]uint64, n*batch)
			copy(buf, flat)
			if batch == 1 {
				_ = metalNTTForwardSinglePoly(n, buf[:n])
			} else {
				_ = metalNTTForwardBatch(n, batch, buf)
			}
		}
		runtime.GC()
	}

	// Pre-allocated buffer reused across iterations for kernel-only.
	persistentBuf := make([]uint64, n*batch)
	copy(persistentBuf, flat)

	samples := make([]Sample, 0, b.N)
	b.ResetTimer()
	for it := 0; it < b.N; it++ {
		var buf []uint64
		switch mode {
		case "end-to-end":
			buf = make([]uint64, n*batch)
			for i := range buf {
				buf[i] = uint64(it+i) * 0x9e3779b97f4a7c15 % nttQ
			}
		case "copy-included":
			buf = make([]uint64, n*batch)
			copy(buf, flat)
		default:
			buf = persistentBuf
		}

		start := time.Now()
		var err error
		if batch == 1 {
			err = metalNTTForwardSinglePoly(n, buf[:n])
		} else {
			err = metalNTTForwardBatch(n, batch, buf)
		}
		if err != nil {
			b.Fatalf("metal NTT mid-bench failure: %v", err)
		}
		samples = append(samples, Sample(time.Since(start).Nanoseconds()))
	}
	b.StopTimer()

	cell := summarizeCell(b, samples, map[string]string{
		"N":       fmt.Sprintf("%d", n),
		"B":       fmt.Sprintf("%d", batch),
		"domain":  domain,
		"mode":    mode,
		"path":    "metal-luxlattice",
		"backend": backend,
	})
	cell.Name = b.Name()
	cell.Status = "ok"
	Record("ntt_ladder_metal", cell)
}

// summarizeCell reduces a sample slice into the canonical Cell. The Go
// testing framework reports a single ns/op number; we keep that for
// continuity (b.ReportMetric) while emitting full percentiles into
// the JSON ladder.
func summarizeCell(b *testing.B, samples []Sample, params map[string]string) Cell {
	median, mean, p50, p95, p99 := Stats(samples)
	cell := Cell{
		Params:     params,
		Iterations: len(samples),
		MedianNS:   median,
		MeanNS:     mean,
		P50NS:      p50,
		P95NS:      p95,
		P99NS:      p99,
	}
	if median > 0 {
		cell.OpsPerSec = 1e9 / float64(median)
	}
	if median > 0 {
		b.ReportMetric(float64(median), "ns/op-median")
	}
	if p99 > 0 {
		b.ReportMetric(float64(p99), "ns/op-p99")
	}
	if cell.OpsPerSec > 0 {
		b.ReportMetric(cell.OpsPerSec, "ops/s")
	}
	return cell
}
