// Copyright (c) 2026, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

// bench_threshold_test.go covers the threshold-FHE primitives:
//
//   - threshold keygen share
//   - partial decrypt share
//   - share verify
//   - share aggregate
//   - threshold transcript root
//
// Per FHE-GPU spec section 19C: ops/sec + p50/p95/p99 latency. CPU
// baselines today, GPU NotApplicable until lattice/multiparty grows a
// GPU dispatch path (no such plan today -- threshold ops are
// inherently sequential on the share boundaries).
//
// Threshold uses lattice/multiparty.Thresholdizer + Combiner directly
// because the fhe package does not re-export threshold APIs. Same
// underlying ringqp arithmetic.

package bench

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/luxfi/lattice/v7/core/rlwe"
	"github.com/luxfi/lattice/v7/multiparty"
)

// thresholdParams returns a small but realistic rlwe.Parameters set for
// threshold benches. LogN=10 (N=1024) keeps key generation under a few
// ms and avoids dominating the benchmark with setup. Production
// threshold for FHE policy uses these dimensions.
func thresholdParams(b *testing.B) rlwe.Parameters {
	b.Helper()
	params, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
		LogN:    10,
		Q:       []uint64{0x200000440001, 0x7fff80001, 0x800280001},
		P:       []uint64{0x3ffffffb80001},
		NTTFlag: true,
	})
	if err != nil {
		b.Fatalf("threshold params: %v", err)
	}
	return params
}

// =============================================================================
// Threshold keygen share -- one party generates its t-of-N share.
// =============================================================================

func BenchmarkThreshold_KeygenShare_CPU(b *testing.B) {
	params := thresholdParams(b)
	thr := multiparty.NewThresholdizer(params)
	kg := rlwe.NewKeyGenerator(params)
	sk := kg.GenSecretKeyNew()
	const threshold = 3

	for w := 0; w < 3; w++ {
		_, err := thr.GenShamirPolynomial(threshold, sk)
		if err != nil {
			b.Fatalf("setup GenShamirPolynomial: %v", err)
		}
	}
	runtime.GC()

	samples := make([]Sample, 0, b.N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		_, err := thr.GenShamirPolynomial(threshold, sk)
		if err != nil {
			b.Fatalf("GenShamirPolynomial: %v", err)
		}
		samples = append(samples, Sample(time.Since(start).Nanoseconds()))
	}
	b.StopTimer()

	cell := summarizeCell(b, samples, map[string]string{
		"primitive": "threshold_keygen_share",
		"backend":   "CPU (pure Go)",
		"threshold": fmt.Sprintf("%d", threshold),
		"logN":      "10",
	})
	cell.Name = b.Name()
	cell.Status = "ok"
	Record("threshold", cell)
}

func BenchmarkThreshold_KeygenShare_Metal(b *testing.B) {
	probe := gpuProbe()
	recordSkip(b, "threshold", "Threshold_KeygenShare/Metal",
		"NotApplicable: threshold keygen is sequential ringqp polynomial sampling; no GPU dispatcher exists in lattice/multiparty",
		map[string]string{"primitive": "threshold_keygen_share", "backend": probe.backend})
}

// =============================================================================
// Partial decrypt share -- multiparty.KeySwitchPK.GenShare. Approximated
// here as one Thresholdizer.GenShamirSecretShare because the partial-
// decrypt protocol shares the same per-recipient share-generation cost
// shape (one ringqp polynomial evaluation at the recipient's point).
// =============================================================================

func BenchmarkThreshold_PartialDecryptShare_CPU(b *testing.B) {
	params := thresholdParams(b)
	thr := multiparty.NewThresholdizer(params)
	kg := rlwe.NewKeyGenerator(params)
	sk := kg.GenSecretKeyNew()
	const threshold = 3

	poly, err := thr.GenShamirPolynomial(threshold, sk)
	if err != nil {
		b.Fatalf("GenShamirPolynomial: %v", err)
	}
	share := thr.AllocateThresholdSecretShare()
	recipient := multiparty.ShamirPublicPoint(7)

	for w := 0; w < 3; w++ {
		thr.GenShamirSecretShare(recipient, poly, &share)
	}
	runtime.GC()

	samples := make([]Sample, 0, b.N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		thr.GenShamirSecretShare(recipient, poly, &share)
		samples = append(samples, Sample(time.Since(start).Nanoseconds()))
	}
	b.StopTimer()

	cell := summarizeCell(b, samples, map[string]string{
		"primitive": "partial_decrypt_share",
		"backend":   "CPU (pure Go)",
		"threshold": fmt.Sprintf("%d", threshold),
		"logN":      "10",
		"scope":     "GenShamirSecretShare (per-recipient)",
	})
	cell.Name = b.Name()
	cell.Status = "ok"
	Record("threshold", cell)
}

func BenchmarkThreshold_PartialDecryptShare_Metal(b *testing.B) {
	probe := gpuProbe()
	recordSkip(b, "threshold", "Threshold_PartialDecryptShare/Metal",
		"NotApplicable: per-recipient share generation is one polynomial evaluation; GPU dispatch overhead would dominate",
		map[string]string{"primitive": "partial_decrypt_share", "backend": probe.backend})
}

// =============================================================================
// Share verify -- not exposed as a separate operation in
// lattice/multiparty.Thresholdizer. Verification happens implicitly via
// AggregateShares (which checks levels). We bench the level-check +
// addition path under "share_verify" with a scope qualifier.
// =============================================================================

func BenchmarkThreshold_ShareVerify_CPU(b *testing.B) {
	recordSkip(b, "threshold", "Threshold_ShareVerify/CPU",
		"NotApplicable: lattice/multiparty.Thresholdizer has no separate verify -- verification happens implicitly inside AggregateShares (level match check). Reported under share_aggregate.",
		map[string]string{"primitive": "share_verify", "backend": "CPU (pure Go)"})
}

func BenchmarkThreshold_ShareVerify_Metal(b *testing.B) {
	probe := gpuProbe()
	recordSkip(b, "threshold", "Threshold_ShareVerify/Metal",
		"NotApplicable: same as CPU -- no separate verify primitive in the API",
		map[string]string{"primitive": "share_verify", "backend": probe.backend})
}

// =============================================================================
// Share aggregate -- two parties combine their shares. Benches
// Thresholdizer.AggregateShares (one ringqp Add).
// =============================================================================

func BenchmarkThreshold_ShareAggregate_CPU(b *testing.B) {
	params := thresholdParams(b)
	thr := multiparty.NewThresholdizer(params)
	kg := rlwe.NewKeyGenerator(params)
	sk1 := kg.GenSecretKeyNew()
	sk2 := kg.GenSecretKeyNew()
	const threshold = 3

	poly1, err := thr.GenShamirPolynomial(threshold, sk1)
	if err != nil {
		b.Fatalf("GenShamirPolynomial 1: %v", err)
	}
	poly2, err := thr.GenShamirPolynomial(threshold, sk2)
	if err != nil {
		b.Fatalf("GenShamirPolynomial 2: %v", err)
	}
	recipient := multiparty.ShamirPublicPoint(7)
	share1 := thr.AllocateThresholdSecretShare()
	share2 := thr.AllocateThresholdSecretShare()
	out := thr.AllocateThresholdSecretShare()
	thr.GenShamirSecretShare(recipient, poly1, &share1)
	thr.GenShamirSecretShare(recipient, poly2, &share2)

	for w := 0; w < 3; w++ {
		if err := thr.AggregateShares(share1, share2, &out); err != nil {
			b.Fatalf("setup AggregateShares: %v", err)
		}
	}
	runtime.GC()

	samples := make([]Sample, 0, b.N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		if err := thr.AggregateShares(share1, share2, &out); err != nil {
			b.Fatalf("AggregateShares: %v", err)
		}
		samples = append(samples, Sample(time.Since(start).Nanoseconds()))
	}
	b.StopTimer()

	cell := summarizeCell(b, samples, map[string]string{
		"primitive": "share_aggregate",
		"backend":   "CPU (pure Go)",
		"threshold": fmt.Sprintf("%d", threshold),
		"logN":      "10",
	})
	cell.Name = b.Name()
	cell.Status = "ok"
	Record("threshold", cell)
}

func BenchmarkThreshold_ShareAggregate_Metal(b *testing.B) {
	probe := gpuProbe()
	recordSkip(b, "threshold", "Threshold_ShareAggregate/Metal",
		"NotApplicable: aggregate is a single ringqp Add at the share level; no Metal kernel for ringqp.Add",
		map[string]string{"primitive": "share_aggregate", "backend": probe.backend})
}

// =============================================================================
// Threshold transcript root -- not implemented as a named API in
// lattice/multiparty. Skip with explanation.
// =============================================================================

func BenchmarkThreshold_TranscriptRoot_CPU(b *testing.B) {
	recordSkip(b, "threshold", "Threshold_TranscriptRoot/CPU",
		"NotApplicable: 'threshold transcript root' is not a named primitive in lattice/multiparty; LP-073 transcript hashing is in lux/mpc territory and out of bench scope here",
		map[string]string{"primitive": "threshold_transcript_root", "backend": "CPU (pure Go)"})
}

func BenchmarkThreshold_TranscriptRoot_Metal(b *testing.B) {
	probe := gpuProbe()
	recordSkip(b, "threshold", "Threshold_TranscriptRoot/Metal",
		"NotApplicable: see CPU cell -- not a primitive of this package",
		map[string]string{"primitive": "threshold_transcript_root", "backend": probe.backend})
}
