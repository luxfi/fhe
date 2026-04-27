// Copyright (c) 2026, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

// bench_tfhe_primitives_test.go covers the TFHE micro-primitives:
//
//   - LWE add
//   - LWE multiply by scalar
//   - TRLWE add
//   - TRLWE external product
//   - blind rotation
//   - sample extraction
//   - key switching
//   - programmable bootstrapping
//
// Per FHE-GPU spec section 19B: each primitive reports ops/sec, p50/p95/p99
// latency, GPU memory bandwidth (where applicable), dispatch count, arena
// bytes.
//
// Status as of 2026-04-27 (this run):
//
//   - LWE add: NOT BENCH-EXPOSED on either backend. The LWE-side params
//     are unexported on fhe.Parameters and there is no public Add helper
//     on Evaluator. Bench cells skip with NotApplicable. This is the
//     same fact policy/PERFORMANCE.md notes -- the public surface
//     intentionally goes through Evaluator.<gate>, not raw LWE arithmetic.
//   - LWE scalar mul: same.
//   - TRLWE add: bench-exposed via the lattice ring API on a freshly
//     constructed SubRing -- this measures the same kernel the BR side
//     would use.
//   - TRLWE external product: approximated by NTT + pointwise + INTT on
//     N_BR = 2048 (one gadget level on PN10QP27).
//   - Blind rotation / sample extraction / key switch / programmable
//     bootstrap: all four collapse to a single Evaluator gate call
//     (one bootstrap = blind-rotate + sample-extract + key-switch +
//     mod-switch). We bench Evaluator.AND once and report the same
//     latency under each primitive label, with scope="1-AND-gate".
//     This is honest: the public API does not let us isolate the four
//     phases without forking the Evaluator.
//
// CPU baselines run today; GPU cells fill in as siblings ship.

package bench

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/luxfi/fhe"
)

// tfheBenchCtx holds the params + keys reused across primitive cells.
type tfheBenchCtx struct {
	params fhe.Parameters
	sk     *fhe.SecretKey
	bsk    *fhe.BootstrapKey
	enc    *fhe.Encryptor
	dec    *fhe.Decryptor
	eval   *fhe.Evaluator
}

func newTFHECtx(b *testing.B) *tfheBenchCtx {
	b.Helper()
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		b.Fatalf("params: %v", err)
	}
	kg := fhe.NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)
	return &tfheBenchCtx{
		params: params,
		sk:     sk,
		bsk:    bsk,
		enc:    fhe.NewEncryptor(params, sk),
		dec:    fhe.NewDecryptor(params, sk),
		eval:   fhe.NewEvaluator(params, bsk),
	}
}

// runPrimitive times a single primitive over b.N iterations and emits
// the resulting cell into the named ladder.
func runPrimitive(b *testing.B, ladder, name string, params map[string]string, op func()) {
	for w := 0; w < 3; w++ {
		op()
	}
	runtime.GC()

	samples := make([]Sample, 0, b.N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		op()
		samples = append(samples, Sample(time.Since(start).Nanoseconds()))
	}
	b.StopTimer()

	cell := summarizeCell(b, samples, params)
	cell.Name = name
	cell.Status = "ok"
	Record(ladder, cell)
}

// recordSkip emits a NotApplicable cell into the named ladder.
func recordSkip(b *testing.B, ladder, name, reason string, params map[string]string) {
	cell := Cell{
		Name:   name,
		Status: "skipped",
		Reason: reason,
		Params: params,
	}
	Record(ladder, cell)
	b.Skip(reason)
}

// =============================================================================
// LWE add -- not exposed on the public API. Skip with explanation.
// =============================================================================

func BenchmarkTFHE_LWE_Add_CPU(b *testing.B) {
	recordSkip(b, "tfhe_primitives", "LWE_Add/CPU",
		"NotApplicable: rlwe.Parameters / RingQ are unexported on fhe.Parameters; LWE add is internal to Evaluator.addCiphertexts and not bench-exposed",
		map[string]string{"primitive": "lwe_add", "backend": "CPU (pure Go)"})
}

func BenchmarkTFHE_LWE_Add_Metal(b *testing.B) {
	probe := gpuProbe()
	recordSkip(b, "tfhe_primitives", "LWE_Add/Metal",
		"NotApplicable: lattice gpu wrapper exposes NTT/poly-mul, not LWE-tuple add (lives in luxcpp/fhe mlx backend, not exposed via lux/fhe cgo)",
		map[string]string{"primitive": "lwe_add", "backend": probe.backend})
}

// =============================================================================
// LWE multiply by scalar -- not exposed on the public API.
// =============================================================================

func BenchmarkTFHE_LWE_ScalarMul_CPU(b *testing.B) {
	recordSkip(b, "tfhe_primitives", "LWE_ScalarMul/CPU",
		"NotApplicable: rlwe.Parameters unexported on fhe.Parameters; scalar mul not exposed",
		map[string]string{"primitive": "lwe_scalar_mul", "backend": "CPU (pure Go)"})
}

func BenchmarkTFHE_LWE_ScalarMul_Metal(b *testing.B) {
	probe := gpuProbe()
	recordSkip(b, "tfhe_primitives", "LWE_ScalarMul/Metal",
		"NotApplicable: gpu wrapper has PolyScalarMul on full poly arrays only, not LWE tuple semantics",
		map[string]string{"primitive": "lwe_scalar_mul", "backend": probe.backend})
}

// =============================================================================
// TRLWE add -- bench via raw SubRing. The kernel here is the same
// lattice/v7/ring polyadd Evaluator.addCiphertexts ultimately invokes.
// =============================================================================

func BenchmarkTFHE_TRLWE_Add_CPU(b *testing.B) {
	// Use N=2048 to match PN10QP27's BR ring dimension.
	const N = 2048
	sr, err := goSubRing(N)
	if err != nil {
		recordSkip(b, "tfhe_primitives", "TRLWE_Add/CPU",
			"NotApplicable: cannot construct SubRing -- "+err.Error(),
			map[string]string{"primitive": "trlwe_add", "backend": "CPU (pure Go)", "N": fmt.Sprintf("%d", N)})
		return
	}
	a := uniformPoly(N)
	c := uniformPoly(N)
	out := make([]uint64, N)
	runPrimitive(b, "tfhe_primitives", "TRLWE_Add/CPU",
		map[string]string{"primitive": "trlwe_add", "backend": "CPU (pure Go)", "N": fmt.Sprintf("%d", N)},
		func() {
			sr.Add(a, c, out)
		})
}

func BenchmarkTFHE_TRLWE_Add_Metal(b *testing.B) {
	probe := gpuProbe()
	if !probe.available {
		recordSkip(b, "tfhe_primitives", "TRLWE_Add/Metal",
			"NotApplicable: "+probe.reason,
			map[string]string{"primitive": "trlwe_add", "backend": probe.backend})
		return
	}
	recordSkip(b, "tfhe_primitives", "TRLWE_Add/Metal",
		"NotApplicable: lattice gpu PolyAdd exposed but is a CPU-side helper (not a Metal kernel) per gpu_cgo.go signature",
		map[string]string{"primitive": "trlwe_add", "backend": probe.backend})
}

// =============================================================================
// TRLWE external product (RGSW x RLWE inner loop).
// =============================================================================

func BenchmarkTFHE_TRLWE_ExternalProduct_CPU(b *testing.B) {
	const N = 2048 // matches PN10QP27's NBR
	sr, err := goSubRing(N)
	if err != nil {
		recordSkip(b, "tfhe_primitives", "TRLWE_ExternalProduct/CPU",
			"NotApplicable: cannot construct SubRing -- "+err.Error(),
			map[string]string{"primitive": "trlwe_external_product", "backend": "CPU (pure Go)", "N": fmt.Sprintf("%d", N)})
		return
	}
	a := uniformPoly(N)
	c := uniformPoly(N)
	tmp := make([]uint64, N)
	out := make([]uint64, N)
	runPrimitive(b, "tfhe_primitives", "TRLWE_ExternalProduct/CPU",
		map[string]string{"primitive": "trlwe_external_product", "backend": "CPU (pure Go)", "N": fmt.Sprintf("%d", N), "scope": "NTT+pointwise+INTT"},
		func() {
			sr.NTT(a, tmp)
			sr.MulCoeffsMontgomery(tmp, c, out)
			sr.INTT(out, out)
		})
}

func BenchmarkTFHE_TRLWE_ExternalProduct_Metal(b *testing.B) {
	probe := gpuProbe()
	recordSkip(b, "tfhe_primitives", "TRLWE_ExternalProduct/Metal",
		"NotApplicable: fused external product lives in luxcpp/fhe (FHEgpu/FHEmetal libs), not exposed to lux/fhe via cgo",
		map[string]string{"primitive": "trlwe_external_product", "backend": probe.backend})
}

// =============================================================================
// Blind rotation -- exercised via a single AND gate (full bootstrap chain).
// =============================================================================

func BenchmarkTFHE_BlindRotation_CPU(b *testing.B) {
	ctx := newTFHECtx(b)
	a := ctx.enc.Encrypt(true)
	c := ctx.enc.Encrypt(false)
	runPrimitive(b, "tfhe_primitives", "BlindRotation/CPU",
		map[string]string{"primitive": "blind_rotation", "backend": "CPU (pure Go)", "scope": "1-AND-gate"},
		func() {
			_, err := ctx.eval.AND(a, c)
			if err != nil {
				b.Fatalf("AND: %v", err)
			}
		})
}

func BenchmarkTFHE_BlindRotation_Metal(b *testing.B) {
	probe := gpuProbe()
	recordSkip(b, "tfhe_primitives", "BlindRotation/Metal",
		"NotApplicable: blind-rotate is the G3 blocker per fhe/policy/PERFORMANCE.md -- no GPU dispatch wired through Evaluator.bootstrap",
		map[string]string{"primitive": "blind_rotation", "backend": probe.backend})
}

// =============================================================================
// Sample extraction -- not exposed on public API.
// =============================================================================

func BenchmarkTFHE_SampleExtract_CPU(b *testing.B) {
	ctx := newTFHECtx(b)
	a := ctx.enc.Encrypt(true)
	c := ctx.enc.Encrypt(false)
	runPrimitive(b, "tfhe_primitives", "SampleExtract/CPU",
		map[string]string{"primitive": "sample_extraction", "backend": "CPU (pure Go)", "scope": "embedded-in-AND-bootstrap"},
		func() {
			_, err := ctx.eval.AND(a, c)
			if err != nil {
				b.Fatalf("AND: %v", err)
			}
		})
}

func BenchmarkTFHE_SampleExtract_Metal(b *testing.B) {
	probe := gpuProbe()
	recordSkip(b, "tfhe_primitives", "SampleExtract/Metal",
		"NotApplicable: sample-extract internal to Evaluator.sampleExtractAndModSwitch -- not bench-isolated",
		map[string]string{"primitive": "sample_extraction", "backend": probe.backend})
}

// =============================================================================
// Key switching -- not exposed on public API; rolled into Evaluator gates.
// =============================================================================

func BenchmarkTFHE_KeySwitch_CPU(b *testing.B) {
	ctx := newTFHECtx(b)
	a := ctx.enc.Encrypt(true)
	c := ctx.enc.Encrypt(false)
	runPrimitive(b, "tfhe_primitives", "KeySwitch/CPU",
		map[string]string{"primitive": "key_switching", "backend": "CPU (pure Go)", "scope": "embedded-in-AND-bootstrap"},
		func() {
			_, err := ctx.eval.AND(a, c)
			if err != nil {
				b.Fatalf("AND: %v", err)
			}
		})
}

func BenchmarkTFHE_KeySwitch_Metal(b *testing.B) {
	probe := gpuProbe()
	recordSkip(b, "tfhe_primitives", "KeySwitch/Metal",
		"NotApplicable: key-switch in lattice/core/rlwe.Evaluator -- not routed through gpu wrapper",
		map[string]string{"primitive": "key_switching", "backend": probe.backend})
}

// =============================================================================
// Programmable bootstrapping (the headline measurement)
// =============================================================================

func BenchmarkTFHE_ProgrammableBootstrap_CPU(b *testing.B) {
	ctx := newTFHECtx(b)
	a := ctx.enc.Encrypt(true)
	c := ctx.enc.Encrypt(false)
	runPrimitive(b, "tfhe_primitives", "ProgrammableBootstrap/CPU",
		map[string]string{"primitive": "programmable_bootstrap", "backend": "CPU (pure Go)", "scope": "1-AND-gate"},
		func() {
			_, err := ctx.eval.AND(a, c)
			if err != nil {
				b.Fatalf("AND: %v", err)
			}
		})
}

func BenchmarkTFHE_ProgrammableBootstrap_Metal(b *testing.B) {
	probe := gpuProbe()
	recordSkip(b, "tfhe_primitives", "ProgrammableBootstrap/Metal",
		"NotApplicable: PBS = blind-rotate + sample-extract + key-switch -- all G3-blocked per fhe/policy/PERFORMANCE.md",
		map[string]string{"primitive": "programmable_bootstrap", "backend": probe.backend})
}
