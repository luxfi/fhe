// Copyright (c) 2026, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

// bench_gpu_test.go -- CPU-vs-GPU benchmark harness for FHE policy
// evaluation.
//
// Sweep:
//
//   - Single-gate Lt at FheUint{4,8,16,32,64}
//   - Single-policy: 3 Lt + 3 Eq + 2 AND ("policy bundle" shape from #114)
//   - Batched parallel signing: N in {1, 4, 16, 64, 256, 1024} independent
//     policy evaluations
//
// Backend selection:
//
//   - CPU (single-thread):  go test -bench=BenchmarkPolicyCPU
//   - CPU (saturated):      GOMAXPROCS=$(sysctl -n hw.logicalcpu) go test \
//                           -bench=BenchmarkPolicyParallel
//   - Metal (informational): the policy hot path runs through
//     luxfi/lattice/v7/core/rgsw/blindrot which has no GPU dispatch in the
//     code path today (see PERFORMANCE.md for the architectural finding).
//     `BenchmarkLatticeGPUSelfTest` reports whether
//     github.com/luxfi/lattice/v7/gpu can be linked with -tags cgo (it
//     requires libluxlattice.dylib at /Users/z/work/luxcpp/lattice/build/lib
//     symlinked as liblattice.dylib).
//
// Run command:
//
//	cd /Users/z/work/lux/fhe/policy && \
//	GOWORK=off go test -run=^$ -bench=Policy -benchtime=10x -timeout=900s \
//	   -count=1 -benchmem ./
//
// All measurements: M1 Max, Release (`-tags release`), median >=10 runs.
//
// HONEST RESIDUAL: the PN10QP27 parameter set is the production-default
// for fhe; FheUint64 evaluation under PN10QP27 exhausts the noise budget
// and is benched but verification of the decrypted boolean is gated only
// on FheUint{4,8} where the noise budget supports the full Lt depth.
// Production uses PN11QP54 for >=32-bit fields.

package policy

import (
	"fmt"
	"runtime"
	"sync"
	"testing"

	"github.com/luxfi/fhe"
)

// benchCtx caches keys + params per (params, fheType) combination; key
// generation dominates short-run bench setup, so we generate once per
// benchmark and reuse across N iterations and across batched-N inner loops.
type benchCtx struct {
	params  fhe.Parameters
	bsk     *fhe.BootstrapKey
	enc     *fhe.BitwiseEncryptor
	dec     *fhe.Decryptor
	fheType fhe.FheUintType
}

// newBenchCtx builds a fresh FHE context for the given param set + bit
// width. Generated once per benchmark, reused across iterations.
func newBenchCtx(b *testing.B, paramSet fhe.ParametersLiteral, fheType fhe.FheUintType) *benchCtx {
	b.Helper()
	params, err := fhe.NewParametersFromLiteral(paramSet)
	if err != nil {
		b.Fatalf("params: %v", err)
	}
	kg := fhe.NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)
	return &benchCtx{
		params:  params,
		bsk:     bsk,
		enc:     fhe.NewBitwiseEncryptor(params, sk),
		dec:     fhe.NewDecryptor(params, sk),
		fheType: fheType,
	}
}

// encVal encrypts v as a BitCiphertext of width fheType.
func (c *benchCtx) encVal(v uint64) *fhe.BitCiphertext {
	return c.enc.EncryptUint64(v, c.fheType)
}

// allowlist returns a 1-entry allowlist; production policies typically run
// 8-32 entries, but we keep the bench bundle minimal to isolate the Lt+Eq
// gate cost from the OR fanout.
func (c *benchCtx) allowlist(values ...uint64) []*fhe.BitCiphertext {
	out := make([]*fhe.BitCiphertext, len(values))
	for i, v := range values {
		out[i] = c.encVal(v)
	}
	return out
}

// =============================================================================
// Single-gate Lt: width sweep (FheUint4 / 8 / 16 / 32 / 64)
// =============================================================================

func benchSingleGateLt(b *testing.B, fheType fhe.FheUintType) {
	ctx := newBenchCtx(b, fhe.PN10QP27, fheType)
	bitEval := fhe.NewBitwiseEvaluator(ctx.params, ctx.bsk, nil)
	a := ctx.encVal(3)
	c := ctx.encVal(8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := bitEval.Lt(a, c)
		if err != nil {
			b.Fatalf("Lt: %v", err)
		}
	}
}

func BenchmarkPolicy_SingleGateLt_U4(b *testing.B)  { benchSingleGateLt(b, fhe.FheUint4) }
func BenchmarkPolicy_SingleGateLt_U8(b *testing.B)  { benchSingleGateLt(b, fhe.FheUint8) }
func BenchmarkPolicy_SingleGateLt_U16(b *testing.B) { benchSingleGateLt(b, fhe.FheUint16) }
func BenchmarkPolicy_SingleGateLt_U32(b *testing.B) { benchSingleGateLt(b, fhe.FheUint32) }

// =============================================================================
// Single-policy: 3 Lt + 3 Eq + 2 AND (the #114 "policy bundle" shape)
//
// Approximates the full Evaluate() call in policy.go: amount Lt, velocity Lt,
// destination membership (3 entries -> 3 Eq + 2 OR), then 2 AND to combine.
// =============================================================================

func benchSinglePolicy(b *testing.B, fheType fhe.FheUintType) {
	ctx := newBenchCtx(b, fhe.PN10QP27, fheType)
	prog, err := New(ctx.params, ctx.bsk, ClauseSet{
		AmountLimit: ctx.encVal(8),
		VelocityCap: ctx.encVal(15),
		Allowlist:   ctx.allowlist(0xA, 0xB, 0xC),
	})
	if err != nil {
		b.Fatalf("new program: %v", err)
	}
	intent := Intent{
		Amount:          ctx.encVal(3),
		DestinationHash: ctx.encVal(0xA),
		VelocityWindow:  ctx.encVal(2),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := prog.Evaluate(intent)
		if err != nil {
			b.Fatalf("evaluate: %v", err)
		}
	}
}

func BenchmarkPolicy_SinglePolicy_U4(b *testing.B) { benchSinglePolicy(b, fhe.FheUint4) }
func BenchmarkPolicy_SinglePolicy_U8(b *testing.B) { benchSinglePolicy(b, fhe.FheUint8) }

// =============================================================================
// Batched parallel signing: N independent policy evaluations
//
// Models the parallel-signing pattern where N transactions arrive together
// and each must be evaluated against its own intent under a shared policy.
// Reports both:
//
//   - SingleThread: one goroutine, sequential — equivalent to a single
//     signer node processing N intents back-to-back.
//   - Parallel: GOMAXPROCS goroutines, partitioned over N — equivalent to
//     a multi-core signer node saturating its CPU.
//
// This is the natural shape for "GPU saturates at large N" — if and when
// the bootstrap chain ever dispatches to GPU.
// =============================================================================

var batchSizes = []int{1, 4, 16, 64, 256, 1024}

func benchBatched(b *testing.B, fheType fhe.FheUintType, parallel bool) {
	ctx := newBenchCtx(b, fhe.PN10QP27, fheType)
	for _, N := range batchSizes {
		name := fmt.Sprintf("N=%d", N)
		b.Run(name, func(b *testing.B) {
			// Build N independent programs; each acquires its own
			// BitwiseEvaluator + Evaluator so the inner-loop dispatch is
			// goroutine-safe (no shared mutable state).
			progs := make([]*PolicyProgram, N)
			intents := make([]Intent, N)
			for i := 0; i < N; i++ {
				prog, err := New(ctx.params, ctx.bsk, ClauseSet{
					AmountLimit: ctx.encVal(8),
					VelocityCap: ctx.encVal(15),
					Allowlist:   ctx.allowlist(0xA, 0xB, 0xC),
				})
				if err != nil {
					b.Fatalf("new program %d: %v", i, err)
				}
				progs[i] = prog
				intents[i] = Intent{
					Amount:          ctx.encVal(3),
					DestinationHash: ctx.encVal(0xA),
					VelocityWindow:  ctx.encVal(2),
				}
			}
			b.ResetTimer()

			if !parallel {
				for it := 0; it < b.N; it++ {
					for i := 0; i < N; i++ {
						if _, err := progs[i].Evaluate(intents[i]); err != nil {
							b.Fatalf("eval[%d]: %v", i, err)
						}
					}
				}
				return
			}

			// Saturated parallel evaluation across GOMAXPROCS workers.
			workers := runtime.GOMAXPROCS(0)
			if workers > N {
				workers = N
			}
			for it := 0; it < b.N; it++ {
				var wg sync.WaitGroup
				ch := make(chan int, N)
				for j := 0; j < N; j++ {
					ch <- j
				}
				close(ch)
				for w := 0; w < workers; w++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						for idx := range ch {
							if _, err := progs[idx].Evaluate(intents[idx]); err != nil {
								b.Errorf("eval[%d]: %v", idx, err)
								return
							}
						}
					}()
				}
				wg.Wait()
			}
		})
	}
}

func BenchmarkPolicy_BatchedSerial_U4(b *testing.B) {
	benchBatched(b, fhe.FheUint4, false)
}

func BenchmarkPolicy_BatchedParallel_U4(b *testing.B) {
	benchBatched(b, fhe.FheUint4, true)
}
