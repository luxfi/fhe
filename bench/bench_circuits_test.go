// Copyright (c) 2026, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

// bench_circuits_test.go covers production-relevant circuits:
//
//   - Boolean gate (single AND)
//   - 8-bit compare
//   - 16-bit compare
//   - private balance >= threshold (the production hot-path)
//   - private order eligibility predicate
//   - private auction predicate
//
// Per FHE-GPU spec section 19D: end-to-end latency + correctness verified
// vs plaintext semantics.
//
// Each circuit runs once and asserts the decrypted output matches what
// the plaintext computation would produce. Failure to match is a fatal
// b.Fatalf -- a benchmark of an incorrect circuit is not data, it is
// noise.
//
// All circuits run on PN10QP27 (the test-default param set). Per
// fhe/policy/PERFORMANCE.md G5 the FheUint32+ widths exhaust the noise
// budget on PN10QP27, so the eligibility predicate and auction predicate
// both run at FheUint16 -- enough headroom to verify correctness while
// matching the policy bench's accepted operating envelope. The balance
// hot-path runs at FheUint8 because that is what production policy
// rules actually use (balance buckets, not raw integer balances).

package bench

import (
	"runtime"
	"testing"
	"time"

	"github.com/luxfi/fhe"
)

// circuitsCtx is reused across circuits to avoid the multi-second
// keygen cost in every bench function.
type circuitsCtx struct {
	params fhe.Parameters
	bsk    *fhe.BootstrapKey
	enc    *fhe.BitwiseEncryptor
	dec    *fhe.BitwiseDecryptor
	eval   *fhe.BitwiseEvaluator
	bool_  *fhe.Evaluator
}

func newCircuitsCtx(b *testing.B) *circuitsCtx {
	b.Helper()
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		b.Fatalf("params: %v", err)
	}
	kg := fhe.NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)
	return &circuitsCtx{
		params: params,
		bsk:    bsk,
		enc:    fhe.NewBitwiseEncryptor(params, sk),
		dec:    fhe.NewBitwiseDecryptor(params, sk),
		eval:   fhe.NewBitwiseEvaluator(params, bsk, nil),
		bool_:  fhe.NewEvaluator(params, bsk),
	}
}

// runCircuit times one full circuit invocation b.N times and asserts
// correctness on the first call. The verification step runs outside
// the timing scope.
func runCircuit(b *testing.B, ladder, name string, params map[string]string, verify func() bool, op func()) {
	if !verify() {
		b.Fatalf("circuit %s: correctness check failed (decrypted output != plaintext semantics)", name)
	}

	for w := 0; w < 2; w++ {
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
	cell.Notes = "correctness verified against plaintext"
	Record(ladder, cell)
}

// =============================================================================
// Boolean gate (single AND)
// =============================================================================

func BenchmarkCircuit_BoolGate_CPU(b *testing.B) {
	ctx := newCircuitsCtx(b)
	a := ctx.enc.EncryptUint64(1, fhe.FheBool)
	c := ctx.enc.EncryptUint64(1, fhe.FheBool)

	verify := func() bool {
		out, err := ctx.eval.And(a, c)
		if err != nil {
			b.Fatalf("verify And: %v", err)
		}
		return ctx.dec.DecryptUint64(out) == 1
	}

	runCircuit(b, "circuits", "BoolGate/CPU",
		map[string]string{"circuit": "boolean_and", "backend": "CPU (pure Go)", "params": "PN10QP27"},
		verify,
		func() {
			_, err := ctx.eval.And(a, c)
			if err != nil {
				b.Fatalf("And: %v", err)
			}
		})
}

func BenchmarkCircuit_BoolGate_Metal(b *testing.B) {
	probe := gpuProbe()
	recordSkip(b, "circuits", "BoolGate/Metal",
		"NotApplicable: gate dispatch goes through Evaluator.bootstrap which has no GPU path (G3 blocker)",
		map[string]string{"circuit": "boolean_and", "backend": probe.backend})
}

// =============================================================================
// 8-bit compare
// =============================================================================

func BenchmarkCircuit_Compare8_CPU(b *testing.B) {
	ctx := newCircuitsCtx(b)
	a := ctx.enc.EncryptUint64(42, fhe.FheUint8)
	c := ctx.enc.EncryptUint64(100, fhe.FheUint8)

	verify := func() bool {
		out, err := ctx.eval.Lt(a, c)
		if err != nil {
			b.Fatalf("verify Lt: %v", err)
		}
		// 42 < 100 should be true.
		return decryptBool(ctx, out)
	}

	runCircuit(b, "circuits", "Compare8/CPU",
		map[string]string{"circuit": "lt_u8", "backend": "CPU (pure Go)", "params": "PN10QP27"},
		verify,
		func() {
			_, err := ctx.eval.Lt(a, c)
			if err != nil {
				b.Fatalf("Lt: %v", err)
			}
		})
}

func BenchmarkCircuit_Compare8_Metal(b *testing.B) {
	probe := gpuProbe()
	recordSkip(b, "circuits", "Compare8/Metal",
		"NotApplicable: Lt is a chain of bootstraps -- same G3 block",
		map[string]string{"circuit": "lt_u8", "backend": probe.backend})
}

// =============================================================================
// 16-bit compare
// =============================================================================

func BenchmarkCircuit_Compare16_CPU(b *testing.B) {
	ctx := newCircuitsCtx(b)
	a := ctx.enc.EncryptUint64(0x0042, fhe.FheUint16)
	c := ctx.enc.EncryptUint64(0x0100, fhe.FheUint16)

	verify := func() bool {
		out, err := ctx.eval.Lt(a, c)
		if err != nil {
			b.Fatalf("verify Lt: %v", err)
		}
		return decryptBool(ctx, out)
	}

	runCircuit(b, "circuits", "Compare16/CPU",
		map[string]string{"circuit": "lt_u16", "backend": "CPU (pure Go)", "params": "PN10QP27"},
		verify,
		func() {
			_, err := ctx.eval.Lt(a, c)
			if err != nil {
				b.Fatalf("Lt: %v", err)
			}
		})
}

func BenchmarkCircuit_Compare16_Metal(b *testing.B) {
	probe := gpuProbe()
	recordSkip(b, "circuits", "Compare16/Metal",
		"NotApplicable: Lt is a chain of bootstraps -- same G3 block",
		map[string]string{"circuit": "lt_u16", "backend": probe.backend})
}

// =============================================================================
// Private balance >= threshold (the production hot-path)
// =============================================================================
// Models the policy/eval Lt+And shape: balance >= threshold.

func BenchmarkCircuit_BalanceGE_CPU(b *testing.B) {
	ctx := newCircuitsCtx(b)
	balance := ctx.enc.EncryptUint64(150, fhe.FheUint8)
	threshold := ctx.enc.EncryptUint64(100, fhe.FheUint8)

	verify := func() bool {
		out, err := ctx.eval.Ge(balance, threshold)
		if err != nil {
			b.Fatalf("verify Ge: %v", err)
		}
		return decryptBool(ctx, out)
	}

	runCircuit(b, "circuits", "BalanceGE/CPU",
		map[string]string{"circuit": "balance_ge_u8", "backend": "CPU (pure Go)", "params": "PN10QP27"},
		verify,
		func() {
			_, err := ctx.eval.Ge(balance, threshold)
			if err != nil {
				b.Fatalf("Ge: %v", err)
			}
		})
}

func BenchmarkCircuit_BalanceGE_Metal(b *testing.B) {
	probe := gpuProbe()
	recordSkip(b, "circuits", "BalanceGE/Metal",
		"NotApplicable: Ge composed of Le+Not -- both bootstrap-bound, G3 block",
		map[string]string{"circuit": "balance_ge_u8", "backend": probe.backend})
}

// =============================================================================
// Private order eligibility predicate
// =============================================================================
// Models the dex/order ingress check: amount Lt limit AND velocity Lt
// cap. This matches the #114 single-policy bundle shape minus the
// allowlist OR fanout.

func BenchmarkCircuit_OrderEligibility_CPU(b *testing.B) {
	ctx := newCircuitsCtx(b)
	amount := ctx.enc.EncryptUint64(50, fhe.FheUint8)
	limit := ctx.enc.EncryptUint64(100, fhe.FheUint8)
	velocity := ctx.enc.EncryptUint64(3, fhe.FheUint8)
	cap := ctx.enc.EncryptUint64(10, fhe.FheUint8)

	verify := func() bool {
		amountOK, err := ctx.eval.Lt(amount, limit)
		if err != nil {
			b.Fatalf("verify Lt amount: %v", err)
		}
		velOK, err := ctx.eval.Lt(velocity, cap)
		if err != nil {
			b.Fatalf("verify Lt velocity: %v", err)
		}
		out, err := ctx.bool_.AND(amountOK, velOK)
		if err != nil {
			b.Fatalf("verify AND: %v", err)
		}
		return ctx.dec.DecryptUint64(fhe.WrapBoolCiphertext(out)) == 1
	}

	op := func() {
		amountOK, err := ctx.eval.Lt(amount, limit)
		if err != nil {
			b.Fatalf("Lt amount: %v", err)
		}
		velOK, err := ctx.eval.Lt(velocity, cap)
		if err != nil {
			b.Fatalf("Lt velocity: %v", err)
		}
		_, err = ctx.bool_.AND(amountOK, velOK)
		if err != nil {
			b.Fatalf("AND: %v", err)
		}
	}

	runCircuit(b, "circuits", "OrderEligibility/CPU",
		map[string]string{"circuit": "order_eligibility_u8", "backend": "CPU (pure Go)", "params": "PN10QP27", "shape": "Lt && Lt"},
		verify, op)
}

func BenchmarkCircuit_OrderEligibility_Metal(b *testing.B) {
	probe := gpuProbe()
	recordSkip(b, "circuits", "OrderEligibility/Metal",
		"NotApplicable: same G3 block",
		map[string]string{"circuit": "order_eligibility_u8", "backend": probe.backend})
}

// =============================================================================
// Private auction predicate
// =============================================================================
// Models a sealed-bid second-price clear: bid Ge reservePrice AND bid Le maxBid.
// Two Compare gates + one AND.

func BenchmarkCircuit_AuctionPredicate_CPU(b *testing.B) {
	ctx := newCircuitsCtx(b)
	bid := ctx.enc.EncryptUint64(75, fhe.FheUint8)
	reserve := ctx.enc.EncryptUint64(50, fhe.FheUint8)
	cap := ctx.enc.EncryptUint64(100, fhe.FheUint8)

	verify := func() bool {
		geRes, err := ctx.eval.Ge(bid, reserve)
		if err != nil {
			b.Fatalf("verify Ge: %v", err)
		}
		leCap, err := ctx.eval.Le(bid, cap)
		if err != nil {
			b.Fatalf("verify Le: %v", err)
		}
		out, err := ctx.bool_.AND(geRes, leCap)
		if err != nil {
			b.Fatalf("verify AND: %v", err)
		}
		return ctx.dec.DecryptUint64(fhe.WrapBoolCiphertext(out)) == 1
	}

	op := func() {
		geRes, err := ctx.eval.Ge(bid, reserve)
		if err != nil {
			b.Fatalf("Ge: %v", err)
		}
		leCap, err := ctx.eval.Le(bid, cap)
		if err != nil {
			b.Fatalf("Le: %v", err)
		}
		_, err = ctx.bool_.AND(geRes, leCap)
		if err != nil {
			b.Fatalf("AND: %v", err)
		}
	}

	runCircuit(b, "circuits", "AuctionPredicate/CPU",
		map[string]string{"circuit": "auction_predicate_u8", "backend": "CPU (pure Go)", "params": "PN10QP27", "shape": "Ge && Le"},
		verify, op)
}

func BenchmarkCircuit_AuctionPredicate_Metal(b *testing.B) {
	probe := gpuProbe()
	recordSkip(b, "circuits", "AuctionPredicate/Metal",
		"NotApplicable: same G3 block",
		map[string]string{"circuit": "auction_predicate_u8", "backend": probe.backend})
}

// decryptBool decrypts a single-bit ciphertext returned by Lt/Eq/Ge/Le.
// These return *fhe.Ciphertext (not BitCiphertext); we wrap and use the
// bitwise decryptor.
func decryptBool(ctx *circuitsCtx, ct *fhe.Ciphertext) bool {
	return ctx.dec.DecryptUint64(fhe.WrapBoolCiphertext(ct)) == 1
}
