// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package fhe

import (
	"testing"
)

// TestLazyCarryConfig verifies configuration defaults.
func TestLazyCarryConfig(t *testing.T) {
	config := DefaultLazyCarryConfig()

	if config.MaxOpsBeforePropagate <= 0 {
		t.Errorf("MaxOpsBeforePropagate should be positive, got %d", config.MaxOpsBeforePropagate)
	}
	if config.OverflowMargin <= 0 {
		t.Errorf("OverflowMargin should be positive, got %d", config.OverflowMargin)
	}
	if !config.PropagateOnCompare {
		t.Error("PropagateOnCompare should be true by default")
	}
}

// TestEVMLazyCarryConfig verifies EVM-specific configuration.
func TestEVMLazyCarryConfig(t *testing.T) {
	config := EVMLazyCarryConfig()

	// EVM config should allow more operations before propagation
	if config.MaxOpsBeforePropagate < 8 {
		t.Errorf("EVM MaxOpsBeforePropagate should be >= 8 for efficiency, got %d",
			config.MaxOpsBeforePropagate)
	}
	if config.MaxOpsBeforePropagate > 32 {
		t.Errorf("EVM MaxOpsBeforePropagate should be <= 32 to avoid overflow, got %d",
			config.MaxOpsBeforePropagate)
	}
}

// setupTest creates the necessary FHE components for testing.
func setupTest(t *testing.T) (Parameters, *SecretKey, *BootstrapKey, *BitwiseEncryptor, *BitwiseDecryptor, *BitwiseEvaluator) {
	t.Helper()

	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	enc := NewBitwiseEncryptor(params, sk)
	dec := NewBitwiseDecryptor(params, sk)
	eval := NewBitwiseEvaluator(params, bsk, nil)

	return params, sk, bsk, enc, dec, eval
}

// TestLazyCarryAddBasic tests basic lazy addition semantics.
func TestLazyCarryAddBasic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping FHE test in short mode")
	}

	_, _, _, enc, dec, eval := setupTest(t)

	config := LazyCarryConfig{
		MaxOpsBeforePropagate: 16,
		OverflowMargin:        1 << 16,
		PropagateOnCompare:    true,
	}
	lce := NewLazyCarryEvaluator(eval, config)

	// Test: 5 + 3 = 8
	a := enc.EncryptUint64(5, FheUint8)
	b := enc.EncryptUint64(3, FheUint8)

	lazyA, err := lce.FromBitCiphertext(a)
	if err != nil {
		t.Fatalf("FromBitCiphertext(a): %v", err)
	}
	lazyB, err := lce.FromBitCiphertext(b)
	if err != nil {
		t.Fatalf("FromBitCiphertext(b): %v", err)
	}

	sum, err := lce.Add(lazyA, lazyB)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Before propagation, OpsWithoutPropagate should be 1
	if sum.OpsWithoutPropagate != 1 {
		t.Errorf("expected OpsWithoutPropagate=1, got %d", sum.OpsWithoutPropagate)
	}

	// Convert back and decrypt
	result, err := lce.ToBitCiphertext(sum)
	if err != nil {
		t.Fatalf("ToBitCiphertext: %v", err)
	}

	decrypted := dec.DecryptUint64(result)
	if decrypted != 8 {
		t.Errorf("expected 5 + 3 = 8, got %d", decrypted)
	}
}

// TestLazyCarryMultipleAdds tests accumulation of multiple additions.
func TestLazyCarryMultipleAdds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping FHE test in short mode")
	}

	_, _, _, enc, dec, eval := setupTest(t)

	config := LazyCarryConfig{
		MaxOpsBeforePropagate: 16, // Won't trigger for 8 adds
		OverflowMargin:        1 << 16,
		PropagateOnCompare:    true,
	}
	lce := NewLazyCarryEvaluator(eval, config)

	// Sum 1 + 2 + 3 + 4 + 5 + 6 + 7 + 8 = 36
	values := []uint64{1, 2, 3, 4, 5, 6, 7, 8}
	expected := uint64(36)

	// Encrypt all values
	lazyValues := make([]*LazyCarryInteger, len(values))
	for i, v := range values {
		ct := enc.EncryptUint64(v, FheUint8)
		lazy, err := lce.FromBitCiphertext(ct)
		if err != nil {
			t.Fatalf("FromBitCiphertext(%d): %v", v, err)
		}
		lazyValues[i] = lazy
	}

	// Accumulate
	sum := lazyValues[0]
	for i := 1; i < len(lazyValues); i++ {
		var err error
		sum, err = lce.Add(sum, lazyValues[i])
		if err != nil {
			t.Fatalf("Add %d: %v", i, err)
		}
	}

	// Verify OpsWithoutPropagate increased
	if sum.OpsWithoutPropagate < len(values)-1 {
		t.Errorf("OpsWithoutPropagate should be >= %d, got %d",
			len(values)-1, sum.OpsWithoutPropagate)
	}

	// Convert and decrypt
	result, err := lce.ToBitCiphertext(sum)
	if err != nil {
		t.Fatalf("ToBitCiphertext: %v", err)
	}

	decrypted := dec.DecryptUint64(result)
	if decrypted != expected {
		t.Errorf("expected sum = %d, got %d", expected, decrypted)
	}
}

// TestLazyCarryPropagationTrigger tests automatic propagation.
func TestLazyCarryPropagationTrigger(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping FHE test in short mode")
	}

	_, _, _, enc, dec, eval := setupTest(t)

	config := LazyCarryConfig{
		MaxOpsBeforePropagate: 4, // Low threshold for testing
		OverflowMargin:        1 << 16,
		PropagateOnCompare:    true,
	}
	lce := NewLazyCarryEvaluator(eval, config)

	// Create initial value
	ct := enc.EncryptUint64(10, FheUint8)
	lazy, err := lce.FromBitCiphertext(ct)
	if err != nil {
		t.Fatalf("FromBitCiphertext: %v", err)
	}

	// Add one value to itself repeatedly
	one := enc.EncryptUint64(1, FheUint8)
	lazyOne, err := lce.FromBitCiphertext(one)
	if err != nil {
		t.Fatalf("FromBitCiphertext(1): %v", err)
	}

	// Perform 5 additions (should trigger propagation at 4)
	sum := lazy
	for i := 0; i < 5; i++ {
		sum, err = lce.Add(sum, lazyOne)
		if err != nil {
			t.Fatalf("Add %d: %v", i, err)
		}
	}

	// After propagation trigger, OpsWithoutPropagate should be low
	// (since propagation was triggered internally)
	// Note: exact value depends on when propagation occurred
	t.Logf("OpsWithoutPropagate after 5 adds: %d", sum.OpsWithoutPropagate)

	// Verify correctness: 10 + 5 = 15
	result, err := lce.ToBitCiphertext(sum)
	if err != nil {
		t.Fatalf("ToBitCiphertext: %v", err)
	}

	decrypted := dec.DecryptUint64(result)
	if decrypted != 15 {
		t.Errorf("expected 10 + 5 = 15, got %d", decrypted)
	}
}

// TestLazyCarryScalarAdd tests scalar addition.
func TestLazyCarryScalarAdd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping FHE test in short mode")
	}

	_, _, _, enc, dec, eval := setupTest(t)

	config := DefaultLazyCarryConfig()
	lce := NewLazyCarryEvaluator(eval, config)

	// Test: 100 + 55 = 155
	ct := enc.EncryptUint64(100, FheUint8)
	lazy, err := lce.FromBitCiphertext(ct)
	if err != nil {
		t.Fatalf("FromBitCiphertext: %v", err)
	}

	sum, err := lce.ScalarAdd(lazy, 55)
	if err != nil {
		t.Fatalf("ScalarAdd: %v", err)
	}

	result, err := lce.ToBitCiphertext(sum)
	if err != nil {
		t.Fatalf("ToBitCiphertext: %v", err)
	}

	decrypted := dec.DecryptUint64(result)
	if decrypted != 155 {
		t.Errorf("expected 100 + 55 = 155, got %d", decrypted)
	}
}

// TestLazyCarryComparison tests comparison operations.
func TestLazyCarryComparison(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping FHE test in short mode")
	}

	_, _, _, enc, dec, eval := setupTest(t)

	config := DefaultLazyCarryConfig()
	lce := NewLazyCarryEvaluator(eval, config)

	// Test equality after additions
	ct10 := enc.EncryptUint64(10, FheUint8)
	ct5 := enc.EncryptUint64(5, FheUint8)

	lazy10, _ := lce.FromBitCiphertext(ct10)
	lazy5, _ := lce.FromBitCiphertext(ct5)

	// 5 + 5 should equal 10
	sum, err := lce.Add(lazy5, lazy5)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	eq, err := lce.Eq(sum, lazy10)
	if err != nil {
		t.Fatalf("Eq: %v", err)
	}

	if !dec.dec.Decrypt(eq) {
		t.Error("expected 5 + 5 == 10 to be true")
	}

	// 5 < 10 should be true
	lt, err := lce.Lt(lazy5, lazy10)
	if err != nil {
		t.Fatalf("Lt: %v", err)
	}

	if !dec.dec.Decrypt(lt) {
		t.Error("expected 5 < 10 to be true")
	}
}

// TestLazyCarryBatchAdd tests batch addition optimization.
func TestLazyCarryBatchAdd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping FHE test in short mode")
	}

	_, _, _, enc, dec, eval := setupTest(t)

	config := DefaultLazyCarryConfig()
	lce := NewLazyCarryEvaluator(eval, config)

	// Batch sum of 1..10 = 55
	values := make([]*LazyCarryInteger, 10)
	for i := 0; i < 10; i++ {
		ct := enc.EncryptUint64(uint64(i+1), FheUint8)
		lazy, err := lce.FromBitCiphertext(ct)
		if err != nil {
			t.Fatalf("FromBitCiphertext(%d): %v", i+1, err)
		}
		values[i] = lazy
	}

	sum, err := lce.BatchAdd(values)
	if err != nil {
		t.Fatalf("BatchAdd: %v", err)
	}

	// BatchAdd should propagate at the end
	if sum.OpsWithoutPropagate != 0 {
		t.Errorf("BatchAdd should propagate, got OpsWithoutPropagate=%d",
			sum.OpsWithoutPropagate)
	}

	result, err := lce.ToBitCiphertext(sum)
	if err != nil {
		t.Fatalf("ToBitCiphertext: %v", err)
	}

	decrypted := dec.DecryptUint64(result)
	if decrypted != 55 {
		t.Errorf("expected sum(1..10) = 55, got %d", decrypted)
	}
}

// TestLazyCarryMetrics tests performance metrics tracking.
func TestLazyCarryMetrics(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping FHE test in short mode")
	}

	_, _, _, enc, _, eval := setupTest(t)

	config := LazyCarryConfig{
		MaxOpsBeforePropagate: 16, // High to avoid auto-propagation
		OverflowMargin:        1 << 16,
		PropagateOnCompare:    true,
	}
	lce := NewLazyCarryEvaluator(eval, config)

	// Perform 8 additions
	ct := enc.EncryptUint64(1, FheUint8)
	lazy, _ := lce.FromBitCiphertext(ct)

	sum := lazy
	for i := 0; i < 7; i++ {
		sum, _ = lce.Add(sum, lazy)
	}

	metrics := sum.GetMetrics()

	t.Logf("Metrics after 8 additions:")
	t.Logf("  TotalAdditions: %d", metrics.TotalAdditions)
	t.Logf("  PBS Operations (lazy): %d", metrics.PBSOperations)
	t.Logf("  PBS Operations (traditional): %d", metrics.TraditionalPBSEstimate)
	t.Logf("  Amortization Ratio: %.2f", metrics.AmortizationRatio)

	// Verify lazy approach uses fewer PBS
	if metrics.AmortizationRatio >= 1.0 && metrics.TotalAdditions > 1 {
		t.Error("lazy carry should have better amortization than traditional")
	}
}

// TestLazyCarryZero tests zero initialization.
func TestLazyCarryZero(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping FHE test in short mode")
	}

	_, _, _, _, dec, eval := setupTest(t)

	config := DefaultLazyCarryConfig()
	lce := NewLazyCarryEvaluator(eval, config)

	zero, err := lce.Zero(FheUint8)
	if err != nil {
		t.Fatalf("Zero: %v", err)
	}

	result, err := lce.ToBitCiphertext(zero)
	if err != nil {
		t.Fatalf("ToBitCiphertext: %v", err)
	}

	decrypted := dec.DecryptUint64(result)
	if decrypted != 0 {
		t.Errorf("expected 0, got %d", decrypted)
	}
}

// BenchmarkLazyCarryAdd benchmarks lazy addition.
func BenchmarkLazyCarryAdd(b *testing.B) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		b.Fatalf("NewParametersFromLiteral: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)
	enc := NewBitwiseEncryptor(params, sk)
	eval := NewBitwiseEvaluator(params, bsk, nil)

	config := DefaultLazyCarryConfig()
	lce := NewLazyCarryEvaluator(eval, config)

	ct := enc.EncryptUint64(42, FheUint8)
	lazy, _ := lce.FromBitCiphertext(ct)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = lce.Add(lazy, lazy)
	}
}

// BenchmarkLazyCarryPropagate benchmarks carry propagation.
func BenchmarkLazyCarryPropagate(b *testing.B) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		b.Fatalf("NewParametersFromLiteral: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)
	enc := NewBitwiseEncryptor(params, sk)
	eval := NewBitwiseEvaluator(params, bsk, nil)

	config := LazyCarryConfig{
		MaxOpsBeforePropagate: 100, // Prevent auto-propagation
		OverflowMargin:        1 << 16,
		PropagateOnCompare:    true,
	}
	lce := NewLazyCarryEvaluator(eval, config)

	ct := enc.EncryptUint64(1, FheUint8)
	lazy, _ := lce.FromBitCiphertext(ct)

	// Accumulate some operations
	sum := lazy
	for i := 0; i < 8; i++ {
		sum, _ = lce.Add(sum, lazy)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = lce.Propagate(sum)
	}
}

// BenchmarkTraditionalAdd benchmarks traditional addition for comparison.
func BenchmarkTraditionalAdd(b *testing.B) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		b.Fatalf("NewParametersFromLiteral: %v", err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)
	enc := NewBitwiseEncryptor(params, sk)
	eval := NewBitwiseEvaluator(params, bsk, nil)

	ct := enc.EncryptUint64(42, FheUint8)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = eval.Add(ct, ct)
	}
}
