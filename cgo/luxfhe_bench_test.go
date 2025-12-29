// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024-2025, Lux Industries Inc
//
// Benchmarks for Lux FHE operations
// Tests GPU acceleration vs CPU baseline

//go:build cgo && luxfhe

package cgo

import (
	"fmt"
	"testing"
)

// =============================================================================
// Benchmark Setup
// =============================================================================

var (
	benchEngine *Engine
	benchParams *Params
	benchSK     *SecretKey
	benchPK     *PublicKey
	benchBSK    *BootstrapKey
	benchKSK    *KeySwitchKey
)

func setupBenchmark(b *testing.B) {
	if benchEngine != nil {
		return
	}

	var err error
	benchEngine, err = NewDefaultEngine()
	if err != nil {
		b.Fatalf("Failed to create engine: %v", err)
	}

	benchParams, err = NewParams(Security128, ModeUTXO64)
	if err != nil {
		b.Fatalf("Failed to create params: %v", err)
	}

	benchSK, err = benchEngine.GenerateSecretKey(benchParams)
	if err != nil {
		b.Fatalf("Failed to generate secret key: %v", err)
	}

	benchPK, err = benchEngine.GeneratePublicKey(benchParams, benchSK)
	if err != nil {
		b.Fatalf("Failed to generate public key: %v", err)
	}

	benchBSK, err = benchEngine.GenerateBootstrapKey(benchParams, benchSK)
	if err != nil {
		b.Fatalf("Failed to generate bootstrap key: %v", err)
	}

	benchKSK, err = benchEngine.GenerateKeySwitchKey(benchParams, benchSK)
	if err != nil {
		b.Fatalf("Failed to generate key switch key: %v", err)
	}
}

// =============================================================================
// Boolean Gate Benchmarks
// =============================================================================

func BenchmarkEncryptBit(b *testing.B) {
	setupBenchmark(b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ct, err := benchEngine.EncryptBit(benchSK, true)
		if err != nil {
			b.Fatal(err)
		}
		ct.Free()
	}
}

func BenchmarkDecryptBit(b *testing.B) {
	setupBenchmark(b)
	ct, _ := benchEngine.EncryptBit(benchSK, true)
	defer ct.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := benchEngine.DecryptBit(benchSK, ct)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAND(b *testing.B) {
	setupBenchmark(b)
	ct1, _ := benchEngine.EncryptBit(benchSK, true)
	ct2, _ := benchEngine.EncryptBit(benchSK, true)
	defer ct1.Free()
	defer ct2.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := benchEngine.And(benchBSK, ct1, ct2)
		if err != nil {
			b.Fatal(err)
		}
		result.Free()
	}
}

func BenchmarkOR(b *testing.B) {
	setupBenchmark(b)
	ct1, _ := benchEngine.EncryptBit(benchSK, true)
	ct2, _ := benchEngine.EncryptBit(benchSK, false)
	defer ct1.Free()
	defer ct2.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := benchEngine.Or(benchBSK, ct1, ct2)
		if err != nil {
			b.Fatal(err)
		}
		result.Free()
	}
}

func BenchmarkXOR(b *testing.B) {
	setupBenchmark(b)
	ct1, _ := benchEngine.EncryptBit(benchSK, true)
	ct2, _ := benchEngine.EncryptBit(benchSK, true)
	defer ct1.Free()
	defer ct2.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := benchEngine.Xor(benchBSK, ct1, ct2)
		if err != nil {
			b.Fatal(err)
		}
		result.Free()
	}
}

func BenchmarkNAND(b *testing.B) {
	setupBenchmark(b)
	ct1, _ := benchEngine.EncryptBit(benchSK, true)
	ct2, _ := benchEngine.EncryptBit(benchSK, true)
	defer ct1.Free()
	defer ct2.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := benchEngine.Nand(benchBSK, ct1, ct2)
		if err != nil {
			b.Fatal(err)
		}
		result.Free()
	}
}

func BenchmarkNOT(b *testing.B) {
	setupBenchmark(b)
	ct, _ := benchEngine.EncryptBit(benchSK, true)
	defer ct.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := benchEngine.Not(ct)
		if err != nil {
			b.Fatal(err)
		}
		result.Free()
	}
}

func BenchmarkMUX(b *testing.B) {
	setupBenchmark(b)
	sel, _ := benchEngine.EncryptBit(benchSK, true)
	ct1, _ := benchEngine.EncryptBit(benchSK, true)
	ct2, _ := benchEngine.EncryptBit(benchSK, false)
	defer sel.Free()
	defer ct1.Free()
	defer ct2.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := benchEngine.Mux(benchBSK, sel, ct1, ct2)
		if err != nil {
			b.Fatal(err)
		}
		result.Free()
	}
}

// =============================================================================
// Integer Operation Benchmarks (64-bit - UTXO mode)
// =============================================================================

func BenchmarkEncryptU64(b *testing.B) {
	setupBenchmark(b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ct, err := benchEngine.EncryptU64(benchSK, 12345678)
		if err != nil {
			b.Fatal(err)
		}
		ct.Free()
	}
}

func BenchmarkDecryptU64(b *testing.B) {
	setupBenchmark(b)
	ct, _ := benchEngine.EncryptU64(benchSK, 12345678)
	defer ct.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := benchEngine.DecryptU64(benchSK, ct)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAddU64(b *testing.B) {
	setupBenchmark(b)
	a, _ := benchEngine.EncryptU64(benchSK, 100)
	b_ct, _ := benchEngine.EncryptU64(benchSK, 200)
	defer a.Free()
	defer b_ct.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := benchEngine.AddU64(benchBSK, a, b_ct)
		if err != nil {
			b.Fatal(err)
		}
		result.Free()
	}
}

func BenchmarkSubU64(b *testing.B) {
	setupBenchmark(b)
	a, _ := benchEngine.EncryptU64(benchSK, 300)
	b_ct, _ := benchEngine.EncryptU64(benchSK, 100)
	defer a.Free()
	defer b_ct.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := benchEngine.SubU64(benchBSK, a, b_ct)
		if err != nil {
			b.Fatal(err)
		}
		result.Free()
	}
}

func BenchmarkMulU64(b *testing.B) {
	setupBenchmark(b)
	a, _ := benchEngine.EncryptU64(benchSK, 12)
	b_ct, _ := benchEngine.EncryptU64(benchSK, 34)
	defer a.Free()
	defer b_ct.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := benchEngine.MulU64(benchBSK, a, b_ct)
		if err != nil {
			b.Fatal(err)
		}
		result.Free()
	}
}

// =============================================================================
// Comparison Benchmarks (ULFHE - PAT-FHE-011)
// =============================================================================

func BenchmarkLt(b *testing.B) {
	setupBenchmark(b)
	a, _ := benchEngine.EncryptU64(benchSK, 100)
	b_ct, _ := benchEngine.EncryptU64(benchSK, 200)
	defer a.Free()
	defer b_ct.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := benchEngine.Lt(benchBSK, a, b_ct)
		if err != nil {
			b.Fatal(err)
		}
		result.Free()
	}
}

func BenchmarkLe(b *testing.B) {
	setupBenchmark(b)
	a, _ := benchEngine.EncryptU64(benchSK, 100)
	b_ct, _ := benchEngine.EncryptU64(benchSK, 100)
	defer a.Free()
	defer b_ct.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := benchEngine.Le(benchBSK, a, b_ct)
		if err != nil {
			b.Fatal(err)
		}
		result.Free()
	}
}

func BenchmarkGt(b *testing.B) {
	setupBenchmark(b)
	a, _ := benchEngine.EncryptU64(benchSK, 200)
	b_ct, _ := benchEngine.EncryptU64(benchSK, 100)
	defer a.Free()
	defer b_ct.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := benchEngine.Gt(benchBSK, a, b_ct)
		if err != nil {
			b.Fatal(err)
		}
		result.Free()
	}
}

func BenchmarkEq(b *testing.B) {
	setupBenchmark(b)
	a, _ := benchEngine.EncryptU64(benchSK, 42)
	b_ct, _ := benchEngine.EncryptU64(benchSK, 42)
	defer a.Free()
	defer b_ct.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := benchEngine.Eq(benchBSK, a, b_ct)
		if err != nil {
			b.Fatal(err)
		}
		result.Free()
	}
}

func BenchmarkInRange(b *testing.B) {
	setupBenchmark(b)
	value, _ := benchEngine.EncryptU64(benchSK, 150)
	defer value.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := benchEngine.InRange(benchBSK, value, 100, 200)
		if err != nil {
			b.Fatal(err)
		}
		result.Free()
	}
}

// =============================================================================
// uint256 Benchmarks (EVM256PP - PAT-FHE-012)
// =============================================================================

func BenchmarkEncryptU256(b *testing.B) {
	setupBenchmark(b)
	limbs := [4]uint64{0x1234, 0x5678, 0x9abc, 0xdef0}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ct, err := benchEngine.EncryptU256(benchSK, limbs)
		if err != nil {
			b.Fatal(err)
		}
		ct.Free()
	}
}

func BenchmarkDecryptU256(b *testing.B) {
	setupBenchmark(b)
	limbs := [4]uint64{0x1234, 0x5678, 0x9abc, 0xdef0}
	ct, _ := benchEngine.EncryptU256(benchSK, limbs)
	defer ct.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := benchEngine.DecryptU256(benchSK, ct)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAddU256(b *testing.B) {
	setupBenchmark(b)
	a_limbs := [4]uint64{0xffffffff, 0, 0, 0}
	b_limbs := [4]uint64{1, 0, 0, 0}
	a, _ := benchEngine.EncryptU256(benchSK, a_limbs)
	b_ct, _ := benchEngine.EncryptU256(benchSK, b_limbs)
	defer a.Free()
	defer b_ct.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := benchEngine.AddU256(a, b_ct)
		if err != nil {
			b.Fatal(err)
		}
		result.Free()
	}
}

func BenchmarkSubU256(b *testing.B) {
	setupBenchmark(b)
	a_limbs := [4]uint64{0x100000000, 0, 0, 0}
	b_limbs := [4]uint64{1, 0, 0, 0}
	a, _ := benchEngine.EncryptU256(benchSK, a_limbs)
	b_ct, _ := benchEngine.EncryptU256(benchSK, b_limbs)
	defer a.Free()
	defer b_ct.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := benchEngine.SubU256(a, b_ct)
		if err != nil {
			b.Fatal(err)
		}
		result.Free()
	}
}

func BenchmarkMulU256(b *testing.B) {
	setupBenchmark(b)
	a_limbs := [4]uint64{0x12345678, 0, 0, 0}
	b_limbs := [4]uint64{0x87654321, 0, 0, 0}
	a, _ := benchEngine.EncryptU256(benchSK, a_limbs)
	b_ct, _ := benchEngine.EncryptU256(benchSK, b_limbs)
	defer a.Free()
	defer b_ct.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := benchEngine.MulU256(benchBSK, a, b_ct)
		if err != nil {
			b.Fatal(err)
		}
		result.Free()
	}
}

func BenchmarkAndU256(b *testing.B) {
	setupBenchmark(b)
	a_limbs := [4]uint64{0xff00ff00, 0xff00ff00, 0xff00ff00, 0xff00ff00}
	b_limbs := [4]uint64{0x0ff00ff0, 0x0ff00ff0, 0x0ff00ff0, 0x0ff00ff0}
	a, _ := benchEngine.EncryptU256(benchSK, a_limbs)
	b_ct, _ := benchEngine.EncryptU256(benchSK, b_limbs)
	defer a.Free()
	defer b_ct.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := benchEngine.AndU256(a, b_ct)
		if err != nil {
			b.Fatal(err)
		}
		result.Free()
	}
}

func BenchmarkShlU256(b *testing.B) {
	setupBenchmark(b)
	a_limbs := [4]uint64{0x12345678, 0, 0, 0}
	a, _ := benchEngine.EncryptU256(benchSK, a_limbs)
	defer a.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := benchEngine.ShlU256(a, 64)
		if err != nil {
			b.Fatal(err)
		}
		result.Free()
	}
}

// =============================================================================
// EVM Opcode Benchmarks
// =============================================================================

func BenchmarkEVMAdd(b *testing.B) {
	setupBenchmark(b)
	a_limbs := [4]uint64{0x100, 0, 0, 0}
	b_limbs := [4]uint64{0x200, 0, 0, 0}
	a, _ := benchEngine.EncryptU256(benchSK, a_limbs)
	b_ct, _ := benchEngine.EncryptU256(benchSK, b_limbs)
	defer a.Free()
	defer b_ct.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := benchEngine.EVMExecute(benchBSK, EVMAdd, a, b_ct)
		if err != nil {
			b.Fatal(err)
		}
		result.Free()
	}
}

func BenchmarkEVMMul(b *testing.B) {
	setupBenchmark(b)
	a_limbs := [4]uint64{0x10, 0, 0, 0}
	b_limbs := [4]uint64{0x20, 0, 0, 0}
	a, _ := benchEngine.EncryptU256(benchSK, a_limbs)
	b_ct, _ := benchEngine.EncryptU256(benchSK, b_limbs)
	defer a.Free()
	defer b_ct.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := benchEngine.EVMExecute(benchBSK, EVMMul, a, b_ct)
		if err != nil {
			b.Fatal(err)
		}
		result.Free()
	}
}

func BenchmarkEVMLt(b *testing.B) {
	setupBenchmark(b)
	a_limbs := [4]uint64{100, 0, 0, 0}
	b_limbs := [4]uint64{200, 0, 0, 0}
	a, _ := benchEngine.EncryptU256(benchSK, a_limbs)
	b_ct, _ := benchEngine.EncryptU256(benchSK, b_limbs)
	defer a.Free()
	defer b_ct.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := benchEngine.EVMExecute(benchBSK, EVMLt, a, b_ct)
		if err != nil {
			b.Fatal(err)
		}
		result.Free()
	}
}

// =============================================================================
// Cross-Chain Bridge Benchmarks (XCFHE - PAT-FHE-013)
// =============================================================================

func BenchmarkBridgeCreate(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bridge, err := NewBridge(ChainLUX, ChainZOO)
		if err != nil {
			b.Fatal(err)
		}
		bridge.Free()
	}
}

// =============================================================================
// Validator Session Benchmarks (VAFHE - PAT-FHE-014)
// =============================================================================

func BenchmarkValidatorCreate(b *testing.B) {
	setupBenchmark(b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vs, err := benchEngine.NewValidatorSession(AttestNVTrust)
		if err != nil {
			b.Fatal(err)
		}
		vs.Free()
	}
}

func BenchmarkValidatorRecordWork(b *testing.B) {
	setupBenchmark(b)
	vs, _ := benchEngine.NewValidatorSession(AttestNVTrust)
	defer vs.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vs.RecordWork(1000)
	}
}

// =============================================================================
// Serialization Benchmarks
// =============================================================================

func BenchmarkSerializeCiphertext(b *testing.B) {
	setupBenchmark(b)
	ct, _ := benchEngine.EncryptBit(benchSK, true)
	defer ct.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		data, err := ct.Serialize()
		if err != nil {
			b.Fatal(err)
		}
		_ = data
	}
}

func BenchmarkDeserializeCiphertext(b *testing.B) {
	setupBenchmark(b)
	ct, _ := benchEngine.EncryptBit(benchSK, true)
	data, _ := ct.Serialize()
	ct.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		newCt, err := benchEngine.DeserializeCiphertext(data)
		if err != nil {
			b.Fatal(err)
		}
		newCt.Free()
	}
}

func BenchmarkSerializeInteger(b *testing.B) {
	setupBenchmark(b)
	ct, _ := benchEngine.EncryptU64(benchSK, 12345678)
	defer ct.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		data, err := ct.Serialize()
		if err != nil {
			b.Fatal(err)
		}
		_ = data
	}
}

// =============================================================================
// Backend Comparison Benchmarks
// =============================================================================

func benchmarkBackend(b *testing.B, backend Backend) {
	engine, err := NewEngine(backend)
	if err != nil {
		b.Skipf("Backend %v not available: %v", backend, err)
		return
	}
	defer engine.Free()

	params, _ := NewParams(Security128, ModeUTXO64)
	defer params.Free()

	sk, _ := engine.GenerateSecretKey(params)
	defer sk.Free()

	bsk, _ := engine.GenerateBootstrapKey(params, sk)
	defer bsk.Free()

	a, _ := engine.EncryptU64(sk, 100)
	defer a.Free()
	b_ct, _ := engine.EncryptU64(sk, 200)
	defer b_ct.Free()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, _ := engine.AddU64(bsk, a, b_ct)
		result.Free()
	}
}

func BenchmarkBackendMLX(b *testing.B) {
	benchmarkBackend(b, BackendMLX)
}

func BenchmarkBackendCUDA(b *testing.B) {
	benchmarkBackend(b, BackendCUDA)
}

func BenchmarkBackendCPU(b *testing.B) {
	benchmarkBackend(b, BackendCPU)
}

// =============================================================================
// Throughput Benchmarks
// =============================================================================

func BenchmarkThroughputGates(b *testing.B) {
	setupBenchmark(b)

	// Create batch of ciphertexts
	const batchSize = 100
	cts := make([]*Ciphertext, batchSize*2)
	for i := 0; i < batchSize*2; i++ {
		ct, _ := benchEngine.EncryptBit(benchSK, i%2 == 0)
		cts[i] = ct
	}
	defer func() {
		for _, ct := range cts {
			ct.Free()
		}
	}()

	b.ResetTimer()
	b.SetBytes(int64(batchSize))

	for i := 0; i < b.N; i++ {
		for j := 0; j < batchSize; j++ {
			result, _ := benchEngine.And(benchBSK, cts[j], cts[j+batchSize])
			result.Free()
		}
	}
}

func BenchmarkThroughputU64Add(b *testing.B) {
	setupBenchmark(b)

	const batchSize = 100
	as := make([]*Integer, batchSize)
	bs := make([]*Integer, batchSize)

	for i := 0; i < batchSize; i++ {
		a, _ := benchEngine.EncryptU64(benchSK, uint64(i*100))
		b_ct, _ := benchEngine.EncryptU64(benchSK, uint64(i*200))
		as[i] = a
		bs[i] = b_ct
	}
	defer func() {
		for i := 0; i < batchSize; i++ {
			as[i].Free()
			bs[i].Free()
		}
	}()

	b.ResetTimer()
	b.SetBytes(int64(batchSize * 8)) // 8 bytes per uint64

	for i := 0; i < b.N; i++ {
		for j := 0; j < batchSize; j++ {
			result, _ := benchEngine.AddU64(benchBSK, as[j], bs[j])
			result.Free()
		}
	}
}

// =============================================================================
// Report Benchmark Results
// =============================================================================

func TestBenchmarkSummary(t *testing.T) {
	engine, err := NewDefaultEngine()
	if err != nil {
		t.Skip("Engine not available")
	}
	defer engine.Free()

	fmt.Println("=== Lux FHE Benchmark Summary ===")
	fmt.Printf("Version: %s\n", Version())
	fmt.Printf("Backend: %s\n", BackendType())
	fmt.Printf("GPU Available: %v\n", HasGPU())

	stats := engine.GetStats()
	fmt.Printf("\nPerformance Statistics:\n")
	fmt.Printf("  NTT Time: %.3f ms\n", stats.NTTTimeMs)
	fmt.Printf("  Bootstrap Time: %.3f ms\n", stats.BootstrapTimeMs)
	fmt.Printf("  Keygen Time: %.3f ms\n", stats.KeygenTimeMs)
	fmt.Printf("  Operations: %d\n", stats.OperationsCount)
	fmt.Printf("  Throughput: %.2f ops/sec\n", stats.ThroughputOpsSec)
	fmt.Printf("  Memory Used: %d bytes\n", stats.MemoryUsedBytes)
	fmt.Printf("  GPU Memory: %d bytes\n", stats.GPUMemoryBytes)
}
