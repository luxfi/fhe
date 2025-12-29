// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package tfhe

import (
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"
)

// BenchmarkBootstrapBaseline measures baseline bootstrap performance
func BenchmarkBootstrapBaseline(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	_ = kg.GenPublicKey(sk)
	bsk := kg.GenBootstrapKey(sk)
	enc := NewEncryptor(params, sk)
	eval := NewEvaluator(params, bsk)

	ct1 := enc.Encrypt(true)
	ct2 := enc.Encrypt(true)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = eval.AND(ct1, ct2)
	}
}

// BenchmarkBootstrapParallelGates measures parallel gate execution
func BenchmarkBootstrapParallelGates(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	_ = kg.GenPublicKey(sk)
	bsk := kg.GenBootstrapKey(sk)
	enc := NewEncryptor(params, sk)

	numGates := 8

	type gateInput struct {
		eval *Evaluator
		ct1  *Ciphertext
		ct2  *Ciphertext
	}

	inputs := make([]gateInput, numGates)
	for i := 0; i < numGates; i++ {
		inputs[i] = gateInput{
			eval: NewEvaluator(params, bsk),
			ct1:  enc.Encrypt(true),
			ct2:  enc.Encrypt(false),
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var wg sync.WaitGroup
		for j := 0; j < numGates; j++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				_, _ = inputs[idx].eval.AND(inputs[idx].ct1, inputs[idx].ct2)
			}(j)
		}
		wg.Wait()
	}
}

// BenchmarkNTTComparison compares NTT implementations
func BenchmarkNTTComparison(b *testing.B) {
	sizes := []int{512, 1024, 2048, 4096}
	Q := uint64(1 << 27)

	for _, N := range sizes {
		b.Run(fmt.Sprintf("N=%d", N), func(b *testing.B) {
			engine := NewNTTEngine(uint32(N), Q)
			coeffs := make([]uint64, N)
			for i := range coeffs {
				coeffs[i] = uint64(rand.Int63n(int64(Q)))
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				engine.NTTInPlace(coeffs)
			}
		})
	}
}

// BenchmarkBatchNTT measures batch NTT performance scaling
func BenchmarkBatchNTT(b *testing.B) {
	N := 1024
	Q := uint64(1 << 27)
	engine := NewNTTEngine(uint32(N), Q)

	batchSizes := []int{1, 4, 16, 64, 256}

	for _, batchSize := range batchSizes {
		b.Run(fmt.Sprintf("batch=%d", batchSize), func(b *testing.B) {
			polys := make([][]uint64, batchSize)
			for i := range polys {
				polys[i] = make([]uint64, N)
				for j := range polys[i] {
					polys[i][j] = uint64(rand.Int63n(int64(Q)))
				}
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				engine.NTTBatch(polys)
			}
		})
	}
}

// BenchmarkPolyMulScaling measures polynomial multiplication scaling
func BenchmarkPolyMulScaling(b *testing.B) {
	N := 1024
	Q := uint64(1 << 27)
	engine := NewNTTEngine(uint32(N), Q)

	a := make([]uint64, N)
	bb := make([]uint64, N)
	result := make([]uint64, N)

	for i := range a {
		a[i] = uint64(rand.Int63n(int64(Q)))
		bb[i] = uint64(rand.Int63n(int64(Q)))
	}

	engine.NTTInPlace(a)
	engine.NTTInPlace(bb)

	b.Run("PolyMul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			engine.PolyMulNTT(a, bb, result)
		}
	})

	b.Run("PolyMulAccum", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			engine.PolyMulNTTAccum(a, bb, result)
		}
	})
}

// BenchmarkModularOps measures modular arithmetic performance
func BenchmarkModularOps(b *testing.B) {
	engine := NewNTTEngine(1024, 1<<27)
	a := uint64(rand.Int63n(int64(engine.Q)))
	bb := uint64(rand.Int63n(int64(engine.Q)))

	b.Run("MulMod_Standard", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = engine.mulMod(a, bb)
		}
	})

	b.Run("MulMod_Barrett", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = engine.mulModBarrett(a, bb)
		}
	})

	b.Run("AddMod", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = engine.addMod(a, bb)
		}
	})

	b.Run("SubMod", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = engine.subMod(a, bb)
		}
	})
}

// BenchmarkExternalProduct measures external product performance
func BenchmarkExternalProduct(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	_ = kg.GenPublicKey(sk)
	bsk := kg.GenBootstrapKey(sk)
	enc := NewEncryptor(params, sk)
	eval := NewEvaluator(params, bsk)

	ct := enc.Encrypt(true)

	// Measure a full bootstrap (which includes external products)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = eval.bootstrap(ct, eval.bsk.TestPolyAND)
	}
}

// BenchmarkKeyGenerationOptimized measures key generation performance
func BenchmarkKeyGenerationOptimized(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	kg := NewKeyGenerator(params)

	b.Run("SecretKey", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = kg.GenSecretKey()
		}
	})

	sk := kg.GenSecretKey()

	b.Run("PublicKey", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = kg.GenPublicKey(sk)
		}
	})

	b.Run("BootstrapKey", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = kg.GenBootstrapKey(sk)
		}
	})
}

// BenchmarkEncryptionOptimized measures encryption performance
func BenchmarkEncryptionOptimized(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	_ = kg.GenPublicKey(sk)
	enc := NewEncryptor(params, sk)

	b.Run("Bit", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = enc.Encrypt(true)
		}
	})

	b.Run("Byte", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = enc.EncryptByte(0xAB)
		}
	})

	b.Run("Uint32", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = enc.EncryptUint32(0xDEADBEEF)
		}
	})
}

// BenchmarkDecryptionOptimized measures decryption performance
func BenchmarkDecryptionOptimized(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	_ = kg.GenPublicKey(sk)
	enc := NewEncryptor(params, sk)
	dec := NewDecryptor(params, sk)

	ctBit := enc.Encrypt(true)
	ctByte := enc.EncryptByte(0xAB)
	ctUint32 := enc.EncryptUint32(0xDEADBEEF)

	b.Run("Bit", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = dec.DecryptBit(ctBit)
		}
	})

	b.Run("Byte", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = dec.DecryptByte(ctByte)
		}
	})

	b.Run("Uint32", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = dec.DecryptUint32(ctUint32)
		}
	})
}

// BenchmarkAllGates measures all boolean gate performance
func BenchmarkAllGates(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	_ = kg.GenPublicKey(sk)
	bsk := kg.GenBootstrapKey(sk)
	enc := NewEncryptor(params, sk)
	eval := NewEvaluator(params, bsk)

	ct1 := enc.Encrypt(true)
	ct2 := enc.Encrypt(false)
	ct3 := enc.Encrypt(true)

	gates := []struct {
		name string
		fn   func() (*Ciphertext, error)
	}{
		{"NOT", func() (*Ciphertext, error) { return eval.NOT(ct1), nil }},
		{"AND", func() (*Ciphertext, error) { return eval.AND(ct1, ct2) }},
		{"OR", func() (*Ciphertext, error) { return eval.OR(ct1, ct2) }},
		{"XOR", func() (*Ciphertext, error) { return eval.XOR(ct1, ct2) }},
		{"NAND", func() (*Ciphertext, error) { return eval.NAND(ct1, ct2) }},
		{"NOR", func() (*Ciphertext, error) { return eval.NOR(ct1, ct2) }},
		{"XNOR", func() (*Ciphertext, error) { return eval.XNOR(ct1, ct2) }},
		{"MUX", func() (*Ciphertext, error) { return eval.MUX(ct1, ct2, ct3) }},
		{"AND3", func() (*Ciphertext, error) { return eval.AND3(ct1, ct2, ct3) }},
		{"OR3", func() (*Ciphertext, error) { return eval.OR3(ct1, ct2, ct3) }},
		{"MAJORITY", func() (*Ciphertext, error) { return eval.MAJORITY(ct1, ct2, ct3) }},
	}

	for _, g := range gates {
		b.Run(g.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = g.fn()
			}
		})
	}
}

// BenchmarkThroughputOptimized measures sustained throughput
func BenchmarkThroughputOptimized(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	_ = kg.GenPublicKey(sk)
	bsk := kg.GenBootstrapKey(sk)
	enc := NewEncryptor(params, sk)

	numWorkers := 4
	opsPerWorker := 100

	b.Run(fmt.Sprintf("Workers=%d", numWorkers), func(b *testing.B) {
		for iter := 0; iter < b.N; iter++ {
			var wg sync.WaitGroup
			start := time.Now()

			for w := 0; w < numWorkers; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					eval := NewEvaluator(params, bsk)
					ct1 := enc.Encrypt(true)
					ct2 := enc.Encrypt(false)

					for i := 0; i < opsPerWorker; i++ {
						_, _ = eval.AND(ct1, ct2)
					}
				}()
			}

			wg.Wait()
			elapsed := time.Since(start)
			totalOps := numWorkers * opsPerWorker
			opsPerSec := float64(totalOps) / elapsed.Seconds()

			b.ReportMetric(opsPerSec, "ops/s")
		}
	})
}

// BenchmarkMemoryAllocation measures memory allocation patterns
func BenchmarkMemoryAllocation(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	_ = kg.GenPublicKey(sk)
	bsk := kg.GenBootstrapKey(sk)
	enc := NewEncryptor(params, sk)
	eval := NewEvaluator(params, bsk)

	ct1 := enc.Encrypt(true)
	ct2 := enc.Encrypt(false)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = eval.AND(ct1, ct2)
	}
}

// BenchmarkParameterSets compares different parameter sets
func BenchmarkParameterSets(b *testing.B) {
	paramSets := []struct {
		name    string
		literal ParametersLiteral
	}{
		{"PN10QP27", PN10QP27},
		{"PN11QP54", PN11QP54},
	}

	for _, ps := range paramSets {
		b.Run(ps.name, func(b *testing.B) {
			params, err := NewParametersFromLiteral(ps.literal)
			if err != nil {
				b.Fatalf("failed to create params: %v", err)
			}

			kg := NewKeyGenerator(params)
			sk := kg.GenSecretKey()
			_ = kg.GenPublicKey(sk)
			bsk := kg.GenBootstrapKey(sk)
			enc := NewEncryptor(params, sk)
			eval := NewEvaluator(params, bsk)

			ct1 := enc.Encrypt(true)
			ct2 := enc.Encrypt(false)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = eval.AND(ct1, ct2)
			}
		})
	}
}

// TestPerformanceReport generates a performance summary
func TestPerformanceReport(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping performance report in short mode")
	}

	params, _ := NewParametersFromLiteral(PN10QP27)
	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	_ = kg.GenPublicKey(sk)
	bsk := kg.GenBootstrapKey(sk)
	enc := NewEncryptor(params, sk)
	dec := NewDecryptor(params, sk)
	eval := NewEvaluator(params, bsk)

	// Measure key generation
	start := time.Now()
	for i := 0; i < 10; i++ {
		_ = kg.GenBootstrapKey(sk)
	}
	bskTime := time.Since(start) / 10

	// Measure encryption
	start = time.Now()
	for i := 0; i < 1000; i++ {
		_ = enc.Encrypt(true)
	}
	encTime := time.Since(start) / 1000

	// Measure decryption
	ct := enc.Encrypt(true)
	start = time.Now()
	for i := 0; i < 1000; i++ {
		_ = dec.Decrypt(ct)
	}
	decTime := time.Since(start) / 1000

	// Measure gates
	ct1 := enc.Encrypt(true)
	ct2 := enc.Encrypt(false)
	ct3 := enc.Encrypt(true)

	gateResults := make(map[string]time.Duration)
	numIter := 10

	start = time.Now()
	for i := 0; i < numIter; i++ {
		_, _ = eval.AND(ct1, ct2)
	}
	gateResults["AND"] = time.Since(start) / time.Duration(numIter)

	start = time.Now()
	for i := 0; i < numIter; i++ {
		_, _ = eval.OR(ct1, ct2)
	}
	gateResults["OR"] = time.Since(start) / time.Duration(numIter)

	start = time.Now()
	for i := 0; i < numIter; i++ {
		_, _ = eval.XOR(ct1, ct2)
	}
	gateResults["XOR"] = time.Since(start) / time.Duration(numIter)

	start = time.Now()
	for i := 0; i < numIter; i++ {
		_, _ = eval.MAJORITY(ct1, ct2, ct3)
	}
	gateResults["MAJORITY"] = time.Since(start) / time.Duration(numIter)

	// Print report
	fmt.Println("\n========== TFHE Performance Report ==========")
	fmt.Printf("Parameters: PN10QP27 (N=%d, Q=%d)\n", params.N(), params.QLWE())
	fmt.Println()
	fmt.Println("Key Generation:")
	fmt.Printf("  Bootstrap Key: %v\n", bskTime)
	fmt.Println()
	fmt.Println("Encryption/Decryption:")
	fmt.Printf("  Encrypt Bit: %v\n", encTime)
	fmt.Printf("  Decrypt Bit: %v\n", decTime)
	fmt.Println()
	fmt.Println("Boolean Gates:")
	for gate, dur := range gateResults {
		gatesPerSec := float64(time.Second) / float64(dur)
		fmt.Printf("  %s: %v (%.1f gates/sec)\n", gate, dur, gatesPerSec)
	}
	fmt.Println("================================================")
}
