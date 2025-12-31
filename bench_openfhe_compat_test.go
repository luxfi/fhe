// Benchmark tests with OpenFHE-compatible parameters
// These benchmarks use parameters that closely match OpenFHE's STD128_LMKCDEY
// for fair comparison between Go and C++ implementations.
package fhe

import (
	"testing"
)

// BenchmarkSTD128_AND benchmarks AND gate with STD128-compatible parameters
func BenchmarkSTD128_AND(b *testing.B) {
	params, err := NewParametersFromLiteral(PN9QP28_STD128)
	if err != nil {
		b.Fatal(err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	enc := NewEncryptor(params, sk)
	eval := NewEvaluator(params, bsk)

	ct1 := enc.EncryptBit(1)
	ct2 := enc.EncryptBit(0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = eval.AND(ct1, ct2)
	}
}

// BenchmarkSTD128_OR benchmarks OR gate with STD128-compatible parameters
func BenchmarkSTD128_OR(b *testing.B) {
	params, err := NewParametersFromLiteral(PN9QP28_STD128)
	if err != nil {
		b.Fatal(err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	enc := NewEncryptor(params, sk)
	eval := NewEvaluator(params, bsk)

	ct1 := enc.EncryptBit(1)
	ct2 := enc.EncryptBit(0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = eval.OR(ct1, ct2)
	}
}

// BenchmarkSTD128_XOR benchmarks XOR gate with STD128-compatible parameters
func BenchmarkSTD128_XOR(b *testing.B) {
	params, err := NewParametersFromLiteral(PN9QP28_STD128)
	if err != nil {
		b.Fatal(err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	enc := NewEncryptor(params, sk)
	eval := NewEvaluator(params, bsk)

	ct1 := enc.EncryptBit(1)
	ct2 := enc.EncryptBit(0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = eval.XOR(ct1, ct2)
	}
}

// BenchmarkSTD128_NOT benchmarks NOT gate with STD128-compatible parameters
func BenchmarkSTD128_NOT(b *testing.B) {
	params, err := NewParametersFromLiteral(PN9QP28_STD128)
	if err != nil {
		b.Fatal(err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	enc := NewEncryptor(params, sk)
	eval := NewEvaluator(params, bsk)

	ct := enc.EncryptBit(1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eval.NOT(ct)
	}
}

// BenchmarkSTD128_NAND benchmarks NAND gate (includes bootstrap) with STD128-compatible parameters
func BenchmarkSTD128_NAND(b *testing.B) {
	params, err := NewParametersFromLiteral(PN9QP28_STD128)
	if err != nil {
		b.Fatal(err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	enc := NewEncryptor(params, sk)
	eval := NewEvaluator(params, bsk)

	ct1 := enc.EncryptBit(1)
	ct2 := enc.EncryptBit(0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = eval.NAND(ct1, ct2)
	}
}

// BenchmarkPN10QP27_AND benchmarks AND gate with original PN10QP27 parameters for comparison
func BenchmarkPN10QP27_AND(b *testing.B) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		b.Fatal(err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	enc := NewEncryptor(params, sk)
	eval := NewEvaluator(params, bsk)

	ct1 := enc.EncryptBit(1)
	ct2 := enc.EncryptBit(0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = eval.AND(ct1, ct2)
	}
}

// BenchmarkPN10QP27_OR benchmarks OR gate with original PN10QP27 parameters for comparison
func BenchmarkPN10QP27_OR(b *testing.B) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		b.Fatal(err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	enc := NewEncryptor(params, sk)
	eval := NewEvaluator(params, bsk)

	ct1 := enc.EncryptBit(1)
	ct2 := enc.EncryptBit(0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = eval.OR(ct1, ct2)
	}
}

// BenchmarkPN10QP27_XOR benchmarks XOR gate with original PN10QP27 parameters for comparison
func BenchmarkPN10QP27_XOR(b *testing.B) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		b.Fatal(err)
	}

	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	enc := NewEncryptor(params, sk)
	eval := NewEvaluator(params, bsk)

	ct1 := enc.EncryptBit(1)
	ct2 := enc.EncryptBit(0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = eval.XOR(ct1, ct2)
	}
}
