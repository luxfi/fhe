// Copyright (c) 2024 The Lux Authors
// Use of this source code is governed by a BSD 3-Clause
// license that can be found in the LICENSE file.

package tfhe

import (
	"testing"
)

// Comprehensive benchmarks for pure Go (lattice) backend
// These mirror the CGO benchmarks for comparison

var (
	benchParams  Parameters
	benchKGen    *KeyGenerator
	benchSK      *SecretKey
	benchPK      *PublicKey
	benchBSK     *BootstrapKey
	benchEnc     *Encryptor
	benchDec     *Decryptor
	benchEval    *Evaluator
	benchBitEnc  *BitwiseEncryptor
	benchBitDec  *BitwiseDecryptor
	benchBitEval *BitwiseEvaluator
)

func setupBenchmark(b *testing.B) {
	if benchKGen != nil {
		return
	}
	var err error
	benchParams, err = NewParametersFromLiteral(PN10QP27)
	if err != nil {
		b.Fatalf("failed to create params: %v", err)
	}
	benchKGen = NewKeyGenerator(benchParams)
	benchSK = benchKGen.GenSecretKey()
	benchPK = benchKGen.GenPublicKey(benchSK)
	benchBSK = benchKGen.GenBootstrapKey(benchSK)
	benchEnc = NewEncryptor(benchParams, benchSK)
	benchDec = NewDecryptor(benchParams, benchSK)
	benchEval = NewEvaluator(benchParams, benchBSK)
	benchBitEnc = NewBitwiseEncryptor(benchParams, benchSK)
	benchBitDec = NewBitwiseDecryptor(benchParams, benchSK)
	benchBitEval = NewBitwiseEvaluator(benchParams, benchBSK, benchSK)
}

// ============================================================================
// Key Generation Benchmarks
// ============================================================================

func BenchmarkLatticeKeyGen(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	kgen := NewKeyGenerator(params)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = kgen.GenSecretKey()
	}
}

func BenchmarkLatticePublicKeyGen(b *testing.B) {
	setupBenchmark(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = benchKGen.GenPublicKey(benchSK)
	}
}

func BenchmarkLatticeBootstrapKeyGen(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	kgen := NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = kgen.GenBootstrapKey(sk)
	}
}

// ============================================================================
// Boolean Encryption/Decryption Benchmarks
// ============================================================================

func BenchmarkLatticeEncryptBit(b *testing.B) {
	setupBenchmark(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = benchEnc.Encrypt(true)
	}
}

func BenchmarkLatticeDecryptBit(b *testing.B) {
	setupBenchmark(b)
	ct := benchEnc.Encrypt(true)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = benchDec.Decrypt(ct)
	}
}

// ============================================================================
// Boolean Gate Benchmarks
// ============================================================================

func BenchmarkLatticeAND(b *testing.B) {
	setupBenchmark(b)
	ct1 := benchEnc.Encrypt(true)
	ct2 := benchEnc.Encrypt(false)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = benchEval.AND(ct1, ct2)
	}
}

func BenchmarkLatticeOR(b *testing.B) {
	setupBenchmark(b)
	ct1 := benchEnc.Encrypt(true)
	ct2 := benchEnc.Encrypt(false)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = benchEval.OR(ct1, ct2)
	}
}

func BenchmarkLatticeXOR(b *testing.B) {
	setupBenchmark(b)
	ct1 := benchEnc.Encrypt(true)
	ct2 := benchEnc.Encrypt(false)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = benchEval.XOR(ct1, ct2)
	}
}

func BenchmarkLatticeNOT(b *testing.B) {
	setupBenchmark(b)
	ct := benchEnc.Encrypt(true)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = benchEval.NOT(ct)
	}
}

func BenchmarkLatticeNAND(b *testing.B) {
	setupBenchmark(b)
	ct1 := benchEnc.Encrypt(true)
	ct2 := benchEnc.Encrypt(true)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = benchEval.NAND(ct1, ct2)
	}
}

func BenchmarkLatticeNOR(b *testing.B) {
	setupBenchmark(b)
	ct1 := benchEnc.Encrypt(true)
	ct2 := benchEnc.Encrypt(true)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = benchEval.NOR(ct1, ct2)
	}
}

func BenchmarkLatticeXNOR(b *testing.B) {
	setupBenchmark(b)
	ct1 := benchEnc.Encrypt(true)
	ct2 := benchEnc.Encrypt(false)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = benchEval.XNOR(ct1, ct2)
	}
}

func BenchmarkLatticeMUX(b *testing.B) {
	setupBenchmark(b)
	sel := benchEnc.Encrypt(true)
	ct1 := benchEnc.Encrypt(true)
	ct2 := benchEnc.Encrypt(false)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = benchEval.MUX(sel, ct1, ct2)
	}
}

// ============================================================================
// Integer Encryption/Decryption Benchmarks
// ============================================================================

func BenchmarkLatticeEncryptInt8(b *testing.B) {
	setupBenchmark(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = benchBitEnc.EncryptUint64(42, FheUint8)
	}
}

func BenchmarkLatticeEncryptInt16(b *testing.B) {
	setupBenchmark(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = benchBitEnc.EncryptUint64(12345, FheUint16)
	}
}

func BenchmarkLatticeEncryptInt32(b *testing.B) {
	setupBenchmark(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = benchBitEnc.EncryptUint64(123456789, FheUint32)
	}
}

func BenchmarkLatticeDecryptInt8(b *testing.B) {
	setupBenchmark(b)
	ct := benchBitEnc.EncryptUint64(42, FheUint8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = benchBitDec.DecryptUint64(ct)
	}
}

func BenchmarkLatticeDecryptInt16(b *testing.B) {
	setupBenchmark(b)
	ct := benchBitEnc.EncryptUint64(12345, FheUint16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = benchBitDec.DecryptUint64(ct)
	}
}

// ============================================================================
// Integer Arithmetic Benchmarks
// ============================================================================

func BenchmarkLatticeAdd8(b *testing.B) {
	setupBenchmark(b)
	a := benchBitEnc.EncryptUint64(10, FheUint8)
	c := benchBitEnc.EncryptUint64(20, FheUint8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = benchBitEval.Add(a, c)
	}
}

func BenchmarkLatticeAdd16(b *testing.B) {
	setupBenchmark(b)
	a := benchBitEnc.EncryptUint64(1000, FheUint16)
	c := benchBitEnc.EncryptUint64(2000, FheUint16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = benchBitEval.Add(a, c)
	}
}

func BenchmarkLatticeSub8(b *testing.B) {
	setupBenchmark(b)
	a := benchBitEnc.EncryptUint64(50, FheUint8)
	c := benchBitEnc.EncryptUint64(20, FheUint8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = benchBitEval.Sub(a, c)
	}
}

func BenchmarkLatticeScalarAdd8(b *testing.B) {
	setupBenchmark(b)
	a := benchBitEnc.EncryptUint64(42, FheUint8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = benchBitEval.ScalarAdd(a, 10)
	}
}

// ============================================================================
// Comparison Benchmarks
// ============================================================================

func BenchmarkLatticeEq8(b *testing.B) {
	setupBenchmark(b)
	a := benchBitEnc.EncryptUint64(42, FheUint8)
	c := benchBitEnc.EncryptUint64(42, FheUint8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = benchBitEval.Eq(a, c)
	}
}

func BenchmarkLatticeLt8(b *testing.B) {
	setupBenchmark(b)
	a := benchBitEnc.EncryptUint64(10, FheUint8)
	c := benchBitEnc.EncryptUint64(20, FheUint8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = benchBitEval.Lt(a, c)
	}
}

func BenchmarkLatticeLe8(b *testing.B) {
	setupBenchmark(b)
	a := benchBitEnc.EncryptUint64(10, FheUint8)
	c := benchBitEnc.EncryptUint64(20, FheUint8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = benchBitEval.Le(a, c)
	}
}

func BenchmarkLatticeGt8(b *testing.B) {
	setupBenchmark(b)
	a := benchBitEnc.EncryptUint64(20, FheUint8)
	c := benchBitEnc.EncryptUint64(10, FheUint8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = benchBitEval.Gt(a, c)
	}
}

func BenchmarkLatticeMin8(b *testing.B) {
	setupBenchmark(b)
	a := benchBitEnc.EncryptUint64(10, FheUint8)
	c := benchBitEnc.EncryptUint64(20, FheUint8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = benchBitEval.Min(a, c)
	}
}

func BenchmarkLatticeMax8(b *testing.B) {
	setupBenchmark(b)
	a := benchBitEnc.EncryptUint64(10, FheUint8)
	c := benchBitEnc.EncryptUint64(20, FheUint8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = benchBitEval.Max(a, c)
	}
}

// ============================================================================
// Bitwise Operation Benchmarks
// ============================================================================

func BenchmarkLatticeBitwiseAnd8(b *testing.B) {
	setupBenchmark(b)
	a := benchBitEnc.EncryptUint64(0xFF, FheUint8)
	c := benchBitEnc.EncryptUint64(0x0F, FheUint8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = benchBitEval.And(a, c)
	}
}

func BenchmarkLatticeBitwiseOr8(b *testing.B) {
	setupBenchmark(b)
	a := benchBitEnc.EncryptUint64(0xF0, FheUint8)
	c := benchBitEnc.EncryptUint64(0x0F, FheUint8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = benchBitEval.Or(a, c)
	}
}

func BenchmarkLatticeBitwiseXor8(b *testing.B) {
	setupBenchmark(b)
	a := benchBitEnc.EncryptUint64(0xFF, FheUint8)
	c := benchBitEnc.EncryptUint64(0x55, FheUint8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = benchBitEval.Xor(a, c)
	}
}

func BenchmarkLatticeBitwiseNot8(b *testing.B) {
	setupBenchmark(b)
	a := benchBitEnc.EncryptUint64(0xFF, FheUint8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = benchBitEval.Not(a)
	}
}

func BenchmarkLatticeShl8(b *testing.B) {
	setupBenchmark(b)
	a := benchBitEnc.EncryptUint64(0x0F, FheUint8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = benchBitEval.Shl(a, 2)
	}
}

func BenchmarkLatticeShr8(b *testing.B) {
	setupBenchmark(b)
	a := benchBitEnc.EncryptUint64(0xF0, FheUint8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = benchBitEval.Shr(a, 2)
	}
}

// ============================================================================
// Control Flow Benchmarks
// ============================================================================

func BenchmarkLatticeSelect8(b *testing.B) {
	setupBenchmark(b)
	cond := benchEnc.Encrypt(true)
	a := benchBitEnc.EncryptUint64(10, FheUint8)
	c := benchBitEnc.EncryptUint64(20, FheUint8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = benchBitEval.Select(cond, a, c)
	}
}

func BenchmarkLatticeCastTo16(b *testing.B) {
	setupBenchmark(b)
	a := benchBitEnc.EncryptUint64(42, FheUint8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = benchBitEval.CastTo(a, FheUint16)
	}
}

// ============================================================================
// Public Key Encryption Benchmarks
// ============================================================================

func BenchmarkLatticePublicEncrypt8(b *testing.B) {
	setupBenchmark(b)
	pubEnc := NewBitwisePublicEncryptor(benchParams, benchPK)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pubEnc.EncryptUint64(42, FheUint8)
	}
}

func BenchmarkLatticePublicEncrypt16(b *testing.B) {
	setupBenchmark(b)
	pubEnc := NewBitwisePublicEncryptor(benchParams, benchPK)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pubEnc.EncryptUint64(12345, FheUint16)
	}
}

// ============================================================================
// Serialization Benchmarks
// ============================================================================

func BenchmarkLatticeSerializeCiphertext(b *testing.B) {
	setupBenchmark(b)
	ct := benchEnc.Encrypt(true)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ct.MarshalBinary()
	}
}

func BenchmarkLatticeDeserializeCiphertext(b *testing.B) {
	setupBenchmark(b)
	ct := benchEnc.Encrypt(true)
	data, _ := ct.MarshalBinary()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var ct2 Ciphertext
		_ = ct2.UnmarshalBinary(data)
	}
}

func BenchmarkLatticeSerializeInteger8(b *testing.B) {
	setupBenchmark(b)
	ct := benchBitEnc.EncryptUint64(42, FheUint8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ct.MarshalBinary()
	}
}

func BenchmarkLatticeSerializeInteger16(b *testing.B) {
	setupBenchmark(b)
	ct := benchBitEnc.EncryptUint64(12345, FheUint16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ct.MarshalBinary()
	}
}

// ============================================================================
// RNG Benchmarks
// ============================================================================

func BenchmarkLatticeRNGRandomUint8(b *testing.B) {
	setupBenchmark(b)
	rng := NewFheRNG(benchParams, benchSK, []byte("benchmark-seed"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rng.RandomUint(FheUint8)
	}
}

func BenchmarkLatticeRNGRandomUint16(b *testing.B) {
	setupBenchmark(b)
	rng := NewFheRNG(benchParams, benchSK, []byte("benchmark-seed"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rng.RandomUint(FheUint16)
	}
}

// ============================================================================
// Memory Allocation Benchmarks
// ============================================================================

func BenchmarkLatticeAllocCiphertext(b *testing.B) {
	setupBenchmark(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ct := benchEnc.Encrypt(true)
		_ = ct
	}
}

func BenchmarkLatticeAllocInteger8(b *testing.B) {
	setupBenchmark(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ct := benchBitEnc.EncryptUint64(42, FheUint8)
		_ = ct
	}
}
