// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package tfhe

import (
	"fmt"
	"testing"
)

// BenchmarkParameters benchmarks parameter set initialization
func BenchmarkParameters(b *testing.B) {
	b.Run("PN10QP27", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := NewParametersFromLiteral(PN10QP27)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("PN11QP54", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := NewParametersFromLiteral(PN11QP54)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkKeyGeneration benchmarks key generation
func BenchmarkKeyGeneration(b *testing.B) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		b.Fatal(err)
	}
	kg := NewKeyGenerator(params)

	b.Run("SecretKey", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			kg.GenSecretKey()
		}
	})

	sk := kg.GenSecretKey()

	b.Run("PublicKey", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			kg.GenPublicKey(sk)
		}
	})

	b.Run("BootstrapKey", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			kg.GenBootstrapKey(sk)
		}
	})
}

// BenchmarkEncryption benchmarks encryption operations
func BenchmarkEncryption(b *testing.B) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		b.Fatal(err)
	}
	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	enc := NewEncryptor(params, sk)

	b.Run("Bit", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			enc.Encrypt(true)
		}
	})

	b.Run("Byte", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			enc.EncryptByte(0x42)
		}
	})
}

// BenchmarkDecryption benchmarks decryption operations
func BenchmarkDecryption(b *testing.B) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		b.Fatal(err)
	}
	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	enc := NewEncryptor(params, sk)
	dec := NewDecryptor(params, sk)

	ctBit := enc.Encrypt(true)
	ctByte := enc.EncryptByte(0x42)

	b.Run("Bit", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			dec.Decrypt(ctBit)
		}
	})

	b.Run("Byte", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			dec.DecryptByte(ctByte)
		}
	})
}

// BenchmarkGates benchmarks boolean gate operations
func BenchmarkGates(b *testing.B) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		b.Fatal(err)
	}
	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bk := kg.GenBootstrapKey(sk)
	enc := NewEncryptor(params, sk)
	eval := NewEvaluator(params, bk, sk)

	ct1 := enc.Encrypt(true)
	ct2 := enc.Encrypt(false)

	// Basic gates
	gates := []struct {
		name string
		fn   func() (*Ciphertext, error)
	}{
		{"AND", func() (*Ciphertext, error) { return eval.AND(ct1, ct2) }},
		{"OR", func() (*Ciphertext, error) { return eval.OR(ct1, ct2) }},
		{"XOR", func() (*Ciphertext, error) { return eval.XOR(ct1, ct2) }},
		{"NAND", func() (*Ciphertext, error) { return eval.NAND(ct1, ct2) }},
		{"NOR", func() (*Ciphertext, error) { return eval.NOR(ct1, ct2) }},
		{"XNOR", func() (*Ciphertext, error) { return eval.XNOR(ct1, ct2) }},
	}

	for _, gate := range gates {
		b.Run(gate.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := gate.fn()
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}

	// NOT is special (no bootstrap)
	b.Run("NOT", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			eval.NOT(ct1)
		}
	})

	// MUX
	ct3 := enc.Encrypt(true)
	b.Run("MUX", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := eval.MUX(ct1, ct2, ct3)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkMultiInputGates benchmarks multi-input gates
func BenchmarkMultiInputGates(b *testing.B) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		b.Fatal(err)
	}
	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bk := kg.GenBootstrapKey(sk)
	enc := NewEncryptor(params, sk)
	eval := NewEvaluator(params, bk, sk)

	ct1 := enc.Encrypt(true)
	ct2 := enc.Encrypt(false)
	ct3 := enc.Encrypt(true)

	b.Run("AND3", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := eval.AND3(ct1, ct2, ct3)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("OR3", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := eval.OR3(ct1, ct2, ct3)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("MAJORITY", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := eval.MAJORITY(ct1, ct2, ct3)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkSerialization benchmarks key and ciphertext serialization
func BenchmarkSerialization(b *testing.B) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		b.Fatal(err)
	}
	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	enc := NewEncryptor(params, sk)
	ct := enc.Encrypt(true)

	b.Run("SecretKey/Marshal", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := sk.MarshalBinary()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	skData, _ := sk.MarshalBinary()
	b.Run("SecretKey/Unmarshal", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			newSK := new(SecretKey)
			err := newSK.UnmarshalBinary(skData)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Ciphertext/Marshal", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := ct.MarshalBinary()
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	ctData, _ := ct.MarshalBinary()
	b.Run("Ciphertext/Unmarshal", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			newCT := new(Ciphertext)
			err := newCT.UnmarshalBinary(ctData)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkCircuit benchmarks a simple circuit (half adder)
func BenchmarkCircuit(b *testing.B) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		b.Fatal(err)
	}
	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bk := kg.GenBootstrapKey(sk)
	enc := NewEncryptor(params, sk)
	eval := NewEvaluator(params, bk, sk)

	a := enc.Encrypt(true)
	cIn := enc.Encrypt(false)

	// Half adder: sum = a XOR b, carry = a AND b
	b.Run("HalfAdder", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := eval.XOR(a, cIn)
			if err != nil {
				b.Fatal(err)
			}
			_, err = eval.AND(a, cIn)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	// Full adder: sum = a XOR b XOR cin, cout = (a AND b) OR (cin AND (a XOR b))
	c := enc.Encrypt(true)
	b.Run("FullAdder", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			axorb, err := eval.XOR(a, cIn)
			if err != nil {
				b.Fatal(err)
			}
			_, err = eval.XOR(axorb, c)
			if err != nil {
				b.Fatal(err)
			}
			aandb, err := eval.AND(a, cIn)
			if err != nil {
				b.Fatal(err)
			}
			candaxorb, err := eval.AND(c, axorb)
			if err != nil {
				b.Fatal(err)
			}
			_, err = eval.OR(aandb, candaxorb)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkThroughput measures operations per second
func BenchmarkThroughput(b *testing.B) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		b.Fatal(err)
	}
	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bk := kg.GenBootstrapKey(sk)
	enc := NewEncryptor(params, sk)
	eval := NewEvaluator(params, bk, sk)

	// Prepare many ciphertexts
	const n = 100
	cts := make([]*Ciphertext, n)
	for i := 0; i < n; i++ {
		cts[i] = enc.Encrypt(i%2 == 0)
	}

	b.Run(fmt.Sprintf("AND_Chain_%d", n), func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			result := cts[0]
			for j := 1; j < n; j++ {
				var err error
				result, err = eval.AND(result, cts[j])
				if err != nil {
					b.Fatal(err)
				}
			}
		}
	})

	b.Run(fmt.Sprintf("XOR_Chain_%d", n), func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			result := cts[0]
			for j := 1; j < n; j++ {
				var err error
				result, err = eval.XOR(result, cts[j])
				if err != nil {
					b.Fatal(err)
				}
			}
		}
	})
}

// BenchmarkMemory reports memory usage for key structures
func BenchmarkMemory(b *testing.B) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		b.Fatal(err)
	}
	kg := NewKeyGenerator(params)

	b.Run("SecretKey", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			kg.GenSecretKey()
		}
	})

	sk := kg.GenSecretKey()
	b.Run("BootstrapKey", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			kg.GenBootstrapKey(sk)
		}
	})
}
