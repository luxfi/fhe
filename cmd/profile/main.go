// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

//go:build profile

// Command profile runs performance profiling on TFHE operations.
//
// Usage:
//
//	go build -tags profile -o profile ./cmd/profile
//	./profile -cpu=cpu.prof -mem=mem.prof -iterations=1000
//
// Analyze profiles:
//
//	go tool pprof -http=:8080 cpu.prof
//	go tool pprof -http=:8081 mem.prof
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/luxfi/tfhe"
)

var (
	cpuProfile = flag.String("cpu", "", "write cpu profile to file")
	memProfile = flag.String("mem", "", "write memory profile to file")
	iterations = flag.Int("iterations", 100, "number of iterations for each operation")
	operation  = flag.String("op", "all", "operation to profile: all, keygen, encrypt, gates, circuit")
	verbose    = flag.Bool("v", false, "verbose output")
)

func main() {
	flag.Parse()

	// Configure profiling
	config := tfhe.ProfileConfig{
		CPUProfile: *cpuProfile,
		MemProfile: *memProfile,
	}

	profiler := tfhe.NewProfiler(config)
	if err := profiler.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start profiler: %v\n", err)
		os.Exit(1)
	}
	defer profiler.Stop()

	// Run profiling workload
	fmt.Printf("Running %d iterations of '%s'\n", *iterations, *operation)
	fmt.Printf("GOMAXPROCS: %d\n", runtime.GOMAXPROCS(0))

	switch *operation {
	case "all":
		profileAll()
	case "keygen":
		profileKeyGen()
	case "encrypt":
		profileEncrypt()
	case "gates":
		profileGates()
	case "circuit":
		profileCircuit()
	default:
		fmt.Fprintf(os.Stderr, "Unknown operation: %s\n", *operation)
		os.Exit(1)
	}

	tfhe.PrintMemStats()
}

func profileAll() {
	profileKeyGen()
	profileEncrypt()
	profileGates()
	profileCircuit()
}

func profileKeyGen() {
	fmt.Println("\n=== Key Generation ===")

	params, err := tfhe.NewParametersFromLiteral(tfhe.PN10QP27)
	if err != nil {
		panic(err)
	}
	kg := tfhe.NewKeyGenerator(params)

	// Secret key generation
	timer := tfhe.NewTimer("SecretKey generation")
	for i := 0; i < *iterations; i++ {
		kg.GenSecretKey()
	}
	d := timer.Stop()
	fmt.Printf("  Average: %v/op\n", d/time.Duration(*iterations))

	// Public key generation
	sk := kg.GenSecretKey()
	timer = tfhe.NewTimer("PublicKey generation")
	for i := 0; i < *iterations; i++ {
		kg.GenPublicKey(sk)
	}
	d = timer.Stop()
	fmt.Printf("  Average: %v/op\n", d/time.Duration(*iterations))

	// Bootstrap key generation (fewer iterations - expensive)
	bkIter := *iterations / 10
	if bkIter < 1 {
		bkIter = 1
	}
	timer = tfhe.NewTimer(fmt.Sprintf("BootstrapKey generation (%d iter)", bkIter))
	for i := 0; i < bkIter; i++ {
		kg.GenBootstrapKey(sk)
	}
	d = timer.Stop()
	fmt.Printf("  Average: %v/op\n", d/time.Duration(bkIter))
}

func profileEncrypt() {
	fmt.Println("\n=== Encryption/Decryption ===")

	params, err := tfhe.NewParametersFromLiteral(tfhe.PN10QP27)
	if err != nil {
		panic(err)
	}
	kg := tfhe.NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	enc := tfhe.NewEncryptor(params, sk)
	dec := tfhe.NewDecryptor(params, sk)

	// Bit encryption
	timer := tfhe.NewTimer("Bit encryption")
	for i := 0; i < *iterations; i++ {
		enc.Encrypt(true)
	}
	d := timer.Stop()
	fmt.Printf("  Average: %v/op\n", d/time.Duration(*iterations))

	// Bit decryption
	ct := enc.Encrypt(true)
	timer = tfhe.NewTimer("Bit decryption")
	for i := 0; i < *iterations; i++ {
		dec.Decrypt(ct)
	}
	d = timer.Stop()
	fmt.Printf("  Average: %v/op\n", d/time.Duration(*iterations))

	// Byte encryption
	timer = tfhe.NewTimer("Byte encryption")
	for i := 0; i < *iterations; i++ {
		enc.EncryptByte(0x42)
	}
	d = timer.Stop()
	fmt.Printf("  Average: %v/op\n", d/time.Duration(*iterations))

	// Byte decryption
	ctByte := enc.EncryptByte(0x42)
	timer = tfhe.NewTimer("Byte decryption")
	for i := 0; i < *iterations; i++ {
		dec.DecryptByte(ctByte)
	}
	d = timer.Stop()
	fmt.Printf("  Average: %v/op\n", d/time.Duration(*iterations))
}

func profileGates() {
	fmt.Println("\n=== Boolean Gates ===")

	params, err := tfhe.NewParametersFromLiteral(tfhe.PN10QP27)
	if err != nil {
		panic(err)
	}
	kg := tfhe.NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bk := kg.GenBootstrapKey(sk)
	enc := tfhe.NewEncryptor(params, sk)
	eval := tfhe.NewEvaluator(params, bk, sk)

	ct1 := enc.Encrypt(true)
	ct2 := enc.Encrypt(false)

	gates := []struct {
		name string
		fn   func() error
	}{
		{"AND", func() error { _, err := eval.AND(ct1, ct2); return err }},
		{"OR", func() error { _, err := eval.OR(ct1, ct2); return err }},
		{"XOR", func() error { _, err := eval.XOR(ct1, ct2); return err }},
		{"NAND", func() error { _, err := eval.NAND(ct1, ct2); return err }},
		{"NOR", func() error { _, err := eval.NOR(ct1, ct2); return err }},
		{"XNOR", func() error { _, err := eval.XNOR(ct1, ct2); return err }},
		{"NOT", func() error { eval.NOT(ct1); return nil }},
	}

	for _, gate := range gates {
		timer := tfhe.NewTimer(gate.name)
		for i := 0; i < *iterations; i++ {
			if err := gate.fn(); err != nil {
				panic(err)
			}
		}
		d := timer.Stop()
		fmt.Printf("  Average: %v/op\n", d/time.Duration(*iterations))
	}

	// MUX
	ct3 := enc.Encrypt(true)
	timer := tfhe.NewTimer("MUX")
	for i := 0; i < *iterations; i++ {
		_, err := eval.MUX(ct1, ct2, ct3)
		if err != nil {
			panic(err)
		}
	}
	d := timer.Stop()
	fmt.Printf("  Average: %v/op\n", d/time.Duration(*iterations))
}

func profileCircuit() {
	fmt.Println("\n=== Circuit Evaluation ===")

	params, err := tfhe.NewParametersFromLiteral(tfhe.PN10QP27)
	if err != nil {
		panic(err)
	}
	kg := tfhe.NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bk := kg.GenBootstrapKey(sk)
	enc := tfhe.NewEncryptor(params, sk)
	eval := tfhe.NewEvaluator(params, bk, sk)

	// 8-bit adder circuit
	a := enc.EncryptByte(0x42)
	b := enc.EncryptByte(0x37)

	timer := tfhe.NewTimer("8-bit Addition")
	for i := 0; i < *iterations; i++ {
		carry := enc.Encrypt(false)
		for bit := 0; bit < 8; bit++ {
			// Full adder for each bit
			axorb, err := eval.XOR(a[bit], b[bit])
			if err != nil {
				panic(err)
			}
			_, err = eval.XOR(axorb, carry)
			if err != nil {
				panic(err)
			}
			aandb, err := eval.AND(a[bit], b[bit])
			if err != nil {
				panic(err)
			}
			candaxorb, err := eval.AND(carry, axorb)
			if err != nil {
				panic(err)
			}
			carry, err = eval.OR(aandb, candaxorb)
			if err != nil {
				panic(err)
			}
		}
	}
	d := timer.Stop()
	fmt.Printf("  Average: %v/op\n", d/time.Duration(*iterations))

	// Gate chain (simulating complex circuit)
	n := 16
	cts := make([]*tfhe.Ciphertext, n)
	for i := 0; i < n; i++ {
		cts[i] = enc.Encrypt(i%2 == 0)
	}

	timer = tfhe.NewTimer(fmt.Sprintf("AND chain (%d gates)", n-1))
	for i := 0; i < *iterations; i++ {
		result := cts[0]
		for j := 1; j < n; j++ {
			result, err = eval.AND(result, cts[j])
			if err != nil {
				panic(err)
			}
		}
	}
	d = timer.Stop()
	fmt.Printf("  Average: %v/op\n", d/time.Duration(*iterations))
	fmt.Printf("  Per gate: %v\n", d/time.Duration(*iterations*(n-1)))
}
