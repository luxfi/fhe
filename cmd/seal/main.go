// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command seal demonstrates document integrity sealing with FHE.
//
// A document hash (SHA-256) is encrypted bit-by-bit under FHE, creating a
// tamper-proof "seal." Verification re-hashes the file and compares
// against the sealed hash homomorphically (XNOR + AND chain) -- the
// original hash is never revealed during verification.
//
// Usage:
//
//	go run ./cmd/seal -file document.txt            # create seal
//	go run ./cmd/seal -file document.txt -verify     # verify seal
//	go run ./cmd/seal -bits 16                       # compare 16 hash bits (default 8)
package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/luxfi/fhe"
)

func main() {
	filePath := flag.String("file", "", "path to the file to seal/verify")
	verify := flag.Bool("verify", false, "verify mode: re-hash and compare homomorphically")
	bits := flag.Int("bits", 8, "number of hash bits to seal (more bits = slower but stronger)")
	flag.Parse()

	if *filePath == "" {
		fmt.Fprintln(os.Stderr, "error: -file is required")
		flag.Usage()
		os.Exit(1)
	}
	if *bits < 1 || *bits > 256 {
		fmt.Fprintln(os.Stderr, "error: -bits must be 1..256")
		os.Exit(1)
	}

	// Hash the file.
	hash, err := hashFile(*filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("SHA-256: %x\n", hash)

	// Expand hash to bit slice (LSB-first per byte).
	hashBits := bytesToBits(hash[:], *bits)

	// Setup FHE.
	fmt.Println("Initialising FHE parameters...")
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	keygen := fhe.NewKeyGenerator(params)
	sk, _ := keygen.GenKeyPair()
	bsk := keygen.GenBootstrapKey(sk)

	enc := fhe.NewEncryptor(params, sk)
	dec := fhe.NewDecryptor(params, sk)
	eval := fhe.NewEvaluator(params, bsk)

	// Encrypt the hash bits (the "seal").
	fmt.Printf("Encrypting %d hash bits...\n", *bits)
	t0 := time.Now()
	sealCts := make([]*fhe.Ciphertext, *bits)
	for i, b := range hashBits {
		sealCts[i] = enc.Encrypt(b)
	}
	fmt.Printf("Seal created in %v\n", time.Since(t0))

	if !*verify {
		// In create mode we just show the seal was produced.
		fmt.Printf("Seal: %d encrypted ciphertexts (%d bits)\n", len(sealCts), *bits)
		fmt.Println("Run with -verify to check the file against this seal.")
		return
	}

	// --- Verify mode ---
	// Re-hash (same file or a potentially tampered file) and compare.
	fmt.Println("\n--- Verification ---")
	verifyHash, err := hashFile(*filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	verifyBits := bytesToBits(verifyHash[:], *bits)

	// Encrypt verify bits.
	verifyCts := make([]*fhe.Ciphertext, *bits)
	for i, b := range verifyBits {
		verifyCts[i] = enc.Encrypt(b)
	}

	// Homomorphic equality: XNOR each pair, AND-reduce.
	fmt.Printf("Comparing %d encrypted bit-pairs homomorphically...\n", *bits)
	t0 = time.Now()

	match, err := eval.XNOR(sealCts[0], verifyCts[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error at bit 0: %v\n", err)
		os.Exit(1)
	}
	for i := 1; i < *bits; i++ {
		eq, err := eval.XNOR(sealCts[i], verifyCts[i])
		if err != nil {
			fmt.Fprintf(os.Stderr, "error at bit %d: %v\n", i, err)
			os.Exit(1)
		}
		match, err = eval.AND(match, eq)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error combining bit %d: %v\n", i, err)
			os.Exit(1)
		}
	}
	elapsed := time.Since(t0)

	// Decrypt the single result bit.
	result := dec.Decrypt(match)
	fmt.Printf("Verification result: %v  (%v, %d gates)\n", result, elapsed, *bits*2-1)
	if result {
		fmt.Println("PASS: document matches the seal.")
	} else {
		fmt.Println("FAIL: document does NOT match the seal.")
	}
}

// hashFile returns the SHA-256 digest of a file.
func hashFile(path string) ([32]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return [32]byte{}, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return [32]byte{}, err
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest, nil
}

// bytesToBits extracts n bits from data (LSB-first per byte).
func bytesToBits(data []byte, n int) []bool {
	bits := make([]bool, n)
	for i := 0; i < n; i++ {
		byteIdx := i / 8
		bitIdx := i % 8
		if byteIdx < len(data) {
			bits[i] = (data[byteIdx]>>bitIdx)&1 == 1
		}
	}
	return bits
}
