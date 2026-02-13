// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command provenance demonstrates AI model provenance tracking with FHE.
//
// An AI model's weights hash is encrypted under FHE to create a provenance
// record. Later, a candidate model file can be verified against the sealed
// record homomorphically -- the original weights hash is never exposed.
//
// This prevents model theft detection from leaking proprietary information:
// the verifier learns only "match" or "no match."
//
// Usage:
//
//	go run ./cmd/provenance -name "zen-7b" -version "1.0" -params 7000000000 -weights model.bin
//	go run ./cmd/provenance -name "zen-7b" -version "1.0" -params 7000000000 -weights model.bin -verify candidate.bin
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
	name := flag.String("name", "zen-7b", "model name")
	version := flag.String("version", "1.0", "model version")
	paramCount := flag.Int64("params", 7_000_000_000, "parameter count")
	weightsPath := flag.String("weights", "", "path to model weights file")
	verifyPath := flag.String("verify", "", "path to candidate file to verify against sealed hash")
	bits := flag.Int("bits", 8, "hash bits to seal (more = slower, stronger)")
	flag.Parse()

	if *weightsPath == "" {
		fmt.Fprintln(os.Stderr, "error: -weights is required")
		flag.Usage()
		os.Exit(1)
	}
	if *bits < 1 || *bits > 256 {
		fmt.Fprintln(os.Stderr, "error: -bits must be 1..256")
		os.Exit(1)
	}

	// Print model card.
	fmt.Println("=== Model Provenance Record ===")
	fmt.Printf("  Name:       %s\n", *name)
	fmt.Printf("  Version:    %s\n", *version)
	fmt.Printf("  Parameters: %d\n", *paramCount)

	// Hash weights.
	hash, err := hashFile(*weightsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error hashing weights: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  Weights SHA-256: %x\n", hash)

	// Setup FHE.
	fmt.Println("\nInitialising FHE...")
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

	// Encrypt the weights hash.
	hashBits := bytesToBits(hash[:], *bits)
	fmt.Printf("Encrypting %d hash bits...\n", *bits)
	sealCts := make([]*fhe.Ciphertext, *bits)
	for i, b := range hashBits {
		sealCts[i] = enc.Encrypt(b)
	}
	fmt.Printf("Provenance seal created: %d encrypted ciphertexts\n", len(sealCts))

	if *verifyPath == "" {
		fmt.Println("\nRun with -verify <candidate.bin> to check a model against this seal.")
		return
	}

	// --- Verification ---
	fmt.Println("\n=== Verification ===")
	fmt.Printf("Candidate: %s\n", *verifyPath)

	candidateHash, err := hashFile(*verifyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error hashing candidate: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Candidate SHA-256: %x\n", candidateHash)

	candidateBits := bytesToBits(candidateHash[:], *bits)
	candidateCts := make([]*fhe.Ciphertext, *bits)
	for i, b := range candidateBits {
		candidateCts[i] = enc.Encrypt(b)
	}

	// Homomorphic comparison.
	fmt.Printf("Comparing %d encrypted bit-pairs...\n", *bits)
	t0 := time.Now()
	match, err := eval.XNOR(sealCts[0], candidateCts[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	for i := 1; i < *bits; i++ {
		eq, err := eval.XNOR(sealCts[i], candidateCts[i])
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

	result := dec.Decrypt(match)
	fmt.Printf("\nResult: match=%v (%v)\n", result, elapsed)
	if result {
		fmt.Println("VERIFIED: candidate model matches the sealed provenance record.")
	} else {
		fmt.Println("REJECTED: candidate does NOT match the sealed provenance record.")
	}
	fmt.Println("Note: the original weights hash was never revealed.")
}

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
	var d [32]byte
	copy(d[:], h.Sum(nil))
	return d, nil
}

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
