// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command mediaseal demonstrates media content authentication using FHE.
//
// A media file (image, video, audio) is hashed and the hash bits are
// encrypted under FHE, creating a "media seal" with provenance metadata.
// Verification checks a file against the seal homomorphically.
// Tamper detection: if even one byte is changed, verification fails.
//
// Usage:
//
//	go run ./cmd/mediaseal -file photo.jpg -creator "Alice" -device "iPhone"
//	go run ./cmd/mediaseal -file photo.jpg -creator "Alice" -device "iPhone" -verify photo.jpg
//	go run ./cmd/mediaseal -file photo.jpg -creator "Alice" -device "iPhone" -verify tampered.jpg
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
	filePath := flag.String("file", "", "path to original media file")
	creator := flag.String("creator", "unknown", "creator name")
	device := flag.String("device", "unknown", "capture device")
	verifyPath := flag.String("verify", "", "path to file to verify against seal")
	bits := flag.Int("bits", 8, "hash bits to seal (1..256)")
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

	// Hash original.
	origHash, err := hashFile(*filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	ts := time.Now().UTC().Format(time.RFC3339)
	fmt.Println("=== Media Seal ===")
	fmt.Printf("  File:      %s\n", *filePath)
	fmt.Printf("  Creator:   %s\n", *creator)
	fmt.Printf("  Device:    %s\n", *device)
	fmt.Printf("  Timestamp: %s\n", ts)
	fmt.Printf("  SHA-256:   %x\n", origHash)

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

	// Encrypt hash bits.
	hashBits := bytesToBits(origHash[:], *bits)
	sealCts := make([]*fhe.Ciphertext, *bits)
	for i, b := range hashBits {
		sealCts[i] = enc.Encrypt(b)
	}
	fmt.Printf("Seal created: %d encrypted hash bits\n", *bits)

	if *verifyPath == "" {
		fmt.Println("\nRun with -verify <file> to check authenticity.")
		return
	}

	// --- Verification ---
	fmt.Println("\n=== Verification ===")
	fmt.Printf("Checking: %s\n", *verifyPath)

	candHash, err := hashFile(*verifyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Candidate SHA-256: %x\n", candHash)

	// Encrypt candidate hash bits.
	candBits := bytesToBits(candHash[:], *bits)
	candCts := make([]*fhe.Ciphertext, *bits)
	for i, b := range candBits {
		candCts[i] = enc.Encrypt(b)
	}

	// Homomorphic equality check.
	fmt.Printf("Comparing %d bit-pairs homomorphically...\n", *bits)
	t0 := time.Now()

	match, err := eval.XNOR(sealCts[0], candCts[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	for i := 1; i < *bits; i++ {
		eq, err := eval.XNOR(sealCts[i], candCts[i])
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
	fmt.Printf("\nResult: authentic=%v (%v)\n", result, elapsed)

	if result {
		fmt.Println("AUTHENTIC: file matches the sealed original.")
		fmt.Printf("  Creator: %s | Device: %s | Sealed: %s\n", *creator, *device, ts)
	} else {
		fmt.Println("TAMPERED: file does NOT match the sealed original!")
		fmt.Println("  Content has been modified since sealing.")
	}
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
