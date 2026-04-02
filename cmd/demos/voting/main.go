// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command voting demonstrates private shareholder voting using FHE.
//
// 100 shareholders vote encrypted yes/no. Votes are tallied homomorphically
// using a ripple-carry adder on encrypted bits. Only the final count is
// decrypted -- individual votes are never revealed.
//
// Usage:
//
//	go run ./cmd/demos/voting
//	go run ./cmd/demos/voting -voters 50 -yes 30
package main

import (
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"time"

	"github.com/luxfi/fhe"
)

const tallyBits = 7 // supports up to 127 voters

func main() {
	nVoters := flag.Int("voters", 100, "number of shareholders (max 127)")
	nYes := flag.Int("yes", -1, "number of yes votes (-1 = random ~67%)")
	flag.Parse()

	if *nVoters < 2 || *nVoters > 127 {
		fmt.Fprintln(os.Stderr, "error: -voters must be 2..127")
		os.Exit(1)
	}

	fmt.Println("=== FHE Private Shareholder Voting Demo ===")
	fmt.Println("Homomorphic tally without revealing individual votes")
	fmt.Println()

	// Generate votes
	votes := make([]bool, *nVoters)
	if *nYes >= 0 {
		if *nYes > *nVoters {
			fmt.Fprintln(os.Stderr, "error: -yes cannot exceed -voters")
			os.Exit(1)
		}
		for i := 0; i < *nYes; i++ {
			votes[i] = true
		}
	} else {
		for i := range votes {
			votes[i] = rand.IntN(3) != 0 // ~67% yes
		}
	}

	expectedYes := 0
	for _, v := range votes {
		if v {
			expectedYes++
		}
	}
	fmt.Printf("Shareholders: %d | Expected: %d yes, %d no\n\n", *nVoters, expectedYes, *nVoters-expectedYes)

	// Setup FHE
	fmt.Print("Initializing FHE parameters... ")
	t0 := time.Now()
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
	fmt.Printf("done (%v)\n\n", time.Since(t0))

	// Encrypt ballots
	fmt.Printf("Encrypting %d ballots...\n", *nVoters)
	t0 = time.Now()
	ballots := make([]*fhe.Ciphertext, *nVoters)
	for i, v := range votes {
		ballots[i] = enc.Encrypt(v)
	}
	fmt.Printf("Encryption done (%v)\n\n", time.Since(t0))

	// Initialize tally accumulator (7-bit: supports 0-127)
	tally := [tallyBits]*fhe.Ciphertext{}
	for i := 0; i < tallyBits; i++ {
		tally[i] = enc.Encrypt(false)
	}

	// Tally votes homomorphically
	fmt.Printf("Tallying %d ballots homomorphically (%d-bit accumulator)...\n", *nVoters, tallyBits)
	t0 = time.Now()
	for i, ballot := range ballots {
		if (i+1)%10 == 0 || i == 0 {
			fmt.Printf("  Processing ballot %d/%d...\n", i+1, *nVoters)
		}
		tally, err = addBit(eval, tally, ballot)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error adding ballot %d: %v\n", i+1, err)
			os.Exit(1)
		}
	}
	tallyElapsed := time.Since(t0)
	fmt.Printf("Tally done (%v, %.1fms per ballot)\n\n",
		tallyElapsed, float64(tallyElapsed.Milliseconds())/float64(*nVoters))

	// Decrypt only the final tally
	var yesCount uint8
	for i := 0; i < tallyBits; i++ {
		if dec.Decrypt(tally[i]) {
			yesCount |= 1 << i
		}
	}
	noCount := *nVoters - int(yesCount)

	fmt.Println("--- Result ---")
	passed := int(yesCount) > *nVoters/2
	if passed {
		fmt.Printf("Vote passed: %d yes, %d no\n", yesCount, noCount)
	} else {
		fmt.Printf("Vote failed: %d yes, %d no\n", yesCount, noCount)
	}
	fmt.Printf("Threshold: >%d (simple majority)\n", *nVoters/2)

	if int(yesCount) == expectedYes {
		fmt.Println("PASS: tally matches expected count")
	} else {
		fmt.Println("FAIL: tally mismatch!")
	}
	fmt.Println("\nNote: individual ballots were never decrypted.")
}

// addBit adds a single encrypted bit to an n-bit encrypted accumulator
// using a ripple-carry adder (XOR for sum, AND for carry).
func addBit(eval *fhe.Evaluator, acc [tallyBits]*fhe.Ciphertext, bit *fhe.Ciphertext) ([tallyBits]*fhe.Ciphertext, error) {
	carry := bit
	var result [tallyBits]*fhe.Ciphertext

	for i := 0; i < tallyBits; i++ {
		sum, err := eval.XOR(acc[i], carry)
		if err != nil {
			return result, fmt.Errorf("bit %d XOR: %w", i, err)
		}
		newCarry, err := eval.AND(acc[i], carry)
		if err != nil {
			return result, fmt.Errorf("bit %d AND: %w", i, err)
		}
		result[i] = sum
		carry = newCarry
	}
	return result, nil
}
