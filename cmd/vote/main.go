// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command vote demonstrates an encrypted voting system using FHE.
//
// Each voter encrypts a single yes/no ballot (1 bit) under FHE.
// The system tallies votes homomorphically using a ripple-carry adder
// built from XOR and AND gates -- individual votes are never decrypted.
// Only the final aggregate count is decrypted.
//
// Usage:
//
//	go run ./cmd/vote                           # 5 voters, random ballots
//	go run ./cmd/vote -voters 8 -yes 5          # 8 voters, 5 yes votes
//	go run ./cmd/vote -voters 4 -yes 4          # unanimous yes
package main

import (
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"time"

	"github.com/luxfi/fhe"
)

func main() {
	nVoters := flag.Int("voters", 5, "number of voters (max 15 for 4-bit tally)")
	nYes := flag.Int("yes", -1, "number of yes votes (-1 = random)")
	flag.Parse()

	if *nVoters < 2 || *nVoters > 15 {
		fmt.Fprintln(os.Stderr, "error: -voters must be 2..15")
		os.Exit(1)
	}

	// Decide votes.
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
			votes[i] = rand.IntN(2) == 1
		}
	}

	// Print plaintext votes (for demo verification).
	expectedYes := 0
	for i, v := range votes {
		label := "no"
		if v {
			label = "yes"
			expectedYes++
		}
		fmt.Printf("  Voter %d: %s\n", i+1, label)
	}
	fmt.Printf("Expected tally: %d yes / %d no\n\n", expectedYes, *nVoters-expectedYes)

	// Setup FHE.
	fmt.Println("Initialising FHE...")
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

	// Encrypt ballots.
	fmt.Println("Encrypting ballots...")
	ballots := make([]*fhe.Ciphertext, *nVoters)
	for i, v := range votes {
		ballots[i] = enc.Encrypt(v)
	}

	// Tally: 4-bit ripple-carry accumulator (supports up to 15 voters).
	const tallyBits = 4
	tally := [tallyBits]*fhe.Ciphertext{
		enc.Encrypt(false),
		enc.Encrypt(false),
		enc.Encrypt(false),
		enc.Encrypt(false),
	}

	fmt.Printf("Tallying %d ballots homomorphically (%d-bit accumulator)...\n", *nVoters, tallyBits)
	t0 := time.Now()

	for i, ballot := range ballots {
		fmt.Printf("  Adding ballot %d/%d...\n", i+1, *nVoters)
		tally, err = addBit(eval, tally, ballot)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error adding ballot %d: %v\n", i+1, err)
			os.Exit(1)
		}
	}
	elapsed := time.Since(t0)

	// Decrypt only the tally.
	var result uint8
	for i := 0; i < tallyBits; i++ {
		if dec.Decrypt(tally[i]) {
			result |= 1 << i
		}
	}

	fmt.Printf("\n--- Result ---\n")
	fmt.Printf("Encrypted tally decrypted: %d yes votes\n", result)
	fmt.Printf("Total voters: %d | No votes: %d\n", *nVoters, *nVoters-int(result))
	fmt.Printf("Elapsed: %v\n", elapsed)

	if int(result) == expectedYes {
		fmt.Println("PASS: tally matches expected count.")
	} else {
		fmt.Println("FAIL: tally mismatch!")
	}
	fmt.Println("\nNote: individual ballots were never decrypted.")
}

// addBit adds a single encrypted bit to an n-bit encrypted accumulator
// using a ripple-carry adder (XOR for sum, AND for carry).
func addBit(eval *fhe.Evaluator, acc [4]*fhe.Ciphertext, bit *fhe.Ciphertext) ([4]*fhe.Ciphertext, error) {
	carry := bit
	var result [4]*fhe.Ciphertext

	for i := 0; i < 4; i++ {
		// sum = acc[i] XOR carry
		sum, err := eval.XOR(acc[i], carry)
		if err != nil {
			return result, fmt.Errorf("bit %d XOR: %w", i, err)
		}
		// newCarry = acc[i] AND carry
		newCarry, err := eval.AND(acc[i], carry)
		if err != nil {
			return result, fmt.Errorf("bit %d AND: %w", i, err)
		}
		result[i] = sum
		carry = newCarry
	}
	return result, nil
}
