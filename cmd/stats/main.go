// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command stats demonstrates secure multiparty statistics using FHE.
//
// N parties each encrypt a private value (salary, score, etc.) as
// individual bits. The system computes the sum homomorphically using
// a ripple-carry adder built from XOR and AND gates. Only the aggregate
// sum and count are decrypted -- individual values remain private.
//
// Usage:
//
//	go run ./cmd/stats                            # 4 parties, random 4-bit values
//	go run ./cmd/stats -values 10,20,30,40        # explicit values (max 255)
//	go run ./cmd/stats -values 5,15,25            # 3 parties
package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"math/rand/v2"

	"github.com/luxfi/fhe"
)

func main() {
	valuesStr := flag.String("values", "", "comma-separated private values (max 255 each)")
	parties := flag.Int("parties", 4, "number of parties (used when -values not set)")
	maxVal := flag.Int("max", 15, "max random value per party (used when -values not set)")
	flag.Parse()

	// Parse or generate values.
	var values []uint8
	if *valuesStr != "" {
		for _, s := range strings.Split(*valuesStr, ",") {
			v, err := strconv.Atoi(strings.TrimSpace(s))
			if err != nil || v < 0 || v > 255 {
				fmt.Fprintf(os.Stderr, "error: invalid value %q (must be 0..255)\n", s)
				os.Exit(1)
			}
			values = append(values, uint8(v))
		}
	} else {
		values = make([]uint8, *parties)
		for i := range values {
			values[i] = uint8(rand.IntN(*maxVal + 1))
		}
	}
	n := len(values)
	if n < 2 {
		fmt.Fprintln(os.Stderr, "error: need at least 2 parties")
		os.Exit(1)
	}

	// Compute expected results.
	var expectedSum int
	for _, v := range values {
		expectedSum += int(v)
	}
	expectedAvg := float64(expectedSum) / float64(n)

	fmt.Println("=== Secure Multiparty Statistics ===")
	fmt.Printf("Parties: %d\n", n)
	for i, v := range values {
		fmt.Printf("  Party %d: [PRIVATE] %d\n", i+1, v)
	}
	fmt.Printf("Expected sum: %d, average: %.2f\n\n", expectedSum, expectedAvg)

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

	// Determine accumulator width: enough bits for max possible sum.
	// max sum = n * 255, need ceil(log2(n*255+1)) bits, cap at 16.
	accBits := 8
	maxSum := n * 255
	for (1 << accBits) <= maxSum {
		accBits++
	}
	if accBits > 16 {
		accBits = 16
	}
	fmt.Printf("Accumulator: %d bits (max representable sum: %d)\n", accBits, (1<<accBits)-1)

	// Encrypt each party's value as 8 bits.
	fmt.Println("Encrypting private values...")
	encValues := make([][8]*fhe.Ciphertext, n)
	for i, v := range values {
		encValues[i] = enc.EncryptByte(byte(v))
	}

	// Initialize accumulator to zero.
	acc := make([]*fhe.Ciphertext, accBits)
	for i := range acc {
		acc[i] = enc.Encrypt(false)
	}

	// Homomorphic summation: add each 8-bit value into the accumulator.
	fmt.Printf("Summing %d encrypted values...\n", n)
	t0 := time.Now()
	for p := 0; p < n; p++ {
		fmt.Printf("  Adding party %d/%d...\n", p+1, n)
		acc, err = addUint8(eval, acc, encValues[p][:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "error adding party %d: %v\n", p+1, err)
			os.Exit(1)
		}
	}
	elapsed := time.Since(t0)

	// Decrypt the sum.
	var decSum uint32
	for i, ct := range acc {
		if dec.Decrypt(ct) {
			decSum |= 1 << i
		}
	}
	decAvg := float64(decSum) / float64(n)

	fmt.Printf("\n--- Aggregated Results ---\n")
	fmt.Printf("Count:   %d parties\n", n)
	fmt.Printf("Sum:     %d (encrypted computation)\n", decSum)
	fmt.Printf("Average: %.2f\n", decAvg)
	fmt.Printf("Elapsed: %v\n", elapsed)

	if int(decSum) == expectedSum {
		fmt.Println("PASS: encrypted sum matches expected value.")
	} else {
		fmt.Printf("FAIL: expected %d, got %d\n", expectedSum, decSum)
	}
	fmt.Println("\nNote: individual values were never revealed to any party.")
}

// addUint8 adds an 8-bit encrypted value into a wider accumulator
// using a ripple-carry adder (XOR for sum, AND for carry).
func addUint8(eval *fhe.Evaluator, acc, val []*fhe.Ciphertext) ([]*fhe.Ciphertext, error) {
	result := make([]*fhe.Ciphertext, len(acc))
	var carry *fhe.Ciphertext
	// halfAdd computes sum=a^b, carry=a&b.
	halfAdd := func(a, b *fhe.Ciphertext) (*fhe.Ciphertext, *fhe.Ciphertext, error) {
		s, err := eval.XOR(a, b)
		if err != nil {
			return nil, nil, err
		}
		c, err := eval.AND(a, b)
		return s, c, err
	}
	for i := 0; i < len(acc); i++ {
		var addend *fhe.Ciphertext
		if i < len(val) {
			addend = val[i]
		}
		switch {
		case addend == nil && carry == nil:
			result[i] = acc[i]
		case carry == nil:
			result[i], carry, _ = halfAdd(acc[i], addend)
		case addend == nil:
			result[i], carry, _ = halfAdd(acc[i], carry)
		default:
			// Full adder: sum = a^b^carry, newCarry = MAJ(a,b,carry).
			ab, err := eval.XOR(acc[i], addend)
			if err != nil {
				return nil, err
			}
			if result[i], err = eval.XOR(ab, carry); err != nil {
				return nil, err
			}
			if carry, err = eval.MAJORITY(acc[i], addend, carry); err != nil {
				return nil, err
			}
		}
	}
	return result, nil
}
