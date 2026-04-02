// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command compliance demonstrates programmable compliance checks on encrypted portfolios.
//
// A portfolio of 5 positions is encrypted. The system verifies SEC diversification
// rules (no single position > 25% of total, total exposure < 80%) entirely on
// encrypted data using boolean circuit comparisons. Only the boolean results are
// decrypted.
//
// Usage:
//
//	go run ./cmd/demos/compliance
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/luxfi/fhe"
)

const valueBits = 8 // 8-bit values (0-255)

type position struct {
	name   string
	weight uint8 // percentage 0-100
}

func main() {
	fmt.Println("=== FHE Programmable Compliance Demo ===")
	fmt.Println("Verify SEC diversification on encrypted portfolio")
	fmt.Println()

	// Setup
	fmt.Print("Initializing FHE... ")
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

	// Portfolio
	portfolio := []position{
		{name: "AAPL", weight: 20},
		{name: "MSFT", weight: 18},
		{name: "NVDA", weight: 15},
		{name: "GOOG", weight: 12},
		{name: "AMZN", weight: 10},
	}
	var totalWeight uint8
	for _, p := range portfolio {
		totalWeight += p.weight
		fmt.Printf("  %s: %d%%\n", p.name, p.weight)
	}
	fmt.Printf("  Total exposure: %d%%\n\n", totalWeight)

	// Encrypt positions
	fmt.Println("Encrypting portfolio positions...")
	t0 = time.Now()
	encWeights := make([][8]*fhe.Ciphertext, len(portfolio))
	for i, p := range portfolio {
		encWeights[i] = encryptByte(enc, p.weight)
	}
	// Encrypt threshold (25%) as constant for comparison
	encThreshold := encryptByte(enc, 25)
	fmt.Printf("Encryption done (%v)\n\n", time.Since(t0))

	// Check 1: no single position > 25%
	fmt.Println("Check 1: Each position <= 25%...")
	t0 = time.Now()
	allCompliant := enc.Encrypt(true) // accumulator
	for i, p := range portfolio {
		t1 := time.Now()
		// leEncrypted returns 1 if weight <= 25
		leResult, err := leEncrypted(eval, encWeights[i], encThreshold)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		// AND into accumulator
		allCompliant, err = eval.AND(allCompliant, leResult)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("  %s checked (%v)\n", p.name, time.Since(t1))
	}
	check1 := dec.Decrypt(allCompliant)
	fmt.Printf("  Diversification: %v (%v)\n\n", check1, time.Since(t0))

	// Check 2: total exposure < 80%
	fmt.Println("Check 2: Total exposure < 80%...")
	t0 = time.Now()
	// Sum weights using ripple-carry adder
	encTotal := encWeights[0]
	for i := 1; i < len(encWeights); i++ {
		t1 := time.Now()
		encTotal, err = addBytes(eval, enc, encTotal, encWeights[i])
		if err != nil {
			fmt.Fprintf(os.Stderr, "error adding: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("  Added position %d (%v)\n", i+1, time.Since(t1))
	}

	encMaxExposure := encryptByte(enc, 80)
	t1 := time.Now()
	ltResult, err := ltEncrypted(eval, encTotal, encMaxExposure)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	check2 := dec.Decrypt(ltResult)
	fmt.Printf("  Total < 80%%: %v (%v)\n\n", check2, time.Since(t1))

	// Verify
	decTotal := decryptByte(dec, encTotal)
	fmt.Printf("  (Verification: encrypted total decrypts to %d%%)\n\n", decTotal)

	// Final
	fmt.Println("--- Result ---")
	fmt.Printf("Portfolio compliant: %v\n", check1 && check2)
	fmt.Println("(Holdings were never revealed to the compliance engine)")
}

func encryptByte(enc *fhe.Encryptor, v uint8) [8]*fhe.Ciphertext {
	var bits [8]*fhe.Ciphertext
	for i := 0; i < 8; i++ {
		bits[i] = enc.Encrypt((v>>i)&1 == 1)
	}
	return bits
}

func decryptByte(dec *fhe.Decryptor, bits [8]*fhe.Ciphertext) uint8 {
	var v uint8
	for i := 0; i < 8; i++ {
		if dec.Decrypt(bits[i]) {
			v |= 1 << i
		}
	}
	return v
}

// addBytes adds two encrypted 8-bit values using ripple-carry.
func addBytes(eval *fhe.Evaluator, enc *fhe.Encryptor, a, b [8]*fhe.Ciphertext) ([8]*fhe.Ciphertext, error) {
	carry := enc.Encrypt(false)
	var result [8]*fhe.Ciphertext
	for i := 0; i < 8; i++ {
		// sum = a XOR b XOR carry (full adder)
		abXor, err := eval.XOR(a[i], b[i])
		if err != nil {
			return result, err
		}
		sum, err := eval.XOR(abXor, carry)
		if err != nil {
			return result, err
		}
		// carry = MAJORITY(a, b, carry)
		carry, err = eval.MAJORITY(a[i], b[i], carry)
		if err != nil {
			return result, err
		}
		result[i] = sum
	}
	return result, nil
}

// ltEncrypted computes a < b on encrypted 8-bit values.
func ltEncrypted(eval *fhe.Evaluator, a, b [8]*fhe.Ciphertext) (*fhe.Ciphertext, error) {
	var isLess, isEqual *fhe.Ciphertext
	for i := valueBits - 1; i >= 0; i-- {
		bitLt, err := eval.ANDNY(a[i], b[i])
		if err != nil {
			return nil, err
		}
		bitXor, err := eval.XOR(a[i], b[i])
		if err != nil {
			return nil, err
		}
		bitEq := eval.NOT(bitXor)
		if isLess == nil {
			isLess = bitLt
			isEqual = bitEq
		} else {
			eqAndLt, err := eval.AND(isEqual, bitLt)
			if err != nil {
				return nil, err
			}
			isLess, err = eval.OR(isLess, eqAndLt)
			if err != nil {
				return nil, err
			}
			isEqual, err = eval.AND(isEqual, bitEq)
			if err != nil {
				return nil, err
			}
		}
	}
	return isLess, nil
}

// leEncrypted computes a <= b: NOT(b < a).
func leEncrypted(eval *fhe.Evaluator, a, b [8]*fhe.Ciphertext) (*fhe.Ciphertext, error) {
	bLtA, err := ltEncrypted(eval, b, a)
	if err != nil {
		return nil, err
	}
	return eval.NOT(bLtA), nil
}
