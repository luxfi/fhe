// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command proof demonstrates compliance proofs on encrypted portfolios using FHE.
//
// A portfolio is encrypted. The system proves two compliance conditions:
//   - No single position exceeds 25% of total
//   - No position matches a sanctioned counterparty ID
//
// Only the boolean proof results are decrypted. Portfolio data stays encrypted.
//
// Usage:
//
//	go run ./cmd/demos/proof
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/luxfi/fhe"
)

const valueBits = 8

type position struct {
	name     string
	weight   uint8 // percentage
	entityID uint8 // counterparty ID
}

func main() {
	fmt.Println("=== FHE Compliance Proof Demo ===")
	fmt.Println("Prove compliance without revealing portfolio data")
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
		{name: "AAPL", weight: 20, entityID: 11},
		{name: "MSFT", weight: 18, entityID: 22},
		{name: "NVDA", weight: 15, entityID: 33},
		{name: "GOOG", weight: 12, entityID: 44},
		{name: "AMZN", weight: 10, entityID: 55},
	}

	sanctionedIDs := []uint8{99, 88, 77}

	fmt.Println("Portfolio (shown for verification):")
	for _, p := range portfolio {
		fmt.Printf("  %s: %d%% (entity %d)\n", p.name, p.weight, p.entityID)
	}
	fmt.Printf("Sanctioned entities: %v\n\n", sanctionedIDs)

	// Encrypt
	fmt.Println("Encrypting portfolio...")
	t0 = time.Now()
	encWeights := make([][8]*fhe.Ciphertext, len(portfolio))
	encEntities := make([][8]*fhe.Ciphertext, len(portfolio))
	for i, p := range portfolio {
		encWeights[i] = encryptByte(enc, p.weight)
		encEntities[i] = encryptByte(enc, p.entityID)
	}
	fmt.Printf("Encryption done (%v)\n\n", time.Since(t0))

	// Proof 1: max position < 25%
	fmt.Println("Proof 1: No position exceeds 25%...")
	t0 = time.Now()
	encThreshold := encryptByte(enc, 25)

	allUnder := enc.Encrypt(true)
	for i, p := range portfolio {
		t1 := time.Now()
		// weight <= 25: NOT(25 < weight)
		threshLtWeight, err := ltEncrypted(eval, encThreshold, encWeights[i])
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		withinLimit := eval.NOT(threshLtWeight) // weight <= 25

		allUnder, err = eval.AND(allUnder, withinLimit)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("  %s checked (%v)\n", p.name, time.Since(t1))
	}
	diversificationOk := dec.Decrypt(allUnder)
	fmt.Printf("  Result: %v (%v)\n\n", diversificationOk, time.Since(t0))

	// Proof 2: no sanctioned counterparty
	fmt.Println("Proof 2: No sanctioned counterparty...")
	t0 = time.Now()
	noSanctioned := enc.Encrypt(true)

	for _, sid := range sanctionedIDs {
		encSanctioned := encryptByte(enc, sid)
		for i, p := range portfolio {
			t1 := time.Now()
			// Check entity != sanctioned using XOR: if any bit differs, they are not equal
			isEqual := enc.Encrypt(true)
			for bit := 0; bit < valueBits; bit++ {
				bitXor, err := eval.XOR(encEntities[i][bit], encSanctioned[bit])
				if err != nil {
					fmt.Fprintf(os.Stderr, "error: %v\n", err)
					os.Exit(1)
				}
				bitsMatch := eval.NOT(bitXor) // bits match if XOR is 0
				isEqual, err = eval.AND(isEqual, bitsMatch)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error: %v\n", err)
					os.Exit(1)
				}
			}
			// notEqual = NOT(isEqual)
			notEqual := eval.NOT(isEqual)
			noSanctioned, err = eval.AND(noSanctioned, notEqual)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("  %s vs entity %d (%v)\n", p.name, sid, time.Since(t1))
		}
	}
	sanctionsOk := dec.Decrypt(noSanctioned)
	fmt.Printf("  Result: %v (%v)\n\n", sanctionsOk, time.Since(t0))

	// Final
	overallPass := diversificationOk && sanctionsOk
	fmt.Println("--- Result ---")
	fmt.Printf("Compliance proof: %s (portfolio data remained encrypted)\n", label(overallPass))
	fmt.Printf("  Diversification (max < 25%%): %s\n", label(diversificationOk))
	fmt.Printf("  Sanctions screening: %s\n", label(sanctionsOk))
}

func label(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}

func encryptByte(enc *fhe.Encryptor, v uint8) [8]*fhe.Ciphertext {
	var bits [8]*fhe.Ciphertext
	for i := 0; i < 8; i++ {
		bits[i] = enc.Encrypt((v>>i)&1 == 1)
	}
	return bits
}

// ltEncrypted computes a < b on 8-bit encrypted values (MSB-first).
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
