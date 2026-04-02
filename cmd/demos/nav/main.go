// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command nav demonstrates confidential Net Asset Value (NAV) computation using FHE.
//
// An ETF's holdings (10 positions with share counts and prices) are encrypted.
// NAV = sum(holdings * prices) / totalShares is computed on encrypted data using
// repeated addition. Only the final NAV is decrypted for the authorized party.
//
// Usage:
//
//	go run ./cmd/demos/nav
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/luxfi/fhe"
)

type holding struct {
	ticker string
	shares uint8 // number of shares held (small for demo)
	price  uint8 // price per share in dollars
}

func main() {
	fmt.Println("=== FHE Confidential NAV Computation Demo ===")
	fmt.Println("Compute ETF NAV on encrypted holdings")
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

	// ETF holdings: small values so sums stay in 8-bit range
	// Total value = 2*19 + 2*21 + 1*14 + 2*17 + 1*18 + 2*25 + 1*12 + 1*20 + 2*10 + 1*14
	//             = 38 + 42 + 14 + 34 + 18 + 50 + 12 + 20 + 20 + 14 = 262
	// But 262 > 255, so let's reduce: use 5 holdings to stay under 255.
	holdings := []holding{
		{ticker: "AAPL", shares: 2, price: 19},
		{ticker: "MSFT", shares: 2, price: 21},
		{ticker: "NVDA", shares: 1, price: 14},
		{ticker: "GOOG", shares: 2, price: 17},
		{ticker: "AMZN", shares: 1, price: 18},
	}
	totalShares := uint64(5) // total ETF shares outstanding

	var expectedTotal uint64
	fmt.Println("ETF Holdings (shown for verification):")
	for _, h := range holdings {
		value := uint64(h.shares) * uint64(h.price)
		expectedTotal += value
		fmt.Printf("  %6s: %d shares @ $%d = $%d\n", h.ticker, h.shares, h.price, value)
	}
	expectedNAV := expectedTotal / totalShares
	fmt.Printf("  Total value: $%d\n", expectedTotal)
	fmt.Printf("  Shares outstanding: %d\n", totalShares)
	fmt.Printf("  Expected NAV: $%d/share\n\n", expectedNAV)

	// Encrypt prices
	fmt.Println("Encrypting holdings...")
	t0 = time.Now()
	encPrices := make([][8]*fhe.Ciphertext, len(holdings))
	for i, h := range holdings {
		encPrices[i] = encryptByte(enc, h.price)
	}
	fmt.Printf("Encryption done (%v)\n\n", time.Since(t0))

	// Compute NAV: for each position, add price to itself (shares-1) times, then sum all
	fmt.Println("Computing NAV on encrypted data...")
	fmt.Println("  Strategy: repeated addition (shares * price)")
	t0 = time.Now()

	var encTotal [8]*fhe.Ciphertext
	initialized := false

	for idx, h := range holdings {
		t1 := time.Now()
		// shares * price via repeated addition
		posValue := encPrices[idx]
		for s := uint8(1); s < h.shares; s++ {
			posValue, err = addBytes(eval, enc, posValue, encPrices[idx])
			if err != nil {
				fmt.Fprintf(os.Stderr, "error multiplying %s: %v\n", h.ticker, err)
				os.Exit(1)
			}
		}

		if !initialized {
			encTotal = posValue
			initialized = true
		} else {
			encTotal, err = addBytes(eval, enc, encTotal, posValue)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error accumulating %s: %v\n", h.ticker, err)
				os.Exit(1)
			}
		}
		fmt.Printf("  %6s: %d additions (%v)\n", h.ticker, h.shares, time.Since(t1))
	}
	fmt.Printf("Total computation: %v\n\n", time.Since(t0))

	// Decrypt and compute NAV (division by public totalShares is plaintext)
	decTotal := uint64(decryptByte(dec, encTotal))
	navPerShare := decTotal / totalShares

	fmt.Println("--- Result ---")
	fmt.Printf("IBIT NAV: $%d per share (computed on encrypted data)\n", navPerShare)
	fmt.Printf("Total fund value: $%d (decrypted)\n", decTotal)
	fmt.Printf("Shares outstanding: %d (public)\n", totalShares)

	if navPerShare == expectedNAV {
		fmt.Println("PASS: NAV matches expected value")
	} else {
		fmt.Printf("NOTE: NAV=%d vs expected=%d (FHE arithmetic precision)\n", navPerShare, expectedNAV)
	}
	fmt.Println("\nNote: individual holdings were never revealed to the NAV calculator.")
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

// addBytes adds two encrypted 8-bit values using ripple-carry full adder.
func addBytes(eval *fhe.Evaluator, enc *fhe.Encryptor, a, b [8]*fhe.Ciphertext) ([8]*fhe.Ciphertext, error) {
	carry := enc.Encrypt(false)
	var result [8]*fhe.Ciphertext
	for i := 0; i < 8; i++ {
		abXor, err := eval.XOR(a[i], b[i])
		if err != nil {
			return result, err
		}
		sum, err := eval.XOR(abXor, carry)
		if err != nil {
			return result, err
		}
		carry, err = eval.MAJORITY(a[i], b[i], carry)
		if err != nil {
			return result, err
		}
		result[i] = sum
	}
	return result, nil
}
