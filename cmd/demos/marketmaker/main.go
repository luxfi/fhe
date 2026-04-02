// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command marketmaker demonstrates private market making with FHE.
//
// Three market makers submit encrypted bid/ask quotes. The system selects
// the best bid (highest) and best ask (lowest) via boolean circuit comparisons.
// Only the winning quotes are decrypted -- losing quotes stay private.
//
// Usage:
//
//	go run ./cmd/demos/marketmaker
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/luxfi/fhe"
)

const priceBits = 8

type quote struct {
	maker string
	bid   uint8
	ask   uint8
}

func main() {
	fmt.Println("=== FHE Private Market Making Demo ===")
	fmt.Println("Select best bid/ask from encrypted quotes")
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

	// Three market makers
	quotes := []quote{
		{maker: "MM1", bid: 84, ask: 86},
		{maker: "MM2", bid: 85, ask: 87},
		{maker: "MM3", bid: 83, ask: 85},
	}
	for _, q := range quotes {
		fmt.Printf("  %s: bid $%d / ask $%d\n", q.maker, q.bid, q.ask)
	}
	fmt.Println()

	// Encrypt
	fmt.Println("Encrypting quotes...")
	t0 = time.Now()
	type encQuote struct {
		maker  string
		encBid [8]*fhe.Ciphertext
		encAsk [8]*fhe.Ciphertext
	}
	encQuotes := make([]encQuote, len(quotes))
	for i, q := range quotes {
		encQuotes[i].maker = q.maker
		encQuotes[i].encBid = encryptByte(enc, q.bid)
		encQuotes[i].encAsk = encryptByte(enc, q.ask)
	}
	fmt.Printf("Encryption done (%v)\n\n", time.Since(t0))

	// Best bid (highest)
	fmt.Println("Finding best bid (highest)...")
	t0 = time.Now()
	bestBidIdx := 0
	for i := 1; i < len(encQuotes); i++ {
		t1 := time.Now()
		// is encQuotes[i].bid > encQuotes[bestBidIdx].bid?
		gtResult, err := gtEncrypted(eval, encQuotes[i].encBid, encQuotes[bestBidIdx].encBid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		isGreater := dec.Decrypt(gtResult)
		fmt.Printf("  %s > %s: %v (%v)\n", encQuotes[i].maker, encQuotes[bestBidIdx].maker, isGreater, time.Since(t1))
		if isGreater {
			bestBidIdx = i
		}
	}
	fmt.Printf("Best bid found (%v)\n\n", time.Since(t0))

	// Best ask (lowest)
	fmt.Println("Finding best ask (lowest)...")
	t0 = time.Now()
	bestAskIdx := 0
	for i := 1; i < len(encQuotes); i++ {
		t1 := time.Now()
		ltResult, err := ltEncrypted(eval, encQuotes[i].encAsk, encQuotes[bestAskIdx].encAsk)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		isLess := dec.Decrypt(ltResult)
		fmt.Printf("  %s < %s: %v (%v)\n", encQuotes[i].maker, encQuotes[bestAskIdx].maker, isLess, time.Since(t1))
		if isLess {
			bestAskIdx = i
		}
	}
	fmt.Printf("Best ask found (%v)\n\n", time.Since(t0))

	// Decrypt winners
	bestBidPrice := decryptByte(dec, encQuotes[bestBidIdx].encBid)
	bestAskPrice := decryptByte(dec, encQuotes[bestAskIdx].encAsk)

	fmt.Println("--- Result ---")
	fmt.Printf("Best bid: %s @ $%d\n", encQuotes[bestBidIdx].maker, bestBidPrice)
	fmt.Printf("Best ask: %s @ $%d\n", encQuotes[bestAskIdx].maker, bestAskPrice)
	fmt.Printf("Spread: $%d\n", bestAskPrice-bestBidPrice)
	fmt.Println("\nNote: losing quotes were never decrypted.")
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

// ltEncrypted computes a < b on encrypted 8-bit values (MSB-first).
func ltEncrypted(eval *fhe.Evaluator, a, b [8]*fhe.Ciphertext) (*fhe.Ciphertext, error) {
	var isLess, isEqual *fhe.Ciphertext
	for i := priceBits - 1; i >= 0; i-- {
		bitLt, err := eval.ANDNY(a[i], b[i]) // NOT(a) AND b
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

// gtEncrypted computes a > b: same as b < a.
func gtEncrypted(eval *fhe.Evaluator, a, b [8]*fhe.Ciphertext) (*fhe.Ciphertext, error) {
	return ltEncrypted(eval, b, a)
}
