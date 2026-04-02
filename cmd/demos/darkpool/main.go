// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command darkpool demonstrates an encrypted dark pool order matching system.
//
// Traders submit encrypted limit orders (price + quantity). The matching engine
// compares encrypted bids against encrypted asks using FHE boolean circuits.
// Only matched fills are decrypted -- unmatched orders remain private.
//
// Usage:
//
//	go run ./cmd/demos/darkpool
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/luxfi/fhe"
)

const priceBits = 8 // 8-bit prices (0-255)

type order struct {
	id    int
	isBid bool
	price uint8
	qty   uint8

	encPrice [8]*fhe.Ciphertext
	encQty   [8]*fhe.Ciphertext
}

func main() {
	fmt.Println("=== FHE Dark Pool Demo ===")
	fmt.Println("Encrypted order matching without revealing prices")
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

	// Orders: 3 bids, 3 asks
	bids := []order{
		{id: 1, isBid: true, price: 85, qty: 100},
		{id: 2, isBid: true, price: 84, qty: 200},
		{id: 3, isBid: true, price: 86, qty: 75},
	}
	asks := []order{
		{id: 4, isBid: false, price: 84, qty: 100},
		{id: 5, isBid: false, price: 87, qty: 250},
		{id: 6, isBid: false, price: 85, qty: 90},
	}

	// Encrypt all orders
	fmt.Println("Encrypting 6 limit orders...")
	t0 = time.Now()
	for i := range bids {
		bids[i].encPrice = encryptByte(enc, bids[i].price)
		bids[i].encQty = encryptByte(enc, bids[i].qty)
	}
	for i := range asks {
		asks[i].encPrice = encryptByte(enc, asks[i].price)
		asks[i].encQty = encryptByte(enc, asks[i].qty)
	}
	fmt.Printf("Encryption done (%v)\n\n", time.Since(t0))

	// Match bids vs asks: bid.price >= ask.price
	fmt.Println("Matching encrypted orders (bid.price >= ask.price)...")
	type match struct {
		bid, ask order
	}
	var matches []match

	for _, bid := range bids {
		for _, ask := range asks {
			t1 := time.Now()
			isGe, err := geEncrypted(eval, bid.encPrice, ask.encPrice)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error comparing: %v\n", err)
				os.Exit(1)
			}
			isMatch := dec.Decrypt(isGe)
			elapsed := time.Since(t1)

			if isMatch {
				matches = append(matches, match{bid: bid, ask: ask})
				fmt.Printf("  Order %d vs %d: MATCH (%v)\n", bid.id, ask.id, elapsed)
			} else {
				fmt.Printf("  Order %d vs %d: no match (%v)\n", bid.id, ask.id, elapsed)
			}
		}
	}

	// Decrypt matched fills
	fmt.Printf("\n--- Matched Fills (%d) ---\n", len(matches))
	for _, m := range matches {
		bidPrice := decryptByte(dec, m.bid.encPrice)
		askPrice := decryptByte(dec, m.ask.encPrice)
		bidQty := decryptByte(dec, m.bid.encQty)
		askQty := decryptByte(dec, m.ask.encQty)

		fillQty := bidQty
		if askQty < fillQty {
			fillQty = askQty
		}
		fmt.Printf("  Matched: Buy %d @ $%d <-> Sell %d @ $%d (fill %d shares)\n",
			bidQty, bidPrice, askQty, askPrice, fillQty)
	}
	fmt.Println("\nNote: unmatched order prices were never revealed.")
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

// geEncrypted computes a >= b on encrypted 8-bit values using MSB-first comparison.
// Returns an encrypted bit: 1 if a >= b, 0 otherwise.
func geEncrypted(eval *fhe.Evaluator, a, b [8]*fhe.Ciphertext) (*fhe.Ciphertext, error) {
	// Compare from MSB to LSB: a >= b iff NOT (a < b)
	// a < b: find first bit where they differ (MSB to LSB); at that bit a=0, b=1
	var isLess, isEqual *fhe.Ciphertext

	for i := priceBits - 1; i >= 0; i-- {
		// bitLt = NOT(a[i]) AND b[i] -- this bit says a < b at position i
		bitLt, err := eval.ANDNY(a[i], b[i])
		if err != nil {
			return nil, fmt.Errorf("bit %d ANDNY: %w", i, err)
		}
		// bitEq = NOT(a[i] XOR b[i]) -- bits are equal
		bitXor, err := eval.XOR(a[i], b[i])
		if err != nil {
			return nil, fmt.Errorf("bit %d XOR: %w", i, err)
		}
		bitEq := eval.NOT(bitXor)

		if isLess == nil {
			isLess = bitLt
			isEqual = bitEq
		} else {
			// isLess = isLess OR (isEqual AND bitLt)
			eqAndLt, err := eval.AND(isEqual, bitLt)
			if err != nil {
				return nil, err
			}
			isLess, err = eval.OR(isLess, eqAndLt)
			if err != nil {
				return nil, err
			}
			// isEqual = isEqual AND bitEq
			isEqual, err = eval.AND(isEqual, bitEq)
			if err != nil {
				return nil, err
			}
		}
	}

	// a >= b is NOT(a < b)
	return eval.NOT(isLess), nil
}
