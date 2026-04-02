// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command auction demonstrates an encrypted sealed-bid auction using FHE.
//
// Five participants submit encrypted sealed bids. The system determines the
// winner via boolean circuit max computation. Only the winning bid is decrypted.
//
// Usage:
//
//	go run ./cmd/demos/auction
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/luxfi/fhe"
)

const bidBits = 8

type bid struct {
	participant string
	amount      uint8
	encAmount   [8]*fhe.Ciphertext
}

func main() {
	fmt.Println("=== FHE Encrypted Sealed-Bid Auction Demo ===")
	fmt.Println("Determine winner without revealing losing bids")
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

	// Five sealed bids
	bids := []bid{
		{participant: "Participant 1", amount: 84},
		{participant: "Participant 2", amount: 92},
		{participant: "Participant 3", amount: 97},
		{participant: "Participant 4", amount: 83},
		{participant: "Participant 5", amount: 88},
	}

	fmt.Println("Sealed bids (shown for demo verification only):")
	for _, b := range bids {
		fmt.Printf("  %s: $%d\n", b.participant, b.amount)
	}
	fmt.Println()

	// Encrypt
	fmt.Println("Encrypting sealed bids...")
	t0 = time.Now()
	for i := range bids {
		bids[i].encAmount = encryptByte(enc, bids[i].amount)
	}
	fmt.Printf("Encryption done (%v)\n\n", time.Since(t0))

	// Tournament: find max via pairwise comparison
	fmt.Println("Determining winner via encrypted comparisons...")
	t0 = time.Now()
	winnerIdx := 0
	for i := 1; i < len(bids); i++ {
		t1 := time.Now()
		gtResult, err := gtEncrypted(eval, bids[i].encAmount, bids[winnerIdx].encAmount)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		isGreater := dec.Decrypt(gtResult)
		elapsed := time.Since(t1)
		if isGreater {
			fmt.Printf("  %s > %s: true (%v) -> new leader\n",
				bids[i].participant, bids[winnerIdx].participant, elapsed)
			winnerIdx = i
		} else {
			fmt.Printf("  %s > %s: false (%v)\n",
				bids[i].participant, bids[winnerIdx].participant, elapsed)
		}
	}
	fmt.Printf("Tournament done (%v)\n\n", time.Since(t0))

	// Decrypt winner only
	winningAmount := decryptByte(dec, bids[winnerIdx].encAmount)

	fmt.Println("--- Result ---")
	fmt.Printf("Winner: %s @ $%d\n", bids[winnerIdx].participant, winningAmount)
	fmt.Println("\nNote: losing bid amounts were never decrypted.")
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

// ltEncrypted computes a < b on 8-bit encrypted values (MSB-first comparison).
func ltEncrypted(eval *fhe.Evaluator, a, b [8]*fhe.Ciphertext) (*fhe.Ciphertext, error) {
	var isLess, isEqual *fhe.Ciphertext
	for i := bidBits - 1; i >= 0; i-- {
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

// gtEncrypted computes a > b: same as b < a.
func gtEncrypted(eval *fhe.Evaluator, a, b [8]*fhe.Ciphertext) (*fhe.Ciphertext, error) {
	return ltEncrypted(eval, b, a)
}
