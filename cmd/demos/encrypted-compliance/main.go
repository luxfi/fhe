// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command encrypted-compliance is the off-chain companion to the
// solidity_interface.sol file in this directory. It runs exactly the same
// compliance gates against luxfi/fhe directly (Go API, no HTTP) that the
// Solidity interface would run on-chain via the luxfi/precompile FHE
// addresses (FHEGe, FHELt, FHEAnd, Decrypt).
//
// Reviewers should read both files side-by-side:
//
//	main.go                  — Go, direct luxfi/fhe calls, runnable today
//	solidity_interface.sol   — EVM, delegates to FHE precompiles, illustrative
//
// This is deliberately a different slice from cmd/demos/compliance/, which
// demonstrates SEC-style portfolio diversification as a hanzoai/base HTTP
// service. Here the focus is a single compliance check (accredited-investor
// income gate + sanction-free jurisdiction gate) run in one shot, showing
// the equivalence between the Go and Solidity call shapes.
//
// Usage:
//
//	go run ./cmd/demos/encrypted-compliance
//	go run ./cmd/demos/encrypted-compliance -income 220 -min-income 200 -jurisdiction 4 -blocked 7
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/luxfi/fhe"
)

const valueBits = 8

func main() {
	var (
		income       = flag.Uint("income", 220, "applicant income, 8-bit (0–255)")
		minIncome    = flag.Uint("min-income", 200, "minimum income for accredited-investor gate")
		jurisdiction = flag.Uint("jurisdiction", 4, "applicant jurisdiction code, 8-bit")
		blocked      = flag.Uint("blocked", 7, "a blocked jurisdiction code, 8-bit")
	)
	flag.Parse()

	for _, v := range []uint{*income, *minIncome, *jurisdiction, *blocked} {
		if v > 255 {
			fmt.Fprintln(os.Stderr, "error: all inputs must fit in 8 bits (0..255)")
			os.Exit(2)
		}
	}

	fmt.Println("Lux FHE — encrypted compliance (off-chain twin of solidity_interface.sol)")
	fmt.Println("=========================================================================")
	fmt.Printf("income          = %-3d   (threshold %d)\n", *income, *minIncome)
	fmt.Printf("jurisdiction    = %-3d   (blocked   %d)\n", *jurisdiction, *blocked)
	fmt.Println()

	// ---- Setup: params, keys, encryptor/evaluator/decryptor. In a live
	// deployment `bsk` (the bootstrap key) is public and ships with the
	// precompile view; `sk` lives in the decryption committee.
	t0 := time.Now()
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		log.Fatalf("parameters: %v", err)
	}
	kg := fhe.NewKeyGenerator(params)
	sk, _ := kg.GenKeyPair()
	bsk := kg.GenBootstrapKey(sk)
	enc := fhe.NewEncryptor(params, sk)
	eval := fhe.NewEvaluator(params, bsk)
	dec := fhe.NewDecryptor(params, sk)
	fmt.Printf("[setup] %s\n", time.Since(t0).Round(time.Millisecond))

	// ---- Encrypt client-side. These ciphertexts are what a Solidity
	// caller would pack as euint8 handles (see solidity_interface.sol).
	encIncome := encryptByte(enc, uint8(*income))
	encMinIncome := encryptByte(enc, uint8(*minIncome))
	encJurisdiction := encryptByte(enc, uint8(*jurisdiction))
	encBlocked := encryptByte(enc, uint8(*blocked))

	// ---- Gate 1 (Solidity: FHE.ge(income, minIncome)): income ≥ threshold.
	t1 := time.Now()
	encIncomeOK, err := geEncrypted(eval, encIncome, encMinIncome)
	if err != nil {
		log.Fatalf("FHEGe(income): %v", err)
	}
	fmt.Printf("[gate ] FHEGe(income, minIncome)             %s\n",
		time.Since(t1).Round(time.Millisecond))

	// ---- Gate 2 (Solidity: FHE.ne(jurisdiction, blocked)): not blocked.
	// We model ne via XOR of bits folded through OR (any bit differs ⇒ ne).
	t2 := time.Now()
	encJurisdictionOK, err := neEncrypted(eval, encJurisdiction, encBlocked)
	if err != nil {
		log.Fatalf("FHENe(jurisdiction): %v", err)
	}
	fmt.Printf("[gate ] FHENe(jurisdiction, blocked)         %s\n",
		time.Since(t2).Round(time.Millisecond))

	// ---- Gate 3 (Solidity: FHE.and(a, b)): combine.
	t3 := time.Now()
	encOverall, err := eval.AND(encIncomeOK, encJurisdictionOK)
	if err != nil {
		log.Fatalf("FHEAnd: %v", err)
	}
	fmt.Printf("[gate ] FHEAnd(incomeOK, jurisdictionOK)     %s\n",
		time.Since(t3).Round(time.Millisecond))

	// ---- Decrypt (Solidity: FHE.decrypt → FHE.reveal at IFHEDecrypt
	// precompile 0x02000000...0083 — see solidity_interface.sol).
	incomeOK := dec.Decrypt(encIncomeOK)
	jurisdictionOK := dec.Decrypt(encJurisdictionOK)
	overall := dec.Decrypt(encOverall)

	fmt.Println()
	fmt.Println("Result")
	fmt.Println("------")
	fmt.Printf("income_ok         : %t\n", incomeOK)
	fmt.Printf("jurisdiction_ok   : %t\n", jurisdictionOK)
	fmt.Printf("overall compliant : %t\n", overall)
	fmt.Println()
	fmt.Printf("total wall time   : %s\n", time.Since(t0).Round(time.Millisecond))

	// Plaintext cross-check for reviewer confidence.
	wantIncome := uint8(*income) >= uint8(*minIncome)
	wantJurisdiction := uint8(*jurisdiction) != uint8(*blocked)
	wantOverall := wantIncome && wantJurisdiction
	if incomeOK != wantIncome || jurisdictionOK != wantJurisdiction || overall != wantOverall {
		fmt.Fprintln(os.Stderr, "error: encrypted result disagrees with plaintext truth")
		os.Exit(1)
	}
	fmt.Println("[sanity] encrypted result matches plaintext truth")
}

// encryptByte: little-endian bit decomposition of an 8-bit value. Matches
// the convention of cmd/demos/compliance and cmd/demos/darkpool.
func encryptByte(enc *fhe.Encryptor, v uint8) [valueBits]*fhe.Ciphertext {
	var bits [valueBits]*fhe.Ciphertext
	for i := 0; i < valueBits; i++ {
		bits[i] = enc.Encrypt((v>>i)&1 == 1)
	}
	return bits
}

// ltEncrypted: a < b, MSB-first cascade. See the in-line comments in
// cmd/demos/encrypted-loan-approval/main.go for a line-by-line walkthrough.
func ltEncrypted(eval *fhe.Evaluator, a, b [valueBits]*fhe.Ciphertext) (*fhe.Ciphertext, error) {
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
			continue
		}
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
	return isLess, nil
}

// geEncrypted: a >= b = NOT(a < b).
func geEncrypted(eval *fhe.Evaluator, a, b [valueBits]*fhe.Ciphertext) (*fhe.Ciphertext, error) {
	lt, err := ltEncrypted(eval, a, b)
	if err != nil {
		return nil, err
	}
	return eval.NOT(lt), nil
}

// neEncrypted: a != b, computed as OR of per-bit XORs. Maps to FHE.ne on
// the Solidity side.
func neEncrypted(eval *fhe.Evaluator, a, b [valueBits]*fhe.Ciphertext) (*fhe.Ciphertext, error) {
	var acc *fhe.Ciphertext
	for i := 0; i < valueBits; i++ {
		x, err := eval.XOR(a[i], b[i])
		if err != nil {
			return nil, err
		}
		if acc == nil {
			acc = x
			continue
		}
		acc, err = eval.OR(acc, x)
		if err != nil {
			return nil, err
		}
	}
	return acc, nil
}
