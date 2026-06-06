// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command encrypted-compliance demonstrates a confidential compliance
// gate: an account holder's encrypted "sanction risk score" and
// "account balance" are checked against policy thresholds (max risk,
// min balance) without the policy engine ever seeing the underlying
// numbers.
//
// This demo is deliberately structured as the Go-side mirror of the
// Solidity precompile call in `./solidity_interface.sol` — for every
// gate evaluated here in Go, the .sol file shows the precompile address
// and signature an EVM contract would invoke. The intent is to make the
// off-chain ↔ on-chain symmetry explicit in one repo.
//
// Flow (mirrors the Solidity contract's logic):
//
//	approved = (risk_score <= MAX_RISK) AND (balance >= MIN_BALANCE)
//
// Usage:
//
//	go run ./cmd/demos/encrypted-compliance                     # defaults
//	go run ./cmd/demos/encrypted-compliance -risk 5 -balance 200
//
// Parameter set: PN10QP27. Runs in ~5–8s on a modern CPU.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/luxfi/fhe"
)

func main() {
	risk := flag.Uint("risk", 4, "encrypted risk score (0..255). Low is good.")
	balance := flag.Uint("balance", 180, "encrypted account balance (0..255 units). High is good.")
	maxRisk := flag.Uint("max-risk", 10, "policy: maximum allowed risk score")
	minBalance := flag.Uint("min-balance", 100, "policy: minimum required balance")
	flag.Parse()

	if *risk > 255 || *balance > 255 || *maxRisk > 255 || *minBalance > 255 {
		fmt.Fprintln(os.Stderr, "error: all inputs must fit in 8 bits (0..255)")
		os.Exit(1)
	}

	expected := uint8(*risk) <= uint8(*maxRisk) && uint8(*balance) >= uint8(*minBalance)

	fmt.Println("=== Encrypted Compliance Gate (FHE) ===")
	fmt.Println()
	fmt.Println("Policy (mirrors solidity_interface.sol::approveTx):")
	fmt.Printf("  approved = (risk_score <= %d) AND (balance >= %d)\n", *maxRisk, *minBalance)
	fmt.Println()

	t0 := time.Now()
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		fail("params: %v", err)
	}
	kg := fhe.NewKeyGenerator(params)
	sk, _ := kg.GenKeyPair()
	bsk := kg.GenBootstrapKey(sk)
	enc := fhe.NewEncryptor(params, sk)
	dec := fhe.NewDecryptor(params, sk)
	eval := fhe.NewEvaluator(params, bsk)
	fmt.Printf("setup            %s\n", since(t0))

	t1 := time.Now()
	encRisk := encryptByte(enc, uint8(*risk))
	encBalance := encryptByte(enc, uint8(*balance))
	encMaxRisk := encryptByte(enc, uint8(*maxRisk))
	encMinBalance := encryptByte(enc, uint8(*minBalance))
	fmt.Printf("encrypt          %s    // sol: TrivialEncrypt @ 0x0200…0080\n", since(t1))

	t2 := time.Now()
	riskOK, err := unsignedLe8(eval, encRisk, encMaxRisk)
	if err != nil {
		fail("Le(risk, maxRisk): %v", err)
	}
	fmt.Printf("FHELe(risk,max)  %s    // sol: FHE.le(risk, maxRisk)\n", since(t2))

	t3 := time.Now()
	balanceOK, err := unsignedGe8(eval, encBalance, encMinBalance)
	if err != nil {
		fail("Ge(balance, minBalance): %v", err)
	}
	fmt.Printf("FHEGe(bal,min)   %s    // sol: FHE.ge(balance, minBalance)\n", since(t3))

	t4 := time.Now()
	approved, err := eval.AND(riskOK, balanceOK)
	if err != nil {
		fail("AND: %v", err)
	}
	fmt.Printf("FHEAnd           %s    // sol: FHE.and(riskOK, balanceOK)\n", since(t4))

	verdict := dec.Decrypt(approved)
	fmt.Println()
	fmt.Printf("riskOK    = %v\n", dec.Decrypt(riskOK))
	fmt.Printf("balanceOK = %v\n", dec.Decrypt(balanceOK))
	fmt.Printf("APPROVED  = %v\n", verdict)
	fmt.Printf("\ntotal wall-time: %s\n", since(t0))

	if verdict != expected {
		fmt.Fprintf(os.Stderr, "FAIL: expected %v, got %v\n", expected, verdict)
		os.Exit(2)
	}
}

func encryptByte(enc *fhe.Encryptor, v uint8) [8]*fhe.Ciphertext {
	var out [8]*fhe.Ciphertext
	for i := 0; i < 8; i++ {
		out[i] = enc.Encrypt(((v >> uint(i)) & 1) == 1)
	}
	return out
}

// unsignedGe8: (a >= b) on 8-bit encrypted unsigned ints; see
// ../encrypted-loan-approval/main.go for the algorithm.
func unsignedGe8(eval *fhe.Evaluator, a, b [8]*fhe.Ciphertext) (*fhe.Ciphertext, error) {
	var isLess, isEqual *fhe.Ciphertext
	for i := 7; i >= 0; i-- {
		bitLt, err := eval.ANDYN(b[i], a[i])
		if err != nil {
			return nil, fmt.Errorf("bitLt[%d]: %w", i, err)
		}
		bitEq, err := eval.XNOR(a[i], b[i])
		if err != nil {
			return nil, fmt.Errorf("bitEq[%d]: %w", i, err)
		}
		if isLess == nil {
			isLess = bitLt
			isEqual = bitEq
			continue
		}
		eqAndLt, err := eval.AND(isEqual, bitLt)
		if err != nil {
			return nil, fmt.Errorf("AND(eq,lt)[%d]: %w", i, err)
		}
		newIsLess, err := eval.OR(isLess, eqAndLt)
		if err != nil {
			return nil, fmt.Errorf("OR(isLess)[%d]: %w", i, err)
		}
		newIsEqual, err := eval.AND(isEqual, bitEq)
		if err != nil {
			return nil, fmt.Errorf("AND(eq)[%d]: %w", i, err)
		}
		isLess = newIsLess
		isEqual = newIsEqual
	}
	return eval.NOT(isLess), nil
}

// unsignedLe8: (a <= b) ≡ (b >= a)
func unsignedLe8(eval *fhe.Evaluator, a, b [8]*fhe.Ciphertext) (*fhe.Ciphertext, error) {
	return unsignedGe8(eval, b, a)
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}

func since(t time.Time) time.Duration {
	return time.Since(t).Round(10 * time.Millisecond)
}
