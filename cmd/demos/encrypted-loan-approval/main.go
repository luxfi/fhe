// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command encrypted-loan-approval demonstrates an FHE-based loan approval
// decision where the lender never sees the borrower's underlying numbers.
//
// Flow:
//
//  1. Borrower locally encrypts (credit_score, debt_to_income) bit-by-bit
//     under their secret key.
//  2. Lender (no secret key — only the bootstrap key) homomorphically
//     evaluates the policy:
//     approved = (credit_score >= MIN_SCORE) AND (debt_to_income <= MAX_DTI)
//     This produces an encrypted boolean — the lender learns nothing about
//     the inputs, only that the evaluation terminated.
//  3. Borrower decrypts the approval bit and learns the verdict.
//
// Implementation note: this demo uses the *bit-level* Evaluator API
// (XNOR / ANDYN / AND / OR / NOT) to assemble a small ripple comparator,
// rather than the higher-level `IntegerEvaluator.Ge` path. The bit-level
// gates are the same primitives that the EVM FHE precompiles internally
// use; see ./cmd/demos/README.md for the precompile-bridge story.
//
// Usage:
//
//	go run ./cmd/demos/encrypted-loan-approval                       # defaults
//	go run ./cmd/demos/encrypted-loan-approval -score 180 -dti 30    # approved
//	go run ./cmd/demos/encrypted-loan-approval -score 120 -dti 45    # rejected
//
// Parameter set: PN10QP27. Runs in ~3–6s on a modern CPU.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/luxfi/fhe"
)

func main() {
	score := flag.Uint("score", 175, "borrower's plaintext credit score (0..255), encrypted before the lender sees it")
	dti := flag.Uint("dti", 28, "borrower's plaintext debt-to-income percentage (0..255), encrypted before the lender sees it")
	minScore := flag.Uint("min-score", 150, "lender's minimum required score (0..255)")
	maxDTI := flag.Uint("max-dti", 35, "lender's maximum allowed debt-to-income (0..255)")
	flag.Parse()

	if *score > 255 || *dti > 255 || *minScore > 255 || *maxDTI > 255 {
		fmt.Fprintln(os.Stderr, "error: all inputs must fit in 8 bits (0..255)")
		os.Exit(1)
	}

	fmt.Println("=== Encrypted Loan Approval (FHE) ===")
	fmt.Println()
	fmt.Println("Policy (public):")
	fmt.Printf("  approved = (credit_score >= %d) AND (debt_to_income <= %d)\n", *minScore, *maxDTI)
	fmt.Println()
	fmt.Println("Borrower's plaintext inputs (NEVER sent in cleartext to the lender):")
	fmt.Printf("  credit_score        = %d\n", *score)
	fmt.Printf("  debt_to_income (%%)  = %d\n", *dti)
	fmt.Println()

	expected := uint8(*score) >= uint8(*minScore) && uint8(*dti) <= uint8(*maxDTI)

	// ---------- Setup: parameters + keys ----------
	t0 := time.Now()
	fmt.Println("[1/5] Initialising FHE (PN10QP27)…")
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		fail("params: %v", err)
	}
	keygen := fhe.NewKeyGenerator(params)
	sk, _ := keygen.GenKeyPair()
	bsk := keygen.GenBootstrapKey(sk)
	enc := fhe.NewEncryptor(params, sk)
	dec := fhe.NewDecryptor(params, sk)
	eval := fhe.NewEvaluator(params, bsk)
	fmt.Printf("      done in %s\n", since(t0))

	// ---------- Step 1: borrower encrypts (8 bits each) ----------
	// The borrower never sends plaintext on the wire — only LWE ciphertexts.
	t1 := time.Now()
	fmt.Println("[2/5] Borrower encrypts (score, dti) bit-by-bit under their secret key…")
	encScore := encryptByte(enc, uint8(*score))
	encDTI := encryptByte(enc, uint8(*dti))
	// In a real deployment the policy thresholds can be plaintext (the
	// lender's published rate card) or themselves encrypted (rule book is
	// confidential). The comparator gates don't care.
	encMinScore := encryptByte(enc, uint8(*minScore))
	encMaxDTI := encryptByte(enc, uint8(*maxDTI))
	fmt.Printf("      done in %s\n", since(t1))

	// ---------- Step 2: lender evaluates "score >= min_score" ----------
	t2 := time.Now()
	fmt.Println("[3/5] Lender evaluates: score >= min_score  (8-bit cascade, ~30 bootstraps)…")
	scoreOK, err := unsignedGe8(eval, encScore, encMinScore)
	if err != nil {
		fail("Ge(score, min): %v", err)
	}
	fmt.Printf("      done in %s\n", since(t2))

	// ---------- Step 3: lender evaluates "dti <= max_dti" ----------
	t3 := time.Now()
	fmt.Println("[4/5] Lender evaluates: dti <= max_dti  (8-bit cascade, ~30 bootstraps)…")
	dtiOK, err := unsignedLe8(eval, encDTI, encMaxDTI)
	if err != nil {
		fail("Le(dti, max): %v", err)
	}
	fmt.Printf("      done in %s\n", since(t3))

	// ---------- Step 4: lender combines the two ----------
	t4 := time.Now()
	fmt.Println("[5/5] Lender combines: scoreOK AND dtiOK  (1 bootstrap)…")
	approved, err := eval.AND(scoreOK, dtiOK)
	if err != nil {
		fail("AND: %v", err)
	}
	fmt.Printf("      done in %s\n", since(t4))
	fmt.Println()

	// ---------- Step 5: borrower decrypts the verdict ----------
	plainScoreOK := dec.Decrypt(scoreOK)
	plainDTIOK := dec.Decrypt(dtiOK)
	verdict := dec.Decrypt(approved)

	fmt.Println("Borrower decrypts the verdict (lender still holds only ciphertext):")
	fmt.Printf("  scoreOK  (private)  = %v\n", plainScoreOK)
	fmt.Printf("  dtiOK    (private)  = %v\n", plainDTIOK)
	fmt.Printf("  APPROVED            = %v\n", verdict)
	fmt.Println()

	if verdict != expected {
		fmt.Fprintf(os.Stderr, "FAIL: expected %v, got %v\n", expected, verdict)
		os.Exit(2)
	}
	fmt.Printf("Total FHE wall-time: %s\n", since(t0))
	fmt.Println()
	fmt.Println("What just happened (the bridge story):")
	fmt.Println("  Each XNOR / ANDYN / AND / OR / NOT gate above is exactly the")
	fmt.Println("  primitive the EVM FHE precompile surface exposes to a smart")
	fmt.Println("  contract (FHEEq / FHELt / FHEGe / FHEAnd). The off-chain Go")
	fmt.Println("  evaluation here and the on-chain precompile evaluation are the")
	fmt.Println("  same operations on the same LWE ciphertext shape — see")
	fmt.Println("  cmd/demos/README.md for the address map.")
}

// encryptByte encrypts an 8-bit value, LSB first.
// Returns [8]*Ciphertext where index 0 is the least-significant bit.
func encryptByte(enc *fhe.Encryptor, v uint8) [8]*fhe.Ciphertext {
	var out [8]*fhe.Ciphertext
	for i := 0; i < 8; i++ {
		out[i] = enc.Encrypt(((v >> uint(i)) & 1) == 1)
	}
	return out
}

// unsignedGe8 computes (a >= b) on 8-bit encrypted unsigned integers as a
// single encrypted bit, using a textbook MSB-to-LSB ripple comparator built
// from XNOR / ANDYN / AND / OR / NOT bootstrapped gates. ~30 gates total
// (8 XNOR + 8 ANDYN + 7 AND + 7 OR + 1 NOT).
//
// Algorithm (MSB → LSB):
//
//	isLess  ← 0
//	isEqual ← 1
//	for i from msb down to lsb:
//	    bitLt   ← b[i] AND NOT(a[i])             // a[i] < b[i]
//	    bitEq   ← a[i] XNOR b[i]                 // a[i] == b[i]
//	    isLess  ← isLess OR (isEqual AND bitLt)
//	    isEqual ← isEqual AND bitEq
//	return NOT isLess                            // a >= b  ⇔  NOT (a < b)
//
// This is exactly the structure a FHEGe precompile would implement on
// 8-bit LWE ciphertexts.
//
// Implementation note: an experimental shortcut via the higher-level
// `IntegerEvaluator.Ge` (radix path) and via the `CMPCOMBINE` fused gate
// gave incorrect outputs on this parameter set during development; this
// plain-gate cascade is the version that decrypted correctly on every
// test vector. The cryptographic primitives themselves (single
// AND/OR/XNOR/NOT bootstrap) are correct.
func unsignedGe8(eval *fhe.Evaluator, a, b [8]*fhe.Ciphertext) (*fhe.Ciphertext, error) {
	var isLess, isEqual *fhe.Ciphertext

	for i := 7; i >= 0; i-- {
		// bitLt = b[i] AND NOT(a[i])  — i.e. a[i] < b[i]
		bitLt, err := eval.ANDYN(b[i], a[i])
		if err != nil {
			return nil, fmt.Errorf("bitLt[%d]: %w", i, err)
		}
		// bitEq = a[i] XNOR b[i]
		bitEq, err := eval.XNOR(a[i], b[i])
		if err != nil {
			return nil, fmt.Errorf("bitEq[%d]: %w", i, err)
		}

		if isLess == nil {
			// MSB: cascade seeds here. isLess := bitLt, isEqual := bitEq.
			isLess = bitLt
			isEqual = bitEq
			continue
		}

		// isLess := isLess OR (isEqual AND bitLt)
		eqAndLt, err := eval.AND(isEqual, bitLt)
		if err != nil {
			return nil, fmt.Errorf("AND(eq,lt)[%d]: %w", i, err)
		}
		newIsLess, err := eval.OR(isLess, eqAndLt)
		if err != nil {
			return nil, fmt.Errorf("OR(isLess)[%d]: %w", i, err)
		}
		// isEqual := isEqual AND bitEq
		newIsEqual, err := eval.AND(isEqual, bitEq)
		if err != nil {
			return nil, fmt.Errorf("AND(eq)[%d]: %w", i, err)
		}
		isLess = newIsLess
		isEqual = newIsEqual
	}

	// a >= b  ⇔  NOT (a < b)
	return eval.NOT(isLess), nil
}

// unsignedLe8 computes (a <= b) — equivalent to (b >= a).
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
