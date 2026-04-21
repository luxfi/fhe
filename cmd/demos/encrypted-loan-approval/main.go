// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command encrypted-loan-approval demonstrates an end-to-end encrypted loan
// approval decision using Lux FHE.
//
// Two 8-bit inputs — a credit score and a debt-to-income (DTI) ratio — are
// encrypted client-side with TFHE. The lender, holding only ciphertexts and
// the public bootstrap key, evaluates two gates homomorphically:
//
//	approved_score = (credit_score >= SCORE_THRESHOLD)   // e.g. 180 on 0..255
//	approved_dti   = (dti           <  DTI_MAX)          // e.g. 100 on 0..255
//	overall        = approved_score AND approved_dti
//
// The lender never sees the plaintext inputs. Only the final boolean
// `overall` is decrypted by the key-holder and printed.
//
// This mirrors the call-shape a Solidity contract would use against the
// luxfi/precompile FHE addresses (FHEGe, FHELt, FHEAnd, Decrypt — see the
// sibling cmd/demos/encrypted-compliance/solidity_interface.sol demo).
//
// Unlike the other cmd/demos/* programs which boot a hanzoai/base HTTP
// server, this demo is a standalone CLI — run it with:
//
//	go run ./cmd/demos/encrypted-loan-approval
//	go run ./cmd/demos/encrypted-loan-approval -score 210 -dti 35
//	go run ./cmd/demos/encrypted-loan-approval -score 120 -dti 42 -min-score 180 -max-dti 45
//
// Wall time is ~30–90s on Apple M-series because of bootstrapping after
// every gate. That's the cost of noise-refresh on 128-bit-secure TFHE;
// see cmd/demos/README.md § Performance for per-gate numbers.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/luxfi/fhe"
)

const valueBits = 8 // 8-bit encoding for both score and DTI

func main() {
	var (
		score    = flag.Uint("score", 210, "applicant credit score (0–255)")
		dti      = flag.Uint("dti", 35, "debt-to-income ratio in percent (0–255)")
		minScore = flag.Uint("min-score", 180, "minimum credit score for approval")
		maxDTI   = flag.Uint("max-dti", 45, "maximum DTI for approval")
	)
	flag.Parse()

	if *score > 255 || *dti > 255 || *minScore > 255 || *maxDTI > 255 {
		fmt.Fprintln(os.Stderr, "error: all inputs must fit in 8 bits (0..255)")
		os.Exit(2)
	}

	fmt.Println("Lux FHE — encrypted loan approval demo")
	fmt.Println("======================================")
	fmt.Printf("applicant credit score = %d (threshold %d)\n", *score, *minScore)
	fmt.Printf("applicant DTI          = %d (max %d)\n", *dti, *maxDTI)
	fmt.Println()

	// ---- Setup: key generation, encryptor, evaluator, decryptor.
	t0 := time.Now()
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		log.Fatalf("parameter construction: %v", err)
	}
	keygen := fhe.NewKeyGenerator(params)
	sk, _ := keygen.GenKeyPair()
	bsk := keygen.GenBootstrapKey(sk)
	enc := fhe.NewEncryptor(params, sk)
	eval := fhe.NewEvaluator(params, bsk)
	dec := fhe.NewDecryptor(params, sk)
	fmt.Printf("[setup] keygen + bootstrap key generated in %s\n", time.Since(t0).Round(time.Millisecond))

	// ---- Client side: encrypt inputs. Only ciphertexts leave the client.
	t1 := time.Now()
	encScore := encryptByte(enc, uint8(*score))
	encDTI := encryptByte(enc, uint8(*dti))
	encScoreThreshold := encryptByte(enc, uint8(*minScore))
	encDTIThreshold := encryptByte(enc, uint8(*maxDTI))
	fmt.Printf("[client] encrypted 4 × uint8 in %s\n", time.Since(t1).Round(time.Millisecond))

	// ---- Lender side: evaluate gates on ciphertexts only.
	// Gate 1: credit_score >= min_score
	t2 := time.Now()
	encScoreOK, err := geEncrypted(eval, encScore, encScoreThreshold)
	if err != nil {
		log.Fatalf("geEncrypted(score): %v", err)
	}
	fmt.Printf("[lender] credit_score >= threshold  evaluated in %s\n",
		time.Since(t2).Round(time.Millisecond))

	// Gate 2: dti < max_dti
	t3 := time.Now()
	encDTIOK, err := ltEncrypted(eval, encDTI, encDTIThreshold)
	if err != nil {
		log.Fatalf("ltEncrypted(dti): %v", err)
	}
	fmt.Printf("[lender] dti < max                  evaluated in %s\n",
		time.Since(t3).Round(time.Millisecond))

	// Gate 3: overall = scoreOK AND dtiOK
	t4 := time.Now()
	encOverall, err := eval.AND(encScoreOK, encDTIOK)
	if err != nil {
		log.Fatalf("AND(scoreOK, dtiOK): %v", err)
	}
	fmt.Printf("[lender] scoreOK AND dtiOK          evaluated in %s\n",
		time.Since(t4).Round(time.Millisecond))

	// ---- Threshold-decrypt the boolean result. In a production deployment
	// this would be the decryption committee (see pkg/threshold/*). Here we
	// use the single-key decryptor for clarity.
	t5 := time.Now()
	scoreOK := dec.Decrypt(encScoreOK)
	dtiOK := dec.Decrypt(encDTIOK)
	overall := dec.Decrypt(encOverall)
	fmt.Printf("[decrypt] 3 booleans in %s\n", time.Since(t5).Round(time.Millisecond))

	fmt.Println()
	fmt.Println("Result")
	fmt.Println("------")
	fmt.Printf("credit_score ≥ %-3d  : %t\n", *minScore, scoreOK)
	fmt.Printf("dti           < %-3d  : %t\n", *maxDTI, dtiOK)
	fmt.Printf("overall approved    : %t\n", overall)
	fmt.Println()
	fmt.Printf("total wall time     : %s\n", time.Since(t0).Round(time.Millisecond))

	// Cross-check: verdict should match the plaintext computation. We print
	// this for reviewer confidence — it's not part of the "encrypted" path.
	wantScoreOK := uint8(*score) >= uint8(*minScore)
	wantDTIOK := uint8(*dti) < uint8(*maxDTI)
	wantOverall := wantScoreOK && wantDTIOK
	if scoreOK != wantScoreOK || dtiOK != wantDTIOK || overall != wantOverall {
		fmt.Fprintln(os.Stderr, "error: encrypted result disagrees with plaintext truth")
		fmt.Fprintf(os.Stderr, "   want score=%t dti=%t overall=%t\n", wantScoreOK, wantDTIOK, wantOverall)
		os.Exit(1)
	}
	fmt.Println("[sanity] encrypted result matches plaintext truth")
}

// encryptByte bit-decomposes v into an 8-bit little-endian array of
// encrypted bits. Matches the convention used by cmd/demos/compliance and
// cmd/demos/darkpool.
func encryptByte(enc *fhe.Encryptor, v uint8) [valueBits]*fhe.Ciphertext {
	var bits [valueBits]*fhe.Ciphertext
	for i := 0; i < valueBits; i++ {
		bits[i] = enc.Encrypt((v>>i)&1 == 1)
	}
	return bits
}

// ltEncrypted computes `a < b` on two 8-bit encrypted values using the
// MSB-first cascade used throughout cmd/demos/. At each bit it tracks
// `isLess` (a currently strictly less than b considering bits seen so
// far) and `isEqual` (a equals b so far); a strict less-than contribution
// from a later bit only flips `isLess` if all higher bits were equal.
func ltEncrypted(eval *fhe.Evaluator, a, b [valueBits]*fhe.Ciphertext) (*fhe.Ciphertext, error) {
	var isLess, isEqual *fhe.Ciphertext
	for i := valueBits - 1; i >= 0; i-- {
		bitLt, err := eval.ANDNY(a[i], b[i]) // bitLt = (!a) & b  →  "this bit makes a<b"
		if err != nil {
			return nil, fmt.Errorf("bit %d ANDNY: %w", i, err)
		}
		bitXor, err := eval.XOR(a[i], b[i])
		if err != nil {
			return nil, fmt.Errorf("bit %d XOR: %w", i, err)
		}
		bitEq := eval.NOT(bitXor)

		if isLess == nil {
			isLess = bitLt
			isEqual = bitEq
			continue
		}
		eqAndLt, err := eval.AND(isEqual, bitLt)
		if err != nil {
			return nil, fmt.Errorf("bit %d AND(isEq,bitLt): %w", i, err)
		}
		isLess, err = eval.OR(isLess, eqAndLt)
		if err != nil {
			return nil, fmt.Errorf("bit %d OR: %w", i, err)
		}
		isEqual, err = eval.AND(isEqual, bitEq)
		if err != nil {
			return nil, fmt.Errorf("bit %d AND(isEq,bitEq): %w", i, err)
		}
	}
	return isLess, nil
}

// geEncrypted computes `a >= b` as NOT(a < b).
func geEncrypted(eval *fhe.Evaluator, a, b [valueBits]*fhe.Ciphertext) (*fhe.Ciphertext, error) {
	lt, err := ltEncrypted(eval, a, b)
	if err != nil {
		return nil, err
	}
	return eval.NOT(lt), nil
}
