// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command crdt demonstrates an encrypted Last-Writer-Wins Register (LWW-Register)
// using FHE -- a core building block for fheCRDT architectures (LP-6500).
//
// Two nodes each write an encrypted (value, timestamp) pair. The merge
// operation compares timestamps homomorphically and selects the latest
// value using MUX gates, all without decrypting individual entries.
// Only the final merged state is decrypted.
//
// Usage:
//
//	go run ./cmd/crdt
//	go run ./cmd/crdt -bitsval 4 -bitsts 4
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/luxfi/fhe"
)

// encryptedRegister holds an encrypted LWW-Register entry.
type encryptedRegister struct {
	value []*fhe.Ciphertext // encrypted value bits (LSB-first)
	ts    []*fhe.Ciphertext // encrypted timestamp bits (LSB-first)
}

func main() {
	bitsVal := flag.Int("bitsval", 4, "bits for value (1..8)")
	bitsTS := flag.Int("bitsts", 4, "bits for timestamp (1..8)")
	flag.Parse()

	if *bitsVal < 1 || *bitsVal > 8 || *bitsTS < 1 || *bitsTS > 8 {
		fmt.Fprintln(os.Stderr, "error: bit widths must be 1..8")
		os.Exit(1)
	}

	// Simulate two concurrent writes.
	nodeAVal, nodeATS := uint8(7), uint8(3)  // Node A writes 7 at time 3
	nodeBVal, nodeBTS := uint8(12), uint8(5) // Node B writes 12 at time 5 (later)

	fmt.Println("=== Encrypted LWW-Register CRDT ===")
	fmt.Printf("Node A: value=%d, timestamp=%d\n", nodeAVal, nodeATS)
	fmt.Printf("Node B: value=%d, timestamp=%d\n", nodeBVal, nodeBTS)
	fmt.Printf("Expected winner: Node B (later timestamp)\n\n")

	// Setup FHE.
	fmt.Println("Initialising FHE...")
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

	// Encrypt both entries.
	regA := encryptEntry(enc, nodeAVal, nodeATS, *bitsVal, *bitsTS)
	regB := encryptEntry(enc, nodeBVal, nodeBTS, *bitsVal, *bitsTS)

	// Merge: compare timestamps, select latest.
	fmt.Println("Merging homomorphically (comparing timestamps, selecting value)...")
	t0 := time.Now()
	merged, err := merge(eval, regA, regB, *bitsVal, *bitsTS)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	elapsed := time.Since(t0)

	// Decrypt merged result.
	mergedVal := decryptUint(dec, merged.value)
	mergedTS := decryptUint(dec, merged.ts)

	fmt.Printf("\n--- Merged State ---\n")
	fmt.Printf("Value:     %d\n", mergedVal)
	fmt.Printf("Timestamp: %d\n", mergedTS)
	fmt.Printf("Elapsed:   %v\n", elapsed)

	if mergedVal == uint8(nodeBVal) && mergedTS == uint8(nodeBTS) {
		fmt.Println("PASS: merge selected the latest write (Node B).")
	} else {
		fmt.Println("FAIL: unexpected merge result!")
	}
}

func encryptEntry(enc *fhe.Encryptor, val, ts uint8, bitsVal, bitsTS int) *encryptedRegister {
	return &encryptedRegister{
		value: encryptUint(enc, val, bitsVal),
		ts:    encryptUint(enc, ts, bitsTS),
	}
}

func encryptUint(enc *fhe.Encryptor, v uint8, nbits int) []*fhe.Ciphertext {
	cts := make([]*fhe.Ciphertext, nbits)
	for i := 0; i < nbits; i++ {
		cts[i] = enc.Encrypt((v>>i)&1 == 1)
	}
	return cts
}

func decryptUint(dec *fhe.Decryptor, cts []*fhe.Ciphertext) uint8 {
	var v uint8
	for i, ct := range cts {
		if dec.Decrypt(ct) {
			v |= 1 << i
		}
	}
	return v
}

// merge performs LWW-Register merge: compare timestamps MSB-to-LSB,
// then MUX-select the winning entry's value and timestamp.
func merge(eval *fhe.Evaluator, a, b *encryptedRegister, bitsVal, bitsTS int) (*encryptedRegister, error) {
	// Compare timestamps: is B > A? (MSB-first scan)
	// bGtA starts as false, eqSoFar starts as true.
	bGtA := eval.NOT(a.ts[0]) // dummy init, overwritten below
	var eqSoFar *fhe.Ciphertext

	// We build bGtA from MSB down.
	for i := bitsTS - 1; i >= 0; i-- {
		// bitGt = B[i] AND NOT(A[i])  -- B's bit is 1, A's is 0
		bitGt, err := eval.ANDNY(a.ts[i], b.ts[i])
		if err != nil {
			return nil, fmt.Errorf("ts bit %d ANDNY: %w", i, err)
		}
		// bitEq = XNOR(A[i], B[i])
		bitEq, err := eval.XNOR(a.ts[i], b.ts[i])
		if err != nil {
			return nil, fmt.Errorf("ts bit %d XNOR: %w", i, err)
		}

		if i == bitsTS-1 {
			bGtA = bitGt
			eqSoFar = bitEq
		} else {
			// bGtA = bGtA OR (eqSoFar AND bitGt)
			contrib, err := eval.AND(eqSoFar, bitGt)
			if err != nil {
				return nil, fmt.Errorf("ts bit %d AND: %w", i, err)
			}
			bGtA, err = eval.OR(bGtA, contrib)
			if err != nil {
				return nil, fmt.Errorf("ts bit %d OR: %w", i, err)
			}
			// eqSoFar = eqSoFar AND bitEq
			eqSoFar, err = eval.AND(eqSoFar, bitEq)
			if err != nil {
				return nil, fmt.Errorf("ts bit %d eq-chain: %w", i, err)
			}
		}
	}

	// MUX-select value and timestamp: if bGtA then B else A.
	mergedVal := make([]*fhe.Ciphertext, bitsVal)
	for i := 0; i < bitsVal; i++ {
		v, err := eval.MUX(bGtA, b.value[i], a.value[i])
		if err != nil {
			return nil, fmt.Errorf("val MUX bit %d: %w", i, err)
		}
		mergedVal[i] = v
	}
	mergedTS := make([]*fhe.Ciphertext, bitsTS)
	for i := 0; i < bitsTS; i++ {
		t, err := eval.MUX(bGtA, b.ts[i], a.ts[i])
		if err != nil {
			return nil, fmt.Errorf("ts MUX bit %d: %w", i, err)
		}
		mergedTS[i] = t
	}

	return &encryptedRegister{value: mergedVal, ts: mergedTS}, nil
}
