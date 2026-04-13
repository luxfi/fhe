// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package encrypted implements CRDT merge operations over FHE ciphertexts.
//
// Each CRDT type carries encrypted values that can be merged by an untrusted
// relay holding only the evaluation key (no secret key). Decryption is never
// required during merge, which is the core security property: the relay learns
// nothing about the plaintext while still producing correct merged state.
//
// Performance budget: every boolean gate costs one bootstrapping (~100ms at
// PN10QP27). Budget accordingly. These primitives target regulatory disclosure
// workflows where merge frequency is minutes, not milliseconds.
package encrypted

import (
	"bytes"
	"encoding/gob"
	"fmt"

	"github.com/luxfi/fhe"
)

// Register holds an encrypted LWW-Register: a (value, timestamp) pair
// where both are bit-level FHE ciphertexts. The relay can merge two
// registers by comparing timestamps homomorphically and MUX-selecting
// the winner, without ever seeing the plaintext of either field.
type Register struct {
	Value    []*fhe.Ciphertext // encrypted value bits (LSB-first)
	TS       []*fhe.Ciphertext // encrypted timestamp bits (LSB-first)
	BitsVal  int               // bit-width of value
	BitsTS   int               // bit-width of timestamp
}

// EncryptRegister encrypts a (value, timestamp) pair into an LWW Register.
func EncryptRegister(enc *fhe.Encryptor, val, ts uint64, bitsVal, bitsTS int) *Register {
	return &Register{
		Value:   encryptUint(enc, val, bitsVal),
		TS:      encryptUint(enc, ts, bitsTS),
		BitsVal: bitsVal,
		BitsTS:  bitsTS,
	}
}

// DecryptRegister recovers the plaintext (value, timestamp) from a Register.
func DecryptRegister(dec *fhe.Decryptor, r *Register) (val, ts uint64) {
	return decryptUint(dec, r.Value), decryptUint(dec, r.TS)
}

// MergeLWW merges two LWW-Registers homomorphically. The register with the
// later timestamp wins. Both registers must have identical bit-widths.
//
// Gate count: O(bitsTS) comparisons + O(bitsVal + bitsTS) MUX selections.
// At PN10QP27 with 8-bit ts and 8-bit val: ~40 bootstraps => ~4 seconds.
func MergeLWW(eval *fhe.Evaluator, a, b *Register) (*Register, error) {
	if a.BitsVal != b.BitsVal || a.BitsTS != b.BitsTS {
		return nil, fmt.Errorf("encrypted/lww: bit-width mismatch: a=(%d,%d) b=(%d,%d)",
			a.BitsVal, a.BitsTS, b.BitsVal, b.BitsTS)
	}
	return mergePair(eval, a, b)
}

// MergeLWWN merges N registers by folding left. Associativity of LWW merge
// guarantees the result is identical regardless of fold order when timestamps
// are distinct. With tied timestamps, the register with the smaller encrypted
// value wins (deterministic across all permutations).
//
// Gate count: O(N * single-merge-cost). N=1 returns the input unchanged.
func MergeLWWN(eval *fhe.Evaluator, registers ...*Register) (*Register, error) {
	if len(registers) == 0 {
		return nil, fmt.Errorf("encrypted/lww: no registers to merge")
	}
	result := registers[0]
	for i := 1; i < len(registers); i++ {
		var err error
		result, err = MergeLWW(eval, result, registers[i])
		if err != nil {
			return nil, fmt.Errorf("encrypted/lww: merge step %d: %w", i, err)
		}
	}
	return result, nil
}

// mergePair performs a single LWW merge: compare timestamps MSB-to-LSB,
// then MUX-select the winning entry's value and timestamp.
//
// Tie-break: when timestamps are equal, the register with the smaller
// encrypted value (compared MSB-to-LSB) wins. This makes merge
// commutative on ties without leaking anything to the relay.
func mergePair(eval *fhe.Evaluator, a, b *Register) (*Register, error) {
	bitsTS := a.BitsTS
	bitsVal := a.BitsVal

	// Compare timestamps: is B > A? Scan from MSB down.
	var bGtA, tsEqSoFar *fhe.Ciphertext

	for i := bitsTS - 1; i >= 0; i-- {
		bitGt, err := eval.ANDNY(a.TS[i], b.TS[i])
		if err != nil {
			return nil, fmt.Errorf("ts bit %d ANDNY: %w", i, err)
		}
		bitEq, err := eval.XNOR(a.TS[i], b.TS[i])
		if err != nil {
			return nil, fmt.Errorf("ts bit %d XNOR: %w", i, err)
		}

		if i == bitsTS-1 {
			bGtA = bitGt
			tsEqSoFar = bitEq
		} else {
			contrib, err := eval.AND(tsEqSoFar, bitGt)
			if err != nil {
				return nil, fmt.Errorf("ts bit %d AND: %w", i, err)
			}
			bGtA, err = eval.OR(bGtA, contrib)
			if err != nil {
				return nil, fmt.Errorf("ts bit %d OR: %w", i, err)
			}
			tsEqSoFar, err = eval.AND(tsEqSoFar, bitEq)
			if err != nil {
				return nil, fmt.Errorf("ts bit %d eq-chain: %w", i, err)
			}
		}
	}

	// Tie-break on value when timestamps are equal.
	// Compute "A value < B value" (i.e. "A wins" on ties means pick smaller).
	// aLtB = A < B on value bits, used only when tsEqSoFar = 1.
	var aValLtB, valEqSoFar *fhe.Ciphertext
	for i := bitsVal - 1; i >= 0; i-- {
		// aLt = A[i]=0 AND B[i]=1 => ANDNY(a, b) = NOT(a) AND b
		aLt, err := eval.ANDNY(a.Value[i], b.Value[i])
		if err != nil {
			return nil, fmt.Errorf("val-tie bit %d ANDNY: %w", i, err)
		}
		vEq, err := eval.XNOR(a.Value[i], b.Value[i])
		if err != nil {
			return nil, fmt.Errorf("val-tie bit %d XNOR: %w", i, err)
		}

		if i == bitsVal-1 {
			aValLtB = aLt
			valEqSoFar = vEq
		} else {
			contrib, err := eval.AND(valEqSoFar, aLt)
			if err != nil {
				return nil, fmt.Errorf("val-tie bit %d AND: %w", i, err)
			}
			aValLtB, err = eval.OR(aValLtB, contrib)
			if err != nil {
				return nil, fmt.Errorf("val-tie bit %d OR: %w", i, err)
			}
			valEqSoFar, err = eval.AND(valEqSoFar, vEq)
			if err != nil {
				return nil, fmt.Errorf("val-tie bit %d eq-chain: %w", i, err)
			}
		}
	}

	// tiePickB = tsEqSoFar AND NOT(aValLtB)
	// When timestamps are equal, pick B only if A is NOT smaller.
	// (If values are also equal, aValLtB=0, tiePickB=1 => pick B. This is
	// fine: total equality means both are identical, so either choice is correct.)
	notALtB := eval.NOT(aValLtB)
	tiePickB, err := eval.AND(tsEqSoFar, notALtB)
	if err != nil {
		return nil, fmt.Errorf("tie AND: %w", err)
	}

	// Final selector: pickB = bGtA OR tiePickB.
	pickB, err := eval.OR(bGtA, tiePickB)
	if err != nil {
		return nil, fmt.Errorf("final OR: %w", err)
	}

	// MUX-select value and timestamp with the combined selector.
	mergedVal := make([]*fhe.Ciphertext, bitsVal)
	for i := 0; i < bitsVal; i++ {
		v, err := eval.MUX(pickB, b.Value[i], a.Value[i])
		if err != nil {
			return nil, fmt.Errorf("val MUX bit %d: %w", i, err)
		}
		mergedVal[i] = v
	}

	mergedTS := make([]*fhe.Ciphertext, bitsTS)
	for i := 0; i < bitsTS; i++ {
		t, err := eval.MUX(pickB, b.TS[i], a.TS[i])
		if err != nil {
			return nil, fmt.Errorf("ts MUX bit %d: %w", i, err)
		}
		mergedTS[i] = t
	}

	return &Register{
		Value:   mergedVal,
		TS:      mergedTS,
		BitsVal: bitsVal,
		BitsTS:  bitsTS,
	}, nil
}

// MarshalRegister serializes a Register for network transport.
func MarshalRegister(r *Register) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(r.BitsVal); err != nil {
		return nil, err
	}
	if err := enc.Encode(r.BitsTS); err != nil {
		return nil, err
	}
	if err := encodeCiphertexts(&buf, r.Value); err != nil {
		return nil, err
	}
	if err := encodeCiphertexts(&buf, r.TS); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalRegister deserializes a Register.
func UnmarshalRegister(data []byte) (*Register, error) {
	buf := bytes.NewReader(data)
	dec := gob.NewDecoder(buf)
	var r Register
	if err := dec.Decode(&r.BitsVal); err != nil {
		return nil, err
	}
	if r.BitsVal > maxBits {
		return nil, fmt.Errorf("register BitsVal %d exceeds max %d", r.BitsVal, maxBits)
	}
	if err := dec.Decode(&r.BitsTS); err != nil {
		return nil, err
	}
	if r.BitsTS > maxBits {
		return nil, fmt.Errorf("register BitsTS %d exceeds max %d", r.BitsTS, maxBits)
	}
	var err error
	r.Value, err = decodeCiphertexts(buf, r.BitsVal)
	if err != nil {
		return nil, err
	}
	r.TS, err = decodeCiphertexts(buf, r.BitsTS)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// -- helpers --

func encryptUint(enc *fhe.Encryptor, v uint64, nbits int) []*fhe.Ciphertext {
	cts := make([]*fhe.Ciphertext, nbits)
	for i := 0; i < nbits; i++ {
		cts[i] = enc.Encrypt((v>>i)&1 == 1)
	}
	return cts
}

func decryptUint(dec *fhe.Decryptor, cts []*fhe.Ciphertext) uint64 {
	var v uint64
	for i, ct := range cts {
		if dec.Decrypt(ct) {
			v |= 1 << i
		}
	}
	return v
}

func encodeCiphertexts(buf *bytes.Buffer, cts []*fhe.Ciphertext) error {
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(len(cts)); err != nil {
		return err
	}
	for i, ct := range cts {
		data, err := ct.MarshalBinary()
		if err != nil {
			return fmt.Errorf("ct %d: %w", i, err)
		}
		if err := enc.Encode(data); err != nil {
			return fmt.Errorf("ct %d encode: %w", i, err)
		}
	}
	return nil
}

// maxBits caps the maximum number of bits (ciphertexts) per field to
// prevent OOM from malformed gob payloads.
const maxBits = 256

func decodeCiphertexts(r *bytes.Reader, n int) ([]*fhe.Ciphertext, error) {
	if n > maxBits {
		return nil, fmt.Errorf("ciphertext count %d exceeds max %d", n, maxBits)
	}
	dec := gob.NewDecoder(r)
	var count int
	if err := dec.Decode(&count); err != nil {
		return nil, err
	}
	if count != n {
		return nil, fmt.Errorf("expected %d ciphertexts, got %d", n, count)
	}
	cts := make([]*fhe.Ciphertext, n)
	for i := 0; i < n; i++ {
		var data []byte
		if err := dec.Decode(&data); err != nil {
			return nil, fmt.Errorf("ct %d: %w", i, err)
		}
		cts[i] = new(fhe.Ciphertext)
		if err := cts[i].UnmarshalBinary(data); err != nil {
			return nil, fmt.Errorf("ct %d unmarshal: %w", i, err)
		}
	}
	return cts, nil
}
