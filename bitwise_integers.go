// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

// This file implements integer operations using bit-level boolean circuits.
// This approach uses the working TFHE boolean gates (AND, OR, XOR, NOT) as
// building blocks, avoiding any patented LUT-based integer techniques.
//
// Based on classic FHE techniques from Chillotti et al. (pre-2020 prior art).

package tfhe

import (
	"fmt"

	"github.com/luxfi/lattice/v6/core/rlwe"
)

// BitCiphertext represents an encrypted integer as a vector of encrypted bits.
// LSB is at index 0.
type BitCiphertext struct {
	bits    []*Ciphertext
	numBits int
	fheType FheUintType
}

// Type returns the FHE type
func (bc *BitCiphertext) Type() FheUintType {
	return bc.fheType
}

// NumBits returns the number of bits
func (bc *BitCiphertext) NumBits() int {
	return bc.numBits
}

// WrapBoolCiphertext wraps a single bit ciphertext into a BitCiphertext of type FheBool
func WrapBoolCiphertext(ct *Ciphertext) *BitCiphertext {
	return &BitCiphertext{
		bits:    []*Ciphertext{ct},
		numBits: 1,
		fheType: FheBool,
	}
}

// BitwiseEncryptor encrypts integers as bit vectors
type BitwiseEncryptor struct {
	params Parameters
	enc    *Encryptor
}

// NewBitwiseEncryptor creates a new bitwise encryptor using secret key
func NewBitwiseEncryptor(params Parameters, sk *SecretKey) *BitwiseEncryptor {
	return &BitwiseEncryptor{
		params: params,
		enc:    NewEncryptor(params, sk),
	}
}

// BitwisePublicEncryptor encrypts integers as bit vectors using public key
// This allows users to encrypt without having the secret key
type BitwisePublicEncryptor struct {
	params Parameters
	enc    *rlwe.Encryptor
}

// NewBitwisePublicEncryptor creates a new bitwise encryptor using public key
func NewBitwisePublicEncryptor(params Parameters, pk *PublicKey) *BitwisePublicEncryptor {
	return &BitwisePublicEncryptor{
		params: params,
		enc:    rlwe.NewEncryptor(params.paramsLWE, pk.PKLWE),
	}
}

// Encrypt encrypts a single bit using public key encryption
func (enc *BitwisePublicEncryptor) Encrypt(value bool) (*Ciphertext, error) {
	pt := rlwe.NewPlaintext(enc.params.paramsLWE, enc.params.paramsLWE.MaxLevel())
	q := enc.params.QLWE()

	// Encode bit as Q/8 (true) or -Q/8 (false)
	if value {
		pt.Value.Coeffs[0][0] = q / 8
	} else {
		pt.Value.Coeffs[0][0] = q - (q / 8) // -Q/8 mod Q
	}

	enc.params.paramsLWE.RingQ().NTT(pt.Value, pt.Value)

	ct := rlwe.NewCiphertext(enc.params.paramsLWE, 1, enc.params.paramsLWE.MaxLevel())
	if err := enc.enc.Encrypt(pt, ct); err != nil {
		return nil, fmt.Errorf("public key encrypt: %w", err)
	}
	ct.IsNTT = true

	return &Ciphertext{ct}, nil
}

// EncryptUint64 encrypts a uint64 value as a bit vector using public key
func (enc *BitwisePublicEncryptor) EncryptUint64(value uint64, t FheUintType) (*BitCiphertext, error) {
	numBits := t.NumBits()
	bits := make([]*Ciphertext, numBits)

	for i := 0; i < numBits; i++ {
		bit := (value >> i) & 1
		ct, err := enc.Encrypt(bit == 1)
		if err != nil {
			return nil, fmt.Errorf("bit %d: %w", i, err)
		}
		bits[i] = ct
	}

	return &BitCiphertext{
		bits:    bits,
		numBits: numBits,
		fheType: t,
	}, nil
}

// EncryptUint64 encrypts a uint64 value as a bit vector
func (enc *BitwiseEncryptor) EncryptUint64(value uint64, t FheUintType) *BitCiphertext {
	numBits := t.NumBits()
	bits := make([]*Ciphertext, numBits)

	for i := 0; i < numBits; i++ {
		bit := (value >> i) & 1
		bits[i] = enc.enc.Encrypt(bit == 1)
	}

	return &BitCiphertext{
		bits:    bits,
		numBits: numBits,
		fheType: t,
	}
}

// BitwiseDecryptor decrypts bit vectors to integers
type BitwiseDecryptor struct {
	params Parameters
	dec    *Decryptor
}

// NewBitwiseDecryptor creates a new bitwise decryptor
func NewBitwiseDecryptor(params Parameters, sk *SecretKey) *BitwiseDecryptor {
	return &BitwiseDecryptor{
		params: params,
		dec:    NewDecryptor(params, sk),
	}
}

// DecryptUint64 decrypts a bit vector to a uint64
func (dec *BitwiseDecryptor) DecryptUint64(bc *BitCiphertext) uint64 {
	var result uint64
	for i := 0; i < bc.numBits; i++ {
		if dec.dec.Decrypt(bc.bits[i]) {
			result |= (1 << i)
		}
	}
	return result
}

// BitwiseEvaluator performs operations on bit vectors using boolean circuits
type BitwiseEvaluator struct {
	params Parameters
	eval   *Evaluator
}

// NewBitwiseEvaluator creates a new bitwise evaluator
func NewBitwiseEvaluator(params Parameters, bsk *BootstrapKey, sk *SecretKey) *BitwiseEvaluator {
	return &BitwiseEvaluator{
		params: params,
		eval:   NewEvaluator(params, bsk),
	}
}

// FullAdder computes sum and carry for a + b + cin
// sum = a XOR b XOR cin
// cout = (a AND b) OR (cin AND (a XOR b))
func (eval *BitwiseEvaluator) FullAdder(a, b, cin *Ciphertext) (sum, cout *Ciphertext, err error) {
	// a XOR b
	axorb, err := eval.eval.XOR(a, b)
	if err != nil {
		return nil, nil, fmt.Errorf("xor(a,b): %w", err)
	}

	// sum = axorb XOR cin
	sum, err = eval.eval.XOR(axorb, cin)
	if err != nil {
		return nil, nil, fmt.Errorf("xor(axorb,cin): %w", err)
	}

	// a AND b
	aandb, err := eval.eval.AND(a, b)
	if err != nil {
		return nil, nil, fmt.Errorf("and(a,b): %w", err)
	}

	// cin AND (a XOR b)
	cinAndAxorb, err := eval.eval.AND(cin, axorb)
	if err != nil {
		return nil, nil, fmt.Errorf("and(cin,axorb): %w", err)
	}

	// cout = (a AND b) OR (cin AND (a XOR b))
	cout, err = eval.eval.OR(aandb, cinAndAxorb)
	if err != nil {
		return nil, nil, fmt.Errorf("or: %w", err)
	}

	return sum, cout, nil
}

// HalfAdder computes sum and carry for a + b
// sum = a XOR b
// cout = a AND b
func (eval *BitwiseEvaluator) HalfAdder(a, b *Ciphertext) (sum, cout *Ciphertext, err error) {
	sum, err = eval.eval.XOR(a, b)
	if err != nil {
		return nil, nil, err
	}

	cout, err = eval.eval.AND(a, b)
	if err != nil {
		return nil, nil, err
	}

	return sum, cout, nil
}

// Add performs ripple-carry addition on two bit vectors
func (eval *BitwiseEvaluator) Add(a, b *BitCiphertext) (*BitCiphertext, error) {
	if a.fheType != b.fheType {
		return nil, fmt.Errorf("type mismatch: %s vs %s", a.fheType, b.fheType)
	}
	if a.numBits != b.numBits {
		return nil, fmt.Errorf("bit count mismatch: %d vs %d", a.numBits, b.numBits)
	}

	numBits := a.numBits
	result := make([]*Ciphertext, numBits)

	// First bit: half adder
	sum, carry, err := eval.HalfAdder(a.bits[0], b.bits[0])
	if err != nil {
		return nil, fmt.Errorf("bit 0: %w", err)
	}
	result[0] = sum

	// Remaining bits: full adders
	for i := 1; i < numBits; i++ {
		sum, carry, err = eval.FullAdder(a.bits[i], b.bits[i], carry)
		if err != nil {
			return nil, fmt.Errorf("bit %d: %w", i, err)
		}
		result[i] = sum
	}
	// Final carry is discarded (overflow)

	return &BitCiphertext{
		bits:    result,
		numBits: numBits,
		fheType: a.fheType,
	}, nil
}

// ScalarAdd adds a scalar to a bit vector
func (eval *BitwiseEvaluator) ScalarAdd(a *BitCiphertext, scalar uint64) (*BitCiphertext, error) {
	numBits := a.numBits
	result := make([]*Ciphertext, numBits)

	// Get first scalar bit
	scalarBit0 := (scalar & 1) == 1

	// First bit: conditional half adder or copy
	var carry *Ciphertext
	var err error

	if scalarBit0 {
		// a + 1: sum = NOT a, carry = a
		result[0] = eval.eval.NOT(a.bits[0])
		carry = a.bits[0] // carry = a.bits[0] (if a=1, there's a carry)
	} else {
		// a + 0: sum = a, carry = 0
		result[0] = a.bits[0]
		carry = eval.encryptBit(false) // carry = 0
	}

	// Remaining bits
	for i := 1; i < numBits; i++ {
		scalarBit := ((scalar >> i) & 1) == 1

		if scalarBit {
			// a + 1 + carry: full adder with b=1
			// sum = a XOR 1 XOR carry = NOT(a) XOR carry
			notA := eval.eval.NOT(a.bits[i])
			result[i], err = eval.eval.XOR(notA, carry)
			if err != nil {
				return nil, fmt.Errorf("bit %d xor: %w", i, err)
			}

			// cout = (a AND 1) OR (carry AND (a XOR 1))
			//      = a OR (carry AND NOT(a))
			carryAndNotA, err := eval.eval.AND(carry, notA)
			if err != nil {
				return nil, fmt.Errorf("bit %d and: %w", i, err)
			}
			carry, err = eval.eval.OR(a.bits[i], carryAndNotA)
			if err != nil {
				return nil, fmt.Errorf("bit %d or: %w", i, err)
			}
		} else {
			// a + 0 + carry: half adder with carry
			result[i], carry, err = eval.HalfAdder(a.bits[i], carry)
			if err != nil {
				return nil, fmt.Errorf("bit %d: %w", i, err)
			}
		}
	}

	return &BitCiphertext{
		bits:    result,
		numBits: numBits,
		fheType: a.fheType,
	}, nil
}

// encryptBit creates a trivial encryption of a constant bit (for internal use)
func (eval *BitwiseEvaluator) encryptBit(value bool) *Ciphertext {
	// Create a trivial ciphertext (noiseless encryption)
	pt := rlwe.NewPlaintext(eval.params.paramsLWE, eval.params.paramsLWE.MaxLevel())

	q := eval.params.QLWE()
	if value {
		pt.Value.Coeffs[0][0] = q / 8
	} else {
		pt.Value.Coeffs[0][0] = q - (q / 8)
	}

	eval.params.paramsLWE.RingQ().NTT(pt.Value, pt.Value)

	ct := rlwe.NewCiphertext(eval.params.paramsLWE, 1, eval.params.paramsLWE.MaxLevel())
	// b = message (trivial encryption: a = 0, b = m)
	ct.Value[0] = *pt.Value.CopyNew()
	// a = 0 (already initialized to zero)
	ct.IsNTT = true

	return &Ciphertext{ct}
}

// Sub performs subtraction a - b using two's complement
func (eval *BitwiseEvaluator) Sub(a, b *BitCiphertext) (*BitCiphertext, error) {
	if a.fheType != b.fheType {
		return nil, fmt.Errorf("type mismatch: %s vs %s", a.fheType, b.fheType)
	}

	// Two's complement: a - b = a + NOT(b) + 1
	// NOT(b)
	notB := eval.Not(b)

	// a + NOT(b)
	sum, err := eval.Add(a, notB)
	if err != nil {
		return nil, err
	}

	// Add 1
	return eval.ScalarAdd(sum, 1)
}

// Not performs bitwise NOT
func (eval *BitwiseEvaluator) Not(a *BitCiphertext) *BitCiphertext {
	result := make([]*Ciphertext, a.numBits)
	for i := 0; i < a.numBits; i++ {
		result[i] = eval.eval.NOT(a.bits[i])
	}
	return &BitCiphertext{
		bits:    result,
		numBits: a.numBits,
		fheType: a.fheType,
	}
}

// And performs bitwise AND
func (eval *BitwiseEvaluator) And(a, b *BitCiphertext) (*BitCiphertext, error) {
	if a.numBits != b.numBits {
		return nil, fmt.Errorf("bit count mismatch")
	}

	result := make([]*Ciphertext, a.numBits)
	for i := 0; i < a.numBits; i++ {
		r, err := eval.eval.AND(a.bits[i], b.bits[i])
		if err != nil {
			return nil, err
		}
		result[i] = r
	}
	return &BitCiphertext{
		bits:    result,
		numBits: a.numBits,
		fheType: a.fheType,
	}, nil
}

// Or performs bitwise OR
func (eval *BitwiseEvaluator) Or(a, b *BitCiphertext) (*BitCiphertext, error) {
	if a.numBits != b.numBits {
		return nil, fmt.Errorf("bit count mismatch")
	}

	result := make([]*Ciphertext, a.numBits)
	for i := 0; i < a.numBits; i++ {
		r, err := eval.eval.OR(a.bits[i], b.bits[i])
		if err != nil {
			return nil, err
		}
		result[i] = r
	}
	return &BitCiphertext{
		bits:    result,
		numBits: a.numBits,
		fheType: a.fheType,
	}, nil
}

// Xor performs bitwise XOR
func (eval *BitwiseEvaluator) Xor(a, b *BitCiphertext) (*BitCiphertext, error) {
	if a.numBits != b.numBits {
		return nil, fmt.Errorf("bit count mismatch")
	}

	result := make([]*Ciphertext, a.numBits)
	for i := 0; i < a.numBits; i++ {
		r, err := eval.eval.XOR(a.bits[i], b.bits[i])
		if err != nil {
			return nil, err
		}
		result[i] = r
	}
	return &BitCiphertext{
		bits:    result,
		numBits: a.numBits,
		fheType: a.fheType,
	}, nil
}

// Eq returns encrypted 1 if a == b, 0 otherwise
func (eval *BitwiseEvaluator) Eq(a, b *BitCiphertext) (*Ciphertext, error) {
	if a.numBits != b.numBits {
		return nil, fmt.Errorf("bit count mismatch")
	}

	// a == b iff all bits are equal
	// bit_eq = NOT(a XOR b) = XNOR
	// result = AND of all bit_eq

	result, err := eval.eval.XNOR(a.bits[0], b.bits[0])
	if err != nil {
		return nil, err
	}

	for i := 1; i < a.numBits; i++ {
		bitEq, err := eval.eval.XNOR(a.bits[i], b.bits[i])
		if err != nil {
			return nil, err
		}
		result, err = eval.eval.AND(result, bitEq)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

// Lt returns encrypted 1 if a < b, 0 otherwise (unsigned)
func (eval *BitwiseEvaluator) Lt(a, b *BitCiphertext) (*Ciphertext, error) {
	if a.numBits != b.numBits {
		return nil, fmt.Errorf("bit count mismatch")
	}

	// Compare from MSB to LSB
	// a < b iff there exists i such that a[i] < b[i] and for all j > i, a[j] == b[j]
	// For each bit: a[i] < b[i] iff NOT(a[i]) AND b[i]

	numBits := a.numBits
	var isLess, isEqual *Ciphertext

	// Start from MSB
	for i := numBits - 1; i >= 0; i-- {
		// a[i] < b[i]: NOT(a[i]) AND b[i]
		notA := eval.eval.NOT(a.bits[i])
		bitLt, err := eval.eval.AND(notA, b.bits[i])
		if err != nil {
			return nil, err
		}

		// a[i] == b[i]: XNOR
		bitEq, err := eval.eval.XNOR(a.bits[i], b.bits[i])
		if err != nil {
			return nil, err
		}

		if isLess == nil {
			isLess = bitLt
			isEqual = bitEq
		} else {
			// isLess = isLess OR (isEqual AND bitLt)
			eqAndLt, err := eval.eval.AND(isEqual, bitLt)
			if err != nil {
				return nil, err
			}
			isLess, err = eval.eval.OR(isLess, eqAndLt)
			if err != nil {
				return nil, err
			}

			// isEqual = isEqual AND bitEq
			isEqual, err = eval.eval.AND(isEqual, bitEq)
			if err != nil {
				return nil, err
			}
		}
	}

	return isLess, nil
}

// Le returns encrypted 1 if a <= b, 0 otherwise
func (eval *BitwiseEvaluator) Le(a, b *BitCiphertext) (*Ciphertext, error) {
	// a <= b iff a < b OR a == b
	lt, err := eval.Lt(a, b)
	if err != nil {
		return nil, err
	}
	eq, err := eval.Eq(a, b)
	if err != nil {
		return nil, err
	}
	return eval.eval.OR(lt, eq)
}

// Gt returns encrypted 1 if a > b, 0 otherwise
func (eval *BitwiseEvaluator) Gt(a, b *BitCiphertext) (*Ciphertext, error) {
	// a > b iff b < a
	return eval.Lt(b, a)
}

// Ge returns encrypted 1 if a >= b, 0 otherwise
func (eval *BitwiseEvaluator) Ge(a, b *BitCiphertext) (*Ciphertext, error) {
	// a >= b iff b <= a
	return eval.Le(b, a)
}

// Min returns the minimum of a and b
func (eval *BitwiseEvaluator) Min(a, b *BitCiphertext) (*BitCiphertext, error) {
	// min(a, b) = a if a < b else b
	// = (a < b) * a + (a >= b) * b
	// For bits: result[i] = (isLess AND a[i]) OR (NOT(isLess) AND b[i])

	isLess, err := eval.Lt(a, b)
	if err != nil {
		return nil, err
	}

	return eval.Select(isLess, a, b)
}

// Max returns the maximum of a and b
func (eval *BitwiseEvaluator) Max(a, b *BitCiphertext) (*BitCiphertext, error) {
	// max(a, b) = a if a > b else b
	isGreater, err := eval.Gt(a, b)
	if err != nil {
		return nil, err
	}

	return eval.Select(isGreater, a, b)
}

// Select returns a if selector is 1, b otherwise
// result[i] = (selector AND a[i]) OR (NOT(selector) AND b[i])
func (eval *BitwiseEvaluator) Select(selector *Ciphertext, a, b *BitCiphertext) (*BitCiphertext, error) {
	if a.numBits != b.numBits {
		return nil, fmt.Errorf("bit count mismatch")
	}

	notSelector := eval.eval.NOT(selector)
	result := make([]*Ciphertext, a.numBits)

	for i := 0; i < a.numBits; i++ {
		// (selector AND a[i])
		selA, err := eval.eval.AND(selector, a.bits[i])
		if err != nil {
			return nil, err
		}

		// (NOT(selector) AND b[i])
		selB, err := eval.eval.AND(notSelector, b.bits[i])
		if err != nil {
			return nil, err
		}

		// OR them together
		result[i], err = eval.eval.OR(selA, selB)
		if err != nil {
			return nil, err
		}
	}

	return &BitCiphertext{
		bits:    result,
		numBits: a.numBits,
		fheType: a.fheType,
	}, nil
}

// Shl performs left shift by a constant amount
func (eval *BitwiseEvaluator) Shl(a *BitCiphertext, shift int) *BitCiphertext {
	if shift >= a.numBits {
		// All zeros
		result := make([]*Ciphertext, a.numBits)
		for i := 0; i < a.numBits; i++ {
			result[i] = eval.encryptBit(false)
		}
		return &BitCiphertext{
			bits:    result,
			numBits: a.numBits,
			fheType: a.fheType,
		}
	}

	result := make([]*Ciphertext, a.numBits)

	// Lower bits become zero
	for i := 0; i < shift; i++ {
		result[i] = eval.encryptBit(false)
	}
	// Upper bits are shifted
	for i := shift; i < a.numBits; i++ {
		result[i] = a.bits[i-shift]
	}

	return &BitCiphertext{
		bits:    result,
		numBits: a.numBits,
		fheType: a.fheType,
	}
}

// CastTo converts a BitCiphertext to a different bit width
// Widening: pads with zero bits
// Narrowing: truncates high bits
func (eval *BitwiseEvaluator) CastTo(a *BitCiphertext, targetType FheUintType) *BitCiphertext {
	targetBits := targetType.NumBits()
	sourceBits := a.numBits

	if targetBits == sourceBits {
		// Same size, just update type
		result := make([]*Ciphertext, targetBits)
		copy(result, a.bits)
		return &BitCiphertext{
			bits:    result,
			numBits: targetBits,
			fheType: targetType,
		}
	}

	result := make([]*Ciphertext, targetBits)

	if targetBits > sourceBits {
		// Widening: copy existing bits, pad with zeros
		copy(result, a.bits)
		for i := sourceBits; i < targetBits; i++ {
			result[i] = eval.encryptBit(false)
		}
	} else {
		// Narrowing: truncate high bits
		copy(result, a.bits[:targetBits])
	}

	return &BitCiphertext{
		bits:    result,
		numBits: targetBits,
		fheType: targetType,
	}
}

// Shr performs right shift by a constant amount
func (eval *BitwiseEvaluator) Shr(a *BitCiphertext, shift int) *BitCiphertext {
	if shift >= a.numBits {
		// All zeros
		result := make([]*Ciphertext, a.numBits)
		for i := 0; i < a.numBits; i++ {
			result[i] = eval.encryptBit(false)
		}
		return &BitCiphertext{
			bits:    result,
			numBits: a.numBits,
			fheType: a.fheType,
		}
	}

	result := make([]*Ciphertext, a.numBits)

	// Lower bits are shifted from upper
	for i := 0; i < a.numBits-shift; i++ {
		result[i] = a.bits[i+shift]
	}
	// Upper bits become zero
	for i := a.numBits - shift; i < a.numBits; i++ {
		result[i] = eval.encryptBit(false)
	}

	return &BitCiphertext{
		bits:    result,
		numBits: a.numBits,
		fheType: a.fheType,
	}
}

// ========== Multiplication, Division, and Remainder ==========

// Mul performs schoolbook binary multiplication: a * b
// Uses the classic shift-and-add algorithm on encrypted bits.
// Complexity: O(n^2) boolean operations for n-bit operands.
func (eval *BitwiseEvaluator) Mul(a, b *BitCiphertext) (*BitCiphertext, error) {
	if a.fheType != b.fheType {
		return nil, fmt.Errorf("type mismatch: %s vs %s", a.fheType, b.fheType)
	}
	if a.numBits != b.numBits {
		return nil, fmt.Errorf("bit count mismatch: %d vs %d", a.numBits, b.numBits)
	}

	numBits := a.numBits

	// Initialize result to zero
	result := eval.Zero(a.fheType)

	// Schoolbook multiplication: for each bit of b, if b[i]=1, add a<<i to result
	for i := 0; i < numBits; i++ {
		// Shift a left by i positions
		shifted := eval.Shl(a, i)

		// Multiply each bit of shifted by b[i] using AND
		// This gives us: shifted * b[i]
		masked, err := eval.andWithBit(shifted, b.bits[i])
		if err != nil {
			return nil, fmt.Errorf("bit %d mask: %w", i, err)
		}

		// Add to accumulator
		result, err = eval.Add(result, masked)
		if err != nil {
			return nil, fmt.Errorf("bit %d add: %w", i, err)
		}
	}

	return result, nil
}

// andWithBit ANDs each bit of a BitCiphertext with a single encrypted bit
func (eval *BitwiseEvaluator) andWithBit(a *BitCiphertext, bit *Ciphertext) (*BitCiphertext, error) {
	result := make([]*Ciphertext, a.numBits)
	for i := 0; i < a.numBits; i++ {
		r, err := eval.eval.AND(a.bits[i], bit)
		if err != nil {
			return nil, err
		}
		result[i] = r
	}
	return &BitCiphertext{
		bits:    result,
		numBits: a.numBits,
		fheType: a.fheType,
	}, nil
}

// Zero returns an encrypted zero of the given type
func (eval *BitwiseEvaluator) Zero(t FheUintType) *BitCiphertext {
	numBits := t.NumBits()
	bits := make([]*Ciphertext, numBits)
	for i := 0; i < numBits; i++ {
		bits[i] = eval.encryptBit(false)
	}
	return &BitCiphertext{
		bits:    bits,
		numBits: numBits,
		fheType: t,
	}
}

// One returns an encrypted one of the given type
func (eval *BitwiseEvaluator) One(t FheUintType) *BitCiphertext {
	numBits := t.NumBits()
	bits := make([]*Ciphertext, numBits)
	bits[0] = eval.encryptBit(true)
	for i := 1; i < numBits; i++ {
		bits[i] = eval.encryptBit(false)
	}
	return &BitCiphertext{
		bits:    bits,
		numBits: numBits,
		fheType: t,
	}
}

// ScalarMul multiplies a BitCiphertext by a plaintext scalar using binary decomposition
func (eval *BitwiseEvaluator) ScalarMul(a *BitCiphertext, scalar uint64) (*BitCiphertext, error) {
	if scalar == 0 {
		return eval.Zero(a.fheType), nil
	}
	if scalar == 1 {
		return eval.Copy(a), nil
	}

	// Binary multiplication using shift-and-add
	result := eval.Zero(a.fheType)
	current := eval.Copy(a)

	for scalar > 0 {
		if scalar&1 == 1 {
			var err error
			result, err = eval.Add(result, current)
			if err != nil {
				return nil, err
			}
		}
		scalar >>= 1
		if scalar > 0 {
			current = eval.Shl(current, 1)
		}
	}

	return result, nil
}

// Copy creates a copy of a BitCiphertext (references same underlying ciphertexts)
func (eval *BitwiseEvaluator) Copy(a *BitCiphertext) *BitCiphertext {
	bits := make([]*Ciphertext, a.numBits)
	copy(bits, a.bits)
	return &BitCiphertext{
		bits:    bits,
		numBits: a.numBits,
		fheType: a.fheType,
	}
}

// Div performs binary long division: a / b (unsigned)
// Returns quotient. Uses non-restoring division algorithm.
// Complexity: O(n^2) boolean operations for n-bit operands.
// Note: Division by zero returns max value (all 1s) per EVM semantics.
func (eval *BitwiseEvaluator) Div(a, b *BitCiphertext) (*BitCiphertext, error) {
	if a.fheType != b.fheType {
		return nil, fmt.Errorf("type mismatch: %s vs %s", a.fheType, b.fheType)
	}
	if a.numBits != b.numBits {
		return nil, fmt.Errorf("bit count mismatch: %d vs %d", a.numBits, b.numBits)
	}

	numBits := a.numBits

	// Check if b is zero - return max value per EVM semantics
	bIsZero, err := eval.IsZero(b)
	if err != nil {
		return nil, fmt.Errorf("zero check: %w", err)
	}

	// Perform division using restoring division algorithm
	// q = quotient, r = remainder (partial)
	quotient := make([]*Ciphertext, numBits)
	remainder := eval.Zero(a.fheType)

	// Process from MSB to LSB of dividend
	for i := numBits - 1; i >= 0; i-- {
		// Shift remainder left by 1 and bring in next bit of dividend
		remainder = eval.Shl(remainder, 1)
		// Bounds check after shift
		if len(remainder.bits) == 0 {
			return nil, fmt.Errorf("internal error: empty remainder after shift at bit %d", i)
		}
		// Set LSB of remainder to a.bits[i]
		remainder.bits[0] = a.bits[i]

		// Compare: remainder >= b
		rGeB, err := eval.Ge(remainder, b)
		if err != nil {
			return nil, fmt.Errorf("bit %d compare: %w", i, err)
		}

		// If remainder >= b, quotient bit = 1 and remainder -= b
		quotient[i] = rGeB

		// remainder = rGeB ? (remainder - b) : remainder
		diff, err := eval.Sub(remainder, b)
		if err != nil {
			return nil, fmt.Errorf("bit %d subtract: %w", i, err)
		}

		remainder, err = eval.Select(rGeB, diff, remainder)
		if err != nil {
			return nil, fmt.Errorf("bit %d select: %w", i, err)
		}
	}

	result := &BitCiphertext{
		bits:    quotient,
		numBits: numBits,
		fheType: a.fheType,
	}

	// If b was zero, return max value (all 1s)
	maxVal := eval.MaxValue(a.fheType)
	return eval.Select(bIsZero, maxVal, result)
}

// Rem performs binary remainder: a % b (unsigned)
// Returns remainder after division.
// Note: Remainder by zero returns a (dividend) per EVM semantics.
func (eval *BitwiseEvaluator) Rem(a, b *BitCiphertext) (*BitCiphertext, error) {
	if a.fheType != b.fheType {
		return nil, fmt.Errorf("type mismatch: %s vs %s", a.fheType, b.fheType)
	}
	if a.numBits != b.numBits {
		return nil, fmt.Errorf("bit count mismatch: %d vs %d", a.numBits, b.numBits)
	}

	numBits := a.numBits

	// Check if b is zero - return a per EVM semantics
	bIsZero, err := eval.IsZero(b)
	if err != nil {
		return nil, fmt.Errorf("zero check: %w", err)
	}

	// Perform division to get remainder
	remainder := eval.Zero(a.fheType)

	// Process from MSB to LSB of dividend
	for i := numBits - 1; i >= 0; i-- {
		// Shift remainder left by 1 and bring in next bit of dividend
		remainder = eval.Shl(remainder, 1)
		// Bounds check after shift
		if len(remainder.bits) == 0 {
			return nil, fmt.Errorf("internal error: empty remainder after shift at bit %d", i)
		}
		remainder.bits[0] = a.bits[i]

		// Compare: remainder >= b
		rGeB, err := eval.Ge(remainder, b)
		if err != nil {
			return nil, fmt.Errorf("bit %d compare: %w", i, err)
		}

		// If remainder >= b, subtract b from remainder
		diff, err := eval.Sub(remainder, b)
		if err != nil {
			return nil, fmt.Errorf("bit %d subtract: %w", i, err)
		}

		remainder, err = eval.Select(rGeB, diff, remainder)
		if err != nil {
			return nil, fmt.Errorf("bit %d select: %w", i, err)
		}
	}

	// If b was zero, return a (the dividend)
	return eval.Select(bIsZero, a, remainder)
}

// IsZero returns encrypted 1 if a == 0, 0 otherwise
func (eval *BitwiseEvaluator) IsZero(a *BitCiphertext) (*Ciphertext, error) {
	// a == 0 iff all bits are 0
	// NOR of all bits: NOT(OR(b0, OR(b1, OR(b2, ...))))
	result := a.bits[0]
	for i := 1; i < a.numBits; i++ {
		var err error
		result, err = eval.eval.OR(result, a.bits[i])
		if err != nil {
			return nil, err
		}
	}
	// NOT the final OR result
	return eval.eval.NOT(result), nil
}

// MaxValue returns an encrypted value with all bits set to 1
func (eval *BitwiseEvaluator) MaxValue(t FheUintType) *BitCiphertext {
	numBits := t.NumBits()
	bits := make([]*Ciphertext, numBits)
	for i := 0; i < numBits; i++ {
		bits[i] = eval.encryptBit(true)
	}
	return &BitCiphertext{
		bits:    bits,
		numBits: numBits,
		fheType: t,
	}
}

// Neg negates a BitCiphertext using two's complement: -a = ~a + 1
func (eval *BitwiseEvaluator) Neg(a *BitCiphertext) (*BitCiphertext, error) {
	notA := eval.Not(a)
	return eval.ScalarAdd(notA, 1)
}
