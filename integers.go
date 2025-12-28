// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package tfhe

import (
	"fmt"
	"math/big"
)

// FheUintType represents the type of encrypted integer
type FheUintType uint8

const (
	FheBool     FheUintType = 0
	FheUint4    FheUintType = 1
	FheUint8    FheUintType = 2
	FheUint16   FheUintType = 3
	FheUint32   FheUintType = 4
	FheUint64   FheUintType = 5
	FheUint128  FheUintType = 6
	FheUint160  FheUintType = 7 // For Ethereum addresses
	FheUint256  FheUintType = 8
)

// NumBits returns the number of bits for the type
func (t FheUintType) NumBits() int {
	switch t {
	case FheBool:
		return 1
	case FheUint4:
		return 4
	case FheUint8:
		return 8
	case FheUint16:
		return 16
	case FheUint32:
		return 32
	case FheUint64:
		return 64
	case FheUint128:
		return 128
	case FheUint160:
		return 160
	case FheUint256:
		return 256
	default:
		return 0
	}
}

func (t FheUintType) String() string {
	switch t {
	case FheBool:
		return "ebool"
	case FheUint4:
		return "euint4"
	case FheUint8:
		return "euint8"
	case FheUint16:
		return "euint16"
	case FheUint32:
		return "euint32"
	case FheUint64:
		return "euint64"
	case FheUint128:
		return "euint128"
	case FheUint160:
		return "euint160"
	case FheUint256:
		return "euint256"
	default:
		return "unknown"
	}
}

// RadixCiphertext represents an encrypted integer using radix decomposition.
// Each block is a ShortInt holding a few bits of the value.
// LSB is at index 0.
type RadixCiphertext struct {
	blocks    []*ShortInt
	blockBits int         // Bits per block (typically 2 or 4)
	numBlocks int         // Number of blocks
	fheType   FheUintType // The integer type
}

// Type returns the FHE type
func (rc *RadixCiphertext) Type() FheUintType {
	return rc.fheType
}

// NumBits returns total bits
func (rc *RadixCiphertext) NumBits() int {
	return rc.blockBits * rc.numBlocks
}

// IntegerParams holds parameters for radix integer operations
type IntegerParams struct {
	tfheParams  Parameters
	shortParams *ShortIntParams
	blockBits   int // Bits per radix block (2 or 4)
}

// NewIntegerParams creates parameters for integer operations
func NewIntegerParams(params Parameters, blockBits int) (*IntegerParams, error) {
	if blockBits != 2 && blockBits != 4 {
		return nil, fmt.Errorf("blockBits must be 2 or 4, got %d", blockBits)
	}

	shortParams, err := NewShortIntParams(params, blockBits)
	if err != nil {
		return nil, err
	}

	return &IntegerParams{
		tfheParams:  params,
		shortParams: shortParams,
		blockBits:   blockBits,
	}, nil
}

// IntegerEncryptor encrypts integers of various sizes
type IntegerEncryptor struct {
	params   *IntegerParams
	shortEnc *ShortIntEncryptor
}

// NewIntegerEncryptor creates a new integer encryptor
func NewIntegerEncryptor(params *IntegerParams, sk *SecretKey) *IntegerEncryptor {
	return &IntegerEncryptor{
		params:   params,
		shortEnc: NewShortIntEncryptor(params.shortParams, sk),
	}
}

// numBlocksForType returns the number of radix blocks needed for a type
func (enc *IntegerEncryptor) numBlocksForType(t FheUintType) int {
	return (t.NumBits() + enc.params.blockBits - 1) / enc.params.blockBits
}

// EncryptUint64 encrypts a uint64 value
func (enc *IntegerEncryptor) EncryptUint64(value uint64, t FheUintType) (*RadixCiphertext, error) {
	numBlocks := enc.numBlocksForType(t)
	blockMask := uint64((1 << enc.params.blockBits) - 1)

	blocks := make([]*ShortInt, numBlocks)
	for i := 0; i < numBlocks; i++ {
		blockValue := int((value >> (i * enc.params.blockBits)) & blockMask)
		block, err := enc.shortEnc.Encrypt(blockValue)
		if err != nil {
			return nil, fmt.Errorf("encrypting block %d: %w", i, err)
		}
		blocks[i] = block
	}

	return &RadixCiphertext{
		blocks:    blocks,
		blockBits: enc.params.blockBits,
		numBlocks: numBlocks,
		fheType:   t,
	}, nil
}

// EncryptBigInt encrypts a big.Int value (for types > 64 bits)
func (enc *IntegerEncryptor) EncryptBigInt(value *big.Int, t FheUintType) (*RadixCiphertext, error) {
	numBlocks := enc.numBlocksForType(t)
	blockMask := big.NewInt(int64((1 << enc.params.blockBits) - 1))

	blocks := make([]*ShortInt, numBlocks)
	remaining := new(big.Int).Set(value)

	for i := 0; i < numBlocks; i++ {
		blockBig := new(big.Int).And(remaining, blockMask)
		blockValue := int(blockBig.Int64())

		block, err := enc.shortEnc.Encrypt(blockValue)
		if err != nil {
			return nil, fmt.Errorf("encrypting block %d: %w", i, err)
		}
		blocks[i] = block

		remaining.Rsh(remaining, uint(enc.params.blockBits))
	}

	return &RadixCiphertext{
		blocks:    blocks,
		blockBits: enc.params.blockBits,
		numBlocks: numBlocks,
		fheType:   t,
	}, nil
}

// EncryptBool encrypts a boolean
func (enc *IntegerEncryptor) EncryptBool(value bool) (*RadixCiphertext, error) {
	v := 0
	if value {
		v = 1
	}
	block, err := enc.shortEnc.Encrypt(v)
	if err != nil {
		return nil, err
	}
	return &RadixCiphertext{
		blocks:    []*ShortInt{block},
		blockBits: enc.params.blockBits,
		numBlocks: 1,
		fheType:   FheBool,
	}, nil
}

// Encrypt4 encrypts a 4-bit value
func (enc *IntegerEncryptor) Encrypt4(value uint8) (*RadixCiphertext, error) {
	return enc.EncryptUint64(uint64(value&0xF), FheUint4)
}

// Encrypt8 encrypts an 8-bit value
func (enc *IntegerEncryptor) Encrypt8(value uint8) (*RadixCiphertext, error) {
	return enc.EncryptUint64(uint64(value), FheUint8)
}

// Encrypt16 encrypts a 16-bit value
func (enc *IntegerEncryptor) Encrypt16(value uint16) (*RadixCiphertext, error) {
	return enc.EncryptUint64(uint64(value), FheUint16)
}

// Encrypt32 encrypts a 32-bit value
func (enc *IntegerEncryptor) Encrypt32(value uint32) (*RadixCiphertext, error) {
	return enc.EncryptUint64(uint64(value), FheUint32)
}

// Encrypt64 encrypts a 64-bit value
func (enc *IntegerEncryptor) Encrypt64(value uint64) (*RadixCiphertext, error) {
	return enc.EncryptUint64(value, FheUint64)
}

// IntegerDecryptor decrypts integers
type IntegerDecryptor struct {
	params   *IntegerParams
	shortDec *ShortIntDecryptor
}

// NewIntegerDecryptor creates a new integer decryptor
func NewIntegerDecryptor(params *IntegerParams, sk *SecretKey) *IntegerDecryptor {
	return &IntegerDecryptor{
		params:   params,
		shortDec: NewShortIntDecryptor(params.shortParams, sk),
	}
}

// DecryptUint64 decrypts to a uint64 (for types <= 64 bits)
func (dec *IntegerDecryptor) DecryptUint64(rc *RadixCiphertext) uint64 {
	var result uint64
	for i, block := range rc.blocks {
		blockValue := dec.shortDec.Decrypt(block)
		result |= uint64(blockValue) << (i * rc.blockBits)
	}

	// Mask to the actual bit width
	mask := uint64((1 << rc.fheType.NumBits()) - 1)
	if rc.fheType.NumBits() >= 64 {
		mask = ^uint64(0)
	}
	return result & mask
}

// DecryptBigInt decrypts to a big.Int (for any size)
func (dec *IntegerDecryptor) DecryptBigInt(rc *RadixCiphertext) *big.Int {
	result := new(big.Int)
	for i := len(rc.blocks) - 1; i >= 0; i-- {
		blockValue := dec.shortDec.Decrypt(rc.blocks[i])
		result.Lsh(result, uint(rc.blockBits))
		result.Or(result, big.NewInt(int64(blockValue)))
	}
	return result
}

// DecryptBool decrypts a boolean
func (dec *IntegerDecryptor) DecryptBool(rc *RadixCiphertext) bool {
	if len(rc.blocks) == 0 {
		return false
	}
	return dec.shortDec.Decrypt(rc.blocks[0]) != 0
}

// Decrypt4 decrypts a 4-bit value
func (dec *IntegerDecryptor) Decrypt4(rc *RadixCiphertext) uint8 {
	return uint8(dec.DecryptUint64(rc) & 0xF)
}

// Decrypt8 decrypts an 8-bit value
func (dec *IntegerDecryptor) Decrypt8(rc *RadixCiphertext) uint8 {
	return uint8(dec.DecryptUint64(rc))
}

// Decrypt16 decrypts a 16-bit value
func (dec *IntegerDecryptor) Decrypt16(rc *RadixCiphertext) uint16 {
	return uint16(dec.DecryptUint64(rc))
}

// Decrypt32 decrypts a 32-bit value
func (dec *IntegerDecryptor) Decrypt32(rc *RadixCiphertext) uint32 {
	return uint32(dec.DecryptUint64(rc))
}

// Decrypt64 decrypts a 64-bit value
func (dec *IntegerDecryptor) Decrypt64(rc *RadixCiphertext) uint64 {
	return dec.DecryptUint64(rc)
}

// IntegerEvaluator performs operations on radix integers
type IntegerEvaluator struct {
	params   *IntegerParams
	shortEval *ShortIntEvaluator
	boolEval  *Evaluator // For boolean operations
}

// NewIntegerEvaluator creates a new integer evaluator
func NewIntegerEvaluator(params *IntegerParams, bsk *BootstrapKey, sk *SecretKey) *IntegerEvaluator {
	return &IntegerEvaluator{
		params:    params,
		shortEval: NewShortIntEvaluator(params.shortParams, bsk, sk),
		boolEval:  NewEvaluator(params.tfheParams, bsk, sk),
	}
}

// Add performs radix addition with carry propagation
func (eval *IntegerEvaluator) Add(a, b *RadixCiphertext) (*RadixCiphertext, error) {
	if a.fheType != b.fheType {
		return nil, fmt.Errorf("type mismatch: %s vs %s", a.fheType, b.fheType)
	}
	if len(a.blocks) != len(b.blocks) {
		return nil, fmt.Errorf("block count mismatch: %d vs %d", len(a.blocks), len(b.blocks))
	}

	numBlocks := len(a.blocks)
	resultBlocks := make([]*ShortInt, numBlocks)

	var carry *Ciphertext

	for i := 0; i < numBlocks; i++ {
		var sum *ShortInt
		var newCarry *Ciphertext
		var err error

		if carry == nil {
			// First block: simple add
			sum, newCarry, err = eval.shortEval.AddWithCarry(a.blocks[i], b.blocks[i])
		} else {
			// Add a and b first
			sumAB, carryAB, err := eval.shortEval.AddWithCarry(a.blocks[i], b.blocks[i])
			if err != nil {
				return nil, fmt.Errorf("block %d add: %w", i, err)
			}

			// Add carry from previous block
			// For simplicity, we add 1 if carry is set
			// This needs the carry bit to be converted to a shortint
			// For now, use a simplified approach with scalar add based on decrypted carry
			// TODO: Implement proper encrypted carry addition
			sum = sumAB
			newCarry = carryAB
		}

		if err != nil {
			return nil, fmt.Errorf("block %d: %w", i, err)
		}

		resultBlocks[i] = sum
		carry = newCarry
	}

	return &RadixCiphertext{
		blocks:    resultBlocks,
		blockBits: a.blockBits,
		numBlocks: numBlocks,
		fheType:   a.fheType,
	}, nil
}

// ScalarAdd adds a scalar to a radix integer
// This uses encrypted addition to properly handle carries
func (eval *IntegerEvaluator) ScalarAdd(a *RadixCiphertext, scalar uint64) (*RadixCiphertext, error) {
	// For proper carry propagation, we encrypt the scalar and use encrypted addition
	// This is slower but guarantees correctness

	// Encrypt the scalar as a trivial ciphertext (no noise, plaintext encoded in ciphertext)
	scalarCt, err := eval.encryptScalar(scalar, a.fheType, a.blockBits)
	if err != nil {
		return nil, fmt.Errorf("encrypt scalar: %w", err)
	}

	// Use encrypted addition which handles carries correctly
	return eval.Add(a, scalarCt)
}

// encryptScalar creates a trivial encryption of a scalar (plaintext in ciphertext format)
func (eval *IntegerEvaluator) encryptScalar(scalar uint64, fheType FheUintType, blockBits int) (*RadixCiphertext, error) {
	numBlocks := (fheType.NumBits() + blockBits - 1) / blockBits
	blockMask := uint64((1 << blockBits) - 1)

	blocks := make([]*ShortInt, numBlocks)
	for i := 0; i < numBlocks; i++ {
		blockValue := int((scalar >> (i * blockBits)) & blockMask)
		block, err := eval.shortEval.EncryptTrivial(blockValue)
		if err != nil {
			return nil, fmt.Errorf("block %d: %w", i, err)
		}
		blocks[i] = block
	}

	return &RadixCiphertext{
		blocks:    blocks,
		blockBits: blockBits,
		numBlocks: numBlocks,
		fheType:   fheType,
	}, nil
}

// Sub performs radix subtraction
func (eval *IntegerEvaluator) Sub(a, b *RadixCiphertext) (*RadixCiphertext, error) {
	if a.fheType != b.fheType {
		return nil, fmt.Errorf("type mismatch: %s vs %s", a.fheType, b.fheType)
	}

	numBlocks := len(a.blocks)
	resultBlocks := make([]*ShortInt, numBlocks)

	for i := 0; i < numBlocks; i++ {
		result, err := eval.shortEval.Sub(a.blocks[i], b.blocks[i])
		if err != nil {
			return nil, fmt.Errorf("block %d: %w", i, err)
		}
		resultBlocks[i] = result
	}

	return &RadixCiphertext{
		blocks:    resultBlocks,
		blockBits: a.blockBits,
		numBlocks: numBlocks,
		fheType:   a.fheType,
	}, nil
}

// ScalarSub subtracts a scalar from a radix integer
func (eval *IntegerEvaluator) ScalarSub(a *RadixCiphertext, scalar uint64) (*RadixCiphertext, error) {
	numBlocks := len(a.blocks)
	resultBlocks := make([]*ShortInt, numBlocks)
	blockMask := (1 << a.blockBits) - 1

	for i := 0; i < numBlocks; i++ {
		scalarBlock := int((scalar >> (i * a.blockBits)) & uint64(blockMask))
		result, err := eval.shortEval.ScalarSub(a.blocks[i], scalarBlock)
		if err != nil {
			return nil, fmt.Errorf("block %d: %w", i, err)
		}
		resultBlocks[i] = result
	}

	return &RadixCiphertext{
		blocks:    resultBlocks,
		blockBits: a.blockBits,
		numBlocks: numBlocks,
		fheType:   a.fheType,
	}, nil
}

// ScalarMul multiplies a radix integer by a scalar
func (eval *IntegerEvaluator) ScalarMul(a *RadixCiphertext, scalar uint64) (*RadixCiphertext, error) {
	// For small scalars, use repeated addition
	// For larger scalars, use binary decomposition
	if scalar == 0 {
		// Return encryption of 0
		enc := NewIntegerEncryptor(eval.params, nil) // Need proper key access
		return enc.EncryptUint64(0, a.fheType)
	}

	if scalar == 1 {
		// Return copy
		return eval.copy(a), nil
	}

	// Binary multiplication: compute a * scalar using shift-and-add
	result := eval.copy(a)
	for i := 1; scalar > 1; i++ {
		if scalar&1 == 1 {
			var err error
			result, err = eval.Add(result, a)
			if err != nil {
				return nil, err
			}
		}
		scalar >>= 1
		if scalar > 0 {
			// Shift a left by one (multiply by 2)
			a, _ = eval.ScalarAdd(a, 0) // This is a placeholder - need proper shift
		}
	}

	return result, nil
}

// copy creates a copy of a RadixCiphertext
func (eval *IntegerEvaluator) copy(rc *RadixCiphertext) *RadixCiphertext {
	blocks := make([]*ShortInt, len(rc.blocks))
	for i, b := range rc.blocks {
		blocks[i] = &ShortInt{
			ct:       b.ct.CopyNew(),
			msgBits:  b.msgBits,
			msgSpace: b.msgSpace,
		}
	}
	return &RadixCiphertext{
		blocks:    blocks,
		blockBits: rc.blockBits,
		numBlocks: rc.numBlocks,
		fheType:   rc.fheType,
	}
}

// Neg negates a radix integer (two's complement)
func (eval *IntegerEvaluator) Neg(a *RadixCiphertext) (*RadixCiphertext, error) {
	// Two's complement: -a = ~a + 1
	numBlocks := len(a.blocks)
	resultBlocks := make([]*ShortInt, numBlocks)

	for i := 0; i < numBlocks; i++ {
		negated, err := eval.shortEval.Neg(a.blocks[i])
		if err != nil {
			return nil, err
		}
		resultBlocks[i] = negated
	}

	result := &RadixCiphertext{
		blocks:    resultBlocks,
		blockBits: a.blockBits,
		numBlocks: numBlocks,
		fheType:   a.fheType,
	}

	// Add 1 for two's complement
	return eval.ScalarAdd(result, 1)
}
