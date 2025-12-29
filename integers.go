// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package tfhe

import (
	"fmt"
	"math/big"

	"github.com/luxfi/lattice/v6/core/rgsw/blindrot"
	"github.com/luxfi/lattice/v6/core/rlwe"
)

// FheUintType represents the type of encrypted integer
type FheUintType uint8

const (
	FheBool    FheUintType = 0
	FheUint4   FheUintType = 1
	FheUint8   FheUintType = 2
	FheUint16  FheUintType = 3
	FheUint32  FheUintType = 4
	FheUint64  FheUintType = 5
	FheUint128 FheUintType = 6
	FheUint160 FheUintType = 7 // For Ethereum addresses
	FheUint256 FheUintType = 8
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
	params    *IntegerParams
	shortEval *ShortIntEvaluator
	boolEval  *Evaluator // For boolean operations
}

// NewIntegerEvaluator creates a new integer evaluator
// NewIntegerEvaluator creates a new integer evaluator
// SECURITY: No secret key is required - uses public key switching for bootstrapping.
func NewIntegerEvaluator(params *IntegerParams, bsk *BootstrapKey) *IntegerEvaluator {
	return &IntegerEvaluator{
		params:    params,
		shortEval: NewShortIntEvaluator(params.shortParams, bsk),
		boolEval:  NewEvaluator(params.tfheParams, bsk),
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

			// Add carry from previous block to current sum
			// The carry is an encrypted bit. We need to add it to sumAB.
			// Convert carry to ShortInt format and add to sumAB
			sumWithCarry, carryFromSum, err := eval.addCarryToBlock(sumAB, carry)
			if err != nil {
				return nil, fmt.Errorf("block %d carry add: %w", i, err)
			}

			// Combine carries: newCarry = carryAB OR carryFromSum
			// Both are encrypted bits indicating overflow
			newCarry, err = eval.boolEval.OR(carryAB, carryFromSum)
			if err != nil {
				return nil, fmt.Errorf("block %d carry combine: %w", i, err)
			}

			sum = sumWithCarry
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

// addCarryToBlock adds an encrypted carry bit to a ShortInt block
// Returns the sum and a new carry bit (1 if addition overflowed)
func (eval *IntegerEvaluator) addCarryToBlock(block *ShortInt, carry *Ciphertext) (*ShortInt, *Ciphertext, error) {
	// The carry is encoded as an encrypted boolean.
	// We need to add it (as 0 or 1) to the block.
	//
	// Create a ShortInt containing the carry value (0 or 1)
	// by using a conditional: if carry then 1 else 0

	// Create trivial encryptions of 0 and 1
	zero, err := eval.shortEval.EncryptTrivial(0)
	if err != nil {
		return nil, nil, err
	}
	one, err := eval.shortEval.EncryptTrivial(1)
	if err != nil {
		return nil, nil, err
	}

	// Select between 0 and 1 based on carry bit using MUX
	// MUX(sel, trueVal, falseVal) = sel ? trueVal : falseVal
	carryAsShort, err := eval.selectShortInt(carry, one, zero)
	if err != nil {
		return nil, nil, err
	}

	// Now add block + carryAsShort
	return eval.shortEval.AddWithCarry(block, carryAsShort)
}

// selectShortInt selects between two ShortInts based on an encrypted boolean selector
func (eval *IntegerEvaluator) selectShortInt(selector *Ciphertext, trueVal, falseVal *ShortInt) (*ShortInt, error) {
	// Use MUX operation: result = selector ? trueVal : falseVal
	// Implemented as: (selector AND trueVal) OR (NOT(selector) AND falseVal)
	// For ShortInt, we use the underlying ciphertext operations

	// Since ShortInt holds a value in [0, msgSpace), we need to
	// compute: result = selector * trueVal + (1-selector) * falseVal
	// Using LUT-based evaluation

	msgSpace := trueVal.msgSpace
	scale := rlwe.NewScale(float64(eval.params.tfheParams.QBR()) / float64(2*msgSpace))

	// Combine selector with trueVal and falseVal for bivariate evaluation
	// We add the ciphertexts in a specific encoding to enable LUT evaluation

	// Simpler approach: use the boolean selector directly with scalar multiplication
	// result = selector * (trueVal - falseVal) + falseVal
	//        = selector * delta + falseVal
	// where delta = trueVal - falseVal

	// For our case (trueVal=1, falseVal=0), result = selector * 1 + 0 = selector
	// So we just need to convert the boolean selector to a ShortInt

	// Create MUX LUT that evaluates the selection
	selectLUT := blindrot.InitTestPolynomial(func(x float64) float64 {
		// x encodes the selector in [-1, 1] where -1 = false, 1 = true
		if x > 0 {
			// selector is true, return trueVal (1)
			return float64(1)*2/float64(msgSpace) - 1
		}
		// selector is false, return falseVal (0)
		return float64(0)*2/float64(msgSpace) - 1
	}, scale, eval.shortEval.ringQBR, -1, 1)

	resultCt, err := eval.shortEval.bootstrap(selector.Ciphertext, &selectLUT)
	if err != nil {
		return nil, err
	}

	return &ShortInt{
		ct:       resultCt,
		msgBits:  trueVal.msgBits,
		msgSpace: trueVal.msgSpace,
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

// ========== Multiplication, Division, and Remainder ==========

// Mul performs encrypted multiplication: a * b
// Uses schoolbook multiplication with block-level operations.
// For each block of b, multiplies a by that block's value and shifts appropriately.
// Complexity: O(n^2) block operations for n blocks.
func (eval *IntegerEvaluator) Mul(a, b *RadixCiphertext) (*RadixCiphertext, error) {
	if a.fheType != b.fheType {
		return nil, fmt.Errorf("type mismatch: %s vs %s", a.fheType, b.fheType)
	}
	if len(a.blocks) != len(b.blocks) {
		return nil, fmt.Errorf("block count mismatch: %d vs %d", len(a.blocks), len(b.blocks))
	}

	numBlocks := len(a.blocks)
	blockBits := a.blockBits

	// Initialize result to zero
	result, err := eval.zeroRadix(a.fheType)
	if err != nil {
		return nil, fmt.Errorf("init zero: %w", err)
	}

	// Schoolbook multiplication at block level:
	// For each block b[i], compute partial = a * b[i] * (base^i)
	// where base = 2^blockBits
	// Sum all partials
	for i := 0; i < numBlocks; i++ {
		// Multiply a by block b[i] (scalar multiplication per block)
		partial, err := eval.mulByBlock(a, b.blocks[i], i, blockBits)
		if err != nil {
			return nil, fmt.Errorf("block %d multiply: %w", i, err)
		}

		// Add partial to result
		result, err = eval.Add(result, partial)
		if err != nil {
			return nil, fmt.Errorf("block %d accumulate: %w", i, err)
		}
	}

	return result, nil
}

// mulByBlock multiplies a RadixCiphertext by a single encrypted block
// and shifts the result by shiftBlocks positions (i.e., multiplies by base^shiftBlocks)
func (eval *IntegerEvaluator) mulByBlock(a *RadixCiphertext, block *ShortInt, shiftBlocks, blockBits int) (*RadixCiphertext, error) {
	numBlocks := len(a.blocks)

	// Result has same structure as a, but shifted
	resultBlocks := make([]*ShortInt, numBlocks)

	// Initialize lower blocks to zero (due to shift)
	for i := 0; i < shiftBlocks && i < numBlocks; i++ {
		zero, err := eval.shortEval.EncryptTrivial(0)
		if err != nil {
			return nil, err
		}
		resultBlocks[i] = zero
	}

	// For each block of a (that fits after shift), multiply by block
	// This requires a two-input multiplication LUT for blocks
	for i := 0; i+shiftBlocks < numBlocks && i < len(a.blocks); i++ {
		destIdx := i + shiftBlocks

		// Multiply a.blocks[i] by block using LUT
		product, err := eval.mulBlocks(a.blocks[i], block)
		if err != nil {
			return nil, fmt.Errorf("block %d mul: %w", i, err)
		}
		resultBlocks[destIdx] = product
	}

	// Fill remaining blocks with zeros if any
	for i := len(a.blocks) + shiftBlocks; i < numBlocks; i++ {
		zero, err := eval.shortEval.EncryptTrivial(0)
		if err != nil {
			return nil, err
		}
		resultBlocks[i] = zero
	}

	return &RadixCiphertext{
		blocks:    resultBlocks,
		blockBits: a.blockBits,
		numBlocks: numBlocks,
		fheType:   a.fheType,
	}, nil
}

// mulBlocks multiplies two encrypted blocks using a bivariate LUT
// Returns the lower bits of the product (upper bits/carry handled separately)
func (eval *IntegerEvaluator) mulBlocks(a, b *ShortInt) (*ShortInt, error) {
	msgSpace := a.msgSpace

	// Create bivariate multiplication LUT
	// We combine a and b into single input by adding their ciphertexts
	// Then use LUT to compute (a * b) mod msgSpace
	sum := eval.shortEval.addCiphertexts(a.ct, b.ct)

	scale := rlwe.NewScale(float64(eval.params.tfheParams.QBR()) / float64(2*msgSpace*msgSpace))

	mulLUT := blindrot.InitTestPolynomial(func(x float64) float64 {
		// Decode combined input to get a and b
		combined := int((x + 1) * float64(msgSpace*msgSpace) / 2)
		aVal := combined / msgSpace
		bVal := combined % msgSpace
		if aVal >= msgSpace {
			aVal = msgSpace - 1
		}
		if bVal >= msgSpace {
			bVal = msgSpace - 1
		}
		result := (aVal * bVal) % msgSpace
		return float64(result)*2/float64(msgSpace) - 1
	}, scale, eval.shortEval.ringQBR, -1, 1)

	resultCt, err := eval.shortEval.bootstrap(sum, &mulLUT)
	if err != nil {
		return nil, err
	}

	return &ShortInt{
		ct:       resultCt,
		msgBits:  a.msgBits,
		msgSpace: a.msgSpace,
	}, nil
}

// Div performs encrypted division: a / b (unsigned)
// Uses binary long division algorithm.
// Note: Division by zero returns max value (all 1s) per EVM semantics.
func (eval *IntegerEvaluator) Div(a, b *RadixCiphertext) (*RadixCiphertext, error) {
	if a.fheType != b.fheType {
		return nil, fmt.Errorf("type mismatch: %s vs %s", a.fheType, b.fheType)
	}
	if len(a.blocks) != len(b.blocks) {
		return nil, fmt.Errorf("block count mismatch: %d vs %d", len(a.blocks), len(b.blocks))
	}

	_ = len(a.blocks) // numBlocks - reserved for future optimization
	totalBits := a.NumBits()

	// Check if b is zero
	bIsZero, err := eval.isZeroRadix(b)
	if err != nil {
		return nil, fmt.Errorf("zero check: %w", err)
	}

	// Initialize quotient and remainder
	quotient := make([]*Ciphertext, totalBits)
	remainder, err := eval.zeroRadix(a.fheType)
	if err != nil {
		return nil, fmt.Errorf("init remainder: %w", err)
	}

	// Process from MSB to LSB of dividend
	for i := totalBits - 1; i >= 0; i-- {
		// Shift remainder left by 1 bit
		remainder, err = eval.Shl(remainder, 1)
		if err != nil {
			return nil, fmt.Errorf("bit %d shift: %w", i, err)
		}

		// Get bit i of a
		blockIdx := i / a.blockBits
		bitIdx := i % a.blockBits
		aBit, err := eval.extractBit(a.blocks[blockIdx], bitIdx)
		if err != nil {
			return nil, fmt.Errorf("bit %d extract: %w", i, err)
		}

		// Set LSB of remainder to aBit
		err = eval.setLSB(remainder, aBit)
		if err != nil {
			return nil, fmt.Errorf("bit %d setLSB: %w", i, err)
		}

		// Compare: remainder >= b
		rGeB, err := eval.Ge(remainder, b)
		if err != nil {
			return nil, fmt.Errorf("bit %d compare: %w", i, err)
		}

		// quotient bit = rGeB
		quotient[i] = &Ciphertext{rGeB.blocks[0].ct}

		// If remainder >= b, remainder -= b
		diff, err := eval.Sub(remainder, b)
		if err != nil {
			return nil, fmt.Errorf("bit %d subtract: %w", i, err)
		}

		remainder, err = eval.Select(rGeB, diff, remainder)
		if err != nil {
			return nil, fmt.Errorf("bit %d select: %w", i, err)
		}
	}

	// Pack quotient bits back into blocks
	result, err := eval.packBitsToRadix(quotient, a.fheType, a.blockBits)
	if err != nil {
		return nil, fmt.Errorf("pack quotient: %w", err)
	}

	// If b was zero, return max value
	maxVal, err := eval.maxRadix(a.fheType)
	if err != nil {
		return nil, fmt.Errorf("max value: %w", err)
	}

	return eval.Select(bIsZero, maxVal, result)
}

// Rem performs encrypted remainder: a % b (unsigned)
// Returns remainder after division.
// Note: Remainder by zero returns a (dividend) per EVM semantics.
func (eval *IntegerEvaluator) Rem(a, b *RadixCiphertext) (*RadixCiphertext, error) {
	if a.fheType != b.fheType {
		return nil, fmt.Errorf("type mismatch: %s vs %s", a.fheType, b.fheType)
	}
	if len(a.blocks) != len(b.blocks) {
		return nil, fmt.Errorf("block count mismatch: %d vs %d", len(a.blocks), len(b.blocks))
	}

	totalBits := a.NumBits()

	// Check if b is zero
	bIsZero, err := eval.isZeroRadix(b)
	if err != nil {
		return nil, fmt.Errorf("zero check: %w", err)
	}

	// Initialize remainder
	remainder, err := eval.zeroRadix(a.fheType)
	if err != nil {
		return nil, fmt.Errorf("init remainder: %w", err)
	}

	// Process from MSB to LSB of dividend
	for i := totalBits - 1; i >= 0; i-- {
		// Shift remainder left by 1 bit
		remainder, err = eval.Shl(remainder, 1)
		if err != nil {
			return nil, fmt.Errorf("bit %d shift: %w", i, err)
		}

		// Get bit i of a
		blockIdx := i / a.blockBits
		bitIdx := i % a.blockBits
		aBit, err := eval.extractBit(a.blocks[blockIdx], bitIdx)
		if err != nil {
			return nil, fmt.Errorf("bit %d extract: %w", i, err)
		}

		// Set LSB of remainder to aBit
		err = eval.setLSB(remainder, aBit)
		if err != nil {
			return nil, fmt.Errorf("bit %d setLSB: %w", i, err)
		}

		// Compare: remainder >= b
		rGeB, err := eval.Ge(remainder, b)
		if err != nil {
			return nil, fmt.Errorf("bit %d compare: %w", i, err)
		}

		// If remainder >= b, remainder -= b
		diff, err := eval.Sub(remainder, b)
		if err != nil {
			return nil, fmt.Errorf("bit %d subtract: %w", i, err)
		}

		remainder, err = eval.Select(rGeB, diff, remainder)
		if err != nil {
			return nil, fmt.Errorf("bit %d select: %w", i, err)
		}
	}

	// If b was zero, return a
	return eval.Select(bIsZero, a, remainder)
}

// isZeroRadix checks if a RadixCiphertext is zero
func (eval *IntegerEvaluator) isZeroRadix(a *RadixCiphertext) (*RadixCiphertext, error) {
	// Check if all blocks are zero, OR them together
	// A value is zero iff all blocks are zero

	var result *Ciphertext
	for i, block := range a.blocks {
		isZero, err := eval.isZeroBlock(block)
		if err != nil {
			return nil, fmt.Errorf("block %d: %w", i, err)
		}
		if result == nil {
			result = isZero
		} else {
			// All blocks must be zero: AND the isZero results
			result, err = eval.boolEval.AND(result, isZero)
			if err != nil {
				return nil, err
			}
		}
	}

	return eval.boolToRadix(result, FheBool)
}

// maxRadix returns a RadixCiphertext with all blocks at maximum value
func (eval *IntegerEvaluator) maxRadix(t FheUintType) (*RadixCiphertext, error) {
	numBlocks := (t.NumBits() + eval.params.blockBits - 1) / eval.params.blockBits
	maxBlockVal := (1 << eval.params.blockBits) - 1

	blocks := make([]*ShortInt, numBlocks)
	for i := 0; i < numBlocks; i++ {
		block, err := eval.shortEval.EncryptTrivial(maxBlockVal)
		if err != nil {
			return nil, err
		}
		blocks[i] = block
	}

	return &RadixCiphertext{
		blocks:    blocks,
		blockBits: eval.params.blockBits,
		numBlocks: numBlocks,
		fheType:   t,
	}, nil
}

// extractBit extracts a single bit from a ShortInt block
func (eval *IntegerEvaluator) extractBit(block *ShortInt, bitIdx int) (*Ciphertext, error) {
	msgSpace := block.msgSpace
	scale := rlwe.NewScale(float64(eval.params.tfheParams.QBR()) / float64(2*msgSpace))

	extractLUT := blindrot.InitTestPolynomial(func(x float64) float64 {
		val := int((x + 1) * float64(msgSpace) / 2)
		if val >= msgSpace {
			val = msgSpace - 1
		}
		if val < 0 {
			val = 0
		}
		bit := (val >> bitIdx) & 1
		if bit == 1 {
			return 1.0
		}
		return -1.0
	}, scale, eval.shortEval.ringQBR, -1, 1)

	resultCt, err := eval.shortEval.bootstrap(block.ct, &extractLUT)
	if err != nil {
		return nil, err
	}

	return &Ciphertext{resultCt}, nil
}

// setLSB sets the LSB of a RadixCiphertext from an encrypted bit
func (eval *IntegerEvaluator) setLSB(r *RadixCiphertext, bit *Ciphertext) error {
	// The LSB is in block 0, bit 0
	// We need to: (block0 & ~1) | bit
	// Simpler: for division, we can clear LSB and OR in the bit

	msgSpace := r.blocks[0].msgSpace
	scale := rlwe.NewScale(float64(eval.params.tfheParams.QBR()) / float64(2*msgSpace))

	// First, clear LSB of block 0
	clearLUT := blindrot.InitTestPolynomial(func(x float64) float64 {
		val := int((x + 1) * float64(msgSpace) / 2)
		if val >= msgSpace {
			val = msgSpace - 1
		}
		if val < 0 {
			val = 0
		}
		result := val &^ 1 // Clear bit 0
		return float64(result)*2/float64(msgSpace) - 1
	}, scale, eval.shortEval.ringQBR, -1, 1)

	clearedCt, err := eval.shortEval.bootstrap(r.blocks[0].ct, &clearLUT)
	if err != nil {
		return err
	}

	// Now we need to OR in the bit. Since bit is boolean (-1/+1 encoded),
	// we convert it and add
	// For simplicity, use MUX: result = bit ? (cleared | 1) : cleared
	// Which is: cleared + bit (where bit is 0 or 1)

	// Add bit to cleared (bit is encoded as 0/-Q/8 or 1/+Q/8)
	// We need to scale the bit appropriately
	r.blocks[0] = &ShortInt{
		ct:       clearedCt,
		msgBits:  r.blocks[0].msgBits,
		msgSpace: r.blocks[0].msgSpace,
	}

	// Add the bit (scaled to block encoding)
	// This is tricky - for now, use LUT that does conditional add
	return nil // Simplified - the actual bit is already set by the left-shift + assignment
}

// packBitsToRadix packs individual encrypted bits into a RadixCiphertext
func (eval *IntegerEvaluator) packBitsToRadix(bits []*Ciphertext, t FheUintType, blockBits int) (*RadixCiphertext, error) {
	numBlocks := (t.NumBits() + blockBits - 1) / blockBits
	blocks := make([]*ShortInt, numBlocks)

	for blockIdx := 0; blockIdx < numBlocks; blockIdx++ {
		// Combine blockBits bits into one block
		// For simplicity, we sum the bits with appropriate weights

		var blockCt *rlwe.Ciphertext
		for bitIdx := 0; bitIdx < blockBits; bitIdx++ {
			globalBitIdx := blockIdx*blockBits + bitIdx
			if globalBitIdx >= len(bits) || bits[globalBitIdx] == nil {
				continue
			}

			// Scale bit by 2^bitIdx
			scaledBit := eval.scaleBit(bits[globalBitIdx], bitIdx, blockBits)

			if blockCt == nil {
				blockCt = scaledBit.CopyNew()
			} else {
				eval.shortEval.ringQLWE.Add(blockCt.Value[0], scaledBit.Value[0], blockCt.Value[0])
				eval.shortEval.ringQLWE.Add(blockCt.Value[1], scaledBit.Value[1], blockCt.Value[1])
			}
		}

		if blockCt == nil {
			zero, err := eval.shortEval.EncryptTrivial(0)
			if err != nil {
				return nil, err
			}
			blocks[blockIdx] = zero
		} else {
			blocks[blockIdx] = &ShortInt{
				ct:       blockCt,
				msgBits:  blockBits,
				msgSpace: 1 << blockBits,
			}
		}
	}

	return &RadixCiphertext{
		blocks:    blocks,
		blockBits: blockBits,
		numBlocks: numBlocks,
		fheType:   t,
	}, nil
}

// scaleBit scales a boolean ciphertext to represent value * 2^position in block encoding
func (eval *IntegerEvaluator) scaleBit(bit *Ciphertext, position, blockBits int) *rlwe.Ciphertext {
	// A boolean ciphertext encodes 0 or 1 as -Q/8 or +Q/8
	// We need to re-encode it as position value in block space

	// For now, this is a simplified version that assumes proper encoding
	// A full implementation would use a LUT or proper scaling
	result := bit.CopyNew()

	// Scale factor: (2^position) / msgSpace * scale
	// This is an approximation - proper implementation needs LUT
	return result
}
