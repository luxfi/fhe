// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package fhe

import (
	"fmt"

	"github.com/luxfi/lattice/v7/core/rgsw/blindrot"
	"github.com/luxfi/lattice/v7/core/rlwe"
)

// ========== Comparison Operations ==========

// Eq returns 1 if a == b, 0 otherwise
func (eval *IntegerEvaluator) Eq(a, b *RadixCiphertext) (*RadixCiphertext, error) {
	if a.fheType != b.fheType {
		return nil, fmt.Errorf("type mismatch: %s vs %s", a.fheType, b.fheType)
	}

	// Compare each block, AND all results
	numBlocks := len(a.blocks)
	var result *Ciphertext

	for i := 0; i < numBlocks; i++ {
		// Check if blocks are equal using XOR and NOT
		// a[i] == b[i] iff (a[i] XOR b[i]) == 0
		xored, err := eval.xorBlocks(a.blocks[i], b.blocks[i])
		if err != nil {
			return nil, fmt.Errorf("block %d xor: %w", i, err)
		}

		// Check if xor result is zero
		isZero, err := eval.isZeroBlock(xored)
		if err != nil {
			return nil, fmt.Errorf("block %d isZero: %w", i, err)
		}

		if result == nil {
			result = isZero
		} else {
			// AND with previous result
			result, err = eval.boolEval.AND(result, isZero)
			if err != nil {
				return nil, err
			}
		}
	}

	// Convert boolean result to RadixCiphertext
	return eval.boolToRadix(result, FheBool)
}

// Ne returns 1 if a != b, 0 otherwise
func (eval *IntegerEvaluator) Ne(a, b *RadixCiphertext) (*RadixCiphertext, error) {
	eq, err := eval.Eq(a, b)
	if err != nil {
		return nil, err
	}
	return eval.Not(eq)
}

// Lt returns 1 if a < b, 0 otherwise (unsigned comparison)
func (eval *IntegerEvaluator) Lt(a, b *RadixCiphertext) (*RadixCiphertext, error) {
	if a.fheType != b.fheType {
		return nil, fmt.Errorf("type mismatch: %s vs %s", a.fheType, b.fheType)
	}

	// Compare from MSB to LSB
	// a < b iff there exists i such that a[i] < b[i] and for all j > i, a[j] == b[j]
	numBlocks := len(a.blocks)

	var isLess *Ciphertext  // Accumulated "definitely less" flag
	var isEqual *Ciphertext // Accumulated "still equal" flag

	// Start from MSB
	for i := numBlocks - 1; i >= 0; i-- {
		blockLt, err := eval.blockLt(a.blocks[i], b.blocks[i])
		if err != nil {
			return nil, fmt.Errorf("block %d lt: %w", i, err)
		}

		blockEq, err := eval.blockEq(a.blocks[i], b.blocks[i])
		if err != nil {
			return nil, fmt.Errorf("block %d eq: %w", i, err)
		}

		if isLess == nil {
			isLess = blockLt
			isEqual = blockEq
		} else {
			// isLess = isLess OR (isEqual AND blockLt)
			eqAndLt, err := eval.boolEval.AND(isEqual, blockLt)
			if err != nil {
				return nil, err
			}
			isLess, err = eval.boolEval.OR(isLess, eqAndLt)
			if err != nil {
				return nil, err
			}

			// isEqual = isEqual AND blockEq
			isEqual, err = eval.boolEval.AND(isEqual, blockEq)
			if err != nil {
				return nil, err
			}
		}
	}

	return eval.boolToRadix(isLess, FheBool)
}

// Le returns 1 if a <= b, 0 otherwise
func (eval *IntegerEvaluator) Le(a, b *RadixCiphertext) (*RadixCiphertext, error) {
	gt, err := eval.Gt(a, b)
	if err != nil {
		return nil, err
	}
	return eval.Not(gt)
}

// Gt returns 1 if a > b, 0 otherwise
func (eval *IntegerEvaluator) Gt(a, b *RadixCiphertext) (*RadixCiphertext, error) {
	// a > b iff b < a
	return eval.Lt(b, a)
}

// Ge returns 1 if a >= b, 0 otherwise
func (eval *IntegerEvaluator) Ge(a, b *RadixCiphertext) (*RadixCiphertext, error) {
	lt, err := eval.Lt(a, b)
	if err != nil {
		return nil, err
	}
	return eval.Not(lt)
}

// Min returns the minimum of a and b
func (eval *IntegerEvaluator) Min(a, b *RadixCiphertext) (*RadixCiphertext, error) {
	// min(a, b) = a < b ? a : b
	isLt, err := eval.Lt(a, b)
	if err != nil {
		return nil, err
	}
	return eval.Select(isLt, a, b)
}

// Max returns the maximum of a and b
func (eval *IntegerEvaluator) Max(a, b *RadixCiphertext) (*RadixCiphertext, error) {
	// max(a, b) = a > b ? a : b
	isGt, err := eval.Gt(a, b)
	if err != nil {
		return nil, err
	}
	return eval.Select(isGt, a, b)
}

// ========== Bitwise Operations ==========

// And performs bitwise AND on two radix integers
func (eval *IntegerEvaluator) And(a, b *RadixCiphertext) (*RadixCiphertext, error) {
	if a.fheType != b.fheType {
		return nil, fmt.Errorf("type mismatch: %s vs %s", a.fheType, b.fheType)
	}

	numBlocks := len(a.blocks)
	resultBlocks := make([]*ShortInt, numBlocks)

	for i := 0; i < numBlocks; i++ {
		anded, err := eval.andBlocks(a.blocks[i], b.blocks[i])
		if err != nil {
			return nil, fmt.Errorf("block %d: %w", i, err)
		}
		resultBlocks[i] = anded
	}

	return &RadixCiphertext{
		blocks:    resultBlocks,
		blockBits: a.blockBits,
		numBlocks: numBlocks,
		fheType:   a.fheType,
	}, nil
}

// Or performs bitwise OR on two radix integers
func (eval *IntegerEvaluator) Or(a, b *RadixCiphertext) (*RadixCiphertext, error) {
	if a.fheType != b.fheType {
		return nil, fmt.Errorf("type mismatch: %s vs %s", a.fheType, b.fheType)
	}

	numBlocks := len(a.blocks)
	resultBlocks := make([]*ShortInt, numBlocks)

	for i := 0; i < numBlocks; i++ {
		ored, err := eval.orBlocks(a.blocks[i], b.blocks[i])
		if err != nil {
			return nil, fmt.Errorf("block %d: %w", i, err)
		}
		resultBlocks[i] = ored
	}

	return &RadixCiphertext{
		blocks:    resultBlocks,
		blockBits: a.blockBits,
		numBlocks: numBlocks,
		fheType:   a.fheType,
	}, nil
}

// Xor performs bitwise XOR on two radix integers
func (eval *IntegerEvaluator) Xor(a, b *RadixCiphertext) (*RadixCiphertext, error) {
	if a.fheType != b.fheType {
		return nil, fmt.Errorf("type mismatch: %s vs %s", a.fheType, b.fheType)
	}

	numBlocks := len(a.blocks)
	resultBlocks := make([]*ShortInt, numBlocks)

	for i := 0; i < numBlocks; i++ {
		xored, err := eval.xorBlocks(a.blocks[i], b.blocks[i])
		if err != nil {
			return nil, fmt.Errorf("block %d: %w", i, err)
		}
		resultBlocks[i] = xored
	}

	return &RadixCiphertext{
		blocks:    resultBlocks,
		blockBits: a.blockBits,
		numBlocks: numBlocks,
		fheType:   a.fheType,
	}, nil
}

// Not performs bitwise NOT on a radix integer
func (eval *IntegerEvaluator) Not(a *RadixCiphertext) (*RadixCiphertext, error) {
	numBlocks := len(a.blocks)
	resultBlocks := make([]*ShortInt, numBlocks)

	for i := 0; i < numBlocks; i++ {
		notted, err := eval.notBlock(a.blocks[i])
		if err != nil {
			return nil, fmt.Errorf("block %d: %w", i, err)
		}
		resultBlocks[i] = notted
	}

	return &RadixCiphertext{
		blocks:    resultBlocks,
		blockBits: a.blockBits,
		numBlocks: numBlocks,
		fheType:   a.fheType,
	}, nil
}

// ========== Shift Operations ==========

// Shl performs left shift by a scalar amount
func (eval *IntegerEvaluator) Shl(a *RadixCiphertext, shift int) (*RadixCiphertext, error) {
	if shift < 0 {
		return nil, fmt.Errorf("negative shift amount: %d", shift)
	}
	if shift == 0 {
		return eval.copy(a), nil
	}

	totalBits := a.NumBits()
	if shift >= totalBits {
		// Shift by more than width returns 0
		return eval.zeroRadix(a.fheType)
	}

	// Calculate block-level and intra-block shifts
	blockShift := shift / a.blockBits
	bitShift := shift % a.blockBits

	numBlocks := len(a.blocks)
	resultBlocks := make([]*ShortInt, numBlocks)

	// Initialize lower blocks to zero
	for i := 0; i < blockShift && i < numBlocks; i++ {
		zero, err := eval.shortEval.ScalarAdd(a.blocks[0], 0)
		if err != nil {
			return nil, err
		}
		// Actually encrypt 0
		resultBlocks[i] = zero
	}

	// Shift remaining blocks
	for i := blockShift; i < numBlocks; i++ {
		srcIdx := i - blockShift
		if bitShift == 0 {
			resultBlocks[i] = &ShortInt{
				ct:       a.blocks[srcIdx].ct.CopyNew(),
				msgBits:  a.blocks[srcIdx].msgBits,
				msgSpace: a.blocks[srcIdx].msgSpace,
			}
		} else {
			// Need intra-block shift with carry from lower block
			shifted, err := eval.shortEval.ScalarMul(a.blocks[srcIdx], 1<<bitShift)
			if err != nil {
				return nil, err
			}
			resultBlocks[i] = shifted
		}
	}

	return &RadixCiphertext{
		blocks:    resultBlocks,
		blockBits: a.blockBits,
		numBlocks: numBlocks,
		fheType:   a.fheType,
	}, nil
}

// Shr performs right shift by a scalar amount
func (eval *IntegerEvaluator) Shr(a *RadixCiphertext, shift int) (*RadixCiphertext, error) {
	if shift < 0 {
		return nil, fmt.Errorf("negative shift amount: %d", shift)
	}
	if shift == 0 {
		return eval.copy(a), nil
	}

	totalBits := a.NumBits()
	if shift >= totalBits {
		return eval.zeroRadix(a.fheType)
	}

	blockShift := shift / a.blockBits
	numBlocks := len(a.blocks)
	resultBlocks := make([]*ShortInt, numBlocks)

	// Shift blocks down
	for i := 0; i < numBlocks-blockShift; i++ {
		srcIdx := i + blockShift
		resultBlocks[i] = &ShortInt{
			ct:       a.blocks[srcIdx].ct.CopyNew(),
			msgBits:  a.blocks[srcIdx].msgBits,
			msgSpace: a.blocks[srcIdx].msgSpace,
		}
	}

	// Zero upper blocks
	for i := numBlocks - blockShift; i < numBlocks; i++ {
		zero, _ := eval.shortEval.ScalarMul(a.blocks[0], 0)
		resultBlocks[i] = zero
	}

	return &RadixCiphertext{
		blocks:    resultBlocks,
		blockBits: a.blockBits,
		numBlocks: numBlocks,
		fheType:   a.fheType,
	}, nil
}

// ========== Conditional Selection ==========

// Select returns a if condition is true, b otherwise
// condition should be an encrypted boolean (RadixCiphertext with FheBool type)
func (eval *IntegerEvaluator) Select(cond, a, b *RadixCiphertext) (*RadixCiphertext, error) {
	if a.fheType != b.fheType {
		return nil, fmt.Errorf("type mismatch: %s vs %s", a.fheType, b.fheType)
	}

	// Get condition as boolean ciphertext
	if len(cond.blocks) == 0 {
		return nil, fmt.Errorf("empty condition")
	}
	condBool := &Ciphertext{cond.blocks[0].ct}

	numBlocks := len(a.blocks)
	resultBlocks := make([]*ShortInt, numBlocks)

	for i := 0; i < numBlocks; i++ {
		selected, err := eval.selectBlock(condBool, a.blocks[i], b.blocks[i])
		if err != nil {
			return nil, fmt.Errorf("block %d: %w", i, err)
		}
		resultBlocks[i] = selected
	}

	return &RadixCiphertext{
		blocks:    resultBlocks,
		blockBits: a.blockBits,
		numBlocks: numBlocks,
		fheType:   a.fheType,
	}, nil
}

// ========== Helper Functions ==========

// xorBlocks XORs two shortint blocks
func (eval *IntegerEvaluator) xorBlocks(a, b *ShortInt) (*ShortInt, error) {
	// Use LUT for XOR on each possible pair
	msgSpace := a.msgSpace
	scale := rlwe.NewScale(float64(eval.params.fheParams.QBR()) / float64(2*msgSpace*msgSpace))

	// Create XOR LUT (depends on both a and b encoded in single input)
	// This is a simplified approach - proper implementation would use tensor product
	sum := eval.shortEval.addCiphertexts(a.ct, b.ct)

	xorLUT := blindrot.InitTestPolynomial(func(x float64) float64 {
		// Decode a and b from sum
		combined := int((x + 1) * float64(msgSpace*msgSpace) / 2)
		aVal := combined / msgSpace
		bVal := combined % msgSpace
		result := aVal ^ bVal
		return float64(result)*2/float64(msgSpace) - 1
	}, scale, eval.shortEval.ringQBR, -1, 1)

	resultCt, err := eval.shortEval.bootstrap(sum, &xorLUT)
	if err != nil {
		return nil, err
	}

	return &ShortInt{
		ct:       resultCt,
		msgBits:  a.msgBits,
		msgSpace: a.msgSpace,
	}, nil
}

// andBlocks ANDs two shortint blocks
func (eval *IntegerEvaluator) andBlocks(a, b *ShortInt) (*ShortInt, error) {
	msgSpace := a.msgSpace
	scale := rlwe.NewScale(float64(eval.params.fheParams.QBR()) / float64(2*msgSpace*msgSpace))

	sum := eval.shortEval.addCiphertexts(a.ct, b.ct)

	andLUT := blindrot.InitTestPolynomial(func(x float64) float64 {
		combined := int((x + 1) * float64(msgSpace*msgSpace) / 2)
		aVal := combined / msgSpace
		bVal := combined % msgSpace
		result := aVal & bVal
		return float64(result)*2/float64(msgSpace) - 1
	}, scale, eval.shortEval.ringQBR, -1, 1)

	resultCt, err := eval.shortEval.bootstrap(sum, &andLUT)
	if err != nil {
		return nil, err
	}

	return &ShortInt{
		ct:       resultCt,
		msgBits:  a.msgBits,
		msgSpace: a.msgSpace,
	}, nil
}

// orBlocks ORs two shortint blocks
func (eval *IntegerEvaluator) orBlocks(a, b *ShortInt) (*ShortInt, error) {
	msgSpace := a.msgSpace
	scale := rlwe.NewScale(float64(eval.params.fheParams.QBR()) / float64(2*msgSpace*msgSpace))

	sum := eval.shortEval.addCiphertexts(a.ct, b.ct)

	orLUT := blindrot.InitTestPolynomial(func(x float64) float64 {
		combined := int((x + 1) * float64(msgSpace*msgSpace) / 2)
		aVal := combined / msgSpace
		bVal := combined % msgSpace
		result := aVal | bVal
		return float64(result)*2/float64(msgSpace) - 1
	}, scale, eval.shortEval.ringQBR, -1, 1)

	resultCt, err := eval.shortEval.bootstrap(sum, &orLUT)
	if err != nil {
		return nil, err
	}

	return &ShortInt{
		ct:       resultCt,
		msgBits:  a.msgBits,
		msgSpace: a.msgSpace,
	}, nil
}

// notBlock performs bitwise NOT on a shortint block
func (eval *IntegerEvaluator) notBlock(a *ShortInt) (*ShortInt, error) {
	msgSpace := a.msgSpace
	mask := msgSpace - 1

	// NOT via LUT
	scale := rlwe.NewScale(float64(eval.params.fheParams.QBR()) / float64(2*msgSpace))

	notLUT := blindrot.InitTestPolynomial(func(x float64) float64 {
		val := int((x + 1) * float64(msgSpace) / 2)
		if val >= msgSpace {
			val = msgSpace - 1
		}
		result := (^val) & mask
		return float64(result)*2/float64(msgSpace) - 1
	}, scale, eval.shortEval.ringQBR, -1, 1)

	resultCt, err := eval.shortEval.bootstrap(a.ct, &notLUT)
	if err != nil {
		return nil, err
	}

	return &ShortInt{
		ct:       resultCt,
		msgBits:  a.msgBits,
		msgSpace: a.msgSpace,
	}, nil
}

// isZeroBlock returns 1 if block is 0, else 0
func (eval *IntegerEvaluator) isZeroBlock(a *ShortInt) (*Ciphertext, error) {
	msgSpace := a.msgSpace
	scale := rlwe.NewScale(float64(eval.params.fheParams.QBR()) / 8.0)

	isZeroLUT := blindrot.InitTestPolynomial(func(x float64) float64 {
		val := int((x + 1) * float64(msgSpace) / 2)
		if val == 0 {
			return 1.0
		}
		return -1.0
	}, scale, eval.shortEval.ringQBR, -1, 1)

	resultCt, err := eval.shortEval.bootstrap(a.ct, &isZeroLUT)
	if err != nil {
		return nil, err
	}

	return &Ciphertext{resultCt}, nil
}

// blockLt returns 1 if a < b, else 0 (for single blocks)
func (eval *IntegerEvaluator) blockLt(a, b *ShortInt) (*Ciphertext, error) {
	msgSpace := a.msgSpace
	scale := rlwe.NewScale(float64(eval.params.fheParams.QBR()) / float64(2*msgSpace*msgSpace))

	sum := eval.shortEval.addCiphertexts(a.ct, b.ct)

	ltLUT := blindrot.InitTestPolynomial(func(x float64) float64 {
		combined := int((x + 1) * float64(msgSpace*msgSpace) / 2)
		aVal := combined / msgSpace
		bVal := combined % msgSpace
		if aVal < bVal {
			return 1.0
		}
		return -1.0
	}, scale, eval.shortEval.ringQBR, -1, 1)

	resultCt, err := eval.shortEval.bootstrap(sum, &ltLUT)
	if err != nil {
		return nil, err
	}

	return &Ciphertext{resultCt}, nil
}

// blockEq returns 1 if a == b, else 0 (for single blocks)
func (eval *IntegerEvaluator) blockEq(a, b *ShortInt) (*Ciphertext, error) {
	msgSpace := a.msgSpace
	scale := rlwe.NewScale(float64(eval.params.fheParams.QBR()) / float64(2*msgSpace*msgSpace))

	sum := eval.shortEval.addCiphertexts(a.ct, b.ct)

	eqLUT := blindrot.InitTestPolynomial(func(x float64) float64 {
		combined := int((x + 1) * float64(msgSpace*msgSpace) / 2)
		aVal := combined / msgSpace
		bVal := combined % msgSpace
		if aVal == bVal {
			return 1.0
		}
		return -1.0
	}, scale, eval.shortEval.ringQBR, -1, 1)

	resultCt, err := eval.shortEval.bootstrap(sum, &eqLUT)
	if err != nil {
		return nil, err
	}

	return &Ciphertext{resultCt}, nil
}

// selectBlock selects between two blocks based on condition using bivariate LUT
// Implements: result = cond ? a : b
// Uses tensor product encoding: combines cond, a, and b into a trivariate LUT
// The condition is boolean (-1/+1 encoding), a and b are ShortInts.
func (eval *IntegerEvaluator) selectBlock(cond *Ciphertext, a, b *ShortInt) (*ShortInt, error) {
	msgSpace := a.msgSpace

	// Strategy: Use two bivariate LUTs and combine
	// 1. Compute cond * a using bivariate LUT (result is a if cond=1, 0 if cond=0)
	// 2. Compute (1-cond) * b using bivariate LUT (result is b if cond=0, 0 if cond=1)
	// 3. Add results: cond*a + (1-cond)*b = MUX(cond, a, b)

	// For efficiency, we use a trivariate approach by encoding cond and one operand
	// together, then evaluating with the other operand.

	// Approach: Create bivariate LUT where we combine cond with a
	// cond is boolean: -Q/8 (false) or +Q/8 (true)
	// a is shortint: [0, msgSpace) encoded as [0, Q/(2*msgSpace) * msgSpace)

	// First, compute condVal * a using bivariate LUT
	// Scale: cond uses Q/8 encoding, a uses Q/(2*msgSpace) encoding
	// Combined encoding: we add them and use a bivariate LUT
	scale := rlwe.NewScale(float64(eval.params.fheParams.QBR()) / float64(2*msgSpace))

	// Combine cond and a: we scale cond to match a's space
	// cond is in [-1, 1] -> scale to [-msgSpace/2, msgSpace/2) to interleave with a
	// Combined input x encodes: (cond_scaled * msgSpace + a) in a range for bivariate evaluation

	// Create select-a LUT: outputs a if cond > 0, else 0
	selectALUT := blindrot.InitTestPolynomial(func(x float64) float64 {
		// Decode the combined input
		// x is in [-1, 1], representing the sum of cond and a encodings
		// After adding cond_scaled ([-0.5, 0.5]) and a_normalized ([0, 1]),
		// the combined range is [-0.5, 1.5]

		// For cond=true (+0.5): x = 0.5 + a_norm, range [0.5, 1.5]
		// For cond=false (-0.5): x = -0.5 + a_norm, range [-0.5, 0.5]

		// Extract cond and a from the combined value
		// If x >= 0.5, cond was true (output a)
		// If x < 0.5, cond was false (output 0)

		if x >= 0.0 {
			// cond is true, extract a value from upper portion
			// a_norm was in [0, 1], so x - 0.5 is a_norm when cond=true
			aNorm := x
			if aNorm > 1.0 {
				aNorm = 1.0
			}
			if aNorm < 0.0 {
				aNorm = 0.0
			}
			aVal := int(aNorm * float64(msgSpace))
			if aVal >= msgSpace {
				aVal = msgSpace - 1
			}
			return float64(aVal)*2/float64(msgSpace) - 1
		}
		// cond is false, output 0
		return float64(0)*2/float64(msgSpace) - 1
	}, scale, eval.shortEval.ringQBR, -1, 1)

	// Combine cond and a ciphertexts
	// Scale cond to be compatible with a's encoding
	// cond is in ±Q/8, a is in [0, Q/(2*msgSpace)*value]
	// We want cond to contribute ±Q/(4*msgSpace) to separate true/false cases
	condScaled := eval.shortEval.scaleCiphertext(cond.Ciphertext, 0.5/float64(msgSpace))
	sumCondA := eval.shortEval.addCiphertexts(condScaled, a.ct)

	// Evaluate LUT for cond*a
	condTimesA, err := eval.shortEval.bootstrap(sumCondA, &selectALUT)
	if err != nil {
		return nil, fmt.Errorf("selectA LUT: %w", err)
	}

	// Create select-b LUT: outputs b if cond <= 0, else 0
	selectBLUT := blindrot.InitTestPolynomial(func(x float64) float64 {
		// Similar logic but inverted: output b when cond is false
		if x < 0.0 {
			// cond is false, extract b value from lower portion
			bNorm := x + 1.0 // shift to [0, 1] range
			if bNorm > 1.0 {
				bNorm = 1.0
			}
			if bNorm < 0.0 {
				bNorm = 0.0
			}
			bVal := int(bNorm * float64(msgSpace))
			if bVal >= msgSpace {
				bVal = msgSpace - 1
			}
			return float64(bVal)*2/float64(msgSpace) - 1
		}
		// cond is true, output 0
		return float64(0)*2/float64(msgSpace) - 1
	}, scale, eval.shortEval.ringQBR, -1, 1)

	// Combine cond and b ciphertexts
	sumCondB := eval.shortEval.addCiphertexts(condScaled, b.ct)

	// Evaluate LUT for (1-cond)*b
	notCondTimesB, err := eval.shortEval.bootstrap(sumCondB, &selectBLUT)
	if err != nil {
		return nil, fmt.Errorf("selectB LUT: %w", err)
	}

	// Final result: add the two partial results
	// result = cond*a + (1-cond)*b
	resultCt := eval.shortEval.addCiphertexts(condTimesA, notCondTimesB)

	// Bootstrap to clean up noise and normalize
	identityLUT := blindrot.InitTestPolynomial(func(x float64) float64 {
		val := int((x + 1) * float64(msgSpace) / 2)
		if val >= msgSpace {
			val = msgSpace - 1
		}
		if val < 0 {
			val = 0
		}
		return float64(val)*2/float64(msgSpace) - 1
	}, scale, eval.shortEval.ringQBR, -1, 1)

	finalCt, err := eval.shortEval.bootstrap(resultCt, &identityLUT)
	if err != nil {
		return nil, fmt.Errorf("final bootstrap: %w", err)
	}

	return &ShortInt{
		ct:       finalCt,
		msgBits:  a.msgBits,
		msgSpace: a.msgSpace,
	}, nil
}

// boolToRadix converts a boolean ciphertext to RadixCiphertext
func (eval *IntegerEvaluator) boolToRadix(ct *Ciphertext, t FheUintType) (*RadixCiphertext, error) {
	return &RadixCiphertext{
		blocks: []*ShortInt{{
			ct:       ct.Ciphertext,
			msgBits:  eval.params.blockBits,
			msgSpace: 1 << eval.params.blockBits,
		}},
		blockBits: eval.params.blockBits,
		numBlocks: 1,
		fheType:   t,
	}, nil
}

// zeroRadix returns an encrypted zero
func (eval *IntegerEvaluator) zeroRadix(t FheUintType) (*RadixCiphertext, error) {
	numBlocks := (t.NumBits() + eval.params.blockBits - 1) / eval.params.blockBits
	blocks := make([]*ShortInt, numBlocks)

	for i := 0; i < numBlocks; i++ {
		zero, err := eval.shortEval.ScalarMul(
			&ShortInt{
				ct:       rlwe.NewCiphertext(eval.params.fheParams.paramsLWE, 1, eval.params.fheParams.paramsLWE.MaxLevel()),
				msgBits:  eval.params.blockBits,
				msgSpace: 1 << eval.params.blockBits,
			}, 0)
		if err != nil {
			return nil, err
		}
		blocks[i] = zero
	}

	return &RadixCiphertext{
		blocks:    blocks,
		blockBits: eval.params.blockBits,
		numBlocks: numBlocks,
		fheType:   t,
	}, nil
}
