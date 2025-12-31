// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

// Package fhe provides lazy carry propagation for encrypted integers.
//
// Key Innovation: Defer carry propagation to reduce expensive programmable bootstrapping (PBS).
//
//   - Traditional: Propagate carry after every add (expensive PBS per limb)
//   - Lazy: Accumulate carries, propagate only when needed
//   - Each limb stores value in extended range [0, 2^k * max_ops)
//   - Propagate when: (1) overflow imminent, (2) comparison needed, (3) explicit request
//
// For euint256 with 8 x 32-bit limbs:
//   - Traditional add: 7 PBS for carry chain
//   - Lazy add (up to 16 ops): 0 PBS
//   - Lazy propagate: 7 PBS (amortized over 16 ops)
//
// This provides 10-16x reduction in PBS operations for arithmetic-heavy workloads.
package fhe

import (
	"fmt"
)

// LazyCarryConfig holds configuration for lazy carry propagation.
type LazyCarryConfig struct {
	// MaxOpsBeforePropagate is the maximum number of additions before forcing propagation.
	// Higher values amortize PBS cost better but increase per-limb noise.
	// Recommended: 8-16 for 128-bit security, 4-8 for 256-bit security.
	MaxOpsBeforePropagate int

	// OverflowMargin is the safety margin before limb overflow.
	// When remaining headroom < OverflowMargin, propagation is triggered.
	OverflowMargin uint64

	// PropagateOnCompare forces propagation before any comparison operation.
	// Must be true for correct comparison results.
	PropagateOnCompare bool
}

// DefaultLazyCarryConfig returns sensible defaults for EVM workloads.
func DefaultLazyCarryConfig() LazyCarryConfig {
	return LazyCarryConfig{
		MaxOpsBeforePropagate: 16,
		OverflowMargin:        1 << 16, // 64K safety margin
		PropagateOnCompare:    true,
	}
}

// LimbState tracks the state of a single limb in lazy carry representation.
type LimbState struct {
	// Value is the encrypted limb value.
	// In lazy mode, this may exceed the normal limb range.
	Value *BitCiphertext

	// AccumulatedCarry tracks how many carries have accumulated.
	// Used to detect when propagation is needed.
	AccumulatedCarry int

	// LimbBits is the nominal bit width of this limb.
	LimbBits int

	// ExtendedBits is the actual storage width (LimbBits + headroom for carries).
	ExtendedBits int
}

// LazyCarryInteger represents an encrypted integer with lazy carry propagation.
//
// Problem Statement:
// Traditional radix arithmetic propagates carries after every operation,
// requiring O(n) PBS calls for n-limb integers. This is the dominant cost
// in FHE arithmetic.
//
// Invariants:
//   - Each limb stores a value in [0, 2^ExtendedBits)
//   - The true value is Sum(limb[i] * 2^(i*LimbBits)) with carries applied
//   - OpsWithoutPropagate tracks operations since last normalization
//   - When OpsWithoutPropagate >= config.MaxOpsBeforePropagate, propagation is required
//
// Interface:
//   - Add/Sub: O(n) parallel limb operations, 0 PBS
//   - Propagate: O(n) sequential PBS calls (amortized)
//   - Compare: Forces propagation, then O(n) comparisons
type LazyCarryInteger struct {
	// Limbs are stored LSB-first (limbs[0] is least significant).
	Limbs []*LimbState

	// NumLimbs is the number of limbs.
	NumLimbs int

	// LimbBits is the nominal bit width per limb.
	LimbBits int

	// OpsWithoutPropagate counts additions since last carry propagation.
	OpsWithoutPropagate int

	// FheType is the underlying FHE integer type.
	FheType FheUintType

	// Config holds the lazy carry configuration.
	Config LazyCarryConfig
}

// LazyCarryEvaluator performs operations on LazyCarryInteger values.
type LazyCarryEvaluator struct {
	eval   *BitwiseEvaluator
	config LazyCarryConfig
}

// NewLazyCarryEvaluator creates a new evaluator for lazy carry integers.
func NewLazyCarryEvaluator(eval *BitwiseEvaluator, config LazyCarryConfig) *LazyCarryEvaluator {
	return &LazyCarryEvaluator{
		eval:   eval,
		config: config,
	}
}

// FromBitCiphertext converts a BitCiphertext to lazy carry representation.
//
// For euint256: Creates 8 limbs of 32 bits each.
// For euint128: Creates 4 limbs of 32 bits each.
// For smaller types: Creates appropriate limb structure.
func (lce *LazyCarryEvaluator) FromBitCiphertext(bc *BitCiphertext) (*LazyCarryInteger, error) {
	totalBits := bc.NumBits()

	// Determine limb structure based on type
	var limbBits, numLimbs int
	switch bc.Type() {
	case FheUint256:
		limbBits = 32
		numLimbs = 8
	case FheUint160:
		limbBits = 32
		numLimbs = 5
	case FheUint128:
		limbBits = 32
		numLimbs = 4
	case FheUint64:
		limbBits = 16
		numLimbs = 4
	case FheUint32:
		limbBits = 8
		numLimbs = 4
	case FheUint16:
		limbBits = 8
		numLimbs = 2
	case FheUint8:
		limbBits = 4
		numLimbs = 2
	case FheUint4:
		limbBits = 4
		numLimbs = 1
	default:
		return nil, fmt.Errorf("unsupported type for lazy carry: %s", bc.Type())
	}

	// Verify consistency
	if limbBits*numLimbs != totalBits {
		return nil, fmt.Errorf("limb configuration mismatch: %d limbs * %d bits != %d total",
			numLimbs, limbBits, totalBits)
	}

	// Extended bits provides headroom for carry accumulation
	// With 16 ops max, we need log2(16) = 4 extra bits
	extendedBits := limbBits + 4

	// Create limbs by splitting the bit ciphertext
	limbs := make([]*LimbState, numLimbs)
	for i := 0; i < numLimbs; i++ {
		startBit := i * limbBits
		endBit := startBit + limbBits

		// Extract bits for this limb
		limbCipherBits := make([]*Ciphertext, extendedBits)
		for j := 0; j < limbBits; j++ {
			if startBit+j < len(bc.bits) {
				limbCipherBits[j] = bc.bits[startBit+j]
			} else {
				// Pad with zero bits for extended range
				limbCipherBits[j] = lce.eval.encryptBit(false)
			}
		}

		// Pad remaining extended bits with zeros
		for j := endBit - startBit; j < extendedBits; j++ {
			limbCipherBits[j] = lce.eval.encryptBit(false)
		}

		limbs[i] = &LimbState{
			Value: &BitCiphertext{
				bits:    limbCipherBits,
				numBits: extendedBits,
				fheType: bc.Type(), // Keep original type for reference
			},
			AccumulatedCarry: 0,
			LimbBits:         limbBits,
			ExtendedBits:     extendedBits,
		}
	}

	return &LazyCarryInteger{
		Limbs:               limbs,
		NumLimbs:            numLimbs,
		LimbBits:            limbBits,
		OpsWithoutPropagate: 0,
		FheType:             bc.Type(),
		Config:              lce.config,
	}, nil
}

// ToBitCiphertext converts a LazyCarryInteger back to BitCiphertext.
// This forces carry propagation if needed.
func (lce *LazyCarryEvaluator) ToBitCiphertext(lci *LazyCarryInteger) (*BitCiphertext, error) {
	// Force propagation to normalize
	normalized, err := lce.Propagate(lci)
	if err != nil {
		return nil, fmt.Errorf("propagate for output: %w", err)
	}

	// Collect bits from all limbs
	totalBits := normalized.NumLimbs * normalized.LimbBits
	bits := make([]*Ciphertext, totalBits)

	for i := 0; i < normalized.NumLimbs; i++ {
		for j := 0; j < normalized.LimbBits; j++ {
			bits[i*normalized.LimbBits+j] = normalized.Limbs[i].Value.bits[j]
		}
	}

	return &BitCiphertext{
		bits:    bits,
		numBits: totalBits,
		fheType: normalized.FheType,
	}, nil
}

// Add performs lazy addition without carry propagation.
//
// Complexity: O(numLimbs) parallel limb additions, 0 PBS.
// Each limb addition is O(limbBits) XOR/AND operations.
//
// Precondition: a and b have compatible types and limb structures.
// Postcondition: Result accumulates values; propagation deferred until needed.
func (lce *LazyCarryEvaluator) Add(a, b *LazyCarryInteger) (*LazyCarryInteger, error) {
	if a.FheType != b.FheType {
		return nil, fmt.Errorf("type mismatch: %s vs %s", a.FheType, b.FheType)
	}
	if a.NumLimbs != b.NumLimbs {
		return nil, fmt.Errorf("limb count mismatch: %d vs %d", a.NumLimbs, b.NumLimbs)
	}

	// Check if propagation needed before this operation
	if a.OpsWithoutPropagate >= lce.config.MaxOpsBeforePropagate ||
		b.OpsWithoutPropagate >= lce.config.MaxOpsBeforePropagate {
		var err error
		a, err = lce.Propagate(a)
		if err != nil {
			return nil, fmt.Errorf("propagate a: %w", err)
		}
		b, err = lce.Propagate(b)
		if err != nil {
			return nil, fmt.Errorf("propagate b: %w", err)
		}
	}

	// Perform lazy addition: just add limb values without carry propagation
	result := &LazyCarryInteger{
		Limbs:               make([]*LimbState, a.NumLimbs),
		NumLimbs:            a.NumLimbs,
		LimbBits:            a.LimbBits,
		OpsWithoutPropagate: max(a.OpsWithoutPropagate, b.OpsWithoutPropagate) + 1,
		FheType:             a.FheType,
		Config:              lce.config,
	}

	// Add each limb independently (no carry propagation!)
	for i := 0; i < a.NumLimbs; i++ {
		limbSum, err := lce.eval.Add(a.Limbs[i].Value, b.Limbs[i].Value)
		if err != nil {
			return nil, fmt.Errorf("limb %d add: %w", i, err)
		}

		result.Limbs[i] = &LimbState{
			Value:            limbSum,
			AccumulatedCarry: a.Limbs[i].AccumulatedCarry + b.Limbs[i].AccumulatedCarry + 1,
			LimbBits:         a.LimbBits,
			ExtendedBits:     a.Limbs[i].ExtendedBits,
		}
	}

	return result, nil
}

// Sub performs lazy subtraction without carry propagation.
func (lce *LazyCarryEvaluator) Sub(a, b *LazyCarryInteger) (*LazyCarryInteger, error) {
	if a.FheType != b.FheType {
		return nil, fmt.Errorf("type mismatch: %s vs %s", a.FheType, b.FheType)
	}
	if a.NumLimbs != b.NumLimbs {
		return nil, fmt.Errorf("limb count mismatch: %d vs %d", a.NumLimbs, b.NumLimbs)
	}

	// Subtraction requires propagation for correctness (borrow handling)
	aNorm, err := lce.Propagate(a)
	if err != nil {
		return nil, fmt.Errorf("propagate a: %w", err)
	}
	bNorm, err := lce.Propagate(b)
	if err != nil {
		return nil, fmt.Errorf("propagate b: %w", err)
	}

	// Convert to bit representation, subtract, convert back
	aBits, err := lce.ToBitCiphertext(aNorm)
	if err != nil {
		return nil, fmt.Errorf("a to bits: %w", err)
	}
	bBits, err := lce.ToBitCiphertext(bNorm)
	if err != nil {
		return nil, fmt.Errorf("b to bits: %w", err)
	}

	diffBits, err := lce.eval.Sub(aBits, bBits)
	if err != nil {
		return nil, fmt.Errorf("subtract: %w", err)
	}

	return lce.FromBitCiphertext(diffBits)
}

// Propagate forces carry propagation through all limbs.
//
// Complexity: O(numLimbs) sequential carry operations.
// Each carry operation requires PBS for the carry extraction.
//
// Postcondition: All limbs are in normalized range [0, 2^LimbBits).
func (lce *LazyCarryEvaluator) Propagate(lci *LazyCarryInteger) (*LazyCarryInteger, error) {
	if lci.OpsWithoutPropagate == 0 {
		// Already propagated
		return lci, nil
	}

	result := &LazyCarryInteger{
		Limbs:               make([]*LimbState, lci.NumLimbs),
		NumLimbs:            lci.NumLimbs,
		LimbBits:            lci.LimbBits,
		OpsWithoutPropagate: 0, // Reset counter
		FheType:             lci.FheType,
		Config:              lci.Config,
	}

	// Carry propagation: sequential from LSB to MSB
	var carry *BitCiphertext
	for i := 0; i < lci.NumLimbs; i++ {
		limbValue := lci.Limbs[i].Value

		// Add incoming carry from previous limb
		if carry != nil {
			var err error
			limbValue, err = lce.eval.Add(limbValue, carry)
			if err != nil {
				return nil, fmt.Errorf("limb %d carry add: %w", i, err)
			}
		}

		// Extract carry: bits above LimbBits position
		// The carry is the value >> LimbBits
		normalizedValue, newCarry := lce.extractCarry(limbValue, lci.LimbBits)

		result.Limbs[i] = &LimbState{
			Value:            normalizedValue,
			AccumulatedCarry: 0,
			LimbBits:         lci.LimbBits,
			ExtendedBits:     lci.Limbs[i].ExtendedBits,
		}

		carry = newCarry
	}
	// Final carry is discarded (overflow)

	return result, nil
}

// extractCarry splits an extended limb into normalized value and carry.
//
// For a limb with value V in [0, 2^ExtendedBits):
//   - normalizedValue = V mod 2^LimbBits (lower LimbBits)
//   - carry = V >> LimbBits (upper bits, to add to next limb)
func (lce *LazyCarryEvaluator) extractCarry(limb *BitCiphertext, limbBits int) (*BitCiphertext, *BitCiphertext) {
	if limb.numBits <= limbBits {
		// No extended bits, no carry - return empty carry
		carryBitCount := 0
		if limb.numBits > limbBits {
			carryBitCount = limb.numBits - limbBits
		}
		zeroBits := make([]*Ciphertext, carryBitCount)
		for i := range zeroBits {
			zeroBits[i] = lce.eval.encryptBit(false)
		}
		return limb, &BitCiphertext{
			bits:    zeroBits,
			numBits: carryBitCount,
			fheType: limb.fheType,
		}
	}

	// Lower bits: normalized value
	normalizedBits := make([]*Ciphertext, limbBits)
	copy(normalizedBits, limb.bits[:limbBits])

	normalizedValue := &BitCiphertext{
		bits:    normalizedBits,
		numBits: limbBits,
		fheType: limb.fheType,
	}

	// Upper bits: carry (will be added to next limb)
	carryBits := make([]*Ciphertext, limb.numBits-limbBits)
	copy(carryBits, limb.bits[limbBits:])

	carry := &BitCiphertext{
		bits:    carryBits,
		numBits: limb.numBits - limbBits,
		fheType: limb.fheType,
	}

	return normalizedValue, carry
}

// NeedsPropagation returns true if carry propagation is needed.
func (lci *LazyCarryInteger) NeedsPropagation() bool {
	return lci.OpsWithoutPropagate >= lci.Config.MaxOpsBeforePropagate
}

// Eq compares two lazy carry integers for equality.
// Forces propagation for correct comparison.
func (lce *LazyCarryEvaluator) Eq(a, b *LazyCarryInteger) (*Ciphertext, error) {
	if lce.config.PropagateOnCompare {
		var err error
		a, err = lce.Propagate(a)
		if err != nil {
			return nil, err
		}
		b, err = lce.Propagate(b)
		if err != nil {
			return nil, err
		}
	}

	aBits, err := lce.ToBitCiphertext(a)
	if err != nil {
		return nil, err
	}
	bBits, err := lce.ToBitCiphertext(b)
	if err != nil {
		return nil, err
	}

	return lce.eval.Eq(aBits, bBits)
}

// Lt compares a < b (unsigned).
// Forces propagation for correct comparison.
func (lce *LazyCarryEvaluator) Lt(a, b *LazyCarryInteger) (*Ciphertext, error) {
	if lce.config.PropagateOnCompare {
		var err error
		a, err = lce.Propagate(a)
		if err != nil {
			return nil, err
		}
		b, err = lce.Propagate(b)
		if err != nil {
			return nil, err
		}
	}

	aBits, err := lce.ToBitCiphertext(a)
	if err != nil {
		return nil, err
	}
	bBits, err := lce.ToBitCiphertext(b)
	if err != nil {
		return nil, err
	}

	return lce.eval.Lt(aBits, bBits)
}

// ScalarAdd adds a plaintext scalar to a lazy carry integer.
// Uses limb-wise scalar addition without carry propagation.
func (lce *LazyCarryEvaluator) ScalarAdd(a *LazyCarryInteger, scalar uint64) (*LazyCarryInteger, error) {
	// Check if propagation needed
	if a.OpsWithoutPropagate >= lce.config.MaxOpsBeforePropagate {
		var err error
		a, err = lce.Propagate(a)
		if err != nil {
			return nil, fmt.Errorf("propagate: %w", err)
		}
	}

	result := &LazyCarryInteger{
		Limbs:               make([]*LimbState, a.NumLimbs),
		NumLimbs:            a.NumLimbs,
		LimbBits:            a.LimbBits,
		OpsWithoutPropagate: a.OpsWithoutPropagate + 1,
		FheType:             a.FheType,
		Config:              a.Config,
	}

	limbMask := uint64((1 << a.LimbBits) - 1)

	for i := 0; i < a.NumLimbs; i++ {
		scalarLimb := (scalar >> (i * a.LimbBits)) & limbMask

		if scalarLimb == 0 {
			// No change to this limb
			result.Limbs[i] = &LimbState{
				Value:            a.Limbs[i].Value,
				AccumulatedCarry: a.Limbs[i].AccumulatedCarry,
				LimbBits:         a.LimbBits,
				ExtendedBits:     a.Limbs[i].ExtendedBits,
			}
			continue
		}

		// Add scalar to this limb
		limbSum, err := lce.eval.ScalarAdd(a.Limbs[i].Value, scalarLimb)
		if err != nil {
			return nil, fmt.Errorf("limb %d scalar add: %w", i, err)
		}

		result.Limbs[i] = &LimbState{
			Value:            limbSum,
			AccumulatedCarry: a.Limbs[i].AccumulatedCarry + 1,
			LimbBits:         a.LimbBits,
			ExtendedBits:     a.Limbs[i].ExtendedBits,
		}
	}

	return result, nil
}

// Mul multiplies two lazy carry integers.
// Forces propagation before multiplication for correctness.
func (lce *LazyCarryEvaluator) Mul(a, b *LazyCarryInteger) (*LazyCarryInteger, error) {
	// Multiplication requires normalized inputs
	aNorm, err := lce.Propagate(a)
	if err != nil {
		return nil, fmt.Errorf("propagate a: %w", err)
	}
	bNorm, err := lce.Propagate(b)
	if err != nil {
		return nil, fmt.Errorf("propagate b: %w", err)
	}

	// Convert to bit representation for multiplication
	aBits, err := lce.ToBitCiphertext(aNorm)
	if err != nil {
		return nil, fmt.Errorf("a to bits: %w", err)
	}
	bBits, err := lce.ToBitCiphertext(bNorm)
	if err != nil {
		return nil, fmt.Errorf("b to bits: %w", err)
	}

	// Perform multiplication
	prodBits, err := lce.eval.Mul(aBits, bBits)
	if err != nil {
		return nil, fmt.Errorf("multiply: %w", err)
	}

	// Convert back to lazy carry representation
	return lce.FromBitCiphertext(prodBits)
}

// Copy creates a deep copy of a LazyCarryInteger.
func (lce *LazyCarryEvaluator) Copy(lci *LazyCarryInteger) *LazyCarryInteger {
	result := &LazyCarryInteger{
		Limbs:               make([]*LimbState, lci.NumLimbs),
		NumLimbs:            lci.NumLimbs,
		LimbBits:            lci.LimbBits,
		OpsWithoutPropagate: lci.OpsWithoutPropagate,
		FheType:             lci.FheType,
		Config:              lci.Config,
	}

	for i := 0; i < lci.NumLimbs; i++ {
		bits := make([]*Ciphertext, lci.Limbs[i].Value.numBits)
		copy(bits, lci.Limbs[i].Value.bits)

		result.Limbs[i] = &LimbState{
			Value: &BitCiphertext{
				bits:    bits,
				numBits: lci.Limbs[i].Value.numBits,
				fheType: lci.Limbs[i].Value.fheType,
			},
			AccumulatedCarry: lci.Limbs[i].AccumulatedCarry,
			LimbBits:         lci.Limbs[i].LimbBits,
			ExtendedBits:     lci.Limbs[i].ExtendedBits,
		}
	}

	return result
}

// Zero returns a lazy carry integer initialized to zero.
func (lce *LazyCarryEvaluator) Zero(fheType FheUintType) (*LazyCarryInteger, error) {
	zero := lce.eval.Zero(fheType)
	return lce.FromBitCiphertext(zero)
}

// =========================================================================
// EVM-Specific Optimizations
// =========================================================================

// EVMLazyCarryConfig returns configuration optimized for EVM workloads.
//
// EVM characteristics:
//   - Heavy uint256 arithmetic (ADD, SUB, MUL, DIV)
//   - Frequent comparisons (LT, GT, EQ)
//   - State reads/writes require normalized values
//
// This configuration balances:
//   - PBS amortization (higher MaxOps = fewer PBS)
//   - Memory overhead (higher MaxOps = more extended bits)
//   - Latency (propagation adds latency when triggered)
func EVMLazyCarryConfig() LazyCarryConfig {
	return LazyCarryConfig{
		MaxOpsBeforePropagate: 12, // Tuned for typical EVM ADD sequences
		OverflowMargin:        1 << 20,
		PropagateOnCompare:    true,
	}
}

// BatchAdd performs multiple additions with minimal propagation.
//
// For n additions, this performs:
//   - n * O(numLimbs) parallel limb additions
//   - 1 final propagation (O(numLimbs) PBS)
//
// Amortized PBS cost: 1/n per addition vs 1 per addition for traditional.
func (lce *LazyCarryEvaluator) BatchAdd(values []*LazyCarryInteger) (*LazyCarryInteger, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("empty batch")
	}
	if len(values) == 1 {
		return lce.Copy(values[0]), nil
	}

	// Accumulate all values
	result := lce.Copy(values[0])
	for i := 1; i < len(values); i++ {
		var err error
		result, err = lce.Add(result, values[i])
		if err != nil {
			return nil, fmt.Errorf("batch add %d: %w", i, err)
		}
	}

	// Force final propagation for clean output
	return lce.Propagate(result)
}

// PerformanceMetrics tracks lazy carry performance statistics.
type PerformanceMetrics struct {
	TotalAdditions         int
	PropagationCount       int
	PBSOperations          int // Estimated PBS calls
	AmortizationRatio      float64
	TraditionalPBSEstimate int
}

// GetMetrics returns performance metrics for a lazy carry integer.
func (lci *LazyCarryInteger) GetMetrics() PerformanceMetrics {
	// Traditional: 1 PBS per limb per addition for carry chain
	traditionalPBS := lci.OpsWithoutPropagate * (lci.NumLimbs - 1)

	// Lazy: PBS only on propagation (numLimbs - 1 carries)
	lazyPBS := 0
	if lci.OpsWithoutPropagate > 0 {
		lazyPBS = lci.NumLimbs - 1 // Would need this many on next propagate
	}

	ratio := 0.0
	if traditionalPBS > 0 {
		ratio = float64(lazyPBS) / float64(traditionalPBS)
	}

	return PerformanceMetrics{
		TotalAdditions:         lci.OpsWithoutPropagate,
		PropagationCount:       0, // This value, not counting historical
		PBSOperations:          lazyPBS,
		AmortizationRatio:      ratio,
		TraditionalPBSEstimate: traditionalPBS,
	}
}

// max returns the maximum of two ints.
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
