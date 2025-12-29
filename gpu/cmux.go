//go:build cgo

// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package gpu

import (
	"fmt"

	"github.com/luxfi/mlx"
)

// RGSW represents an RGSW ciphertext on GPU
// RGSW encrypts a single bit and is used in the bootstrap key
// Shape: [2, L, 2, N] where:
//   - 2: two rows (for C0 and C1 of RLWE)
//   - L: decomposition levels
//   - 2: each row contains an RLWE ciphertext (C0, C1)
//   - N: ring dimension
type RGSW struct {
	Data    *mlx.Array // [2, L, 2, N]
	L       int        // decomposition levels
	N       int        // ring dimension
	Base    uint64     // decomposition base
	BaseLog int        // log2(base)
}

// RLWE represents an RLWE ciphertext on GPU
type RLWE struct {
	C0 *mlx.Array // [N] first polynomial
	C1 *mlx.Array // [N] second polynomial
	N  int        // ring dimension
}

// NewRLWE creates a new zero RLWE ciphertext on GPU
func (e *Engine) NewRLWE() *RLWE {
	N := int(e.cfg.N)
	return &RLWE{
		C0: mlx.Zeros([]int{N}, mlx.Int64),
		C1: mlx.Zeros([]int{N}, mlx.Int64),
		N:  N,
	}
}

// NewRLWEFromArrays creates an RLWE ciphertext from existing arrays
func (e *Engine) NewRLWEFromArrays(c0, c1 *mlx.Array) *RLWE {
	return &RLWE{
		C0: c0,
		C1: c1,
		N:  int(e.cfg.N),
	}
}

// CMux performs controlled multiplexer operation on RLWE ciphertexts
// CMux(sel, d0, d1) = d0 + sel * (d1 - d0)
// When sel encrypts 0: result ≈ d0
// When sel encrypts 1: result ≈ d1
//
// This is the core operation in blind rotation, where sel is an RGSW
// encryption of a secret key bit from the bootstrap key.
func (e *Engine) CMux(sel *RGSW, d0, d1 *RLWE) (*RLWE, error) {
	if sel == nil {
		return nil, fmt.Errorf("nil selector RGSW")
	}
	if d0 == nil || d1 == nil {
		return nil, fmt.Errorf("nil RLWE input")
	}

	N := int(e.cfg.N)
	Q := e.cfg.Q

	// Validate dimensions
	if sel.N != N || d0.N != N || d1.N != N {
		return nil, fmt.Errorf("dimension mismatch: sel.N=%d, d0.N=%d, d1.N=%d, expected %d",
			sel.N, d0.N, d1.N, N)
	}

	// Step 1: Compute difference diff = d1 - d0
	diff, err := e.RLWESub(d1, d0)
	if err != nil {
		return nil, fmt.Errorf("rlwe subtraction failed: %w", err)
	}

	// Step 2: External product: prod = sel ⊡ diff
	prod, err := e.ExternalProduct(sel, diff)
	if err != nil {
		return nil, fmt.Errorf("external product failed: %w", err)
	}

	// Step 3: Result = d0 + prod
	result, err := e.RLWEAdd(d0, prod)
	if err != nil {
		return nil, fmt.Errorf("rlwe addition failed: %w", err)
	}

	// Reduce modulo Q
	qArray := Full([]int{N}, int64(Q), mlx.Int64)
	result.C0 = Remainder(result.C0, qArray)
	result.C1 = Remainder(result.C1, qArray)

	mlx.Eval(result.C0)
	mlx.Eval(result.C1)

	return result, nil
}

// ExternalProduct computes RGSW × RLWE → RLWE
// This is the core multiplication operation for homomorphic evaluation.
//
// Algorithm:
//  1. Decompose RLWE ciphertext (c0, c1) into L digits each
//  2. For each digit level l and RLWE component:
//     - Multiply digit[l] with corresponding RGSW row
//     - Accumulate into result
//  3. Return accumulated RLWE ciphertext
func (e *Engine) ExternalProduct(rgsw *RGSW, rlwe *RLWE) (*RLWE, error) {
	if rgsw == nil {
		return nil, fmt.Errorf("nil RGSW")
	}
	if rlwe == nil {
		return nil, fmt.Errorf("nil RLWE")
	}

	N := rgsw.N
	L := rgsw.L
	base := rgsw.Base
	Q := e.cfg.Q

	// Decompose both components of RLWE
	decompC0 := e.decompose(rlwe.C0, L, base, N) // [L, N]
	decompC1 := e.decompose(rlwe.C1, L, base, N) // [L, N]

	// Initialize result accumulator
	resC0 := mlx.Zeros([]int{N}, mlx.Int64)
	resC1 := mlx.Zeros([]int{N}, mlx.Int64)

	qArray := Full([]int{N}, int64(Q), mlx.Int64)

	// RGSW structure: [2, L, 2, N]
	// Row 0: encryptions for multiplying with C0 decomposition
	// Row 1: encryptions for multiplying with C1 decomposition
	for row := 0; row < 2; row++ {
		var decomp *mlx.Array
		if row == 0 {
			decomp = decompC0
		} else {
			decomp = decompC1
		}

		for l := 0; l < L; l++ {
			// Get digit at level l: [N]
			digit := SliceArgs(decomp, []SliceArg{
				{Start: l, Stop: l + 1},
				{Start: 0, Stop: N},
			})
			digit = Squeeze(digit, 0)

			// Get RGSW entry at [row, l]: [2, N]
			rgswEntry := SliceArgs(rgsw.Data, []SliceArg{
				{Start: row, Stop: row + 1},
				{Start: l, Stop: l + 1},
			})
			rgswEntry = Squeeze(rgswEntry, 0)
			rgswEntry = Squeeze(rgswEntry, 0)

			// rgswEntry[0] and rgswEntry[1] are the two polynomials
			rgswC0 := SliceArgs(rgswEntry, []SliceArg{{Start: 0, Stop: 1}, {Start: 0, Stop: N}})
			rgswC0 = Squeeze(rgswC0, 0)
			rgswC1 := SliceArgs(rgswEntry, []SliceArg{{Start: 1, Stop: 2}, {Start: 0, Stop: N}})
			rgswC1 = Squeeze(rgswC1, 0)

			// Polynomial multiplication (NTT domain = element-wise)
			prodC0 := e.polyMulNTT(digit, rgswC0, N)
			prodC1 := e.polyMulNTT(digit, rgswC1, N)

			// Accumulate
			resC0 = mlx.Add(resC0, prodC0)
			resC1 = mlx.Add(resC1, prodC1)

			// Reduce to prevent overflow
			resC0 = Remainder(resC0, qArray)
			resC1 = Remainder(resC1, qArray)
		}
	}

	return &RLWE{C0: resC0, C1: resC1, N: N}, nil
}

// decompose decomposes a polynomial into L base-'base' digits
// Input: [N], Output: [L, N]
func (e *Engine) decompose(poly *mlx.Array, L int, base uint64, N int) *mlx.Array {
	baseLog := 0
	for b := base; b > 1; b >>= 1 {
		baseLog++
	}

	levels := make([]*mlx.Array, L)

	for l := 0; l < L; l++ {
		shift := l * baseLog
		shiftArray := Full([]int{N}, int64(shift), mlx.Int64)
		baseArray := Full([]int{N}, int64(base), mlx.Int64)

		shifted := RightShift(poly, shiftArray)
		digit := Remainder(shifted, baseArray)

		levels[l] = Reshape(digit, []int{1, N})
	}

	// Concatenate along axis 0
	result := levels[0]
	for l := 1; l < L; l++ {
		result = Concatenate([]mlx.Array{*result, *levels[l]}, 0)
	}

	return result
}

// polyMulNTT multiplies two polynomials element-wise (NTT domain)
func (e *Engine) polyMulNTT(a, b *mlx.Array, N int) *mlx.Array {
	Q := e.cfg.Q
	qFloat := float64(Q)

	// Use float64 to handle overflow
	aFloat := AsType(a, mlx.Float64)
	bFloat := AsType(b, mlx.Float64)

	product := mlx.Multiply(aFloat, bFloat)

	// Modulo Q
	qArrayFloat := Full([]int{N}, qFloat, mlx.Float64)
	quotient := Floor(Divide(product, qArrayFloat))
	remainder := Subtract(product, mlx.Multiply(quotient, qArrayFloat))

	return AsType(remainder, mlx.Int64)
}

// RLWEAdd adds two RLWE ciphertexts
func (e *Engine) RLWEAdd(a, b *RLWE) (*RLWE, error) {
	if a == nil || b == nil {
		return nil, fmt.Errorf("nil RLWE operand")
	}
	if a.N != b.N {
		return nil, fmt.Errorf("dimension mismatch: %d vs %d", a.N, b.N)
	}

	N := a.N
	Q := e.cfg.Q
	qArray := Full([]int{N}, int64(Q), mlx.Int64)

	c0 := mlx.Add(a.C0, b.C0)
	c0 = Remainder(c0, qArray)

	c1 := mlx.Add(a.C1, b.C1)
	c1 = Remainder(c1, qArray)

	return &RLWE{C0: c0, C1: c1, N: N}, nil
}

// RLWESub subtracts two RLWE ciphertexts: a - b
func (e *Engine) RLWESub(a, b *RLWE) (*RLWE, error) {
	if a == nil || b == nil {
		return nil, fmt.Errorf("nil RLWE operand")
	}
	if a.N != b.N {
		return nil, fmt.Errorf("dimension mismatch: %d vs %d", a.N, b.N)
	}

	N := a.N
	Q := e.cfg.Q
	qArray := Full([]int{N}, int64(Q), mlx.Int64)

	// (a - b) mod Q = (a + Q - b) mod Q to handle negative
	c0 := Subtract(a.C0, b.C0)
	c0 = mlx.Add(c0, qArray)
	c0 = Remainder(c0, qArray)

	c1 := Subtract(a.C1, b.C1)
	c1 = mlx.Add(c1, qArray)
	c1 = Remainder(c1, qArray)

	return &RLWE{C0: c0, C1: c1, N: N}, nil
}

// RLWENegate negates an RLWE ciphertext: -a mod Q
func (e *Engine) RLWENegate(a *RLWE) (*RLWE, error) {
	if a == nil {
		return nil, fmt.Errorf("nil RLWE operand")
	}

	N := a.N
	Q := e.cfg.Q
	qArray := Full([]int{N}, int64(Q), mlx.Int64)

	c0 := Subtract(qArray, a.C0)
	c1 := Subtract(qArray, a.C1)

	return &RLWE{C0: c0, C1: c1, N: N}, nil
}

// RLWEMulByMonomial multiplies RLWE by X^k (rotation in negacyclic ring)
func (e *Engine) RLWEMulByMonomial(a *RLWE, k int) (*RLWE, error) {
	if a == nil {
		return nil, fmt.Errorf("nil RLWE operand")
	}

	N := a.N
	Q := e.cfg.Q

	// Normalize k to [0, 2N)
	k = ((k % (2 * N)) + 2*N) % (2 * N)

	// Create index array
	indices := Arange(0, N, 1, mlx.Int32)

	// Compute new indices: (i - k) mod 2N
	kArray := Full([]int{N}, int32(k), mlx.Int32)
	newIndices := Subtract(indices, kArray)
	twoN := Full([]int{N}, int32(2*N), mlx.Int32)
	newIndices = mlx.Add(newIndices, twoN)
	newIndices = Remainder(newIndices, twoN)

	// Check if wrapped (need negation for negacyclic)
	nThreshold := Full([]int{N}, int32(N), mlx.Int32)
	needsNegate := GreaterEqual(newIndices, nThreshold)
	actualIndices := Remainder(newIndices, nThreshold)

	// Gather
	rotC0 := Take(a.C0, actualIndices, 0)
	rotC1 := Take(a.C1, actualIndices, 0)

	// Apply negation
	qArray := Full([]int{N}, int64(Q), mlx.Int64)
	needsNegateInt := AsType(needsNegate, mlx.Int64)
	one := Full([]int{N}, int64(1), mlx.Int64)
	notNeedsNegate := Subtract(one, needsNegateInt)

	rotC0Neg := Subtract(qArray, rotC0)
	rotC1Neg := Subtract(qArray, rotC1)

	c0 := mlx.Add(mlx.Multiply(notNeedsNegate, rotC0), mlx.Multiply(needsNegateInt, rotC0Neg))
	c1 := mlx.Add(mlx.Multiply(notNeedsNegate, rotC1), mlx.Multiply(needsNegateInt, rotC1Neg))

	return &RLWE{C0: c0, C1: c1, N: N}, nil
}

// BatchCMux performs CMux on batches of RLWE ciphertexts
// sel is a single RGSW that selects between d0[i] and d1[i] for each i
func (e *Engine) BatchCMux(sel *RGSW, d0, d1 *BatchRLWE) (*BatchRLWE, error) {
	if sel == nil {
		return nil, fmt.Errorf("nil selector RGSW")
	}
	if d0 == nil || d1 == nil {
		return nil, fmt.Errorf("nil BatchRLWE input")
	}
	if d0.Count != d1.Count {
		return nil, fmt.Errorf("batch size mismatch: %d vs %d", d0.Count, d1.Count)
	}

	batchSize := d0.Count
	N := int(e.cfg.N)
	L := sel.L
	base := sel.Base
	Q := e.cfg.Q

	// Compute difference: diff = d1 - d0
	qArray := Full([]int{batchSize, N}, int64(Q), mlx.Int64)

	diffC0 := Subtract(d1.C0, d0.C0)
	diffC0 = mlx.Add(diffC0, qArray)
	diffC0 = Remainder(diffC0, qArray)

	diffC1 := Subtract(d1.C1, d0.C1)
	diffC1 = mlx.Add(diffC1, qArray)
	diffC1 = Remainder(diffC1, qArray)

	// External product with the same RGSW for all batch elements
	prodC0, prodC1 := e.batchExternalProductSingleRGSW(sel.Data, diffC0, diffC1, L, base, batchSize, N)

	// Result = d0 + prod
	resC0 := mlx.Add(d0.C0, prodC0)
	resC0 = Remainder(resC0, qArray)

	resC1 := mlx.Add(d0.C1, prodC1)
	resC1 = Remainder(resC1, qArray)

	mlx.Eval(resC0)
	mlx.Eval(resC1)

	return &BatchRLWE{
		C0:    resC0,
		C1:    resC1,
		Count: batchSize,
	}, nil
}

// batchExternalProductSingleRGSW computes external product with same RGSW for all batch elements
func (e *Engine) batchExternalProductSingleRGSW(rgsw *mlx.Array, diffC0, diffC1 *mlx.Array, L int, base uint64, batchSize, N int) (*mlx.Array, *mlx.Array) {
	Q := e.cfg.Q

	// Decompose batch
	decompC0 := e.batchDecompose(diffC0, L, base, batchSize, N)
	decompC1 := e.batchDecompose(diffC1, L, base, batchSize, N)

	resC0 := mlx.Zeros([]int{batchSize, N}, mlx.Int64)
	resC1 := mlx.Zeros([]int{batchSize, N}, mlx.Int64)

	qArray := Full([]int{batchSize, N}, int64(Q), mlx.Int64)

	for row := 0; row < 2; row++ {
		var decomp *mlx.Array
		if row == 0 {
			decomp = decompC0
		} else {
			decomp = decompC1
		}

		for l := 0; l < L; l++ {
			// Get batch of digits: [batchSize, N]
			digit := SliceArgs(decomp, []SliceArg{
				{Start: 0, Stop: batchSize},
				{Start: l, Stop: l + 1},
				{Start: 0, Stop: N},
			})
			digit = Squeeze(digit, 1)

			// Get single RGSW row: [2, N]
			rgswRow := SliceArgs(rgsw, []SliceArg{
				{Start: row, Stop: row + 1},
				{Start: l, Stop: l + 1},
			})
			rgswRow = Squeeze(rgswRow, 0)
			rgswRow = Squeeze(rgswRow, 0)

			rgswC0 := SliceArgs(rgswRow, []SliceArg{{Start: 0, Stop: 1}, {Start: 0, Stop: N}})
			rgswC0 = Squeeze(rgswC0, 0)
			rgswC1 := SliceArgs(rgswRow, []SliceArg{{Start: 1, Stop: 2}, {Start: 0, Stop: N}})
			rgswC1 = Squeeze(rgswC1, 0)

			// Broadcast RGSW to batch
			rgswC0Batch := Broadcast(rgswC0, []int{batchSize, N})
			rgswC1Batch := Broadcast(rgswC1, []int{batchSize, N})

			// Multiply and accumulate
			prodC0 := e.batchPolyMulNTT(digit, rgswC0Batch, batchSize, N)
			prodC1 := e.batchPolyMulNTT(digit, rgswC1Batch, batchSize, N)

			resC0 = mlx.Add(resC0, prodC0)
			resC1 = mlx.Add(resC1, prodC1)

			resC0 = Remainder(resC0, qArray)
			resC1 = Remainder(resC1, qArray)
		}
	}

	return resC0, resC1
}

// SampleExtract extracts an LWE ciphertext from an RLWE ciphertext
// Extracts the constant term coefficient
func (e *Engine) SampleExtract(rlwe *RLWE) ([]uint64, uint64, error) {
	if rlwe == nil {
		return nil, 0, fmt.Errorf("nil RLWE")
	}

	N := rlwe.N

	// Evaluate to ensure data is computed
	mlx.Eval(rlwe.C0)
	mlx.Eval(rlwe.C1)

	// Download from GPU
	c0Data := mlx.ToSlice[int64](rlwe.C0)
	c1Data := mlx.ToSlice[int64](rlwe.C1)

	// LWE 'a' vector comes from C0 coefficients with sign adjustment
	// a[0] = c0[0], a[i] = -c0[N-i] for i > 0
	a := make([]uint64, N)
	Q := e.cfg.Q
	a[0] = uint64(c0Data[0])
	for i := 1; i < N; i++ {
		// -c0[N-i] mod Q
		val := c0Data[N-i]
		if val < 0 {
			a[i] = uint64(int64(Q) + val)
		} else {
			a[i] = Q - uint64(val)
		}
	}

	// LWE 'b' is the constant term of C1
	b := uint64(c1Data[0])

	return a, b, nil
}

// BatchSampleExtract extracts LWE ciphertexts from a batch of RLWE ciphertexts
func (e *Engine) BatchSampleExtract(batch *BatchRLWE) (*BatchLWE, error) {
	if batch == nil {
		return nil, fmt.Errorf("nil BatchRLWE")
	}

	batchSize := batch.Count
	N := int(e.cfg.N)
	Q := e.cfg.Q

	// Evaluate
	mlx.Eval(batch.C0)
	mlx.Eval(batch.C1)

	// For sample extraction:
	// a[0] = c0[0]
	// a[i] = -c0[N-i] for i > 0
	// b = c1[0]

	// Extract b values (constant terms of C1)
	bArray := SliceArgs(batch.C1, []SliceArg{
		{Start: 0, Stop: batchSize},
		{Start: 0, Stop: 1},
	})
	bArray = Squeeze(bArray, 1)

	// Construct a vectors with proper index reversal and negation
	// Create reversal indices: [0, N-1, N-2, ..., 1]
	revIndices := make([]int32, N)
	revIndices[0] = 0
	for i := 1; i < N; i++ {
		revIndices[i] = int32(N - i)
	}
	revIndicesArray := mlx.ArrayFromSlice(revIndices, []int{N}, mlx.Int32)
	revIndicesArray = Broadcast(revIndicesArray, []int{batchSize, N})

	// Gather reversed coefficients
	aReversed := TakeAlongAxis(batch.C0, revIndicesArray, 1)

	// Negate all except first element
	// Create mask: [1, 0, 0, ..., 0]
	negMask := make([]int64, N)
	for i := 1; i < N; i++ {
		negMask[i] = 1
	}
	negMaskArray := mlx.ArrayFromSlice(negMask, []int{N}, mlx.Int64)
	negMaskArray = Broadcast(negMaskArray, []int{batchSize, N})

	// Apply negation: a = aReversed if mask=0, else Q - aReversed
	qArray := Full([]int{batchSize, N}, int64(Q), mlx.Int64)
	negated := Subtract(qArray, aReversed)

	one := Full([]int{batchSize, N}, int64(1), mlx.Int64)
	notMask := Subtract(one, negMaskArray)

	aArray := mlx.Add(
		mlx.Multiply(notMask, aReversed),
		mlx.Multiply(negMaskArray, negated),
	)

	// Ensure positive modulo
	aArray = Remainder(aArray, qArray)

	mlx.Eval(aArray)
	mlx.Eval(bArray)

	return &BatchLWE{
		A:     aArray,
		B:     bArray,
		Count: batchSize,
	}, nil
}
