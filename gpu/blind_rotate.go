//go:build cgo

// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package gpu

import (
	"fmt"
	"sync"

	"github.com/luxfi/mlx"
)

// BatchLWE holds a batch of LWE ciphertexts in Structure-of-Arrays format
// for coalesced GPU memory access
type BatchLWE struct {
	A     *mlx.Array // [batch_size, n] - all 'a' vectors contiguous
	B     *mlx.Array // [batch_size] - all 'b' values contiguous
	Count int        // Number of ciphertexts in batch
}

// BatchRLWE holds a batch of RLWE ciphertexts in Structure-of-Arrays format
type BatchRLWE struct {
	C0    *mlx.Array // [batch_size, N] - first polynomial component
	C1    *mlx.Array // [batch_size, N] - second polynomial component
	Count int        // Number of ciphertexts in batch
}

// RLWECiphertext represents a single RLWE ciphertext on GPU
type RLWECiphertext struct {
	C0 *mlx.Array // [N] - first polynomial
	C1 *mlx.Array // [N] - second polynomial
}

// GPUBootstrapKey holds bootstrap key data on GPU
// Shape: [n, 2, L, 2, N] where:
//   - n: LWE dimension
//   - 2: RGSW has 2 rows per level
//   - L: decomposition levels
//   - 2: each row has 2 polynomials (RLWE)
//   - N: ring dimension
type GPUBootstrapKey struct {
	Data    *mlx.Array // [n, 2, L, 2, N]
	n       int        // LWE dimension
	L       int        // decomposition levels
	N       int        // ring dimension
	Base    uint64     // decomposition base (2^BaseLog)
	BaseLog int        // log2 of decomposition base
}

// NewBatchLWE creates a new batch of LWE ciphertexts on GPU
func (e *Engine) NewBatchLWE(batchSize int) *BatchLWE {
	n := int(e.cfg.n)
	return &BatchLWE{
		A:     mlx.Zeros([]int{batchSize, n}, mlx.Int64),
		B:     mlx.Zeros([]int{batchSize}, mlx.Int64),
		Count: batchSize,
	}
}

// NewBatchRLWE creates a new batch of RLWE ciphertexts on GPU
func (e *Engine) NewBatchRLWE(batchSize int) *BatchRLWE {
	N := int(e.cfg.N)
	return &BatchRLWE{
		C0:    mlx.Zeros([]int{batchSize, N}, mlx.Int64),
		C1:    mlx.Zeros([]int{batchSize, N}, mlx.Int64),
		Count: batchSize,
	}
}

// UploadBatchLWE uploads LWE ciphertexts from host to GPU
func (e *Engine) UploadBatchLWE(aVecs [][]uint64, bVals []uint64) (*BatchLWE, error) {
	batchSize := len(bVals)
	if len(aVecs) != batchSize {
		return nil, fmt.Errorf("batch size mismatch: %d a vectors, %d b values", len(aVecs), batchSize)
	}

	n := int(e.cfg.n)

	// Flatten a vectors for contiguous upload
	aFlat := make([]int64, batchSize*n)
	for i := 0; i < batchSize; i++ {
		if len(aVecs[i]) != n {
			return nil, fmt.Errorf("a vector %d has wrong size: %d, expected %d", i, len(aVecs[i]), n)
		}
		for j := 0; j < n; j++ {
			aFlat[i*n+j] = int64(aVecs[i][j])
		}
	}

	// Convert b values
	bFlat := make([]int64, batchSize)
	for i := 0; i < batchSize; i++ {
		bFlat[i] = int64(bVals[i])
	}

	batch := &BatchLWE{
		A:     mlx.ArrayFromSlice(aFlat, []int{batchSize, n}, mlx.Int64),
		B:     mlx.ArrayFromSlice(bFlat, []int{batchSize}, mlx.Int64),
		Count: batchSize,
	}

	mlx.Eval(batch.A)
	mlx.Eval(batch.B)

	return batch, nil
}

// BatchBlindRotate performs blind rotation on a batch of LWE ciphertexts
// This is the core of TFHE bootstrapping.
//
// Algorithm for each ciphertext:
//  1. Compute rotation index from b: rotIdx = round(b * 2N / Q)
//  2. Initialize accumulator: ACC = X^(-rotIdx) * testPoly
//  3. For i = 0 to n-1:
//     a. Compute rotation from a[i]: rot = round(a[i] * 2N / Q)
//     b. ACC = CMux(BSK[i], ACC, ACC * X^rot)
//  4. Result is RLWE ciphertext containing f(phase) in constant term
func (e *Engine) BatchBlindRotate(inputs *BatchLWE, bsk *GPUBootstrapKey, testPoly *mlx.Array) (*BatchRLWE, error) {
	if inputs == nil || inputs.Count == 0 {
		return nil, fmt.Errorf("empty input batch")
	}
	if bsk == nil {
		return nil, fmt.Errorf("nil bootstrap key")
	}
	if testPoly == nil {
		return nil, fmt.Errorf("nil test polynomial")
	}

	batchSize := inputs.Count
	N := int(e.cfg.N)
	n := int(e.cfg.n)
	Q := e.cfg.Q

	// Validate dimensions
	if bsk.n != n || bsk.N != N {
		return nil, fmt.Errorf("bootstrap key dimension mismatch")
	}

	// Step 1: Compute initial rotation indices from b values
	// rotIdx = round(b * 2N / Q) mod 2N
	// We use b * 2N / Q with proper rounding
	scale := float64(2*N) / float64(Q)

	// Convert b to rotation indices on GPU
	bFloat := AsType(inputs.B, mlx.Float32)
	rotIndices := mlx.Multiply(bFloat, Full([]int{batchSize}, float32(scale), mlx.Float32))
	rotIndices = Round(rotIndices)
	rotIndices = AsType(rotIndices, mlx.Int32)

	// Step 2: Initialize accumulators with rotated test polynomials
	// For each i: ACC[i] = X^(-rotIdx[i]) * testPoly
	accC0, accC1 := e.batchInitAccumulator(testPoly, rotIndices, batchSize, N)

	// Step 3: Perform n CMux operations for each ciphertext
	// We process all ciphertexts in parallel using GPU operations
	for i := 0; i < n; i++ {
		// Get a[i] values for all ciphertexts: shape [batchSize]
		aSlice := SliceArgs(inputs.A, []SliceArg{
			{Start: 0, Stop: batchSize},
			{Start: i, Stop: i + 1},
		})
		aSlice = Squeeze(aSlice, -1)

		// Compute rotation amounts from a[i]
		aFloat := AsType(aSlice, mlx.Float32)
		rotAmounts := mlx.Multiply(aFloat, Full([]int{batchSize}, float32(scale), mlx.Float32))
		rotAmounts = Round(rotAmounts)
		rotAmounts = AsType(rotAmounts, mlx.Int32)

		// Compute rotated accumulators: ACC * X^rot
		rotC0, rotC1 := e.batchRotateRLWE(accC0, accC1, rotAmounts, batchSize, N)

		// Extract BSK[i] for CMux: shape [2, L, 2, N]
		bskSlice := SliceArgs(bsk.Data, []SliceArg{
			{Start: i, Stop: i + 1},
		})
		bskSlice = Squeeze(bskSlice, 0)

		// CMux: result = d0 + ExtProd(bsk[i], d1 - d0)
		// where d0 = ACC, d1 = rotatedACC
		accC0, accC1 = e.batchCMux(bskSlice, accC0, accC1, rotC0, rotC1, bsk.L, bsk.Base, batchSize, N)
	}

	// Evaluate all pending operations
	mlx.Eval(accC0)
	mlx.Eval(accC1)

	return &BatchRLWE{
		C0:    accC0,
		C1:    accC1,
		Count: batchSize,
	}, nil
}

// batchInitAccumulator initializes accumulators with rotated test polynomials
// For each ciphertext i: ACC[i] = X^(-rotIdx[i]) * testPoly
func (e *Engine) batchInitAccumulator(testPoly *mlx.Array, rotIndices *mlx.Array, batchSize, N int) (*mlx.Array, *mlx.Array) {
	Q := int64(e.cfg.Q)

	// Broadcast test polynomial to batch: [N] -> [batchSize, N]
	testPolyBatch := Broadcast(testPoly, []int{batchSize, N})

	// Create index array [0, 1, 2, ..., N-1]
	indices := Arange(0, N, 1, mlx.Int32)
	indices = Broadcast(indices, []int{batchSize, N})

	// Expand rotIndices: [batchSize] -> [batchSize, 1]
	rotExpanded := Reshape(rotIndices, []int{batchSize, 1})
	rotExpanded = Broadcast(rotExpanded, []int{batchSize, N})

	// Compute rotated indices: (indices + rotIdx) mod N
	// Note: we add rotIdx (not subtract) because X^(-k) rotation moves coefficients forward
	rotatedIndices := mlx.Add(indices, rotExpanded)

	// Handle negative modulo (rotation can go negative)
	twoN := Full([]int{batchSize, N}, int32(2*N), mlx.Int32)
	rotatedIndices = mlx.Add(rotatedIndices, twoN)
	rotatedIndices = Remainder(rotatedIndices, twoN)

	// For X^(-k) rotation with negacyclic property:
	// If new_idx >= N, coefficient gets negated
	nThreshold := Full([]int{batchSize, N}, int32(N), mlx.Int32)
	needsNegate := GreaterEqual(rotatedIndices, nThreshold)

	// Get actual index within [0, N)
	actualIndices := Remainder(rotatedIndices, nThreshold)

	// Gather rotated coefficients
	// Use take_along_axis for batch gather
	rotatedPoly := TakeAlongAxis(testPolyBatch, actualIndices, 1)

	// Apply negation for negacyclic rotation
	qArray := Full([]int{batchSize, N}, Q, mlx.Int64)
	rotatedPolyNeg := Subtract(qArray, rotatedPoly)

	// Select: if needsNegate then -coeff else coeff
	needsNegateInt := AsType(needsNegate, mlx.Int64)
	one := Full([]int{batchSize, N}, int64(1), mlx.Int64)
	notNeedsNegate := Subtract(one, needsNegateInt)

	accC1 := mlx.Add(
		mlx.Multiply(notNeedsNegate, rotatedPoly),
		mlx.Multiply(needsNegateInt, rotatedPolyNeg),
	)

	// C0 starts as zero
	accC0 := mlx.Zeros([]int{batchSize, N}, mlx.Int64)

	return accC0, accC1
}

// batchRotateRLWE rotates RLWE ciphertexts by given amounts
// Rotation by k: multiply by X^k in the ring, which shifts coefficients
// with negacyclic wrapping
func (e *Engine) batchRotateRLWE(c0, c1, rotAmounts *mlx.Array, batchSize, N int) (*mlx.Array, *mlx.Array) {
	Q := int64(e.cfg.Q)

	// Create index array
	indices := Arange(0, N, 1, mlx.Int32)
	indices = Broadcast(indices, []int{batchSize, N})

	// Expand rotation amounts
	rotExpanded := Reshape(rotAmounts, []int{batchSize, 1})
	rotExpanded = Broadcast(rotExpanded, []int{batchSize, N})

	// New position = (old_position - rotation) mod 2N for negacyclic
	// We read from (idx - rot) mod N, with sign flip if wrap
	newIndices := Subtract(indices, rotExpanded)
	twoN := Full([]int{batchSize, N}, int32(2*N), mlx.Int32)
	newIndices = mlx.Add(newIndices, twoN) // Make positive
	newIndices = Remainder(newIndices, twoN)

	// Check if wrapped (need negation)
	nThreshold := Full([]int{batchSize, N}, int32(N), mlx.Int32)
	needsNegate := GreaterEqual(newIndices, nThreshold)
	actualIndices := Remainder(newIndices, nThreshold)

	// Gather from c0 and c1
	rotC0 := TakeAlongAxis(c0, actualIndices, 1)
	rotC1 := TakeAlongAxis(c1, actualIndices, 1)

	// Apply negation where needed
	qArray := Full([]int{batchSize, N}, Q, mlx.Int64)
	needsNegateInt := AsType(needsNegate, mlx.Int64)
	one := Full([]int{batchSize, N}, int64(1), mlx.Int64)

	rotC0Neg := Subtract(qArray, rotC0)
	rotC1Neg := Subtract(qArray, rotC1)

	notNeedsNegate := Subtract(one, needsNegateInt)
	rotC0 = mlx.Add(mlx.Multiply(notNeedsNegate, rotC0), mlx.Multiply(needsNegateInt, rotC0Neg))
	rotC1 = mlx.Add(mlx.Multiply(notNeedsNegate, rotC1), mlx.Multiply(needsNegateInt, rotC1Neg))

	return rotC0, rotC1
}

// batchCMux performs CMux on a batch of RLWE ciphertexts
// CMux(c, d0, d1) = d0 + ExternalProduct(c, d1 - d0)
// c is RGSW encryption of a bit from BSK
func (e *Engine) batchCMux(rgsw *mlx.Array, d0C0, d0C1, d1C0, d1C1 *mlx.Array, L int, base uint64, batchSize, N int) (*mlx.Array, *mlx.Array) {
	Q := e.cfg.Q

	// Compute difference: diff = d1 - d0
	diffC0 := Subtract(d1C0, d0C0)
	diffC1 := Subtract(d1C1, d0C1)

	// Reduce modulo Q (handle negative results)
	qArray := Full([]int{batchSize, N}, int64(Q), mlx.Int64)
	diffC0 = mlx.Add(diffC0, qArray)
	diffC0 = Remainder(diffC0, qArray)
	diffC1 = mlx.Add(diffC1, qArray)
	diffC1 = Remainder(diffC1, qArray)

	// External product: RGSW × RLWE → RLWE
	prodC0, prodC1 := e.batchExternalProduct(rgsw, diffC0, diffC1, L, base, batchSize, N)

	// Result = d0 + product
	resC0 := mlx.Add(d0C0, prodC0)
	resC1 := mlx.Add(d0C1, prodC1)

	// Reduce modulo Q
	resC0 = Remainder(resC0, qArray)
	resC1 = Remainder(resC1, qArray)

	return resC0, resC1
}

// batchExternalProduct computes RGSW × RLWE → RLWE for a batch
// RGSW has shape [2, L, 2, N]
// RLWE (diffC0, diffC1) has shape [batchSize, N]
func (e *Engine) batchExternalProduct(rgsw *mlx.Array, diffC0, diffC1 *mlx.Array, L int, base uint64, batchSize, N int) (*mlx.Array, *mlx.Array) {
	Q := e.cfg.Q

	// Decompose the RLWE ciphertext into L levels
	// Each level contains digits in base 'base'
	decompC0 := e.batchDecompose(diffC0, L, base, batchSize, N) // [batchSize, L, N]
	decompC1 := e.batchDecompose(diffC1, L, base, batchSize, N) // [batchSize, L, N]

	// Initialize result accumulators
	resC0 := mlx.Zeros([]int{batchSize, N}, mlx.Int64)
	resC1 := mlx.Zeros([]int{batchSize, N}, mlx.Int64)

	qArray := Full([]int{batchSize, N}, int64(Q), mlx.Int64)

	// RGSW matrix structure:
	// Row 0: encryptions for C0 decomposition [L, 2, N]
	// Row 1: encryptions for C1 decomposition [L, 2, N]
	for row := 0; row < 2; row++ {
		var decomp *mlx.Array
		if row == 0 {
			decomp = decompC0
		} else {
			decomp = decompC1
		}

		for l := 0; l < L; l++ {
			// Get decomposition digit l: [batchSize, N]
			digit := SliceArgs(decomp, []SliceArg{
				{Start: 0, Stop: batchSize},
				{Start: l, Stop: l + 1},
				{Start: 0, Stop: N},
			})
			digit = Squeeze(digit, 1)

			// Get RGSW row for this level: [2, N]
			rgswRow := SliceArgs(rgsw, []SliceArg{
				{Start: row, Stop: row + 1},
				{Start: l, Stop: l + 1},
			})
			rgswRow = Squeeze(rgswRow, 0)
			rgswRow = Squeeze(rgswRow, 0)

			// rgswRow[0]: first polynomial, rgswRow[1]: second polynomial
			rgswC0 := SliceArgs(rgswRow, []SliceArg{{Start: 0, Stop: 1}, {Start: 0, Stop: N}})
			rgswC0 = Squeeze(rgswC0, 0)
			rgswC1 := SliceArgs(rgswRow, []SliceArg{{Start: 1, Stop: 2}, {Start: 0, Stop: N}})
			rgswC1 = Squeeze(rgswC1, 0)

			// Broadcast RGSW polynomials to batch size
			rgswC0Batch := Broadcast(rgswC0, []int{batchSize, N})
			rgswC1Batch := Broadcast(rgswC1, []int{batchSize, N})

			// Polynomial multiplication: digit * rgsw (NTT domain)
			// In NTT domain, this is element-wise multiplication
			prodC0 := e.batchPolyMulNTT(digit, rgswC0Batch, batchSize, N)
			prodC1 := e.batchPolyMulNTT(digit, rgswC1Batch, batchSize, N)

			// Accumulate
			resC0 = mlx.Add(resC0, prodC0)
			resC1 = mlx.Add(resC1, prodC1)

			// Reduce periodically to prevent overflow
			resC0 = Remainder(resC0, qArray)
			resC1 = Remainder(resC1, qArray)
		}
	}

	return resC0, resC1
}

// batchDecompose decomposes a polynomial into L base-'base' digits
// Input: [batchSize, N], Output: [batchSize, L, N]
func (e *Engine) batchDecompose(poly *mlx.Array, L int, base uint64, batchSize, N int) *mlx.Array {
	// Decomposition: for each coefficient c, extract L digits in base 'base'
	// digit[l] = (c >> (l * log2(base))) mod base

	baseLog := 0
	for b := base; b > 1; b >>= 1 {
		baseLog++
	}

	// Build result by computing each level
	levels := make([]*mlx.Array, L)

	for l := 0; l < L; l++ {
		shift := l * baseLog
		shiftArray := Full([]int{batchSize, N}, int64(shift), mlx.Int64)
		baseArray := Full([]int{batchSize, N}, int64(base), mlx.Int64)

		// digit = (poly >> shift) mod base
		shifted := RightShift(poly, shiftArray)
		digit := Remainder(shifted, baseArray)

		// Reshape for concatenation: [batchSize, N] -> [batchSize, 1, N]
		levels[l] = Reshape(digit, []int{batchSize, 1, N})
	}

	// Concatenate all levels along axis 1
	result := levels[0]
	for l := 1; l < L; l++ {
		result = Concatenate([]mlx.Array{*result, *levels[l]}, 1)
	}

	return result
}

// batchPolyMulNTT multiplies polynomials element-wise (assumes NTT domain)
func (e *Engine) batchPolyMulNTT(a, b *mlx.Array, batchSize, N int) *mlx.Array {
	Q := e.cfg.Q
	qFloat := float64(Q)

	// Element-wise multiplication in NTT domain
	// For proper modular multiplication, we need to handle overflow
	// Using float64 intermediate to avoid int64 overflow
	aFloat := AsType(a, mlx.Float64)
	bFloat := AsType(b, mlx.Float64)

	product := mlx.Multiply(aFloat, bFloat)

	// Modulo Q using floor division
	qArrayFloat := Full([]int{batchSize, N}, qFloat, mlx.Float64)
	quotient := Floor(Divide(product, qArrayFloat))
	remainder := Subtract(product, mlx.Multiply(quotient, qArrayFloat))

	return AsType(remainder, mlx.Int64)
}

// BlindRotateSingle performs blind rotation on a single LWE ciphertext
// This is used when batch processing isn't needed
func (e *Engine) BlindRotateSingle(a []uint64, b uint64, bsk *GPUBootstrapKey, testPoly []uint64) (*RLWECiphertext, error) {
	N := int(e.cfg.N)
	n := int(e.cfg.n)

	// Validate inputs
	if len(a) != n {
		return nil, fmt.Errorf("wrong LWE dimension: %d, expected %d", len(a), n)
	}
	if len(testPoly) != N {
		return nil, fmt.Errorf("wrong test polynomial size: %d, expected %d", len(testPoly), N)
	}

	// Convert to GPU arrays
	aGPU := make([]int64, n)
	for i := 0; i < n; i++ {
		aGPU[i] = int64(a[i])
	}
	aArray := mlx.ArrayFromSlice(aGPU, []int{1, n}, mlx.Int64)
	bArray := mlx.ArrayFromSlice([]int64{int64(b)}, []int{1}, mlx.Int64)

	testPolyGPU := make([]int64, N)
	for i := 0; i < N; i++ {
		testPolyGPU[i] = int64(testPoly[i])
	}
	testPolyArray := mlx.ArrayFromSlice(testPolyGPU, []int{N}, mlx.Int64)

	batch := &BatchLWE{A: aArray, B: bArray, Count: 1}

	result, err := e.BatchBlindRotate(batch, bsk, testPolyArray)
	if err != nil {
		return nil, err
	}

	// Extract single result
	c0 := SliceArgs(result.C0, []SliceArg{{Start: 0, Stop: 1}, {Start: 0, Stop: N}})
	c0 = Squeeze(c0, 0)
	c1 := SliceArgs(result.C1, []SliceArg{{Start: 0, Stop: 1}, {Start: 0, Stop: N}})
	c1 = Squeeze(c1, 0)

	return &RLWECiphertext{C0: c0, C1: c1}, nil
}

// BatchBlindRotateParallel uses goroutines for additional host-side parallelism
// Useful when GPU isn't available or for hybrid CPU+GPU execution
func (e *Engine) BatchBlindRotateParallel(inputs *BatchLWE, bsk *GPUBootstrapKey, testPoly *mlx.Array, numWorkers int) (*BatchRLWE, error) {
	if inputs == nil || inputs.Count == 0 {
		return nil, fmt.Errorf("empty input batch")
	}

	batchSize := inputs.Count
	if numWorkers <= 0 {
		numWorkers = 4
	}
	if numWorkers > batchSize {
		numWorkers = batchSize
	}

	// For small batches, just use the regular GPU batch function
	if batchSize <= numWorkers || batchSize <= 16 {
		return e.BatchBlindRotate(inputs, bsk, testPoly)
	}

	// Split into sub-batches for parallel processing
	subBatchSize := (batchSize + numWorkers - 1) / numWorkers

	n := int(e.cfg.n)

	results := make([]*BatchRLWE, numWorkers)
	var wg sync.WaitGroup
	errCh := make(chan error, numWorkers)

	for w := 0; w < numWorkers; w++ {
		start := w * subBatchSize
		end := start + subBatchSize
		if end > batchSize {
			end = batchSize
		}
		if start >= end {
			continue
		}

		wg.Add(1)
		go func(workerID, startIdx, endIdx int) {
			defer wg.Done()

			// Extract sub-batch
			subA := SliceArgs(inputs.A, []SliceArg{
				{Start: startIdx, Stop: endIdx},
				{Start: 0, Stop: n},
			})
			subB := SliceArgs(inputs.B, []SliceArg{
				{Start: startIdx, Stop: endIdx},
			})

			subBatch := &BatchLWE{
				A:     subA,
				B:     subB,
				Count: endIdx - startIdx,
			}

			result, err := e.BatchBlindRotate(subBatch, bsk, testPoly)
			if err != nil {
				errCh <- fmt.Errorf("worker %d: %w", workerID, err)
				return
			}
			results[workerID] = result
		}(w, start, end)
	}

	wg.Wait()
	close(errCh)

	// Check for errors
	for err := range errCh {
		return nil, err
	}

	// Concatenate results
	var c0Arrays, c1Arrays []mlx.Array
	for _, r := range results {
		if r != nil {
			c0Arrays = append(c0Arrays, *r.C0)
			c1Arrays = append(c1Arrays, *r.C1)
		}
	}

	if len(c0Arrays) == 0 {
		return nil, fmt.Errorf("no results produced")
	}

	finalC0 := Concatenate(c0Arrays, 0)
	finalC1 := Concatenate(c1Arrays, 0)

	return &BatchRLWE{
		C0:    finalC0,
		C1:    finalC1,
		Count: batchSize,
	}, nil
}
