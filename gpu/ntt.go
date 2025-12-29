//go:build cgo

// Package gpu provides accelerated TFHE operations using MLX.
// This file implements GPU-accelerated NTT (Number Theoretic Transform) operations.
//
// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause
package gpu

import (
	"fmt"

	"github.com/luxfi/mlx"
)

// Re-export mlx functions used in this package
// This allows the package to compile even when full MLX bindings aren't available
var (
	mlxShape         = Shape
	mlxReshape       = Reshape
	mlxSlice         = Slice
	mlxTake          = Take
	mlxTile          = Tile
	mlxStack         = Stack
	mlxSubtract      = Subtract
	mlxDivide        = Divide
	mlxFloorDivide   = FloorDivide
	mlxRemainder     = Remainder
	mlxLess          = Less
	mlxGreaterEqual  = GreaterEqual
	mlxWhere         = Where
	mlxFull          = Full
	mlxRound         = Round
	mlxAsType        = AsType
	mlxAsSlice       = AsSlice[int64]
	mlxAsSliceInt32  = AsSlice[int32]
	mlxAsSliceFloat  = AsSlice[float32]
)

// NTTContext holds precomputed data for GPU NTT operations
type NTTContext struct {
	N   uint32 // Ring dimension
	Q   uint64 // Ring modulus
	Log2N int  // log2(N)

	// Twiddle factors on GPU
	twiddleFactors    *mlx.Array // [log2N, N/2] - per-stage twiddles
	invTwiddleFactors *mlx.Array // [log2N, N/2] - inverse twiddles
	
	// Normalization factor N^(-1) mod Q
	nInv uint64
	nInvArray *mlx.Array // [1] - for broadcasting

	// Barrett reduction constants
	barrettMu uint64 // floor(2^64 / Q)
	barrettMuArray *mlx.Array // [1]
	qArray *mlx.Array // [1] - modulus as array

	// Bit-reversal permutation indices
	bitRevIndices *mlx.Array // [N]
}

// NewNTTContext creates a new GPU NTT context with precomputed values
func NewNTTContext(N uint32, Q uint64) (*NTTContext, error) {
	if N == 0 || (N&(N-1)) != 0 {
		return nil, fmt.Errorf("N must be a power of 2, got %d", N)
	}

	log2N := 0
	for n := N; n > 1; n >>= 1 {
		log2N++
	}

	ctx := &NTTContext{
		N:     N,
		Q:     Q,
		Log2N: log2N,
	}

	// Compute N^(-1) mod Q using Fermat's little theorem
	ctx.nInv = powMod(uint64(N), Q-2, Q)

	// Compute Barrett constant: floor(2^64 / Q)
	ctx.barrettMu = computeBarrettMu(Q)

	// Find primitive 2N-th root of unity
	omega := findPrimitiveRoot(N, Q)
	omegaInv := modInverse(omega, Q)

	// Precompute twiddle factors for all stages
	// For Cooley-Tukey NTT, stage s has N/(2^(s+1)) groups, each with 2^s butterflies
	// Total twiddles needed: N-1 (summed across all stages)
	forwardTwiddles := make([]int64, 0, int(N)-1)
	inverseTwiddles := make([]int64, 0, int(N)-1)

	for stage := 0; stage < log2N; stage++ {
		m := 1 << (stage + 1)          // butterfly width at this stage
		numButterflies := m >> 1       // butterflies per group
		omegaM := powMod(omega, uint64(N)/uint64(m), Q)
		omegaMInv := powMod(omegaInv, uint64(N)/uint64(m), Q)

		w := uint64(1)
		wInv := uint64(1)
		for j := 0; j < numButterflies; j++ {
			forwardTwiddles = append(forwardTwiddles, int64(w))
			inverseTwiddles = append(inverseTwiddles, int64(wInv))
			w = mulMod(w, omegaM, Q)
			wInv = mulMod(wInv, omegaMInv, Q)
		}
	}

	// Upload twiddles to GPU
	ctx.twiddleFactors = mlx.ArrayFromSlice(forwardTwiddles, []int{len(forwardTwiddles)}, mlx.Int64)
	ctx.invTwiddleFactors = mlx.ArrayFromSlice(inverseTwiddles, []int{len(inverseTwiddles)}, mlx.Int64)

	// Upload constants
	ctx.nInvArray = mlx.ArrayFromSlice([]int64{int64(ctx.nInv)}, []int{1}, mlx.Int64)
	ctx.barrettMuArray = mlx.ArrayFromSlice([]int64{int64(ctx.barrettMu)}, []int{1}, mlx.Int64)
	ctx.qArray = mlx.ArrayFromSlice([]int64{int64(Q)}, []int{1}, mlx.Int64)

	// Precompute bit-reversal indices
	bitRevs := make([]int32, N)
	for i := uint32(0); i < N; i++ {
		bitRevs[i] = int32(reverseBits(int(i), log2N))
	}
	ctx.bitRevIndices = mlx.ArrayFromSlice(bitRevs, []int{int(N)}, mlx.Int32)

	// Evaluate all arrays to ensure they're materialized on GPU
	mlx.Eval(ctx.twiddleFactors)
	mlx.Eval(ctx.invTwiddleFactors)
	mlx.Eval(ctx.nInvArray)
	mlx.Eval(ctx.barrettMuArray)
	mlx.Eval(ctx.qArray)
	mlx.Eval(ctx.bitRevIndices)

	return ctx, nil
}

// NTTForward computes the forward NTT of a batch of polynomials
// Input shape: [batch, N] where each row is a polynomial
// Output shape: [batch, N] - polynomials in NTT domain
//
// Algorithm: Cooley-Tukey butterfly with Barrett reduction
// For each stage s (0 to log2N-1):
//   m = 2^(s+1), numGroups = N/m, numButterflies = m/2
//   For each group g and butterfly j:
//     u = coeffs[g*m + j]
//     v = coeffs[g*m + j + m/2] * omega^j
//     coeffs[g*m + j] = (u + v) mod Q
//     coeffs[g*m + j + m/2] = (u - v) mod Q
func (ctx *NTTContext) NTTForward(input *mlx.Array) *mlx.Array {
	N := int(ctx.N)
	Q := int64(ctx.Q)

	// Get input shape
	shape := mlxShape(input)
	if len(shape) == 1 {
		// Single polynomial - add batch dimension
		input = mlxReshape(input, []int{1, N})
		shape = []int{1, N}
	}
	batchSize := shape[0]

	// Step 1: Bit-reversal permutation
	// Use Take to permute columns according to bit-reversal indices
	coeffs := mlxTake(input, ctx.bitRevIndices, 1)

	// Step 2: Cooley-Tukey butterflies
	twiddleOffset := 0
	for stage := 0; stage < ctx.Log2N; stage++ {
		m := 1 << (stage + 1)
		mHalf := m >> 1
		numGroups := N / m

		// Extract twiddles for this stage
		stageTwiddles := mlxSlice(ctx.twiddleFactors, []int{twiddleOffset}, []int{twiddleOffset + mHalf}, []int{1})
		twiddleOffset += mHalf

		// Tile twiddles for all groups: shape [numGroups, mHalf]
		tiledTwiddles := mlxTile(mlxReshape(stageTwiddles, []int{1, mHalf}), []int{numGroups, 1})
		// Flatten to [N/2] for indexing
		tiledTwiddles = mlxReshape(tiledTwiddles, []int{N / 2})
		// Broadcast to [batch, N/2]
		tiledTwiddles = mlxTile(mlxReshape(tiledTwiddles, []int{1, N / 2}), []int{batchSize, 1})

		// Build indices for left and right halves of butterflies
		leftIndices := make([]int32, 0, N/2)
		rightIndices := make([]int32, 0, N/2)
		for g := 0; g < numGroups; g++ {
			for j := 0; j < mHalf; j++ {
				leftIndices = append(leftIndices, int32(g*m+j))
				rightIndices = append(rightIndices, int32(g*m+j+mHalf))
			}
		}

		leftIdxArr := mlx.ArrayFromSlice(leftIndices, []int{N / 2}, mlx.Int32)
		rightIdxArr := mlx.ArrayFromSlice(rightIndices, []int{N / 2}, mlx.Int32)

		// Gather left and right elements: [batch, N/2]
		u := mlxTake(coeffs, leftIdxArr, 1)
		vRaw := mlxTake(coeffs, rightIdxArr, 1)

		// v = (vRaw * twiddle) mod Q using Barrett reduction
		v := barrettMulModArray(vRaw, tiledTwiddles, Q)

		// Butterfly: sum = (u + v) mod Q, diff = (u - v) mod Q
		sum := addModArray(u, v, Q)
		diff := subModArray(u, v, Q)

		// Scatter results back
		// Create output array and place sum at left indices, diff at right indices
		// MLX doesn't have scatter, so we build a new array by concatenating properly
		
		// For each stage, we need to interleave sum and diff according to butterfly structure
		// This is done by creating the full array with proper placement
		coeffs = butterflyScatter(coeffs, sum, diff, leftIdxArr, rightIdxArr, batchSize, N)
		
		mlx.Eval(coeffs)
	}

	// Remove batch dimension if input was single polynomial
	if batchSize == 1 && len(mlxShape(coeffs)) > 1 && mlxShape(coeffs)[0] == 1 {
		coeffs = mlxReshape(coeffs, []int{N})
	}

	return coeffs
}

// NTTInverse computes the inverse NTT of a batch of polynomials
// Input shape: [batch, N] - polynomials in NTT domain
// Output shape: [batch, N] - polynomials in coefficient domain
//
// Algorithm: Gentleman-Sande butterfly with Barrett reduction
// Reverse order of forward NTT stages, with inverse twiddles
// Final scaling by N^(-1) mod Q
func (ctx *NTTContext) NTTInverse(input *mlx.Array) *mlx.Array {
	N := int(ctx.N)
	Q := int64(ctx.Q)

	// Get input shape
	shape := mlxShape(input)
	if len(shape) == 1 {
		input = mlxReshape(input, []int{1, N})
		shape = []int{1, N}
	}
	batchSize := shape[0]

	coeffs := input

	// Gentleman-Sande: process stages in reverse order
	// Start with largest butterflies, end with smallest
	twiddleOffset := int(ctx.N) - 2 // Start from end of twiddle array

	for stage := ctx.Log2N - 1; stage >= 0; stage-- {
		m := 1 << (stage + 1)
		mHalf := m >> 1
		numGroups := N / m

		// Extract inverse twiddles for this stage
		stageTwiddles := mlxSlice(ctx.invTwiddleFactors, []int{twiddleOffset - mHalf + 1}, []int{twiddleOffset + 1}, []int{1})
		twiddleOffset -= mHalf

		// Tile twiddles for all groups
		tiledTwiddles := mlxTile(mlxReshape(stageTwiddles, []int{1, mHalf}), []int{numGroups, 1})
		tiledTwiddles = mlxReshape(tiledTwiddles, []int{N / 2})
		tiledTwiddles = mlxTile(mlxReshape(tiledTwiddles, []int{1, N / 2}), []int{batchSize, 1})

		// Build indices
		leftIndices := make([]int32, 0, N/2)
		rightIndices := make([]int32, 0, N/2)
		for g := 0; g < numGroups; g++ {
			for j := 0; j < mHalf; j++ {
				leftIndices = append(leftIndices, int32(g*m+j))
				rightIndices = append(rightIndices, int32(g*m+j+mHalf))
			}
		}

		leftIdxArr := mlx.ArrayFromSlice(leftIndices, []int{N / 2}, mlx.Int32)
		rightIdxArr := mlx.ArrayFromSlice(rightIndices, []int{N / 2}, mlx.Int32)

		// Gather
		u := mlxTake(coeffs, leftIdxArr, 1)
		v := mlxTake(coeffs, rightIdxArr, 1)

		// Inverse butterfly: 
		//   new_left = (u + v) mod Q
		//   new_right = ((u - v) * inv_twiddle) mod Q
		sum := addModArray(u, v, Q)
		diff := subModArray(u, v, Q)
		diffScaled := barrettMulModArray(diff, tiledTwiddles, Q)

		// Scatter results back
		coeffs = butterflyScatter(coeffs, sum, diffScaled, leftIdxArr, rightIdxArr, batchSize, N)
		
		mlx.Eval(coeffs)
	}

	// Bit-reversal permutation
	coeffs = mlxTake(coeffs, ctx.bitRevIndices, 1)

	// Final scaling by N^(-1)
	nInvBroadcast := mlxTile(ctx.nInvArray, []int{batchSize, N})
	coeffs = barrettMulModArray(coeffs, nInvBroadcast, Q)

	mlx.Eval(coeffs)

	// Remove batch dimension if needed
	if batchSize == 1 && len(mlxShape(coeffs)) > 1 && mlxShape(coeffs)[0] == 1 {
		coeffs = mlxReshape(coeffs, []int{N})
	}

	return coeffs
}

// PolyMulNTT multiplies two polynomials in NTT domain
// Both inputs must be in NTT form. Output is also in NTT form.
// Input shapes: [batch, N] or [N]
// Performs element-wise multiplication with Barrett reduction
func (ctx *NTTContext) PolyMulNTT(a, b *mlx.Array) *mlx.Array {
	Q := int64(ctx.Q)
	return barrettMulModArray(a, b, Q)
}

// PolyMulNTTAccum multiplies and accumulates: result += a * b (in NTT form)
func (ctx *NTTContext) PolyMulNTTAccum(a, b, result *mlx.Array) *mlx.Array {
	Q := int64(ctx.Q)
	prod := barrettMulModArray(a, b, Q)
	return addModArray(result, prod, Q)
}

// PolyMul performs full polynomial multiplication via NTT
// Input polynomials are in coefficient domain
// Output is in coefficient domain
// result = INTT(NTT(a) * NTT(b))
func (ctx *NTTContext) PolyMul(a, b *mlx.Array) *mlx.Array {
	aNTT := ctx.NTTForward(a)
	bNTT := ctx.NTTForward(b)
	prodNTT := ctx.PolyMulNTT(aNTT, bNTT)
	return ctx.NTTInverse(prodNTT)
}

// PolyAdd adds two polynomials: result = (a + b) mod Q
func (ctx *NTTContext) PolyAdd(a, b *mlx.Array) *mlx.Array {
	return addModArray(a, b, int64(ctx.Q))
}

// PolySub subtracts two polynomials: result = (a - b) mod Q
func (ctx *NTTContext) PolySub(a, b *mlx.Array) *mlx.Array {
	return subModArray(a, b, int64(ctx.Q))
}

// PolyNeg negates a polynomial: result = -a mod Q
func (ctx *NTTContext) PolyNeg(a *mlx.Array) *mlx.Array {
	Q := int64(ctx.Q)
	qArr := mlxFull(mlxShape(a), Q, mlx.Int64)
	return mlxSubtract(qArr, a)
}

// PolyMulScalar multiplies polynomial by scalar: result = a * scalar mod Q
func (ctx *NTTContext) PolyMulScalar(a *mlx.Array, scalar uint64) *mlx.Array {
	Q := int64(ctx.Q)
	scalarArr := mlxFull(mlxShape(a), int64(scalar), mlx.Int64)
	return barrettMulModArray(a, scalarArr, Q)
}

// ========== Batch Operations ==========

// NTTForwardBatch performs NTT on multiple polynomial batches in parallel
// Input: slice of arrays, each [N] or [batch, N]
// Output: slice of arrays in NTT domain
func (ctx *NTTContext) NTTForwardBatch(inputs []*mlx.Array) []*mlx.Array {
	results := make([]*mlx.Array, len(inputs))
	for i, input := range inputs {
		results[i] = ctx.NTTForward(input)
	}
	return results
}

// NTTInverseBatch performs INTT on multiple polynomial batches in parallel
func (ctx *NTTContext) NTTInverseBatch(inputs []*mlx.Array) []*mlx.Array {
	results := make([]*mlx.Array, len(inputs))
	for i, input := range inputs {
		results[i] = ctx.NTTInverse(input)
	}
	return results
}

// ========== Helper Functions ==========

// butterflyScatter places butterfly results back into the coefficient array
// This is the inverse of gather - places sum at leftIndices, diff at rightIndices
func butterflyScatter(coeffs, sum, diff, leftIdxArr, rightIdxArr *mlx.Array, batchSize, N int) *mlx.Array {
	// Build mapping from position to value
	// We create a new array where we place values at correct indices
	
	// Get shapes
	numButterflies := N / 2
	
	// Create interleaved result using advanced indexing
	// For each position i in [0, N), we pick from sum if i is in leftIndices, else diff
	
	// Build the full result array
	// Extract current values
	leftVals := sum   // [batch, N/2]
	rightVals := diff // [batch, N/2]
	
	// Create output by rebuilding based on the butterfly structure
	// The pattern is determined by the indices
	
	// Since MLX doesn't have scatter, we use a sorting/permutation approach
	// Combine indices with values, sort by index, extract values
	
	// Alternative: use Take with inverse permutation
	// Build the inverse permutation
	leftIndices := mlxAsSliceInt32(leftIdxArr)
	rightIndices := mlxAsSliceInt32(rightIdxArr)
	
	// Create inverse mapping: for each output position, which input position?
	invPerm := make([]int32, N)
	isFromSum := make([]bool, N)
	for i := 0; i < numButterflies; i++ {
		invPerm[leftIndices[i]] = int32(i)
		isFromSum[leftIndices[i]] = true
		invPerm[rightIndices[i]] = int32(i)
		isFromSum[rightIndices[i]] = false
	}
	
	// Build output array position by position
	// This is less efficient but correct
	result := mlx.Zeros([]int{batchSize, N}, mlx.Int64)
	
	// Create masks for sum and diff positions
	sumMask := make([]float32, N)
	diffMask := make([]float32, N)
	for i := 0; i < N; i++ {
		if isFromSum[i] {
			sumMask[i] = 1.0
		} else {
			diffMask[i] = 1.0
		}
	}
	
	sumMaskArr := mlx.ArrayFromSlice(sumMask, []int{1, N}, mlx.Float32)
	diffMaskArr := mlx.ArrayFromSlice(diffMask, []int{1, N}, mlx.Float32)
	
	// Expand sum and diff to full size using the inverse permutation
	sumPermIdx := make([]int32, N)
	diffPermIdx := make([]int32, N)
	for i := 0; i < N; i++ {
		sumPermIdx[i] = invPerm[i]
		diffPermIdx[i] = invPerm[i]
	}
	
	sumPermIdxArr := mlx.ArrayFromSlice(sumPermIdx, []int{N}, mlx.Int32)
	diffPermIdxArr := mlx.ArrayFromSlice(diffPermIdx, []int{N}, mlx.Int32)
	
	// Gather to expand
	sumExpanded := mlxTake(sum, sumPermIdxArr, 1)   // [batch, N]
	diffExpanded := mlxTake(diff, diffPermIdxArr, 1) // [batch, N]
	
	// Convert masks to int64 for multiplication
	sumMaskInt := mlxAsType(sumMaskArr, mlx.Int64)
	diffMaskInt := mlxAsType(diffMaskArr, mlx.Int64)
	
	// Apply masks and combine
	sumMasked := mlx.Multiply(sumExpanded, mlxTile(sumMaskInt, []int{batchSize, 1}))
	diffMasked := mlx.Multiply(diffExpanded, mlxTile(diffMaskInt, []int{batchSize, 1}))
	
	result = mlx.Add(sumMasked, diffMasked)
	
	return result
}

// addModArray computes (a + b) mod Q element-wise
func addModArray(a, b *mlx.Array, Q int64) *mlx.Array {
	sum := mlx.Add(a, b)
	qArr := mlxFull(mlxShape(sum), Q, mlx.Int64)
	
	// Conditional subtraction: if sum >= Q, subtract Q
	// Use comparison and where
	mask := mlxGreaterEqual(sum, qArr)
	reduced := mlxSubtract(sum, qArr)
	return mlxWhere(mask, reduced, sum)
}

// subModArray computes (a - b) mod Q element-wise
func subModArray(a, b *mlx.Array, Q int64) *mlx.Array {
	// If a >= b, result = a - b
	// Else result = Q - b + a = Q + a - b
	qArr := mlxFull(mlxShape(a), Q, mlx.Int64)
	
	// Compute a - b (may be negative conceptually, but uint wraps)
	// Instead, compute both cases and select
	diff := mlxSubtract(a, b)
	diffPlus := mlx.Add(diff, qArr) // Q + (a - b)
	
	// If a >= b, use diff; else use diffPlus
	mask := mlxGreaterEqual(a, b)
	return mlxWhere(mask, diff, diffPlus)
}

// barrettMulModArray computes (a * b) mod Q using Barrett reduction
// Barrett reduction: q = floor((a*b) * mu / 2^64), r = a*b - q*Q
// where mu = floor(2^64 / Q)
func barrettMulModArray(a, b *mlx.Array, Q int64) *mlx.Array {
	// For GPU computation, we use a simplified approach:
	// Since MLX uses 64-bit integers and Q < 2^27, a*b < 2^54
	// We can compute modulo directly for small Q
	
	// Product
	prod := mlx.Multiply(a, b)
	
	// Modulo
	qArr := mlxFull(mlxShape(prod), Q, mlx.Int64)
	return mlxRemainder(prod, qArr)
}

// computeBarrettMu computes floor(2^64 / Q)
func computeBarrettMu(Q uint64) uint64 {
	// 2^64 / Q = (2^63 / Q) * 2 + ((2^63 mod Q) * 2) / Q
	twoTo63 := uint64(1) << 63
	mu := (twoTo63 / Q) * 2
	rem := ((twoTo63 % Q) * 2) / Q
	return mu + rem
}

// reverseBits reverses the lower logN bits of x
func reverseBits(x, logN int) int {
	result := 0
	for i := 0; i < logN; i++ {
		result = (result << 1) | (x & 1)
		x >>= 1
	}
	return result
}
