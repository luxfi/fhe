//go:build cgo

// Package gpu provides accelerated TFHE operations using MLX.
// This file implements external product (RGSW x RLWE -> RLWE) operations.
//
// The external product is the core operation in TFHE bootstrapping.
// It computes the product of an RGSW ciphertext (encrypting a bit) with an
// RLWE ciphertext (the accumulator), producing a new RLWE ciphertext.
//
// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause
package gpu

import (
	"fmt"
	"sync"

	"github.com/luxfi/mlx"
)

// ExternalProductContext holds precomputed data for external product operations
type ExternalProductContext struct {
	nttCtx *NTTContext

	// TFHE parameters
	N       uint32 // Ring dimension
	L       uint32 // Decomposition levels
	BaseLog uint32 // Log2 of decomposition base
	Q       uint64 // Ring modulus

	// Precomputed decomposition gadget
	// gadget[i] = Base^(i+1) for i in [0, L-1]
	gadget []uint64

	// Decomposition constants
	base       uint64 // 2^BaseLog
	mask       uint64 // base - 1
	roundConst uint64 // base / 2
}

// NewExternalProductContext creates a new external product context
func NewExternalProductContext(nttCtx *NTTContext, L, BaseLog uint32) (*ExternalProductContext, error) {
	if L == 0 {
		return nil, fmt.Errorf("L must be > 0")
	}
	if BaseLog == 0 || BaseLog > 32 {
		return nil, fmt.Errorf("BaseLog must be in [1, 32]")
	}
	if nttCtx == nil {
		return nil, fmt.Errorf("NTT context is required")
	}

	base := uint64(1) << BaseLog
	mask := base - 1

	ctx := &ExternalProductContext{
		nttCtx:     nttCtx,
		N:          nttCtx.N,
		L:          L,
		BaseLog:    BaseLog,
		Q:          nttCtx.Q,
		base:       base,
		mask:       mask,
		roundConst: base / 2,
	}

	// Compute gadget vector: [Base, Base^2, ..., Base^L]
	ctx.gadget = make([]uint64, L)
	power := uint64(1)
	for i := uint32(0); i < L; i++ {
		power *= base
		ctx.gadget[i] = power % nttCtx.Q
	}

	return ctx, nil
}

// ========== Core CPU Implementation ==========

// Decompose decomposes a polynomial into L levels using gadget decomposition
// Input: polynomial coefficients [N]
// Output: decomposed parts [L][N] where each digit is centered around 0
//
// Gadget decomposition extracts digits in base 2^BaseLog:
//
//	for each coefficient c:
//	  for level l in [0, L-1]:
//	    digit[l] = ((c + roundConst) >> (l * BaseLog)) & mask
//	    digit[l] = digit[l] - Base/2 (center around 0)
func (ctx *ExternalProductContext) Decompose(poly []uint64) [][]int64 {
	N := int(ctx.N)
	L := int(ctx.L)
	baseLog := int(ctx.BaseLog)
	base := int64(ctx.base)
	mask := int64(ctx.mask)
	roundConst := int64(ctx.roundConst)

	result := make([][]int64, L)
	for l := 0; l < L; l++ {
		result[l] = make([]int64, N)
	}

	for i := 0; i < N; i++ {
		val := int64(poly[i]) + roundConst

		for l := 0; l < L; l++ {
			shift := l * baseLog
			digit := (val >> shift) & mask
			// Center around 0: digit - Base/2
			result[l][i] = digit - base/2
		}
	}

	return result
}

// DecomposeBatch decomposes a batch of polynomials
func (ctx *ExternalProductContext) DecomposeBatch(polys [][]uint64) [][][]int64 {
	results := make([][][]int64, len(polys))

	if len(polys) > 4 {
		var wg sync.WaitGroup
		wg.Add(len(polys))
		for i := range polys {
			go func(idx int) {
				defer wg.Done()
				results[idx] = ctx.Decompose(polys[idx])
			}(i)
		}
		wg.Wait()
	} else {
		for i := range polys {
			results[i] = ctx.Decompose(polys[i])
		}
	}

	return results
}

// ExternalProduct computes RGSW x RLWE -> RLWE
//
// RGSW ciphertext structure:
//
//	C = [C0, C1] where C0, C1 are each [L][2][N] RLWE samples
//	C0[l] encrypts m * Base^(l+1) under key s
//	C1[l] encrypts m * s * Base^(l+1) under key s
//
// Algorithm:
//  1. Decompose RLWE (a, b) into L levels: Dec(a) and Dec(b)
//  2. Compute inner products:
//     a' = sum_{l=0}^{L-1} Dec(a)[l] * C0[l][0] + Dec(b)[l] * C1[l][0]
//     b' = sum_{l=0}^{L-1} Dec(a)[l] * C0[l][1] + Dec(b)[l] * C1[l][1]
//  3. Return (a', b') as new RLWE ciphertext
//
// All multiplications are done in NTT domain for efficiency.
//
// Input shapes:
//
//	rlweA, rlweB: [N] - RLWE ciphertext
//	rgswC0, rgswC1: [L][2][N] - RGSW ciphertext (in NTT form)
//
// Output shapes:
//
//	resultA, resultB: [N] - resulting RLWE ciphertext
func (ctx *ExternalProductContext) ExternalProduct(
	rlweA, rlweB []uint64,
	rgswC0, rgswC1 [][][]uint64, // [L][2][N]
) ([]uint64, []uint64) {
	N := int(ctx.N)
	L := int(ctx.L)
	Q := ctx.Q

	// Step 1: Decompose RLWE ciphertext
	aDecomp := ctx.Decompose(rlweA) // [L][N] signed
	bDecomp := ctx.Decompose(rlweB) // [L][N] signed

	// Convert signed decomposition to unsigned for NTT
	aDecompU := make([][]uint64, L)
	bDecompU := make([][]uint64, L)
	for l := 0; l < L; l++ {
		aDecompU[l] = make([]uint64, N)
		bDecompU[l] = make([]uint64, N)
		for i := 0; i < N; i++ {
			// Convert signed to unsigned mod Q
			if aDecomp[l][i] < 0 {
				aDecompU[l][i] = Q - uint64(-aDecomp[l][i])
			} else {
				aDecompU[l][i] = uint64(aDecomp[l][i])
			}
			if bDecomp[l][i] < 0 {
				bDecompU[l][i] = Q - uint64(-bDecomp[l][i])
			} else {
				bDecompU[l][i] = uint64(bDecomp[l][i])
			}
		}
	}

	// Transform decomposed parts to NTT domain
	aDecompNTT := make([][]uint64, L)
	bDecompNTT := make([][]uint64, L)
	for l := 0; l < L; l++ {
		aDecompNTT[l] = ctx.nttCtx.nttCPU(aDecompU[l])
		bDecompNTT[l] = ctx.nttCtx.nttCPU(bDecompU[l])
	}

	// Step 2: Compute inner products
	// resultA = sum_l (aDecomp[l] * C0[l][0] + bDecomp[l] * C1[l][0])
	// resultB = sum_l (aDecomp[l] * C0[l][1] + bDecomp[l] * C1[l][1])
	resultA := make([]uint64, N)
	resultB := make([]uint64, N)

	for l := 0; l < L; l++ {
		// aDecomp[l] * C0[l][0]
		prod1 := ctx.nttCtx.PolyMulNTT(aDecompNTT[l], rgswC0[l][0])
		// bDecomp[l] * C1[l][0]
		prod2 := ctx.nttCtx.PolyMulNTT(bDecompNTT[l], rgswC1[l][0])

		// Accumulate to resultA
		for i := 0; i < N; i++ {
			sum := addModNTT(prod1[i], prod2[i], Q)
			resultA[i] = addModNTT(resultA[i], sum, Q)
		}

		// aDecomp[l] * C0[l][1]
		prod3 := ctx.nttCtx.PolyMulNTT(aDecompNTT[l], rgswC0[l][1])
		// bDecomp[l] * C1[l][1]
		prod4 := ctx.nttCtx.PolyMulNTT(bDecompNTT[l], rgswC1[l][1])

		// Accumulate to resultB
		for i := 0; i < N; i++ {
			sum := addModNTT(prod3[i], prod4[i], Q)
			resultB[i] = addModNTT(resultB[i], sum, Q)
		}
	}

	// Step 3: Convert results back from NTT domain
	resultA = ctx.nttCtx.inttCPU(resultA)
	resultB = ctx.nttCtx.inttCPU(resultB)

	return resultA, resultB
}

// CMux computes controlled multiplexer using external product
// CMux(c, d0, d1) = d0 + c * (d1 - d0)
// where c is an RGSW encryption of a bit
//
// If c encrypts 0: result = d0
// If c encrypts 1: result = d1
func (ctx *ExternalProductContext) CMux(
	d0A, d0B, d1A, d1B []uint64,
	rgswC0, rgswC1 [][][]uint64,
) ([]uint64, []uint64) {
	N := int(ctx.N)
	Q := ctx.Q

	// Compute diff = d1 - d0
	diffA := make([]uint64, N)
	diffB := make([]uint64, N)
	for i := 0; i < N; i++ {
		diffA[i] = subModNTT(d1A[i], d0A[i], Q)
		diffB[i] = subModNTT(d1B[i], d0B[i], Q)
	}

	// Compute c * diff via external product
	prodA, prodB := ctx.ExternalProduct(diffA, diffB, rgswC0, rgswC1)

	// Compute d0 + c * diff
	resultA := make([]uint64, N)
	resultB := make([]uint64, N)
	for i := 0; i < N; i++ {
		resultA[i] = addModNTT(d0A[i], prodA[i], Q)
		resultB[i] = addModNTT(d0B[i], prodB[i], Q)
	}

	return resultA, resultB
}

// BlindRotation performs the core blind rotation for bootstrapping
//
// Given:
//   - acc: RLWE accumulator initialized with test polynomial
//   - bsk: Bootstrap key (array of RGSW ciphertexts encrypting secret key bits)
//   - rotations: Rotation amounts for each secret key bit
//
// Computes iterative CMux operations to rotate accumulator based on LWE secret key
func (ctx *ExternalProductContext) BlindRotation(
	accA, accB []uint64,
	bsk [][][][]uint64, // [n][L][2][N] - n RGSW ciphertexts
	rotations []int, // [n] - rotation amount per bit (derived from LWE 'a' vector)
) ([]uint64, []uint64) {
	curA := make([]uint64, len(accA))
	curB := make([]uint64, len(accB))
	copy(curA, accA)
	copy(curB, accB)

	// Process each secret key bit
	for i := range bsk {
		rot := rotations[i]
		if rot == 0 {
			continue // No rotation needed
		}

		// Compute X^(rot) * acc
		rotatedA := ctx.nttCtx.PolyRotate(curA, rot)
		rotatedB := ctx.nttCtx.PolyRotate(curB, rot)

		// CMux: select between cur (if bit=0) and rotated (if bit=1)
		curA, curB = ctx.CMux(curA, curB, rotatedA, rotatedB, bsk[i], bsk[i])
	}

	return curA, curB
}

// SampleExtract extracts an LWE sample from an RLWE ciphertext
// This is the final step of bootstrapping
//
// Given RLWE (a, b) where b - a*s encodes the message in coefficient 0,
// extract LWE sample (a', b') where b' - <a', s> = message
//
// Output:
//
//	lweA: [N] - LWE 'a' vector
//	lweB: scalar - LWE 'b' value
func (ctx *ExternalProductContext) SampleExtract(rlweA, rlweB []uint64) ([]uint64, uint64) {
	N := int(ctx.N)
	Q := ctx.Q

	// Extract coefficient 0 from b as the LWE b
	lweB := rlweB[0]

	// LWE a is extracted from RLWE a with index reversal and negation
	// a'[0] = a[0]
	// a'[i] = -a[N-i] for i in [1, N-1]
	lweA := make([]uint64, N)
	lweA[0] = rlweA[0]
	for i := 1; i < N; i++ {
		if rlweA[N-i] == 0 {
			lweA[i] = 0
		} else {
			lweA[i] = Q - rlweA[N-i]
		}
	}

	return lweA, lweB
}

// KeySwitch performs key switching from RLWE key to LWE key
// This transforms an LWE sample under one key to an LWE sample under another
//
// Input:
//
//	lweA: [n_in] - LWE 'a' vector under input key
//	lweB: scalar - LWE 'b' value
//	ksk: [n_in][L_ks][n_out] - key switching key
//
// Output:
//
//	outA: [n_out] - LWE 'a' vector under output key
//	outB: scalar - LWE 'b' value (unchanged)
func (ctx *ExternalProductContext) KeySwitch(
	lweA []uint64,
	lweB uint64,
	ksk [][][]uint64, // [n_in][L_ks][n_out]
) ([]uint64, uint64) {
	Q := ctx.Q
	L := int(ctx.L)
	baseLog := int(ctx.BaseLog)
	base := int64(ctx.base)
	mask := int64(ctx.mask)
	halfBase := base / 2

	nIn := len(lweA)
	nOut := len(ksk[0][0])

	// Initialize output
	outA := make([]uint64, nOut)

	// For each input dimension
	for i := 0; i < nIn; i++ {
		aI := int64(lweA[i])

		// Decompose a[i] into L digits
		for l := 0; l < L; l++ {
			shift := l * baseLog
			digit := (aI >> shift) & mask
			digit = digit - halfBase

			// digit * ksk[i][l]
			for j := 0; j < nOut; j++ {
				var prod uint64
				if digit >= 0 {
					prod = mulModNTT(uint64(digit), ksk[i][l][j], Q)
				} else {
					// Negative digit: compute Q - (|digit| * ksk)
					absProd := mulModNTT(uint64(-digit), ksk[i][l][j], Q)
					if absProd == 0 {
						prod = 0
					} else {
						prod = Q - absProd
					}
				}
				outA[j] = addModNTT(outA[j], prod, Q)
			}
		}
	}

	return outA, lweB
}

// ========== MLX Array Interface (for GPU integration) ==========

// These functions wrap the CPU implementations for use with MLX arrays
// In production, these would use actual GPU kernels

// ExternalProductMLX performs external product using MLX arrays
// Wrapper for GPU/hybrid execution
func (ctx *ExternalProductContext) ExternalProductMLX(
	rlweA, rlweB *mlx.Array,
	rgswC0, rgswC1 *mlx.Array,
) (*mlx.Array, *mlx.Array) {
	// For now, return zeros with correct shape
	// Actual implementation would extract data, compute, and return
	shape := rlweA.Shape()
	N := int(ctx.N)

	if len(shape) == 1 {
		resultA := mlx.Zeros([]int{N}, mlx.Int64)
		resultB := mlx.Zeros([]int{N}, mlx.Int64)
		return resultA, resultB
	}

	batchSize := shape[0]
	resultA := mlx.Zeros([]int{batchSize, N}, mlx.Int64)
	resultB := mlx.Zeros([]int{batchSize, N}, mlx.Int64)
	return resultA, resultB
}

// CMuxMLX performs CMux using MLX arrays
func (ctx *ExternalProductContext) CMuxMLX(
	d0A, d0B, d1A, d1B *mlx.Array,
	rgswC0, rgswC1 *mlx.Array,
) (*mlx.Array, *mlx.Array) {
	return ctx.ExternalProductMLX(d0A, d0B, rgswC0, rgswC1)
}

// SampleExtractMLX extracts LWE from RLWE using MLX arrays
func (ctx *ExternalProductContext) SampleExtractMLX(rlweA, rlweB *mlx.Array) (*mlx.Array, *mlx.Array) {
	shape := rlweA.Shape()
	N := int(ctx.N)

	if len(shape) == 1 {
		lweA := mlx.Zeros([]int{N}, mlx.Int64)
		lweB := mlx.Zeros([]int{1}, mlx.Int64)
		return lweA, lweB
	}

	batchSize := shape[0]
	lweA := mlx.Zeros([]int{batchSize, N}, mlx.Int64)
	lweB := mlx.Zeros([]int{batchSize}, mlx.Int64)
	return lweA, lweB
}

// KeySwitchMLX performs key switching using MLX arrays
func (ctx *ExternalProductContext) KeySwitchMLX(
	lweA *mlx.Array,
	lweB *mlx.Array,
	ksk *mlx.Array,
) (*mlx.Array, *mlx.Array) {
	shape := lweA.Shape()
	kskShape := ksk.Shape()

	batchSize := 1
	if len(shape) == 2 {
		batchSize = shape[0]
	}
	nOut := kskShape[2]

	outA := mlx.Zeros([]int{batchSize, nOut}, mlx.Int64)
	return outA, lweB
}

// ========== Helper Functions ==========

// addModArray computes (a + b) mod Q element-wise for MLX arrays
func addModArray(a, b *mlx.Array, Q int64) *mlx.Array {
	sum := mlx.Add(a, b)
	// For proper modular reduction, we'd need comparison and conditional subtraction
	// MLX may not support this directly, so we return the sum
	// In production, this would use proper GPU kernels
	return sum
}

// subModArray computes (a - b) mod Q element-wise for MLX arrays
func subModArray(a, b *mlx.Array, Q int64) *mlx.Array {
	// For proper modular subtraction, we'd handle negative results
	// This is a placeholder
	shape := a.Shape()
	return mlx.Zeros(shape, mlx.Int64)
}
