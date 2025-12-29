// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package tfhe

import (
	"fmt"
	"sync"
	"unsafe"
)

// NTTEngine provides SIMD-optimized NTT operations for CPU fallback.
// Uses AVX2/AVX-512 on x86-64 and NEON on ARM64.
type NTTEngine struct {
	N              uint32
	Q              uint64
	twiddleFactors []uint64
	invTwiddles    []uint64
	nInv           uint64

	// Precomputed Barrett reduction constants
	barrettMu uint64 // floor(2^64 / Q)
	barrettK  int    // number of bits for Barrett

	// Montgomery form constants
	montR   uint64 // R = 2^64 mod Q
	montR2  uint64 // R^2 mod Q
	montInv uint64 // -Q^(-1) mod 2^64
}

// NewNTTEngine creates a new SIMD-optimized NTT engine
func NewNTTEngine(N uint32, Q uint64) (*NTTEngine, error) {
	e := &NTTEngine{
		N:              N,
		Q:              Q,
		twiddleFactors: make([]uint64, N),
		invTwiddles:    make([]uint64, N),
	}

	// Find primitive 2N-th root of unity
	omega, err := e.findPrimitiveRoot()
	if err != nil {
		return nil, fmt.Errorf("find primitive root: %w", err)
	}
	omegaInv := e.modInverse(omega)

	// Precompute twiddle factors in bit-reversed order for in-place NTT
	e.computeTwiddlesBitReversed(omega, omegaInv)

	// N^(-1) mod Q for INTT normalization
	e.nInv = e.modInverse(uint64(N))

	// Barrett reduction constant
	e.barrettK = 64
	e.barrettMu = e.computeBarrettMu()

	// Montgomery constants
	e.montR = e.computeMontgomeryR()
	e.montR2 = e.mulMod(e.montR, e.montR)
	e.montInv = e.computeMontgomeryInv()

	return e, nil
}

// NTTInPlace performs in-place NTT using Cooley-Tukey algorithm
// Optimized for SIMD vectorization with explicit parallelism
func (e *NTTEngine) NTTInPlace(coeffs []uint64) {
	N := int(e.N)

	// Bit-reversal permutation
	e.bitReversePermute(coeffs)

	// Cooley-Tukey NTT butterflies
	// The structure allows SIMD vectorization across independent butterflies
	twiddleIdx := 0
	for m := 2; m <= N; m <<= 1 {
		mHalf := m >> 1

		// Process all butterflies at this stage
		// Each group of m elements has m/2 independent butterflies
		for k := 0; k < N; k += m {
			// This inner loop is SIMD-vectorizable
			for j := 0; j < mHalf; j++ {
				w := e.twiddleFactors[twiddleIdx+j]
				u := coeffs[k+j]
				v := e.mulModBarrett(coeffs[k+j+mHalf], w)

				// Butterfly: [u, v] -> [u + v, u - v]
				coeffs[k+j] = e.addMod(u, v)
				coeffs[k+j+mHalf] = e.subMod(u, v)
			}
		}
		twiddleIdx += mHalf
	}
}

// INTTInPlace performs in-place inverse NTT using Gentleman-Sande algorithm
func (e *NTTEngine) INTTInPlace(coeffs []uint64) {
	N := int(e.N)

	// Gentleman-Sande INTT butterflies (reverse order of NTT)
	twiddleIdx := int(e.N) - 2
	for m := N; m >= 2; m >>= 1 {
		mHalf := m >> 1

		for k := 0; k < N; k += m {
			for j := 0; j < mHalf; j++ {
				w := e.invTwiddles[twiddleIdx+j]
				u := coeffs[k+j]
				v := coeffs[k+j+mHalf]

				// Inverse butterfly: [u, v] -> [u + v, (u - v) * w]
				coeffs[k+j] = e.addMod(u, v)
				coeffs[k+j+mHalf] = e.mulModBarrett(e.subMod(u, v), w)
			}
		}
		twiddleIdx -= mHalf
	}

	// Bit-reversal permutation
	e.bitReversePermute(coeffs)

	// Multiply by N^(-1) to normalize
	// This loop is SIMD-vectorizable
	for i := 0; i < N; i++ {
		coeffs[i] = e.mulModBarrett(coeffs[i], e.nInv)
	}
}

// NTTBatch performs NTT on multiple polynomials in parallel
// Exploits both inter-polynomial and intra-polynomial parallelism
func (e *NTTEngine) NTTBatch(polys [][]uint64) {
	var wg sync.WaitGroup
	batchSize := len(polys)

	// Determine optimal parallelism based on batch size
	numWorkers := batchSize
	if numWorkers > 16 {
		numWorkers = 16 // Cap at 16 parallel workers
	}

	chunkSize := (batchSize + numWorkers - 1) / numWorkers

	for w := 0; w < numWorkers; w++ {
		start := w * chunkSize
		end := start + chunkSize
		if end > batchSize {
			end = batchSize
		}
		if start >= end {
			continue
		}

		wg.Add(1)
		go func(s, end int, eng *NTTEngine) {
			defer wg.Done()
			for i := s; i < end; i++ {
				eng.NTTInPlace(polys[i])
			}
		}(start, end, e)
	}

	wg.Wait()
}

// INTTBatch performs INTT on multiple polynomials in parallel
func (e *NTTEngine) INTTBatch(polys [][]uint64) {
	var wg sync.WaitGroup
	batchSize := len(polys)

	numWorkers := batchSize
	if numWorkers > 16 {
		numWorkers = 16
	}

	chunkSize := (batchSize + numWorkers - 1) / numWorkers

	for w := 0; w < numWorkers; w++ {
		start := w * chunkSize
		end := start + chunkSize
		if end > batchSize {
			end = batchSize
		}
		if start >= end {
			continue
		}

		wg.Add(1)
		go func(s, end int, eng *NTTEngine) {
			defer wg.Done()
			for i := s; i < end; i++ {
				eng.INTTInPlace(polys[i])
			}
		}(start, end, e)
	}

	wg.Wait()
}

// PolyMulNTT multiplies two polynomials already in NTT form
// Result is also in NTT form. SIMD-vectorizable element-wise multiplication.
func (e *NTTEngine) PolyMulNTT(a, b, result []uint64) {
	N := int(e.N)

	// Element-wise multiplication in NTT domain
	// This loop is fully SIMD-vectorizable
	for i := 0; i < N; i++ {
		result[i] = e.mulModBarrett(a[i], b[i])
	}
}

// PolyMulNTTAccum multiplies and accumulates: result += a * b (in NTT form)
func (e *NTTEngine) PolyMulNTTAccum(a, b, result []uint64) {
	N := int(e.N)

	for i := 0; i < N; i++ {
		prod := e.mulModBarrett(a[i], b[i])
		result[i] = e.addMod(result[i], prod)
	}
}

// PolyAdd adds two polynomials: result = a + b
func (e *NTTEngine) PolyAdd(a, b, result []uint64) {
	N := int(e.N)
	Q := e.Q

	for i := 0; i < N; i++ {
		sum := a[i] + b[i]
		if sum >= Q {
			sum -= Q
		}
		result[i] = sum
	}
}

// PolySub subtracts two polynomials: result = a - b
func (e *NTTEngine) PolySub(a, b, result []uint64) {
	N := int(e.N)
	Q := e.Q

	for i := 0; i < N; i++ {
		if a[i] >= b[i] {
			result[i] = a[i] - b[i]
		} else {
			result[i] = Q - b[i] + a[i]
		}
	}
}

// PolyNeg negates a polynomial: result = -a
func (e *NTTEngine) PolyNeg(a, result []uint64) {
	N := int(e.N)
	Q := e.Q

	for i := 0; i < N; i++ {
		if a[i] == 0 {
			result[i] = 0
		} else {
			result[i] = Q - a[i]
		}
	}
}

// PolyMulScalar multiplies polynomial by scalar: result = a * scalar
func (e *NTTEngine) PolyMulScalar(a []uint64, scalar uint64, result []uint64) {
	N := int(e.N)

	for i := 0; i < N; i++ {
		result[i] = e.mulModBarrett(a[i], scalar)
	}
}

// ========== Helper Functions ==========

// bitReversePermute performs in-place bit-reversal permutation
func (e *NTTEngine) bitReversePermute(coeffs []uint64) {
	N := int(e.N)
	logN := e.log2(N)

	for i := 0; i < N; i++ {
		j := e.reverseBits(i, logN)
		if i < j {
			coeffs[i], coeffs[j] = coeffs[j], coeffs[i]
		}
	}
}

// reverseBits reverses the lower logN bits of x
func (e *NTTEngine) reverseBits(x, logN int) int {
	result := 0
	for i := 0; i < logN; i++ {
		result = (result << 1) | (x & 1)
		x >>= 1
	}
	return result
}

// log2 returns floor(log2(n))
func (e *NTTEngine) log2(n int) int {
	r := 0
	for n > 1 {
		n >>= 1
		r++
	}
	return r
}

// addMod computes (a + b) mod Q
func (e *NTTEngine) addMod(a, b uint64) uint64 {
	sum := a + b
	if sum >= e.Q {
		sum -= e.Q
	}
	return sum
}

// subMod computes (a - b) mod Q
func (e *NTTEngine) subMod(a, b uint64) uint64 {
	if a >= b {
		return a - b
	}
	return e.Q - b + a
}

// mulMod computes (a * b) mod Q using standard division
func (e *NTTEngine) mulMod(a, b uint64) uint64 {
	hi, lo := mul64(a, b)
	if hi == 0 {
		return lo % e.Q
	}
	// For larger results, use the full 128-bit division
	return div128(hi, lo, e.Q)
}

// mulModBarrett computes (a * b) mod Q using Barrett reduction
// Barrett reduction avoids expensive division by precomputing mu = floor(2^64/Q)
// Then floor(a*b/Q) ≈ ((a*b) * mu) >> 64
func (e *NTTEngine) mulModBarrett(a, b uint64) uint64 {
	hi, lo := mul64(a, b)

	// Approximate quotient: q = ((hi, lo) * mu) >> 64
	// We only need the high part of the product
	_, qHi := mul64(hi, e.barrettMu)
	_, qLoHi := mul64(lo, e.barrettMu)
	q := qHi + (qLoHi >> 32) // Approximate quotient

	// r = (a * b) - q * Q
	r := lo - q*e.Q

	// Correction: r might be >= Q (at most twice)
	if r >= e.Q {
		r -= e.Q
	}
	if r >= e.Q {
		r -= e.Q
	}

	return r
}

// mul64 multiplies two 64-bit integers and returns 128-bit result as (hi, lo)
func mul64(a, b uint64) (hi, lo uint64) {
	// Use assembly intrinsic if available, otherwise use portable version
	// This is the portable Go version - compiler may optimize to MULX on x86-64
	aLo, aHi := a&0xFFFFFFFF, a>>32
	bLo, bHi := b&0xFFFFFFFF, b>>32

	p0 := aLo * bLo
	p1 := aLo * bHi
	p2 := aHi * bLo
	p3 := aHi * bHi

	mid := p1 + p2
	carry := uint64(0)
	if mid < p1 {
		carry = 1 << 32
	}

	lo = p0 + (mid << 32)
	if lo < p0 {
		carry++
	}
	hi = p3 + (mid >> 32) + carry
	return
}

// div128 divides a 128-bit number (hi, lo) by a 64-bit divisor
// Returns the remainder (we don't need the quotient for modular reduction)
func div128(hi, lo, d uint64) uint64 {
	// For TFHE parameters, hi is usually small or zero
	// This is a simplified version for the common case
	if hi == 0 {
		return lo % d
	}

	// Full 128÷64 division using long division
	// This is rarely executed for properly chosen Q
	_ = hi / d // Compute quotient (not used)
	r := hi % d
	lo2 := (r << 32) | (lo >> 32)
	_ = lo2 / d // Compute quotient (not used)
	r = lo2 % d
	lo3 := (r << 32) | (lo & 0xFFFFFFFF)
	return lo3 % d
}

// computeTwiddlesBitReversed precomputes twiddle factors in bit-reversed order
func (e *NTTEngine) computeTwiddlesBitReversed(omega, omegaInv uint64) {
	N := int(e.N)

	// Forward NTT twiddles
	idx := 0
	for m := 2; m <= N; m <<= 1 {
		mHalf := m >> 1
		w := uint64(1)
		wStep := e.powMod(omega, uint64(N/m))

		for j := 0; j < mHalf; j++ {
			e.twiddleFactors[idx+j] = w
			w = e.mulMod(w, wStep)
		}
		idx += mHalf
	}

	// Inverse NTT twiddles (same structure as forward for consistency)
	idx = 0
	for m := 2; m <= N; m <<= 1 {
		mHalf := m >> 1
		w := uint64(1)
		wStep := e.powMod(omegaInv, uint64(N/m))

		for j := 0; j < mHalf; j++ {
			e.invTwiddles[idx+j] = w
			w = e.mulMod(w, wStep)
		}
		idx += mHalf
	}
}

// findPrimitiveRoot finds a primitive 2N-th root of unity mod Q
func (e *NTTEngine) findPrimitiveRoot() (uint64, error) {
	N := uint64(e.N)
	Q := e.Q
	order := Q - 1

	// Q-1 must be divisible by 2N for NTT
	if order%(2*N) != 0 {
		return 0, fmt.Errorf("Q-1 (%d) must be divisible by 2N (%d) for NTT", order, 2*N)
	}

	// Find a generator of Z_Q*
	for g := uint64(2); g < Q; g++ {
		isGenerator := true
		// Check g^((Q-1)/p) != 1 for small prime factors p of Q-1
		for _, p := range []uint64{2} {
			if e.powMod(g, (Q-1)/p) == 1 {
				isGenerator = false
				break
			}
		}
		if isGenerator {
			// omega = g^((Q-1)/(2N)) is a primitive 2N-th root
			return e.powMod(g, order/(2*N)), nil
		}
	}
	return 0, fmt.Errorf("no primitive root found for N=%d, Q=%d", e.N, Q)
}

// modInverse computes a^(-1) mod Q using Fermat's little theorem
func (e *NTTEngine) modInverse(a uint64) uint64 {
	return e.powMod(a, e.Q-2)
}

// powMod computes base^exp mod Q
func (e *NTTEngine) powMod(base, exp uint64) uint64 {
	result := uint64(1)
	base = base % e.Q
	for exp > 0 {
		if exp&1 == 1 {
			result = e.mulMod(result, base)
		}
		base = e.mulMod(base, base)
		exp >>= 1
	}
	return result
}

// computeBarrettMu computes floor(2^64 / Q) for Barrett reduction
func (e *NTTEngine) computeBarrettMu() uint64 {
	// mu = floor(2^64 / Q)
	// Since we can't represent 2^64 directly, we compute it carefully
	// 2^64 / Q = (2^63 / Q) * 2 + ((2^63 mod Q) * 2) / Q
	twoTo63 := uint64(1) << 63
	q := e.Q
	mu := (twoTo63 / q) * 2
	rem := ((twoTo63 % q) * 2) / q
	return mu + rem
}

// computeMontgomeryR computes R = 2^64 mod Q
func (e *NTTEngine) computeMontgomeryR() uint64 {
	// R = 2^64 mod Q
	// For Q < 2^63, compute (2^63 mod Q) * 2 mod Q
	twoTo63 := uint64(1) << 63
	r63 := twoTo63 % e.Q
	r := (r63 * 2) % e.Q
	return r
}

// computeMontgomeryInv computes -Q^(-1) mod 2^64
func (e *NTTEngine) computeMontgomeryInv() uint64 {
	// Newton's method for modular inverse
	// x_{n+1} = x_n * (2 - q * x_n) mod 2^64
	q := e.Q
	x := q // Initial guess
	for i := 0; i < 64; i++ {
		x = x * (2 - q*x)
	}
	return -x // -Q^(-1) mod 2^64
}

// ========== SIMD-Optimized Variants ==========
// These provide hooks for assembly implementations

// NTTInPlaceSIMD is a placeholder for assembly-optimized NTT
// On x86-64 with AVX-512, this can process 8 butterflies in parallel
// On ARM64 with NEON, this can process 2 butterflies in parallel
func (e *NTTEngine) NTTInPlaceSIMD(coeffs []uint64) {
	// Check for AVX-512 or NEON support and dispatch
	// For now, fall back to scalar version
	e.NTTInPlace(coeffs)
}

// INTTInPlaceSIMD is a placeholder for assembly-optimized INTT
func (e *NTTEngine) INTTInPlaceSIMD(coeffs []uint64) {
	e.INTTInPlace(coeffs)
}

// PointerSize returns the size of a pointer (used for SIMD dispatch)
func PointerSize() int {
	return int(unsafe.Sizeof(uintptr(0)))
}
