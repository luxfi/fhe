// Copyright (C) 2024-2025 Lux Industries Inc.
// SPDX-License-Identifier: Apache-2.0
//
// GPU-native NTT-friendly Prime Set
// Optimized for 32-bit arithmetic with Montgomery reduction
//
// Design rationale:
// - 30-32 bit primes fit in uint32_t with room for Montgomery multiplication
// - All primes p satisfy p = 1 (mod 2N) for NTT support up to N=8192
// - Primitive roots are precomputed and validated
// - Montgomery parameters precomputed for each prime
//
// Patent: PAT-FHE-GPU-PRIMES - Stage-Aligned GPU NTT Prime Selection

#ifndef LUX_FHE_GPU_PRIMES_H
#define LUX_FHE_GPU_PRIMES_H

#include <cstdint>
#include <array>
#include <vector>
#include <string>

namespace lux::fhe::gpu {

//=============================================================================
// Constants
//=============================================================================

// Maximum supported polynomial degree for NTT
constexpr uint32_t GPU_MAX_N = 8192;

// Number of GPU-optimized primes in the set
constexpr uint32_t GPU_PRIME_COUNT = 8;

// Bit width for GPU primes (30-31 bits for Montgomery headroom)
constexpr uint32_t GPU_PRIME_BITS = 31;

//=============================================================================
// GPU-Native NTT-Friendly Primes
//
// Selection criteria:
// 1. p = 1 (mod 2*GPU_MAX_N) = 1 (mod 16384) for NTT support up to N=8192
// 2. p fits in 31 bits (< 2^31) to allow Montgomery multiplication in 64-bit
// 3. p is prime (Miller-Rabin verified)
// 4. Primitive 2N-th root of unity exists
//
// These primes are specifically chosen for GPU kernels.
// CPU primes are handled separately in the CPU backend.
//=============================================================================

// GPU Prime Set: p_i = 1 + k_i * 16384 where p_i is prime
// Sorted in descending order for optimal RNS reconstruction
// All primes verified: p = 1 (mod 16384), is_prime(p) = true
constexpr uint32_t GPU_PRIME_0 = 0x7FFE0001;  // 2147352577 = 1 + 131064 * 16384
constexpr uint32_t GPU_PRIME_1 = 0x7FFBC001;  // 2147205121 = 1 + 131055 * 16384
constexpr uint32_t GPU_PRIME_2 = 0x7FF9C001;  // 2147074049 = 1 + 131047 * 16384
constexpr uint32_t GPU_PRIME_3 = 0x7FF80001;  // 2146959361 = 1 + 131040 * 16384
constexpr uint32_t GPU_PRIME_4 = 0x7FF44001;  // 2146713601 = 1 + 131025 * 16384
constexpr uint32_t GPU_PRIME_5 = 0x7FEFC001;  // 2146418689 = 1 + 131007 * 16384
constexpr uint32_t GPU_PRIME_6 = 0x7FEE8001;  // 2146336769 = 1 + 131002 * 16384
constexpr uint32_t GPU_PRIME_7 = 0x7FEAC001;  // 2146091009 = 1 + 130987 * 16384

// Array of all GPU primes for iteration
constexpr std::array<uint32_t, GPU_PRIME_COUNT> GPU_PRIMES = {
    GPU_PRIME_0, GPU_PRIME_1, GPU_PRIME_2, GPU_PRIME_3,
    GPU_PRIME_4, GPU_PRIME_5, GPU_PRIME_6, GPU_PRIME_7
};

//=============================================================================
// Montgomery Parameters
//
// For prime p, Montgomery multiplication uses:
// - R = 2^32 (Montgomery radix)
// - R_inv = R^(-1) mod p
// - p_inv = -p^(-1) mod R (used in Montgomery reduction)
// - R2 = R^2 mod p (for converting to Montgomery form)
//=============================================================================

struct MontgomeryParams {
    uint32_t prime;      // The prime p
    uint32_t r_inv;      // R^(-1) mod p where R = 2^32
    uint32_t p_inv;      // -p^(-1) mod 2^32
    uint32_t r2;         // R^2 mod p
    uint32_t root;       // Primitive 2*GPU_MAX_N-th root of unity
    uint32_t root_inv;   // Inverse of root mod p
};

// Precomputed Montgomery parameters for each GPU prime
extern const std::array<MontgomeryParams, GPU_PRIME_COUNT> GPU_MONTGOMERY_PARAMS;

//=============================================================================
// GPUPrimeSet Class
//
// Manages the GPU-optimized prime set with validation and lookup.
//=============================================================================

class GPUPrimeSet {
public:
    // Get singleton instance
    static GPUPrimeSet& instance();

    // Get prime by index
    uint32_t getPrime(size_t index) const;

    // Get Montgomery parameters for a prime
    const MontgomeryParams& getMontgomeryParams(size_t index) const;

    // Find Montgomery parameters by prime value
    const MontgomeryParams* findByPrime(uint32_t prime) const;

    // Get primitive root of unity for NTT of size N
    // Returns w such that w^N = 1 (mod p) and w is primitive
    uint32_t getPrimitiveRoot(size_t primeIndex, uint32_t nttSize) const;

    // Get inverse primitive root for inverse NTT
    uint32_t getPrimitiveRootInverse(size_t primeIndex, uint32_t nttSize) const;

    // Convert to Montgomery form: a -> aR mod p
    static uint32_t toMontgomery(uint32_t a, const MontgomeryParams& params);

    // Convert from Montgomery form: aR -> a mod p
    static uint32_t fromMontgomery(uint32_t aR, const MontgomeryParams& params);

    // Montgomery multiplication: (aR * bR) -> abR mod p
    static uint32_t montgomeryMul(uint32_t aR, uint32_t bR, const MontgomeryParams& params);

    // Montgomery modular exponentiation
    static uint32_t montgomeryPow(uint32_t baseR, uint32_t exp, const MontgomeryParams& params);

    // Validate prime set at runtime (for debugging)
    bool validate() const;

    // Get number of primes
    constexpr size_t size() const { return GPU_PRIME_COUNT; }

    // Check if a prime is in the GPU set
    bool isGPUPrime(uint32_t p) const;

    // Get maximum supported NTT size
    constexpr uint32_t maxNTTSize() const { return GPU_MAX_N; }

private:
    GPUPrimeSet();
    ~GPUPrimeSet() = default;

    // Disable copy/move
    GPUPrimeSet(const GPUPrimeSet&) = delete;
    GPUPrimeSet& operator=(const GPUPrimeSet&) = delete;

    // Validation helpers
    static bool isPrime(uint32_t n);
    static bool isNTTFriendly(uint32_t p, uint32_t maxN);
    static uint32_t modPow(uint32_t base, uint32_t exp, uint32_t mod);
    static uint32_t modInverse(uint32_t a, uint32_t mod);

    bool m_validated;
};

//=============================================================================
// Inline Montgomery Arithmetic (for GPU kernel inlining)
//=============================================================================

// Montgomery reduction: given x < p*R, compute xR^(-1) mod p
inline uint32_t montgomeryReduce(uint64_t x, uint32_t p, uint32_t p_inv) {
    uint32_t m = static_cast<uint32_t>(x) * p_inv;
    uint64_t t = x + static_cast<uint64_t>(m) * p;
    uint32_t result = static_cast<uint32_t>(t >> 32);
    return result >= p ? result - p : result;
}

// Montgomery multiplication inline
inline uint32_t montgomeryMulInline(uint32_t a, uint32_t b, uint32_t p, uint32_t p_inv) {
    uint64_t product = static_cast<uint64_t>(a) * b;
    return montgomeryReduce(product, p, p_inv);
}

// Barrett reduction for values < 2p (common after addition)
inline uint32_t barrettReduce(uint32_t a, uint32_t p) {
    return a >= p ? a - p : a;
}

// Modular addition with lazy reduction
inline uint32_t modAdd(uint32_t a, uint32_t b, uint32_t p) {
    uint32_t sum = a + b;
    return sum >= p ? sum - p : sum;
}

// Modular subtraction with lazy reduction
inline uint32_t modSub(uint32_t a, uint32_t b, uint32_t p) {
    return a >= b ? a - b : a + p - b;
}

//=============================================================================
// Prime Selection Utilities
//=============================================================================

// Select optimal number of primes for a given bit width
size_t selectPrimeCount(uint32_t totalBitWidth);

// Get product of first n primes (for CRT reconstruction bounds)
__uint128_t getPrimeProduct(size_t count);

// Verify CRT coefficient validity for reconstruction
bool verifyCRTBounds(size_t primeCount, uint32_t coeffBitWidth);

} // namespace lux::fhe::gpu

#endif // LUX_FHE_GPU_PRIMES_H
