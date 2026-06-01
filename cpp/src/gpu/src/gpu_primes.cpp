// Copyright (C) 2024-2025 Lux Industries Inc.
// SPDX-License-Identifier: Apache-2.0
//
// GPU-native NTT-friendly Prime Set Implementation
// See gpu_primes.h for design rationale.

#include "gpu_primes.h"
#include <stdexcept>
#include <cstring>

namespace lux::fhe::gpu {

//=============================================================================
// Precomputed Montgomery Parameters
//
// For each prime p:
// - R = 2^32
// - r_inv = R^(-1) mod p
// - p_inv = -p^(-1) mod R (Montgomery constant)
// - r2 = R^2 mod p (for to_montgomery conversion)
// - root = primitive 2*GPU_MAX_N-th root of unity
// - root_inv = root^(-1) mod p
//
// These values were computed offline and verified.
//=============================================================================

const std::array<MontgomeryParams, GPU_PRIME_COUNT> GPU_MONTGOMERY_PARAMS = {{
    // GPU_PRIME_0 = 0x7FFE0001 = 2147352577
    {
        .prime = 0x7FFE0001,
        .r_inv = 0x3FFE0004,
        .p_inv = 0x7FFDFFFF,
        .r2 = 0x002FFFE4,
        .root = 0x2E09B547,
        .root_inv = 0x20B8A92C
    },
    // GPU_PRIME_1 = 0x7FFBC001 = 2147205121
    {
        .prime = 0x7FFBC001,
        .r_inv = 0x37FC0412,
        .p_inv = 0x6FFBBFFF,
        .r2 = 0x4241FF74,
        .root = 0x2A4EDE95,
        .root_inv = 0x27AD53BE
    },
    // GPU_PRIME_2 = 0x7FF9C001 = 2147074049
    {
        .prime = 0x7FF9C001,
        .r_inv = 0x37FA2427,
        .p_inv = 0x6FF9BFFF,
        .r2 = 0x476BFECC,
        .root = 0x3BD9B6E7,
        .root_inv = 0x2C2C4EE3
    },
    // GPU_PRIME_3 = 0x7FF80001 = 2146959361
    {
        .prime = 0x7FF80001,
        .r_inv = 0x3FF80040,
        .p_inv = 0x7FF7FFFF,
        .r2 = 0x0FBFFE04,
        .root = 0x74FB5C53,
        .root_inv = 0x75F55F6C
    },
    // GPU_PRIME_4 = 0x7FF44001 = 2146713601
    {
        .prime = 0x7FF44001,
        .r_inv = 0x37F4FC8A,
        .p_inv = 0x6FF43FFF,
        .r2 = 0x724DFBB4,
        .root = 0x7A3A824E,
        .root_inv = 0x576FC86E
    },
    // GPU_PRIME_5 = 0x7FEFC001 = 2146418689
    {
        .prime = 0x7FEFC001,
        .r_inv = 0x37F0C508,
        .p_inv = 0x6FEFBFFF,
        .r2 = 0x459E37C3,
        .root = 0x0849C038,
        .root_inv = 0x27AA3607
    },
    // GPU_PRIME_6 = 0x7FEE8001 = 2146336769
    {
        .prime = 0x7FEE8001,
        .r_inv = 0x1FF2E132,
        .p_inv = 0x3FEE7FFF,
        .r2 = 0x27007671,
        .root = 0x01CB102D,
        .root_inv = 0x40144EF1
    },
    // GPU_PRIME_7 = 0x7FEAC001 = 2146091009
    {
        .prime = 0x7FEAC001,
        .r_inv = 0x77E175C4,
        .p_inv = 0xEFEABFFF,
        .r2 = 0x6B5371E6,
        .root = 0x21954F52,
        .root_inv = 0x3693C6C8
    }
}};

//=============================================================================
// Static helper functions
//=============================================================================

// Extended Euclidean Algorithm for modular inverse
static uint64_t extGCD(int64_t a, int64_t b, int64_t& x, int64_t& y) {
    if (b == 0) {
        x = 1;
        y = 0;
        return a;
    }
    int64_t x1, y1;
    uint64_t gcd = extGCD(b, a % b, x1, y1);
    x = y1;
    y = x1 - (a / b) * y1;
    return gcd;
}

// Modular inverse using extended GCD
static uint32_t computeModInverse(uint32_t a, uint64_t mod) {
    int64_t x, y;
    extGCD(static_cast<int64_t>(a), static_cast<int64_t>(mod), x, y);
    return static_cast<uint32_t>((x % static_cast<int64_t>(mod) + mod) % mod);
}

// Modular exponentiation
static uint32_t computeModPow(uint32_t base, uint64_t exp, uint32_t mod) {
    uint64_t result = 1;
    uint64_t b = base;
    while (exp > 0) {
        if (exp & 1) {
            result = (result * b) % mod;
        }
        b = (b * b) % mod;
        exp >>= 1;
    }
    return static_cast<uint32_t>(result);
}

// Miller-Rabin primality test
static bool millerRabinTest(uint32_t n, uint32_t a) {
    if (n < 2) return false;
    if (n == 2) return true;
    if (n % 2 == 0) return false;

    uint32_t d = n - 1;
    uint32_t r = 0;
    while ((d & 1) == 0) {
        d >>= 1;
        r++;
    }

    uint64_t x = computeModPow(a, d, n);
    if (x == 1 || x == n - 1) return true;

    for (uint32_t i = 0; i < r - 1; i++) {
        x = (x * x) % n;
        if (x == n - 1) return true;
    }
    return false;
}

//=============================================================================
// GPUPrimeSet Implementation
//=============================================================================

GPUPrimeSet& GPUPrimeSet::instance() {
    static GPUPrimeSet instance;
    return instance;
}

GPUPrimeSet::GPUPrimeSet() : m_validated(false) {
    // Validate on first construction in debug builds
#ifndef NDEBUG
    m_validated = validate();
#else
    m_validated = true;
#endif
}

uint32_t GPUPrimeSet::getPrime(size_t index) const {
    if (index >= GPU_PRIME_COUNT) {
        throw std::out_of_range("Prime index out of range");
    }
    return GPU_PRIMES[index];
}

const MontgomeryParams& GPUPrimeSet::getMontgomeryParams(size_t index) const {
    if (index >= GPU_PRIME_COUNT) {
        throw std::out_of_range("Montgomery params index out of range");
    }
    return GPU_MONTGOMERY_PARAMS[index];
}

const MontgomeryParams* GPUPrimeSet::findByPrime(uint32_t prime) const {
    for (size_t i = 0; i < GPU_PRIME_COUNT; i++) {
        if (GPU_MONTGOMERY_PARAMS[i].prime == prime) {
            return &GPU_MONTGOMERY_PARAMS[i];
        }
    }
    return nullptr;
}

uint32_t GPUPrimeSet::getPrimitiveRoot(size_t primeIndex, uint32_t nttSize) const {
    if (primeIndex >= GPU_PRIME_COUNT) {
        throw std::out_of_range("Prime index out of range");
    }
    if (nttSize > GPU_MAX_N || (nttSize & (nttSize - 1)) != 0) {
        throw std::invalid_argument("NTT size must be power of 2 and <= GPU_MAX_N");
    }

    const MontgomeryParams& params = GPU_MONTGOMERY_PARAMS[primeIndex];
    uint32_t p = params.prime;
    uint32_t baseRoot = params.root;

    // The stored root is for 2*GPU_MAX_N
    // For NTT of size N, we need w where w^N = 1
    // baseRoot^(2*GPU_MAX_N) = 1, so w = baseRoot^(2*GPU_MAX_N/N)
    uint32_t exponent = (2 * GPU_MAX_N) / nttSize;
    return computeModPow(baseRoot, exponent, p);
}

uint32_t GPUPrimeSet::getPrimitiveRootInverse(size_t primeIndex, uint32_t nttSize) const {
    uint32_t root = getPrimitiveRoot(primeIndex, nttSize);
    uint32_t p = GPU_PRIMES[primeIndex];
    return computeModInverse(root, p);
}

uint32_t GPUPrimeSet::toMontgomery(uint32_t a, const MontgomeryParams& params) {
    // aR mod p = (a * R^2) * R^(-1) mod p = montgomeryMul(a, R^2)
    uint64_t product = static_cast<uint64_t>(a) * params.r2;
    return montgomeryReduce(product, params.prime, params.p_inv);
}

uint32_t GPUPrimeSet::fromMontgomery(uint32_t aR, const MontgomeryParams& params) {
    // Convert from Montgomery: aR -> a
    return montgomeryReduce(aR, params.prime, params.p_inv);
}

uint32_t GPUPrimeSet::montgomeryMul(uint32_t aR, uint32_t bR, const MontgomeryParams& params) {
    uint64_t product = static_cast<uint64_t>(aR) * bR;
    return montgomeryReduce(product, params.prime, params.p_inv);
}

uint32_t GPUPrimeSet::montgomeryPow(uint32_t baseR, uint32_t exp, const MontgomeryParams& params) {
    // Start with 1 in Montgomery form
    uint32_t resultR = toMontgomery(1, params);

    while (exp > 0) {
        if (exp & 1) {
            resultR = montgomeryMul(resultR, baseR, params);
        }
        baseR = montgomeryMul(baseR, baseR, params);
        exp >>= 1;
    }
    return resultR;
}

bool GPUPrimeSet::isPrime(uint32_t n) {
    // Deterministic Miller-Rabin for 32-bit numbers
    // Using bases 2, 7, 61 is sufficient for all 32-bit numbers
    if (n < 2) return false;
    if (n == 2 || n == 7 || n == 61) return true;
    if (n % 2 == 0) return false;

    return millerRabinTest(n, 2) &&
           millerRabinTest(n, 7) &&
           millerRabinTest(n, 61);
}

bool GPUPrimeSet::isNTTFriendly(uint32_t p, uint32_t maxN) {
    // Check p = 1 (mod 2*maxN)
    uint32_t required = 2 * maxN;
    return (p - 1) % required == 0;
}

uint32_t GPUPrimeSet::modPow(uint32_t base, uint32_t exp, uint32_t mod) {
    return computeModPow(base, exp, mod);
}

uint32_t GPUPrimeSet::modInverse(uint32_t a, uint32_t mod) {
    return computeModInverse(a, mod);
}

bool GPUPrimeSet::validate() const {
    for (size_t i = 0; i < GPU_PRIME_COUNT; i++) {
        uint32_t p = GPU_PRIMES[i];

        // Check primality
        if (!isPrime(p)) {
            return false;
        }

        // Check NTT-friendliness: p = 1 (mod 2*GPU_MAX_N)
        if (!isNTTFriendly(p, GPU_MAX_N)) {
            return false;
        }

        // Check bit width (30-31 bits)
        if (p < (1ULL << 30) || p >= (1ULL << 31)) {
            return false;
        }

        // Verify primitive root
        const MontgomeryParams& params = GPU_MONTGOMERY_PARAMS[i];
        uint32_t order = 2 * GPU_MAX_N;

        // root^order should equal 1 mod p
        if (computeModPow(params.root, order, p) != 1) {
            return false;
        }

        // root^(order/2) should NOT equal 1 mod p (primitivity check)
        if (computeModPow(params.root, order / 2, p) == 1) {
            return false;
        }
    }
    return true;
}

bool GPUPrimeSet::isGPUPrime(uint32_t p) const {
    for (size_t i = 0; i < GPU_PRIME_COUNT; i++) {
        if (GPU_PRIMES[i] == p) return true;
    }
    return false;
}

//=============================================================================
// Prime Selection Utilities
//=============================================================================

size_t selectPrimeCount(uint32_t totalBitWidth) {
    // Each prime provides ~31 bits
    // With CRT, we need enough primes to represent totalBitWidth + safety margin
    constexpr uint32_t BITS_PER_PRIME = 31;
    constexpr uint32_t SAFETY_MARGIN = 2;  // Extra bits for intermediate products

    size_t count = (totalBitWidth + SAFETY_MARGIN + BITS_PER_PRIME - 1) / BITS_PER_PRIME;
    return std::min(count, static_cast<size_t>(GPU_PRIME_COUNT));
}

__uint128_t getPrimeProduct(size_t count) {
    if (count == 0 || count > GPU_PRIME_COUNT) {
        return 0;
    }

    __uint128_t product = 1;
    for (size_t i = 0; i < count; i++) {
        product *= GPU_PRIMES[i];
    }
    return product;
}

bool verifyCRTBounds(size_t primeCount, uint32_t coeffBitWidth) {
    // CRT can represent values up to product of primes
    // Coefficients need at most coeffBitWidth bits
    // Product must exceed 2^coeffBitWidth

    __uint128_t product = getPrimeProduct(primeCount);
    __uint128_t required = static_cast<__uint128_t>(1) << coeffBitWidth;

    return product > required;
}

} // namespace lux::fhe::gpu
