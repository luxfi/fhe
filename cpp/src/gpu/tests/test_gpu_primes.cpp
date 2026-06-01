// Copyright (C) 2024-2025 Lux Industries Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Test suite for GPU-native NTT primes and twiddle tables

#include "gpu_primes.h"
#include "twiddle_tables.h"
#include <iostream>
#include <iomanip>
#include <cassert>
#include <cmath>
#include <chrono>
#include <vector>

using namespace lux::fhe::gpu;

//=============================================================================
// Test Utilities
//=============================================================================

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    std::cout << "  Testing " << #name << "... " << std::flush; \
    try {

#define TEST_END \
        std::cout << "PASSED" << std::endl; \
        tests_passed++; \
    } catch (const std::exception& e) { \
        std::cout << "FAILED: " << e.what() << std::endl; \
        tests_failed++; \
    }

#define ASSERT_EQ(a, b) \
    if ((a) != (b)) { \
        throw std::runtime_error( \
            "Assertion failed: " #a " != " #b " (" + \
            std::to_string(a) + " != " + std::to_string(b) + ")"); \
    }

#define ASSERT_TRUE(cond) \
    if (!(cond)) { \
        throw std::runtime_error("Assertion failed: " #cond); \
    }

//=============================================================================
// Modular arithmetic helpers for verification
//=============================================================================

static uint32_t modPow(uint32_t base, uint64_t exp, uint32_t mod) {
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

static bool isPrime(uint32_t n) {
    if (n < 2) return false;
    if (n == 2) return true;
    if (n % 2 == 0) return false;
    for (uint32_t i = 3; i * i <= n; i += 2) {
        if (n % i == 0) return false;
    }
    return true;
}

//=============================================================================
// Test: GPU Prime Set Validation
//=============================================================================

void test_gpu_prime_set() {
    std::cout << "\n=== GPU Prime Set Tests ===" << std::endl;

    TEST(prime_count) {
        ASSERT_EQ(GPU_PRIME_COUNT, 8);
        ASSERT_EQ(GPU_PRIMES.size(), 8);
    } TEST_END

    TEST(primes_are_prime) {
        for (size_t i = 0; i < GPU_PRIME_COUNT; i++) {
            ASSERT_TRUE(isPrime(GPU_PRIMES[i]));
        }
    } TEST_END

    TEST(primes_are_ntt_friendly) {
        // Each prime must be 1 (mod 2*GPU_MAX_N) = 1 (mod 16384)
        for (size_t i = 0; i < GPU_PRIME_COUNT; i++) {
            uint32_t p = GPU_PRIMES[i];
            ASSERT_EQ((p - 1) % (2 * GPU_MAX_N), 0);
        }
    } TEST_END

    TEST(primes_fit_in_31_bits) {
        for (size_t i = 0; i < GPU_PRIME_COUNT; i++) {
            uint32_t p = GPU_PRIMES[i];
            ASSERT_TRUE(p < (1ULL << 31));
            ASSERT_TRUE(p >= (1ULL << 30));
        }
    } TEST_END

    TEST(primes_are_distinct_and_sorted) {
        for (size_t i = 1; i < GPU_PRIME_COUNT; i++) {
            ASSERT_TRUE(GPU_PRIMES[i-1] > GPU_PRIMES[i]);  // Descending order
        }
    } TEST_END

    TEST(singleton_validation) {
        GPUPrimeSet& primeSet = GPUPrimeSet::instance();
        ASSERT_TRUE(primeSet.validate());
    } TEST_END
}

//=============================================================================
// Test: Montgomery Arithmetic
//=============================================================================

void test_montgomery_arithmetic() {
    std::cout << "\n=== Montgomery Arithmetic Tests ===" << std::endl;

    GPUPrimeSet& primeSet = GPUPrimeSet::instance();

    TEST(to_from_montgomery_roundtrip) {
        for (size_t i = 0; i < GPU_PRIME_COUNT; i++) {
            const MontgomeryParams& params = primeSet.getMontgomeryParams(i);

            // Test several values
            std::vector<uint32_t> testValues = {0, 1, 2, 100, 12345, params.prime - 1};
            for (uint32_t val : testValues) {
                uint32_t mont = GPUPrimeSet::toMontgomery(val, params);
                uint32_t back = GPUPrimeSet::fromMontgomery(mont, params);
                ASSERT_EQ(back, val);
            }
        }
    } TEST_END

    TEST(montgomery_multiplication) {
        for (size_t i = 0; i < GPU_PRIME_COUNT; i++) {
            const MontgomeryParams& params = primeSet.getMontgomeryParams(i);
            uint32_t p = params.prime;

            // Test a * b mod p
            uint32_t a = 12345;
            uint32_t b = 67890;
            uint64_t expected = (static_cast<uint64_t>(a) * b) % p;

            uint32_t aM = GPUPrimeSet::toMontgomery(a, params);
            uint32_t bM = GPUPrimeSet::toMontgomery(b, params);
            uint32_t resultM = GPUPrimeSet::montgomeryMul(aM, bM, params);
            uint32_t result = GPUPrimeSet::fromMontgomery(resultM, params);

            ASSERT_EQ(result, static_cast<uint32_t>(expected));
        }
    } TEST_END

    TEST(montgomery_exponentiation) {
        for (size_t i = 0; i < GPU_PRIME_COUNT; i++) {
            const MontgomeryParams& params = primeSet.getMontgomeryParams(i);
            uint32_t p = params.prime;

            // Test base^exp mod p
            uint32_t base = 7;
            uint32_t exp = 1000;
            uint32_t expected = modPow(base, exp, p);

            uint32_t baseM = GPUPrimeSet::toMontgomery(base, params);
            uint32_t resultM = GPUPrimeSet::montgomeryPow(baseM, exp, params);
            uint32_t result = GPUPrimeSet::fromMontgomery(resultM, params);

            ASSERT_EQ(result, expected);
        }
    } TEST_END

    TEST(inline_montgomery_reduce) {
        for (size_t i = 0; i < GPU_PRIME_COUNT; i++) {
            const MontgomeryParams& params = primeSet.getMontgomeryParams(i);

            uint32_t a = 12345;
            uint32_t b = 67890;
            uint64_t product = static_cast<uint64_t>(
                GPUPrimeSet::toMontgomery(a, params)
            ) * GPUPrimeSet::toMontgomery(b, params);

            uint32_t reduced = montgomeryReduce(product, params.prime, params.p_inv);
            uint32_t result = GPUPrimeSet::fromMontgomery(reduced, params);

            uint64_t expected = (static_cast<uint64_t>(a) * b) % params.prime;
            ASSERT_EQ(result, static_cast<uint32_t>(expected));
        }
    } TEST_END
}

//=============================================================================
// Test: Primitive Roots
//=============================================================================

void test_primitive_roots() {
    std::cout << "\n=== Primitive Root Tests ===" << std::endl;

    GPUPrimeSet& primeSet = GPUPrimeSet::instance();

    TEST(primitive_root_order) {
        for (size_t i = 0; i < GPU_PRIME_COUNT; i++) {
            const MontgomeryParams& params = primeSet.getMontgomeryParams(i);
            uint32_t p = params.prime;
            uint32_t root = params.root;

            // root^(2*GPU_MAX_N) should equal 1
            uint32_t order = 2 * GPU_MAX_N;
            ASSERT_EQ(modPow(root, order, p), 1);

            // root^(order/2) should NOT equal 1 (primitivity)
            ASSERT_TRUE(modPow(root, order / 2, p) != 1);
        }
    } TEST_END

    TEST(get_primitive_root_for_sizes) {
        std::vector<uint32_t> testSizes = {1024, 2048, 4096, 8192};

        for (size_t i = 0; i < GPU_PRIME_COUNT; i++) {
            uint32_t p = GPU_PRIMES[i];

            for (uint32_t n : testSizes) {
                uint32_t root = primeSet.getPrimitiveRoot(i, n);

                // root^N should equal 1
                ASSERT_EQ(modPow(root, n, p), 1);

                // root^(N/2) should NOT equal 1
                ASSERT_TRUE(modPow(root, n / 2, p) != 1);
            }
        }
    } TEST_END

    TEST(root_inverse_correct) {
        for (size_t i = 0; i < GPU_PRIME_COUNT; i++) {
            uint32_t p = GPU_PRIMES[i];

            for (uint32_t n : {1024u, 4096u}) {
                uint32_t root = primeSet.getPrimitiveRoot(i, n);
                uint32_t rootInv = primeSet.getPrimitiveRootInverse(i, n);

                // root * rootInv should equal 1 mod p
                uint64_t product = (static_cast<uint64_t>(root) * rootInv) % p;
                ASSERT_EQ(product, 1);
            }
        }
    } TEST_END
}

//=============================================================================
// Test: Twiddle Tables
//=============================================================================

void test_twiddle_tables() {
    std::cout << "\n=== Twiddle Table Tests ===" << std::endl;

    TwiddleTableManager& manager = TwiddleTableManager::instance();
    GPUPrimeSet& primeSet = GPUPrimeSet::instance();

    TEST(supported_sizes) {
        ASSERT_TRUE(TwiddleTableManager::isSupportedSize(1024));
        ASSERT_TRUE(TwiddleTableManager::isSupportedSize(2048));
        ASSERT_TRUE(TwiddleTableManager::isSupportedSize(4096));
        ASSERT_TRUE(TwiddleTableManager::isSupportedSize(8192));
        ASSERT_TRUE(!TwiddleTableManager::isSupportedSize(512));
        ASSERT_TRUE(!TwiddleTableManager::isSupportedSize(3000));
    } TEST_END

    TEST(log2_size) {
        ASSERT_EQ(TwiddleTableManager::log2Size(1024), 10);
        ASSERT_EQ(TwiddleTableManager::log2Size(2048), 11);
        ASSERT_EQ(TwiddleTableManager::log2Size(4096), 12);
        ASSERT_EQ(TwiddleTableManager::log2Size(8192), 13);
    } TEST_END

    TEST(sequential_twiddle_table) {
        const TwiddleTable& table = manager.getTable(
            0, 1024, TwiddleLayout::SEQUENTIAL, false
        );

        ASSERT_EQ(table.prime, GPU_PRIMES[0]);
        ASSERT_EQ(table.ntt_size, 1024);
        ASSERT_EQ(table.forward.size(), 512);  // N/2 twiddles
        ASSERT_EQ(table.inverse.size(), 512);

        // First twiddle should be 1 (w^0 = 1)
        ASSERT_EQ(table.forward[0], 1);
        ASSERT_EQ(table.inverse[0], 1);
    } TEST_END

    TEST(bit_reversed_twiddle_table) {
        const TwiddleTable& table = manager.getTable(
            0, 1024, TwiddleLayout::BIT_REVERSED, false
        );

        ASSERT_EQ(table.forward.size(), 512);

        // Bit-reversed index 0 maps to 0, so first should still be 1
        ASSERT_EQ(table.forward[0], 1);
    } TEST_END

    TEST(stage_aligned_twiddles) {
        const StageAlignedTwiddles& table = manager.getStageAlignedTable(
            0, 1024, false
        );

        ASSERT_EQ(table.prime, GPU_PRIMES[0]);
        ASSERT_EQ(table.ntt_size, 1024);
        ASSERT_EQ(table.num_stages, 10);  // log2(1024)

        // Each stage should have N/2 = 512 twiddles total
        size_t totalTwiddles = 0;
        for (uint32_t s = 0; s < table.num_stages; s++) {
            totalTwiddles += table.stage_forward[s].size();
        }
        ASSERT_EQ(totalTwiddles, 512 * 10);  // N/2 per stage * num_stages
    } TEST_END

    TEST(montgomery_form_twiddles) {
        const StageAlignedTwiddles& tableMont = manager.getStageAlignedTable(
            0, 1024, true
        );
        const StageAlignedTwiddles& tableStd = manager.getStageAlignedTable(
            0, 1024, false
        );

        ASSERT_TRUE(tableMont.montgomery_form);
        ASSERT_TRUE(!tableStd.montgomery_form);

        // Convert Montgomery form back and verify equality
        const MontgomeryParams& params = primeSet.getMontgomeryParams(0);

        for (uint32_t s = 0; s < tableMont.num_stages; s++) {
            for (size_t i = 0; i < tableMont.stage_forward[s].size(); i++) {
                uint32_t montVal = tableMont.stage_forward[s][i];
                uint32_t stdVal = tableStd.stage_forward[s][i];
                uint32_t converted = GPUPrimeSet::fromMontgomery(montVal, params);
                ASSERT_EQ(converted, stdVal);
            }
        }
    } TEST_END

    TEST(n_inverse_correct) {
        const TwiddleTable& table = manager.getTable(0, 1024, TwiddleLayout::SEQUENTIAL, false);
        uint32_t p = GPU_PRIMES[0];

        // n_inv * n should equal 1 mod p
        uint64_t product = (static_cast<uint64_t>(table.n_inv) * 1024) % p;
        ASSERT_EQ(product, 1);
    } TEST_END
}

//=============================================================================
// Test: GPU Format Conversion
//=============================================================================

void test_gpu_format() {
    std::cout << "\n=== GPU Format Tests ===" << std::endl;

    TwiddleTableManager& manager = TwiddleTableManager::instance();

    TEST(gpu_format_conversion) {
        const StageAlignedTwiddles& table = manager.getStageAlignedTable(0, 1024, true);
        GPUTwiddleData gpu = toGPUFormat(table);

        ASSERT_EQ(gpu.prime, GPU_PRIMES[0]);
        ASSERT_EQ(gpu.ntt_size, 1024);
        ASSERT_EQ(gpu.num_stages, 10);
        ASSERT_EQ(gpu.flags & 1, 1);  // Montgomery form flag

        // Stage offsets should be valid
        ASSERT_EQ(gpu.stage_offsets.size(), 11);  // num_stages + 1
        ASSERT_EQ(gpu.stage_offsets[0], 0);

        // Flat arrays should have correct size
        size_t expectedSize = 512 * 10;  // N/2 per stage
        ASSERT_EQ(gpu.forward_flat.size(), expectedSize);
        ASSERT_EQ(gpu.inverse_flat.size(), expectedSize);
    } TEST_END

    TEST(stage_offset_validity) {
        const StageAlignedTwiddles& table = manager.getStageAlignedTable(0, 4096, true);
        GPUTwiddleData gpu = toGPUFormat(table);

        // Each stage offset should be sum of previous stage sizes
        uint32_t expectedOffset = 0;
        for (uint32_t s = 0; s < gpu.num_stages; s++) {
            ASSERT_EQ(gpu.stage_offsets[s], expectedOffset);
            expectedOffset += 2048;  // N/2 for each stage
        }
    } TEST_END
}

//=============================================================================
// Test: Bit Reversal
//=============================================================================

void test_bit_reversal() {
    std::cout << "\n=== Bit Reversal Tests ===" << std::endl;

    TEST(bit_reversal_permutation) {
        std::vector<uint32_t> perm;
        generateBitReversalPermutation(8, perm);

        // For n=8: 0->0, 1->4, 2->2, 3->6, 4->1, 5->5, 6->3, 7->7
        ASSERT_EQ(perm[0], 0);
        ASSERT_EQ(perm[1], 4);
        ASSERT_EQ(perm[2], 2);
        ASSERT_EQ(perm[3], 6);
        ASSERT_EQ(perm[4], 1);
        ASSERT_EQ(perm[5], 5);
        ASSERT_EQ(perm[6], 3);
        ASSERT_EQ(perm[7], 7);
    } TEST_END

    TEST(bit_reversal_involution) {
        std::vector<uint32_t> perm;
        generateBitReversalPermutation(1024, perm);

        // Bit reversal is an involution: perm[perm[i]] = i
        for (size_t i = 0; i < 1024; i++) {
            ASSERT_EQ(perm[perm[i]], i);
        }
    } TEST_END
}

//=============================================================================
// Test: Prime Selection Utilities
//=============================================================================

void test_prime_utilities() {
    std::cout << "\n=== Prime Selection Utility Tests ===" << std::endl;

    TEST(select_prime_count) {
        // For 64 bits, need at least 3 primes (3 * 31 = 93 > 64)
        ASSERT_TRUE(selectPrimeCount(64) >= 3);

        // For 128 bits, need at least 5 primes
        ASSERT_TRUE(selectPrimeCount(128) >= 5);

        // For 248 bits (max with 8 primes), need 8 primes
        ASSERT_EQ(selectPrimeCount(248), 8);
    } TEST_END

    TEST(prime_product) {
        __uint128_t product1 = getPrimeProduct(1);
        ASSERT_EQ(static_cast<uint64_t>(product1), GPU_PRIMES[0]);

        __uint128_t product2 = getPrimeProduct(2);
        ASSERT_TRUE(product2 > product1);

        // 8 primes should give > 248 bits
        __uint128_t product8 = getPrimeProduct(8);
        ASSERT_TRUE(product8 > (static_cast<__uint128_t>(1) << 120));
    } TEST_END

    TEST(crt_bounds_verification) {
        // 2 primes should cover 62 bits
        ASSERT_TRUE(verifyCRTBounds(2, 60));

        // 4 primes should cover 120 bits
        ASSERT_TRUE(verifyCRTBounds(4, 120));

        // 8 primes should cover at least 240 bits
        ASSERT_TRUE(verifyCRTBounds(8, 240));
    } TEST_END

    TEST(is_gpu_prime) {
        GPUPrimeSet& primeSet = GPUPrimeSet::instance();

        for (size_t i = 0; i < GPU_PRIME_COUNT; i++) {
            ASSERT_TRUE(primeSet.isGPUPrime(GPU_PRIMES[i]));
        }

        // Random prime should not be in set
        ASSERT_TRUE(!primeSet.isGPUPrime(1000000007));
    } TEST_END
}

//=============================================================================
// Performance Test
//=============================================================================

void test_performance() {
    std::cout << "\n=== Performance Tests ===" << std::endl;

    TwiddleTableManager& manager = TwiddleTableManager::instance();

    TEST(twiddle_generation_time) {
        manager.clearCache();

        auto start = std::chrono::high_resolution_clock::now();

        // Generate all stage-aligned tables for all primes and sizes
        for (uint32_t n : SUPPORTED_NTT_SIZES) {
            for (uint32_t i = 0; i < GPU_PRIME_COUNT; i++) {
                manager.getStageAlignedTable(i, n, true);
            }
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        std::cout << "(" << duration.count() << "ms) ";
        ASSERT_TRUE(duration.count() < 5000);  // Should complete in < 5 seconds
    } TEST_END

    TEST(cache_hit_performance) {
        // Tables should already be cached
        auto start = std::chrono::high_resolution_clock::now();

        for (int iter = 0; iter < 1000; iter++) {
            for (uint32_t n : SUPPORTED_NTT_SIZES) {
                for (uint32_t i = 0; i < GPU_PRIME_COUNT; i++) {
                    const auto& table = manager.getStageAlignedTable(i, n, true);
                    (void)table;
                }
            }
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

        std::cout << "(" << duration.count() << "us for 32000 lookups) ";
        ASSERT_TRUE(duration.count() < 100000);  // 32000 lookups in < 100ms
    } TEST_END

    TEST(memory_usage) {
        size_t memUsage = manager.getMemoryUsage();
        std::cout << "(" << memUsage / 1024 << " KB) ";

        // Should be reasonable - rough estimate:
        // 4 sizes * 8 primes * 2 forms * (N/2 * log2(N) * 2 * 4 bytes)
        // For N=8192: ~2.5 MB for stage-aligned tables
        ASSERT_TRUE(memUsage < 50 * 1024 * 1024);  // Less than 50 MB
    } TEST_END
}

//=============================================================================
// Main
//=============================================================================

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "GPU-Native NTT Prime & Twiddle Tests" << std::endl;
    std::cout << "========================================" << std::endl;

    test_gpu_prime_set();
    test_montgomery_arithmetic();
    test_primitive_roots();
    test_twiddle_tables();
    test_gpu_format();
    test_bit_reversal();
    test_prime_utilities();
    test_performance();

    std::cout << "\n========================================" << std::endl;
    std::cout << "Results: " << tests_passed << " passed, "
              << tests_failed << " failed" << std::endl;
    std::cout << "========================================" << std::endl;

    return tests_failed > 0 ? 1 : 0;
}
