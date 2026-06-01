// Copyright (C) 2024-2025 Lux Industries Inc.
// SPDX-License-Identifier: Apache-2.0
//
// MLX GPU Backend Tests

#include <iostream>
#include <cassert>
#include <vector>
#include <random>

#ifdef WITH_MLX
#include "math/hal/mlx/fhe.h"
#include "math/hal/mlx/ntt.h"
#include <mlx/mlx.h>
namespace mx = mlx::core;
#endif

#define TEST(name) void test_##name()
#define RUN_TEST(name) do { \
    std::cout << "Running " #name "... "; \
    test_##name(); \
    std::cout << "PASSED" << std::endl; \
} while(0)

#ifdef WITH_MLX
using namespace lbcrypto::gpu;

TEST(metal_available) {
    bool available = mx::metal::is_available();
    std::cout << "(Metal: " << (available ? "yes" : "no") << ") ";
    // Don't assert - Metal may not be available on all systems
}

TEST(ntt_roundtrip) {
    const uint32_t N = 1024;
    const uint64_t Q = 268441601ULL;

    NTTEngine ntt(N, Q);

    // Create test data
    std::vector<int64_t> data(N);
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(0, Q - 1);
    for (auto& v : data) v = static_cast<int64_t>(dist(gen));

    // Keep a copy for comparison
    std::vector<int64_t> original = data;

    // Create MLX array
    mx::array poly = mx::array(data.data(), {1, static_cast<int>(N)}, mx::int64);
    mx::eval(poly);

    // Forward + inverse should return original
    ntt.forward(poly);
    ntt.inverse(poly);

    mx::eval(poly);
    auto result_ptr = poly.data<int64_t>();

    // Compare with original (allowing for modular arithmetic)
    for (uint32_t i = 0; i < N; ++i) {
        uint64_t orig = static_cast<uint64_t>(original[i]) % Q;
        uint64_t result = static_cast<uint64_t>(result_ptr[i]) % Q;
        assert(orig == result);
    }
}

TEST(ntt_batch) {
    const uint32_t N = 512;
    const uint64_t Q = 268441601ULL;
    const int batch = 10;

    NTTEngine ntt(N, Q);

    // Create batch data
    std::vector<int64_t> data(batch * N);
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(0, Q - 1);
    for (auto& v : data) v = static_cast<int64_t>(dist(gen));

    std::vector<int64_t> original = data;

    mx::array polys = mx::array(data.data(), {batch, static_cast<int>(N)}, mx::int64);
    mx::eval(polys);

    ntt.forward(polys);
    ntt.inverse(polys);

    mx::eval(polys);
    auto result_ptr = polys.data<int64_t>();

    // Verify each polynomial in batch
    for (int b = 0; b < batch; ++b) {
        for (uint32_t i = 0; i < N; ++i) {
            uint64_t orig = static_cast<uint64_t>(original[b * N + i]) % Q;
            uint64_t result = static_cast<uint64_t>(result_ptr[b * N + i]) % Q;
            assert(orig == result);
        }
    }
}

TEST(fhe_engine_init) {
    FHEConfig config;
    config.N = 1024;
    config.n = 512;
    config.L = 4;

    auto engine = createOptimizedEngine(config);
    assert(engine != nullptr);
    assert(engine->initialize());
    engine->shutdown();
}

TEST(fhe_engine_ntt) {
    FHEConfig config;
    config.N = 1024;
    config.n = 512;
    config.L = 4;

    auto engine = createOptimizedEngine(config);
    assert(engine->initialize());

    // Create test data
    std::vector<int64_t> data(config.N);
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(0, config.Q - 1);
    for (auto& v : data) v = static_cast<int64_t>(dist(gen));

    std::vector<int64_t> original = data;

    mx::array poly = mx::array(data.data(), {1, static_cast<int>(config.N)}, mx::int64);
    mx::eval(poly);

    engine->batchNTT(poly, false);  // Forward
    engine->batchNTT(poly, true);   // Inverse
    engine->sync();

    mx::eval(poly);
    auto result_ptr = poly.data<int64_t>();

    for (uint32_t i = 0; i < config.N; ++i) {
        uint64_t orig = static_cast<uint64_t>(original[i]) % config.Q;
        uint64_t result = static_cast<uint64_t>(result_ptr[i]) % config.Q;
        assert(orig == result);
    }

    engine->shutdown();
}
#endif

TEST(placeholder) {
    // Placeholder test that always passes
    assert(true);
}

int main() {
    std::cout << "=== Lux FHE MLX Backend Tests ===" << std::endl;

#ifdef WITH_MLX
    RUN_TEST(metal_available);
    RUN_TEST(ntt_roundtrip);
    RUN_TEST(ntt_batch);
    RUN_TEST(fhe_engine_init);
    RUN_TEST(fhe_engine_ntt);
#else
    std::cout << "MLX not enabled, running placeholder tests only" << std::endl;
#endif

    RUN_TEST(placeholder);

    std::cout << "\nAll tests passed!" << std::endl;
    return 0;
}
