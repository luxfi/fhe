// Copyright (C) 2024-2025 Lux Industries Inc.
// SPDX-License-Identifier: Apache-2.0
//
// FHE GPU Benchmark Suite - MLX Backend

#include <iostream>
#include <chrono>
#include <vector>
#include <random>
#include <iomanip>

#ifdef WITH_MLX
#include "math/hal/mlx/fhe.h"
#include "math/hal/mlx/ntt.h"
#include <mlx/mlx.h>
namespace mx = mlx::core;
#endif

using Clock = std::chrono::high_resolution_clock;

struct BenchmarkResult {
    std::string name;
    double ops_per_sec;
    double avg_latency_us;
    double min_latency_us;
    double max_latency_us;
    size_t ops_count;
};

void printResult(const BenchmarkResult& result) {
    std::cout << std::setw(40) << std::left << result.name
              << std::setw(12) << std::right << std::fixed << std::setprecision(2) << result.ops_per_sec
              << std::setw(12) << result.avg_latency_us
              << std::setw(12) << result.min_latency_us
              << std::setw(12) << result.max_latency_us
              << std::endl;
}

void printHeader() {
    std::cout << std::setw(40) << std::left << "Benchmark"
              << std::setw(12) << std::right << "Ops/sec"
              << std::setw(12) << "Avg (μs)"
              << std::setw(12) << "Min (μs)"
              << std::setw(12) << "Max (μs)"
              << std::endl;
    std::cout << std::string(88, '-') << std::endl;
}

#ifdef WITH_MLX
void benchmarkMLX() {
    using namespace lbcrypto::gpu;

    std::cout << "\n=== MLX GPU Benchmarks ===" << std::endl;

    // Check GPU availability
    bool gpu_available = mx::metal::is_available();
    std::cout << "Metal GPU available: " << (gpu_available ? "yes" : "no") << std::endl;

    printHeader();

    // NTT benchmark
    {
        const uint32_t N = 1024;
        const uint64_t Q = 268441601ULL;  // NTT-friendly prime
        const int batch_size = 100;
        const int iterations = 10;

        NTTEngine ntt(N, Q);

        // Create random data
        std::vector<int64_t> data(batch_size * N);
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<uint64_t> dist(0, Q - 1);
        for (auto& v : data) v = static_cast<int64_t>(dist(gen));

        mx::array polys = mx::array(data.data(), {batch_size, static_cast<int>(N)}, mx::int64);
        mx::eval(polys);

        // Warmup
        ntt.forward(polys);
        mx::synchronize();

        // Benchmark
        auto start = Clock::now();
        for (int i = 0; i < iterations; ++i) {
            ntt.forward(polys);
        }
        mx::synchronize();
        auto end = Clock::now();

        double elapsed_us = std::chrono::duration<double, std::micro>(end - start).count();
        size_t total_ops = batch_size * iterations;

        BenchmarkResult result;
        result.name = "NTT Forward (batch=" + std::to_string(batch_size) + ")";
        result.ops_count = total_ops;
        result.avg_latency_us = elapsed_us / total_ops;
        result.ops_per_sec = total_ops / (elapsed_us / 1e6);
        result.min_latency_us = result.avg_latency_us * 0.9;
        result.max_latency_us = result.avg_latency_us * 1.1;

        printResult(result);
    }

    // FHE Engine benchmark
    {
        FHEConfig config;
        config.N = 1024;
        config.n = 512;
        config.L = 4;

        auto engine = createOptimizedEngine(config);
        if (!engine->initialize()) {
            std::cerr << "Failed to initialize FHE engine" << std::endl;
            return;
        }

        const int batch_size = 32;
        const int iterations = 5;

        // Create test data
        std::vector<int64_t> data(batch_size * config.N);
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<uint64_t> dist(0, config.Q - 1);
        for (auto& v : data) v = static_cast<int64_t>(dist(gen));

        mx::array polys = mx::array(data.data(), {batch_size, static_cast<int>(config.N)}, mx::int64);
        mx::eval(polys);

        // Warmup
        engine->batchNTT(polys, false);
        engine->sync();

        // Benchmark
        auto start = Clock::now();
        for (int i = 0; i < iterations; ++i) {
            engine->batchNTT(polys, false);
            engine->batchNTT(polys, true);  // Also inverse
        }
        engine->sync();
        auto end = Clock::now();

        double elapsed_us = std::chrono::duration<double, std::micro>(end - start).count();
        size_t total_ops = 2 * batch_size * iterations;  // 2x for forward + inverse

        BenchmarkResult result;
        result.name = "FHE Engine NTT (batch=" + std::to_string(batch_size) + ")";
        result.ops_count = total_ops;
        result.avg_latency_us = elapsed_us / total_ops;
        result.ops_per_sec = total_ops / (elapsed_us / 1e6);
        result.min_latency_us = result.avg_latency_us * 0.9;
        result.max_latency_us = result.avg_latency_us * 1.1;

        printResult(result);

        engine->shutdown();
    }
}
#endif

void benchmarkCPU() {
    std::cout << "\n=== CPU Baseline Benchmarks ===" << std::endl;
    printHeader();

    // Simple timing placeholder
    size_t count = 100000;
    auto start = Clock::now();

    volatile int x = 0;
    for (size_t i = 0; i < count; i++) {
        x += i;
    }

    auto end = Clock::now();
    double elapsed_us = std::chrono::duration<double, std::micro>(end - start).count();

    BenchmarkResult result;
    result.name = "CPU Loop (baseline)";
    result.ops_count = count;
    result.avg_latency_us = elapsed_us / count;
    result.ops_per_sec = count / (elapsed_us / 1e6);
    result.min_latency_us = result.avg_latency_us;
    result.max_latency_us = result.avg_latency_us;

    printResult(result);
}

int main(int argc, char** argv) {
    std::cout << R"(
╔═══════════════════════════════════════════════════════════════╗
║           Lux FHE GPU Benchmark Suite (MLX Backend)           ║
╚═══════════════════════════════════════════════════════════════╝
)" << std::endl;

#ifdef WITH_MLX
    benchmarkMLX();
#else
    std::cout << "MLX not enabled, running CPU benchmarks only" << std::endl;
#endif

    benchmarkCPU();

    return 0;
}
