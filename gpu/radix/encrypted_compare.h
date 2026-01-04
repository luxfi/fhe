// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024-2025, Lux Industries Inc
//
// Optimized Encrypted Comparison for Solidity/EVM
//
// Key innovation: Kogge-Stone parallel prefix comparison with GPU acceleration
// - Traditional: Serial bit-by-bit comparison O(n) depth
// - Optimized: Parallel prefix O(log n) depth with early termination hints
//
// Patent: PAT-FHE-C8 - Encrypted Comparison for Solidity
// For enterprise licensing: fhe@lux.network

#ifndef LUXFHE_ENCRYPTED_COMPARE_H
#define LUXFHE_ENCRYPTED_COMPARE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// =============================================================================
// Forward Declarations
// =============================================================================

typedef void* LuxFHEEngine;
typedef void* LuxFHECiphertext;
typedef void* LuxFHEInteger;
typedef void* LuxFHECompareContext;

// =============================================================================
// Comparison Result Types
// =============================================================================

// Comparison operations for Solidity FHE precompile
typedef enum {
    LUXFHE_CMP_LT  = 0,    // a < b
    LUXFHE_CMP_LE  = 1,    // a <= b
    LUXFHE_CMP_GT  = 2,    // a > b
    LUXFHE_CMP_GE  = 3,    // a >= b
    LUXFHE_CMP_EQ  = 4,    // a == b
    LUXFHE_CMP_NE  = 5,    // a != b
    LUXFHE_CMP_MIN = 6,    // min(a, b)
    LUXFHE_CMP_MAX = 7     // max(a, b)
} LuxFHECompareOp;

// Integer bit widths matching Solidity FHE types
typedef enum {
    LUXFHE_UINT4   = 4,
    LUXFHE_UINT8   = 8,
    LUXFHE_UINT16  = 16,
    LUXFHE_UINT32  = 32,
    LUXFHE_UINT64  = 64,
    LUXFHE_UINT128 = 128,
    LUXFHE_UINT160 = 160,   // Ethereum address
    LUXFHE_UINT256 = 256
} LuxFHEUintWidth;

// =============================================================================
// Kogge-Stone Parallel Comparison Tree
// =============================================================================

// Configuration for parallel prefix network
typedef struct {
    uint32_t num_bits;           // Total bits to compare
    uint32_t block_size;         // Bits per radix block (2 or 4)
    uint32_t num_stages;         // log2(num_bits) stages
    bool     use_gpu;            // Enable GPU acceleration
    bool     early_termination;  // Enable early termination hints
    uint32_t batch_size;         // Operations to batch for GPU
} LuxFHEKoggeStoneConfig;

// Stage data for Kogge-Stone tree
typedef struct {
    uint32_t stage;              // Current stage index
    uint32_t stride;             // Distance between compared elements
    uint32_t num_ops;            // Operations in this stage
} LuxFHEKoggeStoneStage;

// =============================================================================
// Parallel Compare Context
// =============================================================================

// Create comparison context with Kogge-Stone configuration
LuxFHECompareContext luxfhe_compare_context_create(
    LuxFHEEngine engine,
    LuxFHEKoggeStoneConfig config
);

// Free comparison context
void luxfhe_compare_context_free(LuxFHECompareContext ctx);

// Get Kogge-Stone stage info
LuxFHEKoggeStoneStage luxfhe_compare_get_stage_info(
    LuxFHECompareContext ctx,
    uint32_t stage
);

// =============================================================================
// Core Comparison Operations (Solidity FHE Interface)
// =============================================================================

// FHE.lt(euintN a, euintN b) -> ebool
// Parallel prefix less-than comparison
// Algorithm:
//   1. Compute bit differences: d[i] = a[i] XOR b[i]
//   2. Kogge-Stone parallel prefix to find MSB difference
//   3. Result = b[msb_diff_position]
LuxFHECiphertext luxfhe_lt(
    LuxFHEEngine engine,
    LuxFHECompareContext ctx,
    LuxFHEInteger a,
    LuxFHEInteger b
);

// FHE.le(euintN a, euintN b) -> ebool
LuxFHECiphertext luxfhe_le(
    LuxFHEEngine engine,
    LuxFHECompareContext ctx,
    LuxFHEInteger a,
    LuxFHEInteger b
);

// FHE.gt(euintN a, euintN b) -> ebool
LuxFHECiphertext luxfhe_gt(
    LuxFHEEngine engine,
    LuxFHECompareContext ctx,
    LuxFHEInteger a,
    LuxFHEInteger b
);

// FHE.ge(euintN a, euintN b) -> ebool
LuxFHECiphertext luxfhe_ge(
    LuxFHEEngine engine,
    LuxFHECompareContext ctx,
    LuxFHEInteger a,
    LuxFHEInteger b
);

// FHE.eq(euintN a, euintN b) -> ebool
// Parallel XOR-reduction for equality
LuxFHECiphertext luxfhe_eq(
    LuxFHEEngine engine,
    LuxFHECompareContext ctx,
    LuxFHEInteger a,
    LuxFHEInteger b
);

// FHE.ne(euintN a, euintN b) -> ebool
LuxFHECiphertext luxfhe_ne(
    LuxFHEEngine engine,
    LuxFHECompareContext ctx,
    LuxFHEInteger a,
    LuxFHEInteger b
);

// FHE.min(euintN a, euintN b) -> euintN
// Returns encrypted minimum using oblivious selection
LuxFHEInteger luxfhe_min(
    LuxFHEEngine engine,
    LuxFHECompareContext ctx,
    LuxFHEInteger a,
    LuxFHEInteger b
);

// FHE.max(euintN a, euintN b) -> euintN
LuxFHEInteger luxfhe_max(
    LuxFHEEngine engine,
    LuxFHECompareContext ctx,
    LuxFHEInteger a,
    LuxFHEInteger b
);

// =============================================================================
// Batch Comparison (GPU-Optimized)
// =============================================================================

// Batch comparison for multiple pairs
// Enables GPU kernel saturation for high throughput
typedef struct {
    LuxFHEInteger* a_values;     // Array of first operands
    LuxFHEInteger* b_values;     // Array of second operands
    uint32_t       count;        // Number of comparisons
    LuxFHECompareOp op;          // Comparison operation
} LuxFHECompareBatch;

// Execute batch comparison
// Returns array of results (ebool for lt/le/gt/ge/eq/ne, euint for min/max)
void* luxfhe_compare_batch(
    LuxFHEEngine engine,
    LuxFHECompareContext ctx,
    LuxFHECompareBatch* batch
);

// Free batch results
void luxfhe_compare_batch_free(void* results, uint32_t count, LuxFHECompareOp op);

// =============================================================================
// Scalar Comparison (Plaintext Operand)
// =============================================================================

// FHE.lt(euintN a, uintN b) -> ebool (plaintext right operand)
// Optimization: precompute b's bit representation
LuxFHECiphertext luxfhe_lt_scalar(
    LuxFHEEngine engine,
    LuxFHECompareContext ctx,
    LuxFHEInteger a,
    const uint8_t* b_bytes,
    uint32_t b_len
);

// FHE.eq(euintN a, uintN b) -> ebool (plaintext right operand)
LuxFHECiphertext luxfhe_eq_scalar(
    LuxFHEEngine engine,
    LuxFHECompareContext ctx,
    LuxFHEInteger a,
    const uint8_t* b_bytes,
    uint32_t b_len
);

// =============================================================================
// GPU Kernel Interface (Metal/CUDA)
// =============================================================================

#ifdef LUXFHE_GPU_ENABLED

// Kogge-Stone parallel prefix kernel configuration
typedef struct {
    uint32_t workgroup_size;     // Threads per workgroup
    uint32_t num_workgroups;     // Total workgroups
    uint32_t shared_mem_bytes;   // Shared memory per workgroup
} LuxFHEGPUKernelConfig;

// Get optimal kernel config for hardware
LuxFHEGPUKernelConfig luxfhe_compare_get_kernel_config(
    LuxFHEEngine engine,
    uint32_t num_bits,
    uint32_t batch_size
);

// Launch Kogge-Stone parallel prefix kernel
// Computes (G, P) pairs: Generate and Propagate signals for comparison
// G[i] = a[i] > b[i], P[i] = a[i] == b[i]
int luxfhe_gpu_kogge_stone_prefix(
    LuxFHEEngine engine,
    LuxFHECompareContext ctx,
    LuxFHEGPUKernelConfig* config,
    LuxFHEInteger* a_batch,
    LuxFHEInteger* b_batch,
    uint32_t batch_size,
    LuxFHECiphertext* results
);

// Early termination hint computation
// Returns encrypted hint indicating MSB difference position
LuxFHECiphertext luxfhe_gpu_early_term_hint(
    LuxFHEEngine engine,
    LuxFHECompareContext ctx,
    LuxFHEInteger a,
    LuxFHEInteger b
);

#endif // LUXFHE_GPU_ENABLED

// =============================================================================
// Statistics and Profiling
// =============================================================================

typedef struct {
    uint64_t total_comparisons;       // Total comparison operations
    uint64_t gpu_kernel_launches;     // GPU kernel invocations
    uint64_t early_terminations;      // Early termination opportunities
    double   avg_depth_reduction;     // Average depth reduction vs serial
    double   avg_latency_us;          // Average latency in microseconds
    double   throughput_ops_sec;      // Operations per second
} LuxFHECompareStats;

// Get comparison statistics
LuxFHECompareStats luxfhe_compare_get_stats(LuxFHECompareContext ctx);

// Reset statistics
void luxfhe_compare_reset_stats(LuxFHECompareContext ctx);

// =============================================================================
// Solidity Interface Specification
// =============================================================================

/*
 * Solidity FHE Precompile Interface for Comparison Operations
 *
 * Address: 0x0100 (FHE Precompile Base)
 *
 * Function Selectors:
 *   lt(bytes32 a, bytes32 b)  -> 0x1234...  // Returns encrypted bool
 *   le(bytes32 a, bytes32 b)  -> 0x2345...
 *   gt(bytes32 a, bytes32 b)  -> 0x3456...
 *   ge(bytes32 a, bytes32 b)  -> 0x4567...
 *   eq(bytes32 a, bytes32 b)  -> 0x5678...
 *   ne(bytes32 a, bytes32 b)  -> 0x6789...
 *   min(bytes32 a, bytes32 b) -> 0x789a...  // Returns encrypted uint
 *   max(bytes32 a, bytes32 b) -> 0x89ab...
 *
 * Input Format:
 *   - bytes32 handle: Ciphertext handle in global ciphertext store
 *   - Type info encoded in handle's upper bits
 *
 * Gas Costs (approximate):
 *   - lt/gt/le/ge: 50000 + 500 * log2(bit_width) gas
 *   - eq/ne: 30000 + 300 * log2(bit_width) gas
 *   - min/max: 80000 + 800 * log2(bit_width) gas
 *
 * Example Solidity Usage:
 *
 *   import "fhe/FHE.sol";
 *
 *   contract Auction {
 *       euint256 highestBid;
 *       eaddress highestBidder;
 *
 *       function bid(einput encryptedBid, bytes calldata proof) external {
 *           euint256 bidAmount = FHE.asEuint256(encryptedBid, proof);
 *
 *           // Encrypted comparison: is new bid higher?
 *           ebool isHigher = FHE.gt(bidAmount, highestBid);
 *
 *           // Oblivious selection: update if higher
 *           highestBid = FHE.select(isHigher, bidAmount, highestBid);
 *           highestBidder = FHE.select(isHigher,
 *               FHE.asEaddress(msg.sender),
 *               highestBidder);
 *       }
 *   }
 */

#ifdef __cplusplus
}
#endif

// =============================================================================
// C++ API (when compiled as C++)
// =============================================================================

#ifdef __cplusplus

#include <vector>
#include <memory>
#include <functional>

namespace luxfhe {
namespace compare {

// Encrypted bit type (forward declaration)
class EncryptedBit;
class EncryptedInteger;

// =============================================================================
// Kogge-Stone Parallel Prefix Tree
// =============================================================================

// Generate-Propagate pair for comparison
// G = a > b (generate: this position determines result)
// P = a == b (propagate: defer to higher position)
struct GPPair {
    std::shared_ptr<EncryptedBit> G;  // Generate signal
    std::shared_ptr<EncryptedBit> P;  // Propagate signal
};

// Kogge-Stone operator: combines two GP pairs
// (G1, P1) o (G0, P0) = (G1 OR (P1 AND G0), P1 AND P0)
class KoggeStoneOp {
public:
    virtual ~KoggeStoneOp() = default;

    // Combine two GP pairs homomorphically
    virtual GPPair combine(const GPPair& high, const GPPair& low) = 0;
};

// =============================================================================
// ParallelCompare Class
// =============================================================================

class ParallelCompare {
public:
    // Configuration
    struct Config {
        uint32_t num_bits = 256;
        uint32_t block_size = 4;
        bool use_gpu = true;
        bool early_termination = true;
        uint32_t batch_size = 1024;
    };

    // Constructor
    explicit ParallelCompare(Config config);
    ~ParallelCompare();

    // Disable copy, enable move
    ParallelCompare(const ParallelCompare&) = delete;
    ParallelCompare& operator=(const ParallelCompare&) = delete;
    ParallelCompare(ParallelCompare&&) noexcept;
    ParallelCompare& operator=(ParallelCompare&&) noexcept;

    // =========================================================================
    // Core Comparison (Kogge-Stone Algorithm)
    // =========================================================================

    // Less-than comparison using parallel prefix
    // Depth: O(log n) vs O(n) for serial
    std::shared_ptr<EncryptedBit> lessThan(
        const EncryptedInteger& a,
        const EncryptedInteger& b
    );

    // Equality using parallel XOR-reduction
    std::shared_ptr<EncryptedBit> equal(
        const EncryptedInteger& a,
        const EncryptedInteger& b
    );

    // =========================================================================
    // Derived Operations
    // =========================================================================

    std::shared_ptr<EncryptedBit> lessEqual(
        const EncryptedInteger& a,
        const EncryptedInteger& b
    );

    std::shared_ptr<EncryptedBit> greaterThan(
        const EncryptedInteger& a,
        const EncryptedInteger& b
    );

    std::shared_ptr<EncryptedBit> greaterEqual(
        const EncryptedInteger& a,
        const EncryptedInteger& b
    );

    std::shared_ptr<EncryptedBit> notEqual(
        const EncryptedInteger& a,
        const EncryptedInteger& b
    );

    // =========================================================================
    // Selection Operations
    // =========================================================================

    // Oblivious minimum: returns a if a < b, else b
    std::shared_ptr<EncryptedInteger> min(
        const EncryptedInteger& a,
        const EncryptedInteger& b
    );

    // Oblivious maximum
    std::shared_ptr<EncryptedInteger> max(
        const EncryptedInteger& a,
        const EncryptedInteger& b
    );

    // Oblivious selection: returns a if cond is true, else b
    std::shared_ptr<EncryptedInteger> select(
        const EncryptedBit& cond,
        const EncryptedInteger& a,
        const EncryptedInteger& b
    );

    // =========================================================================
    // Batch Operations (GPU-Optimized)
    // =========================================================================

    std::vector<std::shared_ptr<EncryptedBit>> batchLessThan(
        const std::vector<EncryptedInteger>& a_vec,
        const std::vector<EncryptedInteger>& b_vec
    );

    std::vector<std::shared_ptr<EncryptedBit>> batchEqual(
        const std::vector<EncryptedInteger>& a_vec,
        const std::vector<EncryptedInteger>& b_vec
    );

    // =========================================================================
    // Scalar Comparisons (Optimized)
    // =========================================================================

    std::shared_ptr<EncryptedBit> lessThanScalar(
        const EncryptedInteger& a,
        const std::vector<uint8_t>& b_plaintext
    );

    std::shared_ptr<EncryptedBit> equalScalar(
        const EncryptedInteger& a,
        const std::vector<uint8_t>& b_plaintext
    );

private:
    class Impl;
    std::unique_ptr<Impl> impl_;

    // Kogge-Stone tree building
    std::vector<GPPair> buildGPPairs(
        const EncryptedInteger& a,
        const EncryptedInteger& b
    );

    // Parallel prefix computation
    GPPair parallelPrefix(const std::vector<GPPair>& gp_pairs);

    // GPU kernel dispatch
    void dispatchGPUKernel(
        const std::vector<GPPair>& gp_pairs,
        uint32_t stage,
        uint32_t stride
    );
};

// =============================================================================
// GPU Kernel Launcher
// =============================================================================

class GPUCompareKernel {
public:
    struct LaunchParams {
        uint32_t workgroup_size = 256;
        uint32_t num_workgroups = 0;  // 0 = auto
        size_t shared_mem_bytes = 0;
    };

    virtual ~GPUCompareKernel() = default;

    // Launch Kogge-Stone stage kernel
    // Each stage computes GP pairs with distance 2^stage
    virtual void launchKoggeStoneStage(
        const LaunchParams& params,
        std::vector<GPPair>& gp_pairs,
        uint32_t stage
    ) = 0;

    // Launch XOR-reduction kernel for equality
    virtual void launchXorReduction(
        const LaunchParams& params,
        std::vector<std::shared_ptr<EncryptedBit>>& xor_bits
    ) = 0;

    // Launch oblivious selection kernel
    virtual void launchSelect(
        const LaunchParams& params,
        const EncryptedBit& cond,
        const EncryptedInteger& a,
        const EncryptedInteger& b,
        EncryptedInteger& result
    ) = 0;
};

// Factory for platform-specific kernel
std::unique_ptr<GPUCompareKernel> createGPUCompareKernel();

} // namespace compare
} // namespace luxfhe

#endif // __cplusplus

#endif // LUXFHE_ENCRYPTED_COMPARE_H
