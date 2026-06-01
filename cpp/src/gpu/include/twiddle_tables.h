// Copyright (C) 2024-2025 Lux Industries Inc.
// SPDX-License-Identifier: Apache-2.0
//
// GPU-Optimized Twiddle Factor Tables for NTT
//
// Design rationale:
// - Stage-aligned layout for coalesced GPU memory access
// - Bit-reversed order for decimation-in-time (DIT) NTT
// - Montgomery form twiddles for efficient modular multiplication
// - Precomputed for common sizes: N=1024, 2048, 4096, 8192
//
// Memory layout:
// - Traditional: twiddles[i] for butterfly at position i
// - Stage-aligned: twiddles[stage][group][element] for coalesced access
//
// Patent: PAT-FHE-TWIDDLE - Stage-Aligned Twiddle Factor Layout for GPU NTT

#ifndef LUX_FHE_TWIDDLE_TABLES_H
#define LUX_FHE_TWIDDLE_TABLES_H

#include "gpu_primes.h"
#include <cstdint>
#include <array>
#include <vector>
#include <memory>
#include <span>

namespace lux::fhe::gpu {

//=============================================================================
// Constants
//=============================================================================

// Supported NTT sizes
constexpr uint32_t NTT_SIZE_1024 = 1024;
constexpr uint32_t NTT_SIZE_2048 = 2048;
constexpr uint32_t NTT_SIZE_4096 = 4096;
constexpr uint32_t NTT_SIZE_8192 = 8192;

// Number of supported NTT sizes
constexpr size_t NTT_SIZE_COUNT = 4;

// Array of supported sizes for iteration
constexpr std::array<uint32_t, NTT_SIZE_COUNT> SUPPORTED_NTT_SIZES = {
    NTT_SIZE_1024, NTT_SIZE_2048, NTT_SIZE_4096, NTT_SIZE_8192
};

//=============================================================================
// Twiddle Layout Enum
//=============================================================================

enum class TwiddleLayout {
    // Traditional sequential layout: w^0, w^1, w^2, ..., w^(N/2-1)
    SEQUENTIAL,

    // Bit-reversed for decimation-in-time NTT
    BIT_REVERSED,

    // Stage-aligned for GPU coalesced access:
    // Stage s has N/(2^(s+1)) groups, each with 2^s elements
    STAGE_ALIGNED
};

//=============================================================================
// TwiddleTable Structure
//
// Holds twiddle factors for one prime and one NTT size.
//=============================================================================

struct TwiddleTable {
    uint32_t prime;           // The prime modulus
    uint32_t ntt_size;        // NTT size (N)
    TwiddleLayout layout;     // Memory layout
    bool montgomery_form;     // True if values are in Montgomery form

    // Forward NTT twiddles: w^(bit_rev(i)) for DIT
    std::vector<uint32_t> forward;

    // Inverse NTT twiddles: w^(-bit_rev(i)) for DIT inverse
    std::vector<uint32_t> inverse;

    // Precomputed N^(-1) mod p for final scaling in inverse NTT
    uint32_t n_inv;

    // Precomputed N^(-1) in Montgomery form
    uint32_t n_inv_mont;
};

//=============================================================================
// StageAlignedTwiddles Structure
//
// Stage-aligned layout optimized for GPU butterfly operations.
// Each stage s (0 to log2(N)-1) has twiddles arranged for coalesced access.
//=============================================================================

struct StageAlignedTwiddles {
    uint32_t prime;
    uint32_t ntt_size;
    uint32_t num_stages;      // log2(ntt_size)
    bool montgomery_form;

    // Stage-indexed twiddle factors
    // stage_twiddles[s] contains twiddles for stage s
    // Within each stage: twiddles for butterfly groups are contiguous
    std::vector<std::vector<uint32_t>> stage_forward;
    std::vector<std::vector<uint32_t>> stage_inverse;

    // N^(-1) for inverse NTT scaling
    uint32_t n_inv;
    uint32_t n_inv_mont;

    // Get twiddles for a specific stage
    const std::vector<uint32_t>& getStageForward(uint32_t stage) const {
        return stage_forward[stage];
    }

    const std::vector<uint32_t>& getStageInverse(uint32_t stage) const {
        return stage_inverse[stage];
    }
};

//=============================================================================
// TwiddleTableManager Class
//
// Manages precomputed twiddle tables for all primes and NTT sizes.
// Singleton pattern with lazy initialization.
//=============================================================================

class TwiddleTableManager {
public:
    // Get singleton instance
    static TwiddleTableManager& instance();

    // Get or create twiddle table for sequential/bit-reversed layout
    const TwiddleTable& getTable(
        uint32_t primeIndex,
        uint32_t nttSize,
        TwiddleLayout layout = TwiddleLayout::BIT_REVERSED,
        bool montgomeryForm = true
    );

    // Get or create stage-aligned twiddles (preferred for GPU)
    const StageAlignedTwiddles& getStageAlignedTable(
        uint32_t primeIndex,
        uint32_t nttSize,
        bool montgomeryForm = true
    );

    // Precompute all tables for a given NTT size
    void precomputeForSize(uint32_t nttSize);

    // Precompute all tables for all sizes
    void precomputeAll();

    // Clear cached tables (for memory reclamation)
    void clearCache();

    // Get memory usage estimate in bytes
    size_t getMemoryUsage() const;

    // Check if a size is supported
    static bool isSupportedSize(uint32_t nttSize);

    // Get log2 of NTT size
    static uint32_t log2Size(uint32_t nttSize);

    // Bit reversal utilities (public for use by utility functions)
    static uint32_t bitReverse(uint32_t x, uint32_t bits);
    static void generateBitReversalTable(uint32_t n, std::vector<uint32_t>& table);

private:
    TwiddleTableManager();
    ~TwiddleTableManager() = default;

    // Disable copy/move
    TwiddleTableManager(const TwiddleTableManager&) = delete;
    TwiddleTableManager& operator=(const TwiddleTableManager&) = delete;

    // Internal table generation
    TwiddleTable generateTable(
        uint32_t primeIndex,
        uint32_t nttSize,
        TwiddleLayout layout,
        bool montgomeryForm
    );

    StageAlignedTwiddles generateStageAlignedTable(
        uint32_t primeIndex,
        uint32_t nttSize,
        bool montgomeryForm
    );

    // Cache storage
    // Key: (primeIndex << 16) | (sizeIndex << 2) | (layout << 1) | montgomeryForm
    std::vector<std::unique_ptr<TwiddleTable>> m_tables;
    std::vector<std::unique_ptr<StageAlignedTwiddles>> m_stageAlignedTables;

    // Fast lookup using flat index
    size_t computeTableIndex(uint32_t primeIndex, uint32_t nttSize,
                            TwiddleLayout layout, bool montgomeryForm) const;
    size_t computeStageAlignedIndex(uint32_t primeIndex, uint32_t nttSize,
                                    bool montgomeryForm) const;
};

//=============================================================================
// GPU-Ready Twiddle Data Structures
//
// These structures are designed for direct upload to GPU memory.
//=============================================================================

// Compact twiddle data for GPU upload
struct GPUTwiddleData {
    uint32_t prime;
    uint32_t ntt_size;
    uint32_t num_stages;
    uint32_t flags;           // Bit 0: montgomery_form

    // Flat array of all stage twiddles concatenated
    // Stage offsets: stage_offset[s] = sum of stage sizes for stages < s
    std::vector<uint32_t> forward_flat;
    std::vector<uint32_t> inverse_flat;

    // Stage offsets for indexing
    std::vector<uint32_t> stage_offsets;

    // N^(-1) values
    uint32_t n_inv;
    uint32_t n_inv_mont;
};

// Convert StageAlignedTwiddles to GPU-ready format
GPUTwiddleData toGPUFormat(const StageAlignedTwiddles& table);

//=============================================================================
// Utility Functions
//=============================================================================

// Generate bit-reversal permutation for NTT
void generateBitReversalPermutation(uint32_t n, std::vector<uint32_t>& perm);

// Apply bit-reversal permutation to data in-place
template<typename T>
void applyBitReversalInPlace(std::vector<T>& data, const std::vector<uint32_t>& perm) {
    size_t n = data.size();
    for (size_t i = 0; i < n; i++) {
        if (perm[i] > i) {
            std::swap(data[i], data[perm[i]]);
        }
    }
}

// Compute twiddle factor: w = root^exp mod prime
uint32_t computeTwiddle(uint32_t root, uint32_t exp, uint32_t prime);

// Compute twiddle in Montgomery form
uint32_t computeTwiddleMontgomery(
    uint32_t root,
    uint32_t exp,
    const MontgomeryParams& params
);

//=============================================================================
// Inline Twiddle Access for GPU Kernels
//=============================================================================

// Get twiddle index for DIT butterfly at stage s, group g, position p
inline uint32_t ditTwiddleIndex(uint32_t stage, uint32_t group, uint32_t pos,
                                uint32_t /*nttSize*/) {
    // For DIT NTT, twiddle index = group * stride + pos
    // where stride = 2^stage
    return (group << stage) + pos;
}

// Get twiddle for stage-aligned layout
inline uint32_t stageAlignedTwiddleOffset(uint32_t stage, uint32_t butterfly,
                                          uint32_t numButterflies) {
    // Linear offset within the stage
    return butterfly;
    (void)stage;
    (void)numButterflies;
}

} // namespace lux::fhe::gpu

#endif // LUX_FHE_TWIDDLE_TABLES_H
