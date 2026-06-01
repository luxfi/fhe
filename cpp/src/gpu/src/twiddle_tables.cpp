// Copyright (C) 2024-2025 Lux Industries Inc.
// SPDX-License-Identifier: Apache-2.0
//
// GPU-Optimized Twiddle Factor Tables Implementation
// See twiddle_tables.h for design rationale.

#include "twiddle_tables.h"
#include <stdexcept>
#include <cmath>
#include <cassert>

namespace lux::fhe::gpu {

//=============================================================================
// Static Helper Functions
//=============================================================================

// Modular exponentiation for twiddle computation
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

// Modular inverse using Fermat's little theorem (for prime modulus)
static uint32_t modInverse(uint32_t a, uint32_t p) {
    return modPow(a, p - 2, p);
}

//=============================================================================
// TwiddleTableManager Implementation
//=============================================================================

TwiddleTableManager& TwiddleTableManager::instance() {
    static TwiddleTableManager instance;
    return instance;
}

TwiddleTableManager::TwiddleTableManager() {
    // Reserve space for all possible tables
    // Index = primeIndex * (NTT_SIZE_COUNT * 4) + sizeIndex * 4 + layout * 2 + montgomeryForm
    size_t maxTables = GPU_PRIME_COUNT * NTT_SIZE_COUNT * 4;
    m_tables.resize(maxTables);

    // Stage-aligned tables: primeIndex * (NTT_SIZE_COUNT * 2) + sizeIndex * 2 + montgomeryForm
    size_t maxStageAligned = GPU_PRIME_COUNT * NTT_SIZE_COUNT * 2;
    m_stageAlignedTables.resize(maxStageAligned);
}

bool TwiddleTableManager::isSupportedSize(uint32_t nttSize) {
    for (uint32_t size : SUPPORTED_NTT_SIZES) {
        if (size == nttSize) return true;
    }
    return false;
}

uint32_t TwiddleTableManager::log2Size(uint32_t nttSize) {
    uint32_t log2n = 0;
    uint32_t n = nttSize;
    while (n > 1) {
        n >>= 1;
        log2n++;
    }
    return log2n;
}

uint32_t TwiddleTableManager::bitReverse(uint32_t x, uint32_t bits) {
    uint32_t result = 0;
    for (uint32_t i = 0; i < bits; i++) {
        result = (result << 1) | (x & 1);
        x >>= 1;
    }
    return result;
}

void TwiddleTableManager::generateBitReversalTable(uint32_t n, std::vector<uint32_t>& table) {
    uint32_t bits = log2Size(n);
    table.resize(n);
    for (uint32_t i = 0; i < n; i++) {
        table[i] = bitReverse(i, bits);
    }
}

size_t TwiddleTableManager::computeTableIndex(uint32_t primeIndex, uint32_t nttSize,
                                              TwiddleLayout layout, bool montgomeryForm) const {
    // Find size index
    size_t sizeIndex = 0;
    for (size_t i = 0; i < NTT_SIZE_COUNT; i++) {
        if (SUPPORTED_NTT_SIZES[i] == nttSize) {
            sizeIndex = i;
            break;
        }
    }

    return primeIndex * (NTT_SIZE_COUNT * 4) +
           sizeIndex * 4 +
           static_cast<size_t>(layout) * 2 +
           (montgomeryForm ? 1 : 0);
}

size_t TwiddleTableManager::computeStageAlignedIndex(uint32_t primeIndex, uint32_t nttSize,
                                                     bool montgomeryForm) const {
    size_t sizeIndex = 0;
    for (size_t i = 0; i < NTT_SIZE_COUNT; i++) {
        if (SUPPORTED_NTT_SIZES[i] == nttSize) {
            sizeIndex = i;
            break;
        }
    }

    return primeIndex * (NTT_SIZE_COUNT * 2) +
           sizeIndex * 2 +
           (montgomeryForm ? 1 : 0);
}

const TwiddleTable& TwiddleTableManager::getTable(
    uint32_t primeIndex, uint32_t nttSize,
    TwiddleLayout layout, bool montgomeryForm) {

    if (primeIndex >= GPU_PRIME_COUNT) {
        throw std::out_of_range("Prime index out of range");
    }
    if (!isSupportedSize(nttSize)) {
        throw std::invalid_argument("Unsupported NTT size");
    }

    size_t index = computeTableIndex(primeIndex, nttSize, layout, montgomeryForm);

    if (!m_tables[index]) {
        m_tables[index] = std::make_unique<TwiddleTable>(
            generateTable(primeIndex, nttSize, layout, montgomeryForm)
        );
    }

    return *m_tables[index];
}

const StageAlignedTwiddles& TwiddleTableManager::getStageAlignedTable(
    uint32_t primeIndex, uint32_t nttSize, bool montgomeryForm) {

    if (primeIndex >= GPU_PRIME_COUNT) {
        throw std::out_of_range("Prime index out of range");
    }
    if (!isSupportedSize(nttSize)) {
        throw std::invalid_argument("Unsupported NTT size");
    }

    size_t index = computeStageAlignedIndex(primeIndex, nttSize, montgomeryForm);

    if (!m_stageAlignedTables[index]) {
        m_stageAlignedTables[index] = std::make_unique<StageAlignedTwiddles>(
            generateStageAlignedTable(primeIndex, nttSize, montgomeryForm)
        );
    }

    return *m_stageAlignedTables[index];
}

TwiddleTable TwiddleTableManager::generateTable(
    uint32_t primeIndex, uint32_t nttSize,
    TwiddleLayout layout, bool montgomeryForm) {

    const GPUPrimeSet& primeSet = GPUPrimeSet::instance();
    const MontgomeryParams& params = primeSet.getMontgomeryParams(primeIndex);
    uint32_t p = params.prime;

    TwiddleTable table;
    table.prime = p;
    table.ntt_size = nttSize;
    table.layout = layout;
    table.montgomery_form = montgomeryForm;

    // Get primitive N-th root of unity
    uint32_t root = primeSet.getPrimitiveRoot(primeIndex, nttSize);
    uint32_t rootInv = primeSet.getPrimitiveRootInverse(primeIndex, nttSize);

    // Compute N^(-1) mod p
    table.n_inv = modInverse(nttSize, p);
    table.n_inv_mont = montgomeryForm ?
        GPUPrimeSet::toMontgomery(table.n_inv, params) : table.n_inv;

    // Generate twiddles based on layout
    uint32_t halfN = nttSize / 2;
    table.forward.resize(halfN);
    table.inverse.resize(halfN);

    if (layout == TwiddleLayout::SEQUENTIAL) {
        // Sequential: w^0, w^1, ..., w^(N/2-1)
        uint32_t w = 1;
        uint32_t wInv = 1;
        for (uint32_t i = 0; i < halfN; i++) {
            table.forward[i] = montgomeryForm ?
                GPUPrimeSet::toMontgomery(w, params) : w;
            table.inverse[i] = montgomeryForm ?
                GPUPrimeSet::toMontgomery(wInv, params) : wInv;

            w = static_cast<uint32_t>((static_cast<uint64_t>(w) * root) % p);
            wInv = static_cast<uint32_t>((static_cast<uint64_t>(wInv) * rootInv) % p);
        }
    }
    else if (layout == TwiddleLayout::BIT_REVERSED) {
        // Bit-reversed order for DIT NTT
        uint32_t bits = log2Size(halfN);

        for (uint32_t i = 0; i < halfN; i++) {
            uint32_t revI = bitReverse(i, bits);
            uint32_t w = modPow(root, revI, p);
            uint32_t wInv = modPow(rootInv, revI, p);

            table.forward[i] = montgomeryForm ?
                GPUPrimeSet::toMontgomery(w, params) : w;
            table.inverse[i] = montgomeryForm ?
                GPUPrimeSet::toMontgomery(wInv, params) : wInv;
        }
    }
    else {
        // STAGE_ALIGNED - use the dedicated function
        throw std::invalid_argument("Use getStageAlignedTable for STAGE_ALIGNED layout");
    }

    return table;
}

StageAlignedTwiddles TwiddleTableManager::generateStageAlignedTable(
    uint32_t primeIndex, uint32_t nttSize, bool montgomeryForm) {

    const GPUPrimeSet& primeSet = GPUPrimeSet::instance();
    const MontgomeryParams& params = primeSet.getMontgomeryParams(primeIndex);
    uint32_t p = params.prime;

    StageAlignedTwiddles table;
    table.prime = p;
    table.ntt_size = nttSize;
    table.num_stages = log2Size(nttSize);
    table.montgomery_form = montgomeryForm;

    // Get primitive N-th root of unity
    uint32_t root = primeSet.getPrimitiveRoot(primeIndex, nttSize);
    uint32_t rootInv = primeSet.getPrimitiveRootInverse(primeIndex, nttSize);

    // Compute N^(-1) mod p
    table.n_inv = modInverse(nttSize, p);
    table.n_inv_mont = montgomeryForm ?
        GPUPrimeSet::toMontgomery(table.n_inv, params) : table.n_inv;

    // Initialize stage vectors
    table.stage_forward.resize(table.num_stages);
    table.stage_inverse.resize(table.num_stages);

    // Generate twiddles for each stage
    // For DIT NTT, stage s has N/2^(s+1) groups of 2^s butterflies
    // Twiddle for stage s, butterfly b: w^(b * N / 2^(s+1))

    for (uint32_t stage = 0; stage < table.num_stages; stage++) {
        uint32_t groupSize = 1u << stage;           // 2^s butterflies per group
        uint32_t numGroups = nttSize >> (stage + 1); // N / 2^(s+1) groups
        uint32_t twiddleCount = nttSize >> 1;       // Total butterflies = N/2

        table.stage_forward[stage].resize(twiddleCount);
        table.stage_inverse[stage].resize(twiddleCount);

        // Stride for twiddle exponent calculation
        uint32_t stride = nttSize >> (stage + 1);

        uint32_t idx = 0;
        for (uint32_t group = 0; group < numGroups; group++) {
            for (uint32_t bf = 0; bf < groupSize; bf++) {
                // Twiddle exponent = bf * stride
                uint32_t exp = bf * stride;

                uint32_t w = modPow(root, exp, p);
                uint32_t wInv = modPow(rootInv, exp, p);

                table.stage_forward[stage][idx] = montgomeryForm ?
                    GPUPrimeSet::toMontgomery(w, params) : w;
                table.stage_inverse[stage][idx] = montgomeryForm ?
                    GPUPrimeSet::toMontgomery(wInv, params) : wInv;

                idx++;
            }
        }
    }

    return table;
}

void TwiddleTableManager::precomputeForSize(uint32_t nttSize) {
    if (!isSupportedSize(nttSize)) {
        throw std::invalid_argument("Unsupported NTT size");
    }

    // Precompute stage-aligned tables (preferred for GPU) for all primes
    for (uint32_t primeIndex = 0; primeIndex < GPU_PRIME_COUNT; primeIndex++) {
        getStageAlignedTable(primeIndex, nttSize, true);  // Montgomery form
        getStageAlignedTable(primeIndex, nttSize, false); // Standard form
    }
}

void TwiddleTableManager::precomputeAll() {
    for (uint32_t size : SUPPORTED_NTT_SIZES) {
        precomputeForSize(size);
    }
}

void TwiddleTableManager::clearCache() {
    for (auto& table : m_tables) {
        table.reset();
    }
    for (auto& table : m_stageAlignedTables) {
        table.reset();
    }
}

size_t TwiddleTableManager::getMemoryUsage() const {
    size_t total = 0;

    for (const auto& table : m_tables) {
        if (table) {
            total += sizeof(TwiddleTable);
            total += table->forward.size() * sizeof(uint32_t);
            total += table->inverse.size() * sizeof(uint32_t);
        }
    }

    for (const auto& table : m_stageAlignedTables) {
        if (table) {
            total += sizeof(StageAlignedTwiddles);
            for (const auto& stage : table->stage_forward) {
                total += stage.size() * sizeof(uint32_t);
            }
            for (const auto& stage : table->stage_inverse) {
                total += stage.size() * sizeof(uint32_t);
            }
        }
    }

    return total;
}

//=============================================================================
// GPU-Ready Format Conversion
//=============================================================================

GPUTwiddleData toGPUFormat(const StageAlignedTwiddles& table) {
    GPUTwiddleData gpu;
    gpu.prime = table.prime;
    gpu.ntt_size = table.ntt_size;
    gpu.num_stages = table.num_stages;
    gpu.flags = table.montgomery_form ? 1 : 0;
    gpu.n_inv = table.n_inv;
    gpu.n_inv_mont = table.n_inv_mont;

    // Compute total size and stage offsets
    size_t totalSize = 0;
    gpu.stage_offsets.resize(table.num_stages + 1);

    for (uint32_t s = 0; s < table.num_stages; s++) {
        gpu.stage_offsets[s] = static_cast<uint32_t>(totalSize);
        totalSize += table.stage_forward[s].size();
    }
    gpu.stage_offsets[table.num_stages] = static_cast<uint32_t>(totalSize);

    // Flatten stage twiddles into contiguous arrays
    gpu.forward_flat.reserve(totalSize);
    gpu.inverse_flat.reserve(totalSize);

    for (uint32_t s = 0; s < table.num_stages; s++) {
        gpu.forward_flat.insert(gpu.forward_flat.end(),
                               table.stage_forward[s].begin(),
                               table.stage_forward[s].end());
        gpu.inverse_flat.insert(gpu.inverse_flat.end(),
                               table.stage_inverse[s].begin(),
                               table.stage_inverse[s].end());
    }

    return gpu;
}

//=============================================================================
// Utility Functions
//=============================================================================

void generateBitReversalPermutation(uint32_t n, std::vector<uint32_t>& perm) {
    uint32_t bits = TwiddleTableManager::log2Size(n);
    perm.resize(n);
    for (uint32_t i = 0; i < n; i++) {
        perm[i] = TwiddleTableManager::bitReverse(i, bits);
    }
}

uint32_t computeTwiddle(uint32_t root, uint32_t exp, uint32_t prime) {
    return modPow(root, exp, prime);
}

uint32_t computeTwiddleMontgomery(uint32_t root, uint32_t exp,
                                  const MontgomeryParams& params) {
    uint32_t w = modPow(root, exp, params.prime);
    return GPUPrimeSet::toMontgomery(w, params);
}

} // namespace lux::fhe::gpu
