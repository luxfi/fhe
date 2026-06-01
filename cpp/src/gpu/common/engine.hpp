// Copyright (C) 2024-2025 Lux Industries Inc.
// SPDX-License-Identifier: Apache-2.0
//
// GPU FHE Engine - Abstract interface for GPU-accelerated FHE operations
// Supports CUDA (NVIDIA), Metal (Apple), and CPU fallback

#ifndef LUX_FHE_GPU_ENGINE_HPP
#define LUX_FHE_GPU_ENGINE_HPP

#include <cstdint>
#include <cstddef>
#include <vector>
#include <memory>
#include <string>
#include <functional>

namespace lux::fhe::gpu {

// Forward declarations
class Ciphertext;
class BootstrappingKey;
class KeySwitchingKey;
class NTTContext;

//=============================================================================
// GPU Backend Type
//=============================================================================
enum class BackendType {
    CPU,      // Fallback CPU implementation
    CUDA,     // NVIDIA CUDA
    METAL,    // Apple Metal/MLX
    AUTO      // Auto-detect best available
};

//=============================================================================
// Device Information
//=============================================================================
struct DeviceInfo {
    int device_id;
    std::string name;
    size_t total_memory;
    size_t free_memory;
    int compute_capability_major;
    int compute_capability_minor;
    bool supports_fp64;
    bool supports_tensor_cores;
    int multiprocessor_count;
    int max_threads_per_block;
};

//=============================================================================
// Operation Mode (for DMAFHE - PAT-FHE-010)
//=============================================================================
enum class OperationMode {
    UTXO_64,   // 64-bit optimized for UTXO operations
    EVM_256,   // 256-bit optimized for EVM operations
    AUTO       // Automatic detection based on ciphertext metadata
};

//=============================================================================
// Performance Statistics
//=============================================================================
struct PerformanceStats {
    double ntt_time_ms;
    double bootstrap_time_ms;
    double keygen_time_ms;
    double encrypt_time_ms;
    double decrypt_time_ms;
    size_t memory_used_bytes;
    size_t operations_count;
    double throughput_ops_per_sec;
};

//=============================================================================
// GPU Engine Interface
//=============================================================================
class Engine {
public:
    virtual ~Engine() = default;

    // Initialization
    virtual bool initialize(int device_id = 0) = 0;
    virtual void shutdown() = 0;
    virtual bool isInitialized() const = 0;

    // Device information
    virtual BackendType getBackendType() const = 0;
    virtual DeviceInfo getDeviceInfo() const = 0;
    virtual std::vector<DeviceInfo> listDevices() const = 0;

    // Mode selection (DMAFHE)
    virtual void setOperationMode(OperationMode mode) = 0;
    virtual OperationMode getOperationMode() const = 0;
    virtual OperationMode detectOptimalMode(const Ciphertext& ct) const = 0;

    // NTT Operations
    virtual void nttForward(uint64_t* data, size_t n, uint64_t modulus) = 0;
    virtual void nttInverse(uint64_t* data, size_t n, uint64_t modulus) = 0;
    virtual void nttForwardBatch(uint64_t** data, size_t count, size_t n, uint64_t modulus) = 0;

    // Bootstrapping
    virtual void bootstrap(Ciphertext& ct, const BootstrappingKey& bsk) = 0;
    virtual void bootstrapBatch(std::vector<Ciphertext>& cts, const BootstrappingKey& bsk) = 0;

    // Key operations
    virtual void keySwitch(Ciphertext& ct, const KeySwitchingKey& ksk) = 0;
    virtual void generateBootstrappingKey(BootstrappingKey& bsk, const void* secret_key) = 0;

    // Arithmetic operations
    virtual void add(Ciphertext& result, const Ciphertext& a, const Ciphertext& b) = 0;
    virtual void sub(Ciphertext& result, const Ciphertext& a, const Ciphertext& b) = 0;
    virtual void mul(Ciphertext& result, const Ciphertext& a, const Ciphertext& b) = 0;

    // Comparison operations (ULFHE - PAT-FHE-011)
    virtual void compare(Ciphertext& result, const Ciphertext& a, const Ciphertext& b) = 0;
    virtual void rangeCheck(Ciphertext& result, const Ciphertext& value, uint64_t min, uint64_t max) = 0;
    virtual void batchRangeCheck(std::vector<Ciphertext>& results,
                                  const std::vector<Ciphertext>& values,
                                  uint64_t min, uint64_t max) = 0;

    // EVM256 Operations (PAT-FHE-012)
    virtual void add256(Ciphertext& result, const Ciphertext& a, const Ciphertext& b) = 0;
    virtual void mul256(Ciphertext& result, const Ciphertext& a, const Ciphertext& b) = 0;
    virtual void mod256(Ciphertext& result, const Ciphertext& a) = 0;

    // Memory management
    virtual void* allocateDevice(size_t bytes) = 0;
    virtual void freeDevice(void* ptr) = 0;
    virtual void copyToDevice(void* dst, const void* src, size_t bytes) = 0;
    virtual void copyFromDevice(void* dst, const void* src, size_t bytes) = 0;

    // Synchronization
    virtual void synchronize() = 0;
    virtual void synchronizeStream(int stream_id) = 0;

    // Performance
    virtual PerformanceStats getPerformanceStats() const = 0;
    virtual void resetPerformanceStats() = 0;

    // Factory method
    static std::unique_ptr<Engine> create(BackendType type = BackendType::AUTO);
};

//=============================================================================
// Multi-GPU Engine (VAFHE - PAT-FHE-014)
//=============================================================================
class MultiGPUEngine {
public:
    MultiGPUEngine();
    ~MultiGPUEngine();

    // Initialization
    bool initialize(const std::vector<int>& device_ids = {});
    void shutdown();
    int getDeviceCount() const;

    // Batch processing across GPUs
    void bootstrapBatch(std::vector<Ciphertext>& cts, const BootstrappingKey& bsk);
    void processWorkload(std::function<void(Engine&, int, int)> work, size_t total_items);

    // Load balancing
    void setLoadBalancingStrategy(const std::string& strategy);
    std::vector<PerformanceStats> getPerDeviceStats() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

//=============================================================================
// Attestation Support (VAFHE - PAT-FHE-014)
//=============================================================================
struct AttestationQuote {
    std::vector<uint8_t> quote_data;
    std::string enclave_id;
    std::string gpu_model;
    uint64_t timestamp;
    std::vector<uint8_t> signature;
};

class TEEKeyVault {
public:
    virtual ~TEEKeyVault() = default;

    // Key management
    virtual bool loadKeys(const std::vector<uint8_t>& sealed_keys) = 0;
    virtual std::vector<uint8_t> sealKeys() = 0;
    virtual void transferToGPU(Engine& gpu) = 0;

    // Attestation
    virtual AttestationQuote generateQuote() = 0;
    virtual bool verifyQuote(const AttestationQuote& quote) = 0;

    // Factory
    static std::unique_ptr<TEEKeyVault> create();
};

} // namespace lux::fhe::gpu

#endif // LUX_FHE_GPU_ENGINE_HPP
