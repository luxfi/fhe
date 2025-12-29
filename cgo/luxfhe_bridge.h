// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024-2025, Lux Industries Inc
//
// C bridge header for Lux FHE operations
// Wraps the unified MLX/CUDA/CPU backend from ~/work/lux/mlx/fhe/
//
// For enterprise licensing: fhe@lux.network

#ifndef LUXFHE_BRIDGE_H
#define LUXFHE_BRIDGE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// =============================================================================
// Version and Info
// =============================================================================

#define LUXFHE_VERSION_MAJOR 1
#define LUXFHE_VERSION_MINOR 0
#define LUXFHE_VERSION_PATCH 0

// Get version string
const char* luxfhe_version(void);

// Get backend type ("MLX", "CUDA", "CPU")
const char* luxfhe_backend_type(void);

// Check if GPU is available
bool luxfhe_has_gpu(void);

// =============================================================================
// Opaque Handle Types
// =============================================================================

typedef void* LuxFHEEngine;
typedef void* LuxFHEParams;
typedef void* LuxFHESecretKey;
typedef void* LuxFHEPublicKey;
typedef void* LuxFHEBootstrapKey;
typedef void* LuxFHEKeySwitchKey;
typedef void* LuxFHECiphertext;
typedef void* LuxFHEInteger;
typedef void* LuxFHEUint256;

// =============================================================================
// Backend Selection (DMAFHE - PAT-FHE-010)
// =============================================================================

typedef enum {
    LUXFHE_BACKEND_AUTO = 0,      // Auto-detect best backend
    LUXFHE_BACKEND_MLX = 1,       // Apple Metal via MLX
    LUXFHE_BACKEND_CUDA = 2,      // NVIDIA CUDA
    LUXFHE_BACKEND_CPU = 3        // CPU with SIMD
} LuxFHEBackend;

// Operation mode (DMAFHE dual-mode)
typedef enum {
    LUXFHE_MODE_AUTO = 0,         // Auto-detect from ciphertext
    LUXFHE_MODE_UTXO_64 = 1,      // 64-bit optimized for UTXO
    LUXFHE_MODE_EVM_256 = 2       // 256-bit optimized for EVM
} LuxFHEMode;

// Security levels
typedef enum {
    LUXFHE_SECURITY_128 = 0,      // 128-bit security
    LUXFHE_SECURITY_192 = 1,      // 192-bit security
    LUXFHE_SECURITY_256 = 2       // 256-bit security
} LuxFHESecurity;

// =============================================================================
// Engine Management
// =============================================================================

// Create engine with specified backend
LuxFHEEngine luxfhe_engine_create(LuxFHEBackend backend);

// Create engine with auto-detection
LuxFHEEngine luxfhe_engine_create_default(void);

// Free engine
void luxfhe_engine_free(LuxFHEEngine engine);

// Set operation mode (DMAFHE)
void luxfhe_engine_set_mode(LuxFHEEngine engine, LuxFHEMode mode);

// Get current mode
LuxFHEMode luxfhe_engine_get_mode(LuxFHEEngine engine);

// Get backend type
LuxFHEBackend luxfhe_engine_get_backend(LuxFHEEngine engine);

// =============================================================================
// Parameter Generation
// =============================================================================

// Create TFHE parameters
LuxFHEParams luxfhe_params_create(LuxFHESecurity security, LuxFHEMode mode);

// Free parameters
void luxfhe_params_free(LuxFHEParams params);

// Get parameter info
int luxfhe_params_get_n(LuxFHEParams params);          // LWE dimension
int luxfhe_params_get_N(LuxFHEParams params);          // Ring dimension
int luxfhe_params_get_k(LuxFHEParams params);          // GLWE dimension

// =============================================================================
// Key Generation
// =============================================================================

// Generate secret key
LuxFHESecretKey luxfhe_keygen_secret(LuxFHEEngine engine, LuxFHEParams params);

// Generate public key from secret key
LuxFHEPublicKey luxfhe_keygen_public(LuxFHEEngine engine, LuxFHEParams params, LuxFHESecretKey sk);

// Generate bootstrapping key (GPU-accelerated)
LuxFHEBootstrapKey luxfhe_keygen_bootstrap(LuxFHEEngine engine, LuxFHEParams params, LuxFHESecretKey sk);

// Generate key switching key
LuxFHEKeySwitchKey luxfhe_keygen_keyswitch(LuxFHEEngine engine, LuxFHEParams params, LuxFHESecretKey sk);

// Free keys
void luxfhe_secretkey_free(LuxFHESecretKey sk);
void luxfhe_publickey_free(LuxFHEPublicKey pk);
void luxfhe_bootstrapkey_free(LuxFHEBootstrapKey bsk);
void luxfhe_keyswitchkey_free(LuxFHEKeySwitchKey ksk);

// =============================================================================
// Encryption / Decryption (Boolean)
// =============================================================================

// Encrypt a bit
LuxFHECiphertext luxfhe_encrypt_bit(LuxFHEEngine engine, LuxFHESecretKey sk, int bit);

// Encrypt with public key
LuxFHECiphertext luxfhe_encrypt_bit_public(LuxFHEEngine engine, LuxFHEPublicKey pk, int bit);

// Decrypt a bit
int luxfhe_decrypt_bit(LuxFHEEngine engine, LuxFHESecretKey sk, LuxFHECiphertext ct);

// Free ciphertext
void luxfhe_ciphertext_free(LuxFHECiphertext ct);

// Clone ciphertext
LuxFHECiphertext luxfhe_ciphertext_clone(LuxFHECiphertext ct);

// =============================================================================
// Boolean Gates (with GPU-accelerated bootstrapping)
// =============================================================================

LuxFHECiphertext luxfhe_and(LuxFHEEngine engine, LuxFHEBootstrapKey bsk, LuxFHECiphertext a, LuxFHECiphertext b);
LuxFHECiphertext luxfhe_or(LuxFHEEngine engine, LuxFHEBootstrapKey bsk, LuxFHECiphertext a, LuxFHECiphertext b);
LuxFHECiphertext luxfhe_xor(LuxFHEEngine engine, LuxFHEBootstrapKey bsk, LuxFHECiphertext a, LuxFHECiphertext b);
LuxFHECiphertext luxfhe_nand(LuxFHEEngine engine, LuxFHEBootstrapKey bsk, LuxFHECiphertext a, LuxFHECiphertext b);
LuxFHECiphertext luxfhe_nor(LuxFHEEngine engine, LuxFHEBootstrapKey bsk, LuxFHECiphertext a, LuxFHECiphertext b);
LuxFHECiphertext luxfhe_xnor(LuxFHEEngine engine, LuxFHEBootstrapKey bsk, LuxFHECiphertext a, LuxFHECiphertext b);
LuxFHECiphertext luxfhe_not(LuxFHEEngine engine, LuxFHECiphertext ct);
LuxFHECiphertext luxfhe_mux(LuxFHEEngine engine, LuxFHEBootstrapKey bsk, LuxFHECiphertext sel, LuxFHECiphertext a, LuxFHECiphertext b);

// =============================================================================
// Integer Operations (64-bit - UTXO mode)
// =============================================================================

// Encrypt 64-bit integer
LuxFHEInteger luxfhe_encrypt_u64(LuxFHEEngine engine, LuxFHESecretKey sk, uint64_t value);

// Encrypt with public key
LuxFHEInteger luxfhe_encrypt_u64_public(LuxFHEEngine engine, LuxFHEPublicKey pk, uint64_t value);

// Decrypt 64-bit integer
uint64_t luxfhe_decrypt_u64(LuxFHEEngine engine, LuxFHESecretKey sk, LuxFHEInteger ct);

// Free integer ciphertext
void luxfhe_integer_free(LuxFHEInteger ct);

// Clone integer
LuxFHEInteger luxfhe_integer_clone(LuxFHEInteger ct);

// =============================================================================
// Integer Arithmetic (GPU-accelerated)
// =============================================================================

LuxFHEInteger luxfhe_add_u64(LuxFHEEngine engine, LuxFHEBootstrapKey bsk, LuxFHEInteger a, LuxFHEInteger b);
LuxFHEInteger luxfhe_sub_u64(LuxFHEEngine engine, LuxFHEBootstrapKey bsk, LuxFHEInteger a, LuxFHEInteger b);
LuxFHEInteger luxfhe_mul_u64(LuxFHEEngine engine, LuxFHEBootstrapKey bsk, LuxFHEInteger a, LuxFHEInteger b);
LuxFHEInteger luxfhe_neg_u64(LuxFHEEngine engine, LuxFHEInteger a);

// Scalar operations
LuxFHEInteger luxfhe_add_scalar_u64(LuxFHEEngine engine, LuxFHEInteger a, uint64_t scalar);
LuxFHEInteger luxfhe_sub_scalar_u64(LuxFHEEngine engine, LuxFHEInteger a, uint64_t scalar);
LuxFHEInteger luxfhe_mul_scalar_u64(LuxFHEEngine engine, LuxFHEInteger a, uint64_t scalar);

// =============================================================================
// Comparison Operations (ULFHE - PAT-FHE-011)
// =============================================================================

// O(1) comparisons via single bootstrapping with LUT
LuxFHECiphertext luxfhe_lt(LuxFHEEngine engine, LuxFHEBootstrapKey bsk, LuxFHEInteger a, LuxFHEInteger b);
LuxFHECiphertext luxfhe_le(LuxFHEEngine engine, LuxFHEBootstrapKey bsk, LuxFHEInteger a, LuxFHEInteger b);
LuxFHECiphertext luxfhe_gt(LuxFHEEngine engine, LuxFHEBootstrapKey bsk, LuxFHEInteger a, LuxFHEInteger b);
LuxFHECiphertext luxfhe_ge(LuxFHEEngine engine, LuxFHEBootstrapKey bsk, LuxFHEInteger a, LuxFHEInteger b);
LuxFHECiphertext luxfhe_eq(LuxFHEEngine engine, LuxFHEBootstrapKey bsk, LuxFHEInteger a, LuxFHEInteger b);
LuxFHECiphertext luxfhe_ne(LuxFHEEngine engine, LuxFHEBootstrapKey bsk, LuxFHEInteger a, LuxFHEInteger b);

// Range check (for UTXO validation)
LuxFHECiphertext luxfhe_in_range(LuxFHEEngine engine, LuxFHEBootstrapKey bsk, LuxFHEInteger value, uint64_t min, uint64_t max);

// Min/max
LuxFHEInteger luxfhe_min(LuxFHEEngine engine, LuxFHEBootstrapKey bsk, LuxFHEInteger a, LuxFHEInteger b);
LuxFHEInteger luxfhe_max(LuxFHEEngine engine, LuxFHEBootstrapKey bsk, LuxFHEInteger a, LuxFHEInteger b);

// =============================================================================
// uint256 Operations (EVM256PP - PAT-FHE-012)
// =============================================================================

// Encrypt uint256 (4 limbs)
LuxFHEUint256 luxfhe_encrypt_u256(LuxFHEEngine engine, LuxFHESecretKey sk, const uint64_t limbs[4]);

// Encrypt with public key
LuxFHEUint256 luxfhe_encrypt_u256_public(LuxFHEEngine engine, LuxFHEPublicKey pk, const uint64_t limbs[4]);

// Decrypt uint256
void luxfhe_decrypt_u256(LuxFHEEngine engine, LuxFHESecretKey sk, LuxFHEUint256 ct, uint64_t limbs[4]);

// Free uint256
void luxfhe_uint256_free(LuxFHEUint256 ct);

// Clone uint256
LuxFHEUint256 luxfhe_uint256_clone(LuxFHEUint256 ct);

// uint256 arithmetic (GPU parallel)
LuxFHEUint256 luxfhe_add_u256(LuxFHEEngine engine, LuxFHEUint256 a, LuxFHEUint256 b);
LuxFHEUint256 luxfhe_sub_u256(LuxFHEEngine engine, LuxFHEUint256 a, LuxFHEUint256 b);
LuxFHEUint256 luxfhe_mul_u256(LuxFHEEngine engine, LuxFHEBootstrapKey bsk, LuxFHEUint256 a, LuxFHEUint256 b);

// uint256 bitwise
LuxFHEUint256 luxfhe_and_u256(LuxFHEEngine engine, LuxFHEUint256 a, LuxFHEUint256 b);
LuxFHEUint256 luxfhe_or_u256(LuxFHEEngine engine, LuxFHEUint256 a, LuxFHEUint256 b);
LuxFHEUint256 luxfhe_xor_u256(LuxFHEEngine engine, LuxFHEUint256 a, LuxFHEUint256 b);
LuxFHEUint256 luxfhe_not_u256(LuxFHEEngine engine, LuxFHEUint256 a);
LuxFHEUint256 luxfhe_shl_u256(LuxFHEEngine engine, LuxFHEUint256 a, uint32_t shift);
LuxFHEUint256 luxfhe_shr_u256(LuxFHEEngine engine, LuxFHEUint256 a, uint32_t shift);

// uint256 comparisons
LuxFHECiphertext luxfhe_lt_u256(LuxFHEEngine engine, LuxFHEBootstrapKey bsk, LuxFHEUint256 a, LuxFHEUint256 b);
LuxFHECiphertext luxfhe_eq_u256(LuxFHEEngine engine, LuxFHEBootstrapKey bsk, LuxFHEUint256 a, LuxFHEUint256 b);

// =============================================================================
// EVM Opcodes (EVM256PP)
// =============================================================================

typedef enum {
    LUXFHE_EVM_ADD = 0x01,
    LUXFHE_EVM_MUL = 0x02,
    LUXFHE_EVM_SUB = 0x03,
    LUXFHE_EVM_DIV = 0x04,
    LUXFHE_EVM_MOD = 0x06,
    LUXFHE_EVM_ADDMOD = 0x08,
    LUXFHE_EVM_MULMOD = 0x09,
    LUXFHE_EVM_EXP = 0x0a,
    LUXFHE_EVM_LT = 0x10,
    LUXFHE_EVM_GT = 0x11,
    LUXFHE_EVM_EQ = 0x14,
    LUXFHE_EVM_AND = 0x16,
    LUXFHE_EVM_OR = 0x17,
    LUXFHE_EVM_XOR = 0x18,
    LUXFHE_EVM_NOT = 0x19,
    LUXFHE_EVM_SHL = 0x1b,
    LUXFHE_EVM_SHR = 0x1c,
    LUXFHE_EVM_SAR = 0x1d
} LuxFHEEVMOpcode;

// Execute EVM opcode on encrypted operands
LuxFHEUint256 luxfhe_evm_execute(LuxFHEEngine engine, LuxFHEBootstrapKey bsk, 
                                  LuxFHEEVMOpcode opcode, LuxFHEUint256 a, LuxFHEUint256 b);

// Batch execute multiple operations
int luxfhe_evm_execute_batch(LuxFHEEngine engine, LuxFHEBootstrapKey bsk,
                             const LuxFHEEVMOpcode* opcodes, const LuxFHEUint256* operands_a,
                             const LuxFHEUint256* operands_b, LuxFHEUint256* results, size_t count);

// =============================================================================
// Cross-Chain Bridge (XCFHE - PAT-FHE-013)
// =============================================================================

typedef void* LuxFHEBridgeContext;

// Chain IDs
#define LUXFHE_CHAIN_LUX     96369
#define LUXFHE_CHAIN_ZOO     200200
#define LUXFHE_CHAIN_HANZO   36963

// Create bridge context
LuxFHEBridgeContext luxfhe_bridge_create(uint64_t source_chain, uint64_t dest_chain);

// Free bridge context
void luxfhe_bridge_free(LuxFHEBridgeContext ctx);

// Re-encrypt ciphertext for destination chain
LuxFHECiphertext luxfhe_bridge_reencrypt(LuxFHEBridgeContext ctx, LuxFHECiphertext ct,
                                          const uint8_t* dest_pubkey, size_t pubkey_len);

// Verify re-encryption proof
bool luxfhe_bridge_verify(LuxFHEBridgeContext ctx, const uint8_t* proof, size_t proof_len);

// =============================================================================
// Validator Acceleration (VAFHE - PAT-FHE-014)
// =============================================================================

typedef void* LuxFHEValidatorSession;

// Attestation types
typedef enum {
    LUXFHE_ATTEST_SGX = 0,
    LUXFHE_ATTEST_TDX = 1,
    LUXFHE_ATTEST_SEV = 2,
    LUXFHE_ATTEST_NVTRUST = 3,
    LUXFHE_ATTEST_ARM_CCA = 4
} LuxFHEAttestationType;

// Trust levels
typedef enum {
    LUXFHE_TRUST_PUBLIC = 1,       // Consumer GPU, stake-based
    LUXFHE_TRUST_PRIVATE = 2,      // SGX/A100
    LUXFHE_TRUST_CONFIDENTIAL = 3, // H100+TDX/SEV
    LUXFHE_TRUST_SOVEREIGN = 4     // Blackwell
} LuxFHETrustLevel;

// Create validator session
LuxFHEValidatorSession luxfhe_validator_create(LuxFHEEngine engine, LuxFHEAttestationType attest_type);

// Submit attestation quote
bool luxfhe_validator_attest(LuxFHEValidatorSession session, const uint8_t* quote, size_t quote_len);

// Get trust level
LuxFHETrustLevel luxfhe_validator_trust_level(LuxFHEValidatorSession session);

// Record work (returns credits earned)
uint64_t luxfhe_validator_record_work(LuxFHEValidatorSession session, uint64_t operations);

// Free session
void luxfhe_validator_free(LuxFHEValidatorSession session);

// =============================================================================
// Batch Operations (GPU-optimized)
// =============================================================================

// Batch encrypt
int luxfhe_batch_encrypt_u64(LuxFHEEngine engine, LuxFHESecretKey sk, 
                              const uint64_t* values, LuxFHEInteger* results, size_t count);

// Batch decrypt
int luxfhe_batch_decrypt_u64(LuxFHEEngine engine, LuxFHESecretKey sk,
                              const LuxFHEInteger* cts, uint64_t* results, size_t count);

// Batch bootstrap
int luxfhe_batch_bootstrap(LuxFHEEngine engine, LuxFHEBootstrapKey bsk,
                            LuxFHECiphertext* cts, size_t count);

// Batch add
int luxfhe_batch_add_u64(LuxFHEEngine engine, LuxFHEBootstrapKey bsk,
                          const LuxFHEInteger* as, const LuxFHEInteger* bs,
                          LuxFHEInteger* results, size_t count);

// =============================================================================
// NTT Operations (Direct Access)
// =============================================================================

// Forward NTT (for advanced users)
void luxfhe_ntt_forward(LuxFHEEngine engine, uint64_t* data, size_t n, uint64_t modulus);

// Inverse NTT
void luxfhe_ntt_inverse(LuxFHEEngine engine, uint64_t* data, size_t n, uint64_t modulus);

// Batch NTT
void luxfhe_ntt_forward_batch(LuxFHEEngine engine, uint64_t** data, size_t count, size_t n, uint64_t modulus);

// =============================================================================
// Serialization
// =============================================================================

// Serialize ciphertext
uint8_t* luxfhe_serialize_ciphertext(LuxFHECiphertext ct, size_t* out_len);

// Deserialize ciphertext
LuxFHECiphertext luxfhe_deserialize_ciphertext(LuxFHEEngine engine, const uint8_t* data, size_t len);

// Serialize integer
uint8_t* luxfhe_serialize_integer(LuxFHEInteger ct, size_t* out_len);

// Deserialize integer
LuxFHEInteger luxfhe_deserialize_integer(LuxFHEEngine engine, const uint8_t* data, size_t len);

// Serialize uint256
uint8_t* luxfhe_serialize_uint256(LuxFHEUint256 ct, size_t* out_len);

// Deserialize uint256
LuxFHEUint256 luxfhe_deserialize_uint256(LuxFHEEngine engine, const uint8_t* data, size_t len);

// Serialize keys
uint8_t* luxfhe_serialize_secretkey(LuxFHESecretKey sk, size_t* out_len);
LuxFHESecretKey luxfhe_deserialize_secretkey(LuxFHEEngine engine, const uint8_t* data, size_t len);

uint8_t* luxfhe_serialize_publickey(LuxFHEPublicKey pk, size_t* out_len);
LuxFHEPublicKey luxfhe_deserialize_publickey(LuxFHEEngine engine, const uint8_t* data, size_t len);

uint8_t* luxfhe_serialize_bootstrapkey(LuxFHEBootstrapKey bsk, size_t* out_len);
LuxFHEBootstrapKey luxfhe_deserialize_bootstrapkey(LuxFHEEngine engine, const uint8_t* data, size_t len);

// Free serialized data
void luxfhe_free_bytes(uint8_t* data);

// =============================================================================
// Performance Metrics
// =============================================================================

typedef struct {
    double ntt_time_ms;
    double bootstrap_time_ms;
    double keygen_time_ms;
    double encrypt_time_ms;
    double decrypt_time_ms;
    uint64_t operations_count;
    double throughput_ops_sec;
    size_t memory_used_bytes;
    size_t gpu_memory_used_bytes;
} LuxFHEStats;

// Get performance statistics
LuxFHEStats luxfhe_get_stats(LuxFHEEngine engine);

// Reset statistics
void luxfhe_reset_stats(LuxFHEEngine engine);

// =============================================================================
// Error Handling
// =============================================================================

typedef enum {
    LUXFHE_OK = 0,
    LUXFHE_ERR_INVALID_PARAM = 1,
    LUXFHE_ERR_OUT_OF_MEMORY = 2,
    LUXFHE_ERR_GPU_UNAVAILABLE = 3,
    LUXFHE_ERR_BACKEND_INIT = 4,
    LUXFHE_ERR_KEYGEN_FAILED = 5,
    LUXFHE_ERR_ENCRYPT_FAILED = 6,
    LUXFHE_ERR_DECRYPT_FAILED = 7,
    LUXFHE_ERR_BOOTSTRAP_FAILED = 8,
    LUXFHE_ERR_SERIALIZATION = 9,
    LUXFHE_ERR_ATTESTATION_FAILED = 10,
    LUXFHE_ERR_BRIDGE_FAILED = 11
} LuxFHEError;

// Get last error
LuxFHEError luxfhe_get_last_error(void);

// Get error message
const char* luxfhe_get_error_message(LuxFHEError err);

// Clear error
void luxfhe_clear_error(void);

#ifdef __cplusplus
}
#endif

#endif // LUXFHE_BRIDGE_H
