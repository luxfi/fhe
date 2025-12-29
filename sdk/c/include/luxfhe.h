// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025, Lux Industries Inc
//
// LuxFHE C API - Production-ready C bindings for the Lux TFHE library
//
// This header provides a stable C ABI for integrating LuxFHE into C/C++ projects.
// All functions are thread-safe unless documented otherwise.

#ifndef LUXFHE_H
#define LUXFHE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// =============================================================================
// Version Information
// =============================================================================

#define LUXFHE_VERSION_MAJOR 1
#define LUXFHE_VERSION_MINOR 0
#define LUXFHE_VERSION_PATCH 0
#define LUXFHE_VERSION_STRING "1.0.0"

// =============================================================================
// Error Codes
// =============================================================================

typedef enum {
    LUXFHE_OK = 0,
    LUXFHE_ERR_NULL_POINTER = -1,
    LUXFHE_ERR_INVALID_PARAM = -2,
    LUXFHE_ERR_ALLOCATION = -3,
    LUXFHE_ERR_NOT_INITIALIZED = -4,
    LUXFHE_ERR_KEY_NOT_SET = -5,
    LUXFHE_ERR_SERIALIZATION = -6,
    LUXFHE_ERR_DESERIALIZATION = -7,
    LUXFHE_ERR_OPERATION = -8,
    LUXFHE_ERR_TYPE_MISMATCH = -9,
    LUXFHE_ERR_OUT_OF_RANGE = -10,
} LuxFHE_Error;

// =============================================================================
// Opaque Handle Types
// =============================================================================

// All handles are opaque pointers to internal Go structures
typedef struct LuxFHE_Context_s* LuxFHE_Context;
typedef struct LuxFHE_SecretKey_s* LuxFHE_SecretKey;
typedef struct LuxFHE_PublicKey_s* LuxFHE_PublicKey;
typedef struct LuxFHE_BootstrapKey_s* LuxFHE_BootstrapKey;
typedef struct LuxFHE_Ciphertext_s* LuxFHE_Ciphertext;
typedef struct LuxFHE_Integer_s* LuxFHE_Integer;
typedef struct LuxFHE_Encryptor_s* LuxFHE_Encryptor;
typedef struct LuxFHE_Decryptor_s* LuxFHE_Decryptor;
typedef struct LuxFHE_Evaluator_s* LuxFHE_Evaluator;

// =============================================================================
// Parameter Sets
// =============================================================================

typedef enum {
    // ~128-bit security, good performance (recommended for most use cases)
    LUXFHE_PARAMS_PN10QP27 = 0,
    // ~128-bit security, higher precision
    LUXFHE_PARAMS_PN11QP54 = 1,
} LuxFHE_ParamSet;

// =============================================================================
// Version and Info
// =============================================================================

// Get library version string
const char* luxfhe_version(void);

// Get library version components
void luxfhe_version_info(int* major, int* minor, int* patch);

// Get error message for error code
const char* luxfhe_error_string(LuxFHE_Error err);

// =============================================================================
// Context Management
// =============================================================================

// Create a new context with the specified parameter set
// Returns LUXFHE_OK on success, error code otherwise
LuxFHE_Error luxfhe_context_new(LuxFHE_ParamSet params, LuxFHE_Context* out);

// Free a context and all associated resources
void luxfhe_context_free(LuxFHE_Context ctx);

// Get parameter info for a context
LuxFHE_Error luxfhe_context_params(LuxFHE_Context ctx, 
                                    int* n_lwe, int* n_br, 
                                    uint64_t* q_lwe, uint64_t* q_br);

// =============================================================================
// Key Generation
// =============================================================================

// Generate a new secret key
LuxFHE_Error luxfhe_keygen_secret(LuxFHE_Context ctx, LuxFHE_SecretKey* out);

// Generate a public key from a secret key
LuxFHE_Error luxfhe_keygen_public(LuxFHE_Context ctx, 
                                   LuxFHE_SecretKey sk,
                                   LuxFHE_PublicKey* out);

// Generate a bootstrap key (evaluation key) from a secret key
LuxFHE_Error luxfhe_keygen_bootstrap(LuxFHE_Context ctx,
                                      LuxFHE_SecretKey sk,
                                      LuxFHE_BootstrapKey* out);

// Generate all keys at once (convenience function)
LuxFHE_Error luxfhe_keygen_all(LuxFHE_Context ctx,
                                LuxFHE_SecretKey* sk,
                                LuxFHE_PublicKey* pk,
                                LuxFHE_BootstrapKey* bsk);

// Free keys
void luxfhe_secretkey_free(LuxFHE_SecretKey sk);
void luxfhe_publickey_free(LuxFHE_PublicKey pk);
void luxfhe_bootstrapkey_free(LuxFHE_BootstrapKey bsk);

// =============================================================================
// Encryptor / Decryptor / Evaluator
// =============================================================================

// Create an encryptor using secret key (for testing/trusted environments)
LuxFHE_Error luxfhe_encryptor_new_sk(LuxFHE_Context ctx,
                                      LuxFHE_SecretKey sk,
                                      LuxFHE_Encryptor* out);

// Create an encryptor using public key (for untrusted environments)
LuxFHE_Error luxfhe_encryptor_new_pk(LuxFHE_Context ctx,
                                      LuxFHE_PublicKey pk,
                                      LuxFHE_Encryptor* out);

// Create a decryptor (requires secret key)
LuxFHE_Error luxfhe_decryptor_new(LuxFHE_Context ctx,
                                   LuxFHE_SecretKey sk,
                                   LuxFHE_Decryptor* out);

// Create an evaluator (requires bootstrap key and secret key for key-switching)
LuxFHE_Error luxfhe_evaluator_new(LuxFHE_Context ctx,
                                   LuxFHE_BootstrapKey bsk,
                                   LuxFHE_SecretKey sk,
                                   LuxFHE_Evaluator* out);

// Free encryptor/decryptor/evaluator
void luxfhe_encryptor_free(LuxFHE_Encryptor enc);
void luxfhe_decryptor_free(LuxFHE_Decryptor dec);
void luxfhe_evaluator_free(LuxFHE_Evaluator eval);

// =============================================================================
// Boolean Encryption / Decryption
// =============================================================================

// Encrypt a boolean value
LuxFHE_Error luxfhe_encrypt_bool(LuxFHE_Encryptor enc, 
                                  bool value, 
                                  LuxFHE_Ciphertext* out);

// Decrypt a ciphertext to boolean
LuxFHE_Error luxfhe_decrypt_bool(LuxFHE_Decryptor dec,
                                  LuxFHE_Ciphertext ct,
                                  bool* out);

// Free a ciphertext
void luxfhe_ciphertext_free(LuxFHE_Ciphertext ct);

// Clone a ciphertext
LuxFHE_Error luxfhe_ciphertext_clone(LuxFHE_Ciphertext ct, 
                                      LuxFHE_Ciphertext* out);

// =============================================================================
// Byte Encryption / Decryption (8-bit)
// =============================================================================

// Encrypt a byte (8-bit unsigned integer)
LuxFHE_Error luxfhe_encrypt_byte(LuxFHE_Encryptor enc,
                                  uint8_t value,
                                  LuxFHE_Integer* out);

// Decrypt an encrypted byte
LuxFHE_Error luxfhe_decrypt_byte(LuxFHE_Decryptor dec,
                                  LuxFHE_Integer ct,
                                  uint8_t* out);

// =============================================================================
// Integer Encryption / Decryption (variable width)
// =============================================================================

// Encrypt a 16-bit unsigned integer
LuxFHE_Error luxfhe_encrypt_uint16(LuxFHE_Encryptor enc,
                                    uint16_t value,
                                    LuxFHE_Integer* out);

// Encrypt a 32-bit unsigned integer
LuxFHE_Error luxfhe_encrypt_uint32(LuxFHE_Encryptor enc,
                                    uint32_t value,
                                    LuxFHE_Integer* out);

// Encrypt a 64-bit unsigned integer
LuxFHE_Error luxfhe_encrypt_uint64(LuxFHE_Encryptor enc,
                                    uint64_t value,
                                    LuxFHE_Integer* out);

// Decrypt integers
LuxFHE_Error luxfhe_decrypt_uint16(LuxFHE_Decryptor dec,
                                    LuxFHE_Integer ct,
                                    uint16_t* out);

LuxFHE_Error luxfhe_decrypt_uint32(LuxFHE_Decryptor dec,
                                    LuxFHE_Integer ct,
                                    uint32_t* out);

LuxFHE_Error luxfhe_decrypt_uint64(LuxFHE_Decryptor dec,
                                    LuxFHE_Integer ct,
                                    uint64_t* out);

// Free an integer ciphertext
void luxfhe_integer_free(LuxFHE_Integer ct);

// Clone an integer ciphertext
LuxFHE_Error luxfhe_integer_clone(LuxFHE_Integer ct, LuxFHE_Integer* out);

// Get bit width of an integer ciphertext
int luxfhe_integer_bitwidth(LuxFHE_Integer ct);

// =============================================================================
// Boolean Gates (with bootstrapping)
// =============================================================================

LuxFHE_Error luxfhe_not(LuxFHE_Evaluator eval,
                         LuxFHE_Ciphertext ct,
                         LuxFHE_Ciphertext* out);

LuxFHE_Error luxfhe_and(LuxFHE_Evaluator eval,
                         LuxFHE_Ciphertext ct1,
                         LuxFHE_Ciphertext ct2,
                         LuxFHE_Ciphertext* out);

LuxFHE_Error luxfhe_or(LuxFHE_Evaluator eval,
                        LuxFHE_Ciphertext ct1,
                        LuxFHE_Ciphertext ct2,
                        LuxFHE_Ciphertext* out);

LuxFHE_Error luxfhe_xor(LuxFHE_Evaluator eval,
                         LuxFHE_Ciphertext ct1,
                         LuxFHE_Ciphertext ct2,
                         LuxFHE_Ciphertext* out);

LuxFHE_Error luxfhe_nand(LuxFHE_Evaluator eval,
                          LuxFHE_Ciphertext ct1,
                          LuxFHE_Ciphertext ct2,
                          LuxFHE_Ciphertext* out);

LuxFHE_Error luxfhe_nor(LuxFHE_Evaluator eval,
                         LuxFHE_Ciphertext ct1,
                         LuxFHE_Ciphertext ct2,
                         LuxFHE_Ciphertext* out);

LuxFHE_Error luxfhe_xnor(LuxFHE_Evaluator eval,
                          LuxFHE_Ciphertext ct1,
                          LuxFHE_Ciphertext ct2,
                          LuxFHE_Ciphertext* out);

// Multiplexer: if sel then ct_true else ct_false
LuxFHE_Error luxfhe_mux(LuxFHE_Evaluator eval,
                         LuxFHE_Ciphertext sel,
                         LuxFHE_Ciphertext ct_true,
                         LuxFHE_Ciphertext ct_false,
                         LuxFHE_Ciphertext* out);

// =============================================================================
// Multi-Input Gates
// =============================================================================

LuxFHE_Error luxfhe_and3(LuxFHE_Evaluator eval,
                          LuxFHE_Ciphertext ct1,
                          LuxFHE_Ciphertext ct2,
                          LuxFHE_Ciphertext ct3,
                          LuxFHE_Ciphertext* out);

LuxFHE_Error luxfhe_or3(LuxFHE_Evaluator eval,
                         LuxFHE_Ciphertext ct1,
                         LuxFHE_Ciphertext ct2,
                         LuxFHE_Ciphertext ct3,
                         LuxFHE_Ciphertext* out);

LuxFHE_Error luxfhe_majority(LuxFHE_Evaluator eval,
                              LuxFHE_Ciphertext ct1,
                              LuxFHE_Ciphertext ct2,
                              LuxFHE_Ciphertext ct3,
                              LuxFHE_Ciphertext* out);

// =============================================================================
// Integer Arithmetic
// =============================================================================

LuxFHE_Error luxfhe_int_add(LuxFHE_Evaluator eval,
                             LuxFHE_Integer a,
                             LuxFHE_Integer b,
                             LuxFHE_Integer* out);

LuxFHE_Error luxfhe_int_sub(LuxFHE_Evaluator eval,
                             LuxFHE_Integer a,
                             LuxFHE_Integer b,
                             LuxFHE_Integer* out);

LuxFHE_Error luxfhe_int_neg(LuxFHE_Evaluator eval,
                             LuxFHE_Integer a,
                             LuxFHE_Integer* out);

LuxFHE_Error luxfhe_int_mul(LuxFHE_Evaluator eval,
                             LuxFHE_Integer a,
                             LuxFHE_Integer b,
                             LuxFHE_Integer* out);

// Scalar operations (plaintext * ciphertext)
LuxFHE_Error luxfhe_int_add_scalar(LuxFHE_Evaluator eval,
                                    LuxFHE_Integer a,
                                    int64_t scalar,
                                    LuxFHE_Integer* out);

LuxFHE_Error luxfhe_int_mul_scalar(LuxFHE_Evaluator eval,
                                    LuxFHE_Integer a,
                                    int64_t scalar,
                                    LuxFHE_Integer* out);

// =============================================================================
// Integer Comparisons
// =============================================================================

// All comparison functions return an encrypted boolean
LuxFHE_Error luxfhe_int_eq(LuxFHE_Evaluator eval,
                            LuxFHE_Integer a,
                            LuxFHE_Integer b,
                            LuxFHE_Ciphertext* out);

LuxFHE_Error luxfhe_int_ne(LuxFHE_Evaluator eval,
                            LuxFHE_Integer a,
                            LuxFHE_Integer b,
                            LuxFHE_Ciphertext* out);

LuxFHE_Error luxfhe_int_lt(LuxFHE_Evaluator eval,
                            LuxFHE_Integer a,
                            LuxFHE_Integer b,
                            LuxFHE_Ciphertext* out);

LuxFHE_Error luxfhe_int_le(LuxFHE_Evaluator eval,
                            LuxFHE_Integer a,
                            LuxFHE_Integer b,
                            LuxFHE_Ciphertext* out);

LuxFHE_Error luxfhe_int_gt(LuxFHE_Evaluator eval,
                            LuxFHE_Integer a,
                            LuxFHE_Integer b,
                            LuxFHE_Ciphertext* out);

LuxFHE_Error luxfhe_int_ge(LuxFHE_Evaluator eval,
                            LuxFHE_Integer a,
                            LuxFHE_Integer b,
                            LuxFHE_Ciphertext* out);

LuxFHE_Error luxfhe_int_min(LuxFHE_Evaluator eval,
                             LuxFHE_Integer a,
                             LuxFHE_Integer b,
                             LuxFHE_Integer* out);

LuxFHE_Error luxfhe_int_max(LuxFHE_Evaluator eval,
                             LuxFHE_Integer a,
                             LuxFHE_Integer b,
                             LuxFHE_Integer* out);

// =============================================================================
// Integer Bitwise Operations
// =============================================================================

LuxFHE_Error luxfhe_int_bitand(LuxFHE_Evaluator eval,
                                LuxFHE_Integer a,
                                LuxFHE_Integer b,
                                LuxFHE_Integer* out);

LuxFHE_Error luxfhe_int_bitor(LuxFHE_Evaluator eval,
                               LuxFHE_Integer a,
                               LuxFHE_Integer b,
                               LuxFHE_Integer* out);

LuxFHE_Error luxfhe_int_bitxor(LuxFHE_Evaluator eval,
                                LuxFHE_Integer a,
                                LuxFHE_Integer b,
                                LuxFHE_Integer* out);

LuxFHE_Error luxfhe_int_bitnot(LuxFHE_Evaluator eval,
                                LuxFHE_Integer a,
                                LuxFHE_Integer* out);

LuxFHE_Error luxfhe_int_shl(LuxFHE_Evaluator eval,
                             LuxFHE_Integer a,
                             uint32_t bits,
                             LuxFHE_Integer* out);

LuxFHE_Error luxfhe_int_shr(LuxFHE_Evaluator eval,
                             LuxFHE_Integer a,
                             uint32_t bits,
                             LuxFHE_Integer* out);

// =============================================================================
// Control Flow
// =============================================================================

// Select: if cond then if_true else if_false
LuxFHE_Error luxfhe_int_select(LuxFHE_Evaluator eval,
                                LuxFHE_Ciphertext cond,
                                LuxFHE_Integer if_true,
                                LuxFHE_Integer if_false,
                                LuxFHE_Integer* out);

// =============================================================================
// Serialization
// =============================================================================

// Serialize to bytes (caller must free with luxfhe_bytes_free)
LuxFHE_Error luxfhe_secretkey_serialize(LuxFHE_SecretKey sk,
                                         uint8_t** data, size_t* len);

LuxFHE_Error luxfhe_publickey_serialize(LuxFHE_PublicKey pk,
                                         uint8_t** data, size_t* len);

LuxFHE_Error luxfhe_ciphertext_serialize(LuxFHE_Ciphertext ct,
                                          uint8_t** data, size_t* len);

LuxFHE_Error luxfhe_integer_serialize(LuxFHE_Integer ct,
                                       uint8_t** data, size_t* len);

// Deserialize from bytes
LuxFHE_Error luxfhe_secretkey_deserialize(LuxFHE_Context ctx,
                                           const uint8_t* data, size_t len,
                                           LuxFHE_SecretKey* out);

LuxFHE_Error luxfhe_publickey_deserialize(LuxFHE_Context ctx,
                                           const uint8_t* data, size_t len,
                                           LuxFHE_PublicKey* out);

LuxFHE_Error luxfhe_ciphertext_deserialize(LuxFHE_Context ctx,
                                            const uint8_t* data, size_t len,
                                            LuxFHE_Ciphertext* out);

LuxFHE_Error luxfhe_integer_deserialize(LuxFHE_Context ctx,
                                         const uint8_t* data, size_t len,
                                         LuxFHE_Integer* out);

// Free serialized bytes
void luxfhe_bytes_free(uint8_t* data);

#ifdef __cplusplus
}
#endif

#endif // LUXFHE_H
