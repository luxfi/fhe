// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025, Lux Industries Inc
//
// C bridge header for OpenFHE BinFHE (TFHE) operations
// This header defines the C interface that Go calls via CGO

#ifndef TFHE_BRIDGE_H
#define TFHE_BRIDGE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// Opaque handle types
typedef void* TfheContext;
typedef void* TfheSecretKey;
typedef void* TfhePublicKey;
typedef void* TfheCiphertext;
typedef void* TfheBootstrapKey;

// Security levels matching OpenFHE BINFHE_PARAMSET
typedef enum {
    TFHE_TOY = 0,            // ~16-bit security (testing only)
    TFHE_STD128 = 1,         // 128-bit security (CGGI/GINX)
    TFHE_STD128_AP = 2,      // 128-bit security (AP variant)
    TFHE_STD128_LMKCDEY = 3, // 128-bit security (LMKCDEY - fastest)
    TFHE_STD192 = 4,         // 192-bit security
    TFHE_STD256 = 5          // 256-bit security
} TfheSecurityLevel;

// Bootstrapping method
typedef enum {
    TFHE_METHOD_GINX = 0,    // GINX (default)
    TFHE_METHOD_AP = 1,      // AP variant
    TFHE_METHOD_LMKCDEY = 2  // LMKCDEY (fastest)
} TfheMethod;

// =============================================================================
// Context Management
// =============================================================================

// Create a new TFHE context with specified security level and method
TfheContext tfhe_context_new(TfheSecurityLevel level, TfheMethod method);

// Free a TFHE context
void tfhe_context_free(TfheContext ctx);

// Get version of the bridge library
uint32_t tfhe_version(void);

// =============================================================================
// Key Generation
// =============================================================================

// Generate a secret key
TfheSecretKey tfhe_keygen(TfheContext ctx);

// Free a secret key
void tfhe_secretkey_free(TfheSecretKey sk);

// Generate bootstrap key (required for gate evaluation)
int tfhe_bootstrap_keygen(TfheContext ctx, TfheSecretKey sk);

// Generate key switching key
int tfhe_keyswitch_keygen(TfheContext ctx, TfheSecretKey sk);

// Check if bootstrap key is generated
bool tfhe_has_bootstrap_key(TfheContext ctx);

// =============================================================================
// Public Key Generation
// =============================================================================

// Generate a public key from secret key
TfhePublicKey tfhe_public_keygen(TfheContext ctx, TfheSecretKey sk);

// Free a public key
void tfhe_public_key_free(TfhePublicKey pk);

// Serialize public key to bytes
int tfhe_publickey_serialize(TfhePublicKey pk, uint8_t** out, size_t* out_len);

// Deserialize public key from bytes
TfhePublicKey tfhe_publickey_deserialize(TfheContext ctx, const uint8_t* data, size_t len);

// =============================================================================
// Encryption / Decryption (Boolean)
// =============================================================================

// Encrypt a boolean value (0 or 1)
TfheCiphertext tfhe_encrypt(TfheContext ctx, TfheSecretKey sk, int value);

// Encrypt a bit (alias for tfhe_encrypt)
TfheCiphertext tfhe_encrypt_bit(TfheContext ctx, TfheSecretKey sk, int value);

// Encrypt a bit with public key
TfheCiphertext tfhe_encrypt_bit_public(TfheContext ctx, TfhePublicKey pk, int value);

// Decrypt a ciphertext to boolean
int tfhe_decrypt(TfheContext ctx, TfheSecretKey sk, TfheCiphertext ct);

// Decrypt a bit (alias for tfhe_decrypt)
int tfhe_decrypt_bit(TfheContext ctx, TfheSecretKey sk, TfheCiphertext ct);

// Free a ciphertext
void tfhe_ciphertext_free(TfheCiphertext ct);

// Free a secret key (alias for backward compatibility)
void tfhe_secret_key_free(TfheSecretKey sk);

// Clone a ciphertext
TfheCiphertext tfhe_ciphertext_clone(TfheCiphertext ct);

// =============================================================================
// Boolean Gates (with bootstrapping)
// =============================================================================

TfheCiphertext tfhe_and(TfheContext ctx, TfheCiphertext ct1, TfheCiphertext ct2);
TfheCiphertext tfhe_or(TfheContext ctx, TfheCiphertext ct1, TfheCiphertext ct2);
TfheCiphertext tfhe_xor(TfheContext ctx, TfheCiphertext ct1, TfheCiphertext ct2);
TfheCiphertext tfhe_nand(TfheContext ctx, TfheCiphertext ct1, TfheCiphertext ct2);
TfheCiphertext tfhe_nor(TfheContext ctx, TfheCiphertext ct1, TfheCiphertext ct2);
TfheCiphertext tfhe_xnor(TfheContext ctx, TfheCiphertext ct1, TfheCiphertext ct2);
TfheCiphertext tfhe_not(TfheContext ctx, TfheCiphertext ct);
TfheCiphertext tfhe_mux(TfheContext ctx, TfheCiphertext sel, TfheCiphertext ct1, TfheCiphertext ct2);

// =============================================================================
// Integer Operations (radix representation)
// =============================================================================

// Integer ciphertext handle
typedef void* TfheInteger;

// Integer types
typedef enum {
    TFHE_UINT4 = 4,
    TFHE_UINT8 = 8,
    TFHE_UINT16 = 16,
    TFHE_UINT32 = 32,
    TFHE_UINT64 = 64,
    TFHE_UINT128 = 128,
    TFHE_UINT160 = 160,
    TFHE_UINT256 = 256
} TfheIntType;

// Encrypt an integer
TfheInteger tfhe_encrypt_integer(TfheContext ctx, TfheSecretKey sk, int64_t value, int bitLen);

// Encrypt an integer with public key
TfheInteger tfhe_encrypt_integer_public(TfheContext ctx, TfhePublicKey pk, int64_t value, int bitLen);

// Decrypt an integer
int64_t tfhe_decrypt_integer(TfheContext ctx, TfheSecretKey sk, TfheInteger ct);

// Free an integer ciphertext
void tfhe_integer_free(TfheInteger ct);

// Clone an integer ciphertext
TfheInteger tfhe_integer_clone(TfheInteger ct);

// Get the type of an integer ciphertext
TfheIntType tfhe_integer_type(TfheInteger ct);

// =============================================================================
// Integer Arithmetic
// =============================================================================

TfheInteger tfhe_add(TfheContext ctx, TfheInteger a, TfheInteger b);
TfheInteger tfhe_sub(TfheContext ctx, TfheInteger a, TfheInteger b);
TfheInteger tfhe_neg(TfheContext ctx, TfheInteger a);
TfheInteger tfhe_add_scalar(TfheContext ctx, TfheInteger a, int64_t scalar);
TfheInteger tfhe_sub_scalar(TfheContext ctx, TfheInteger a, int64_t scalar);
TfheInteger tfhe_mul_scalar(TfheContext ctx, TfheInteger a, int64_t scalar);

// =============================================================================
// Integer Comparisons
// =============================================================================

TfheCiphertext tfhe_eq(TfheContext ctx, TfheInteger a, TfheInteger b);
TfheCiphertext tfhe_ne(TfheContext ctx, TfheInteger a, TfheInteger b);
TfheCiphertext tfhe_lt(TfheContext ctx, TfheInteger a, TfheInteger b);
TfheCiphertext tfhe_le(TfheContext ctx, TfheInteger a, TfheInteger b);
TfheCiphertext tfhe_gt(TfheContext ctx, TfheInteger a, TfheInteger b);
TfheCiphertext tfhe_ge(TfheContext ctx, TfheInteger a, TfheInteger b);
TfheInteger tfhe_min(TfheContext ctx, TfheInteger a, TfheInteger b);
TfheInteger tfhe_max(TfheContext ctx, TfheInteger a, TfheInteger b);

// =============================================================================
// Integer Bitwise Operations
// =============================================================================

TfheInteger tfhe_bitwise_and(TfheContext ctx, TfheInteger a, TfheInteger b);
TfheInteger tfhe_bitwise_or(TfheContext ctx, TfheInteger a, TfheInteger b);
TfheInteger tfhe_bitwise_xor(TfheContext ctx, TfheInteger a, TfheInteger b);
TfheInteger tfhe_bitwise_not(TfheContext ctx, TfheInteger a);
TfheInteger tfhe_shl(TfheContext ctx, TfheInteger a, int bits);
TfheInteger tfhe_shr(TfheContext ctx, TfheInteger a, int bits);

// =============================================================================
// Control Flow
// =============================================================================

TfheInteger tfhe_select(TfheContext ctx, TfheCiphertext cond, TfheInteger if_true, TfheInteger if_false);
TfheInteger tfhe_cast_to(TfheContext ctx, TfheInteger a, int target_bitlen);

// =============================================================================
// Serialization
// =============================================================================

// Serialize ciphertext to bytes (returns malloc'd buffer, caller must free)
uint8_t* tfhe_serialize_ciphertext(TfheContext ctx, TfheCiphertext ct, size_t* out_len);

// Deserialize ciphertext from bytes
TfheCiphertext tfhe_deserialize_ciphertext(TfheContext ctx, const uint8_t* data, size_t len);

// Serialize secret key to bytes (returns malloc'd buffer, caller must free)
uint8_t* tfhe_serialize_secret_key(TfheContext ctx, TfheSecretKey sk, size_t* out_len);

// Deserialize secret key from bytes
TfheSecretKey tfhe_deserialize_secret_key(TfheContext ctx, const uint8_t* data, size_t len);

// Serialize public key to bytes (returns malloc'd buffer, caller must free)
uint8_t* tfhe_serialize_public_key(TfheContext ctx, TfhePublicKey pk, size_t* out_len);

// Deserialize public key from bytes
TfhePublicKey tfhe_deserialize_public_key(TfheContext ctx, const uint8_t* data, size_t len);

// Serialize integer ciphertext to bytes (returns malloc'd buffer, caller must free)
uint8_t* tfhe_serialize_integer(TfheContext ctx, TfheInteger ct, size_t* out_len);

// Deserialize integer ciphertext from bytes
TfheInteger tfhe_deserialize_integer(TfheContext ctx, const uint8_t* data, size_t len);

#ifdef __cplusplus
}
#endif

#endif // TFHE_BRIDGE_H
