// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025, Lux Industries Inc
//
// Example: Encrypted comparison using LuxFHE
// Demonstrates how to compare encrypted integers without revealing values

#include <stdio.h>
#include <stdlib.h>
#include "luxfhe.h"

// Compare two encrypted bytes (a < b)
// This is a simple ripple comparator implementation
LuxFHE_Error compare_bytes(
    LuxFHE_Evaluator eval,
    LuxFHE_Decryptor dec,
    LuxFHE_Ciphertext a_bits[8],
    LuxFHE_Ciphertext b_bits[8],
    LuxFHE_Ciphertext* result
) {
    // Start with "less than" = false
    // For each bit from MSB to LSB:
    //   lt = lt OR (eq AND (NOT a_i) AND b_i)
    //   eq = eq AND (a_i XNOR b_i)
    
    // This is simplified - real implementation would use encrypted lt and eq
    // For demonstration, we'll use gate composition
    
    // ... (implementation would go here)
    // For now, just return an error as this requires full integer support
    return LUXFHE_ERR_OPERATION;
}

int main(void) {
    printf("LuxFHE Encrypted Comparison Example\n");
    printf("====================================\n\n");
    
    printf("This example demonstrates encrypted comparison.\n");
    printf("Two encrypted integers can be compared without decrypting them!\n\n");
    
    // Create context
    LuxFHE_Context ctx = NULL;
    LuxFHE_Error err = luxfhe_context_new(LUXFHE_PARAMS_PN10QP27, &ctx);
    if (err != LUXFHE_OK) {
        fprintf(stderr, "Failed to create context\n");
        return 1;
    }
    
    // Generate keys
    LuxFHE_SecretKey sk = NULL;
    LuxFHE_PublicKey pk = NULL;
    LuxFHE_BootstrapKey bsk = NULL;
    luxfhe_keygen_all(ctx, &sk, &pk, &bsk);
    
    // Create components
    LuxFHE_Encryptor enc = NULL;
    LuxFHE_Decryptor dec = NULL;
    LuxFHE_Evaluator eval = NULL;
    luxfhe_encryptor_new_sk(ctx, sk, &enc);
    luxfhe_decryptor_new(ctx, sk, &dec);
    luxfhe_evaluator_new(ctx, bsk, &eval);
    
    // Demonstrate the concept with single bits
    printf("Single-bit comparison demo:\n");
    printf("---------------------------\n");
    
    // a < b for single bits: (NOT a) AND b
    bool a = false;
    bool b = true;
    printf("Comparing: a = %s, b = %s\n", a ? "1" : "0", b ? "1" : "0");
    printf("Expected: a < b = %s\n", (a < b) ? "true" : "false");
    
    LuxFHE_Ciphertext ct_a = NULL;
    LuxFHE_Ciphertext ct_b = NULL;
    luxfhe_encrypt_bool(enc, a, &ct_a);
    luxfhe_encrypt_bool(enc, b, &ct_b);
    
    // Compute (NOT a) AND b
    LuxFHE_Ciphertext ct_not_a = NULL;
    luxfhe_not(eval, ct_a, &ct_not_a);
    
    LuxFHE_Ciphertext ct_lt = NULL;
    luxfhe_and(eval, ct_not_a, ct_b, &ct_lt);
    
    bool result;
    luxfhe_decrypt_bool(dec, ct_lt, &result);
    printf("Computed: a < b = %s\n", result ? "true" : "false");
    
    // Test equality: a XNOR b
    printf("\nEquality test:\n");
    LuxFHE_Ciphertext ct_eq = NULL;
    luxfhe_xnor(eval, ct_a, ct_b, &ct_eq);
    luxfhe_decrypt_bool(dec, ct_eq, &result);
    printf("a == b = %s (expected: %s)\n", 
           result ? "true" : "false",
           (a == b) ? "true" : "false");
    
    printf("\nNote: Full multi-bit comparison requires integer operations.\n");
    printf("See the integer API for complete comparison functionality.\n");
    
    // Cleanup
    luxfhe_ciphertext_free(ct_a);
    luxfhe_ciphertext_free(ct_b);
    luxfhe_ciphertext_free(ct_not_a);
    luxfhe_ciphertext_free(ct_lt);
    luxfhe_ciphertext_free(ct_eq);
    luxfhe_evaluator_free(eval);
    luxfhe_encryptor_free(enc);
    luxfhe_decryptor_free(dec);
    luxfhe_secretkey_free(sk);
    luxfhe_publickey_free(pk);
    luxfhe_bootstrapkey_free(bsk);
    luxfhe_context_free(ctx);
    
    return 0;
}
