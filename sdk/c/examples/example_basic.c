// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025, Lux Industries Inc
//
// Basic example demonstrating LuxFHE C API

#include <stdio.h>
#include <stdlib.h>
#include "luxfhe.h"

int main(void) {
    printf("LuxFHE Basic Example\n");
    printf("====================\n\n");
    
    // Print version
    printf("Library version: %s\n\n", luxfhe_version());
    
    // Create context with standard 128-bit security parameters
    printf("Creating context...\n");
    LuxFHE_Context ctx = NULL;
    LuxFHE_Error err = luxfhe_context_new(LUXFHE_PARAMS_PN10QP27, &ctx);
    if (err != LUXFHE_OK) {
        fprintf(stderr, "Failed to create context: %s\n", luxfhe_error_string(err));
        return 1;
    }
    
    // Print parameter info
    int n_lwe, n_br;
    uint64_t q_lwe, q_br;
    luxfhe_context_params(ctx, &n_lwe, &n_br, &q_lwe, &q_br);
    printf("Parameters: LWE N=%d Q=%lu, BR N=%d Q=%lu\n\n", n_lwe, q_lwe, n_br, q_br);
    
    // Generate keys
    printf("Generating keys...\n");
    LuxFHE_SecretKey sk = NULL;
    LuxFHE_PublicKey pk = NULL;
    LuxFHE_BootstrapKey bsk = NULL;
    
    err = luxfhe_keygen_all(ctx, &sk, &pk, &bsk);
    if (err != LUXFHE_OK) {
        fprintf(stderr, "Failed to generate keys: %s\n", luxfhe_error_string(err));
        luxfhe_context_free(ctx);
        return 1;
    }
    printf("Keys generated successfully!\n\n");
    
    // Create encryptor, decryptor, evaluator
    LuxFHE_Encryptor enc = NULL;
    LuxFHE_Decryptor dec = NULL;
    LuxFHE_Evaluator eval = NULL;
    
    luxfhe_encryptor_new_sk(ctx, sk, &enc);
    luxfhe_decryptor_new(ctx, sk, &dec);
    luxfhe_evaluator_new(ctx, bsk, &eval);
    
    // Demonstrate encryption and gates
    printf("Demonstrating homomorphic computation:\n");
    printf("--------------------------------------\n\n");
    
    // Encrypt two bits
    bool a = true;
    bool b = false;
    printf("Input: a = %s, b = %s\n\n", a ? "true" : "false", b ? "true" : "false");
    
    LuxFHE_Ciphertext ct_a = NULL;
    LuxFHE_Ciphertext ct_b = NULL;
    luxfhe_encrypt_bool(enc, a, &ct_a);
    luxfhe_encrypt_bool(enc, b, &ct_b);
    
    // AND gate
    LuxFHE_Ciphertext ct_and = NULL;
    luxfhe_and(eval, ct_a, ct_b, &ct_and);
    bool result;
    luxfhe_decrypt_bool(dec, ct_and, &result);
    printf("AND(a, b) = %s (expected: %s)\n", 
           result ? "true" : "false",
           (a && b) ? "true" : "false");
    
    // OR gate
    LuxFHE_Ciphertext ct_or = NULL;
    luxfhe_or(eval, ct_a, ct_b, &ct_or);
    luxfhe_decrypt_bool(dec, ct_or, &result);
    printf("OR(a, b)  = %s (expected: %s)\n", 
           result ? "true" : "false",
           (a || b) ? "true" : "false");
    
    // XOR gate
    LuxFHE_Ciphertext ct_xor = NULL;
    luxfhe_xor(eval, ct_a, ct_b, &ct_xor);
    luxfhe_decrypt_bool(dec, ct_xor, &result);
    printf("XOR(a, b) = %s (expected: %s)\n", 
           result ? "true" : "false",
           (a ^ b) ? "true" : "false");
    
    // NOT gate
    LuxFHE_Ciphertext ct_not = NULL;
    luxfhe_not(eval, ct_a, &ct_not);
    luxfhe_decrypt_bool(dec, ct_not, &result);
    printf("NOT(a)    = %s (expected: %s)\n", 
           result ? "true" : "false",
           (!a) ? "true" : "false");
    
    // MUX gate
    printf("\nMUX demonstration:\n");
    LuxFHE_Ciphertext ct_sel = NULL;
    luxfhe_encrypt_bool(enc, true, &ct_sel);
    
    LuxFHE_Ciphertext ct_mux = NULL;
    luxfhe_mux(eval, ct_sel, ct_a, ct_b, &ct_mux);
    luxfhe_decrypt_bool(dec, ct_mux, &result);
    printf("MUX(true, a, b)  = %s (should select a = %s)\n", 
           result ? "true" : "false",
           a ? "true" : "false");
    
    luxfhe_ciphertext_free(ct_sel);
    luxfhe_encrypt_bool(enc, false, &ct_sel);
    luxfhe_mux(eval, ct_sel, ct_a, ct_b, &ct_mux);
    luxfhe_decrypt_bool(dec, ct_mux, &result);
    printf("MUX(false, a, b) = %s (should select b = %s)\n", 
           result ? "true" : "false",
           b ? "true" : "false");
    
    printf("\nAll operations completed successfully!\n");
    
    // Cleanup
    luxfhe_ciphertext_free(ct_a);
    luxfhe_ciphertext_free(ct_b);
    luxfhe_ciphertext_free(ct_and);
    luxfhe_ciphertext_free(ct_or);
    luxfhe_ciphertext_free(ct_xor);
    luxfhe_ciphertext_free(ct_not);
    luxfhe_ciphertext_free(ct_sel);
    luxfhe_ciphertext_free(ct_mux);
    luxfhe_evaluator_free(eval);
    luxfhe_encryptor_free(enc);
    luxfhe_decryptor_free(dec);
    luxfhe_secretkey_free(sk);
    luxfhe_publickey_free(pk);
    luxfhe_bootstrapkey_free(bsk);
    luxfhe_context_free(ctx);
    
    return 0;
}
