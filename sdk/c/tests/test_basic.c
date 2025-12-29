// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025, Lux Industries Inc
//
// Basic tests for LuxFHE C API

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "luxfhe.h"

#define TEST(name) printf("Testing %s... ", #name)
#define PASS() printf("PASS\n")
#define FAIL(msg) do { printf("FAIL: %s\n", msg); exit(1); } while(0)
#define CHECK(cond, msg) do { if (!(cond)) FAIL(msg); } while(0)

void test_version(void) {
    TEST(version);
    
    const char* ver = luxfhe_version();
    CHECK(ver != NULL, "version is null");
    printf("(v%s) ", ver);
    
    int major, minor, patch;
    luxfhe_version_info(&major, &minor, &patch);
    CHECK(major == 1, "major version mismatch");
    CHECK(minor == 0, "minor version mismatch");
    CHECK(patch == 0, "patch version mismatch");
    
    PASS();
}

void test_error_strings(void) {
    TEST(error_strings);
    
    const char* msg = luxfhe_error_string(LUXFHE_OK);
    CHECK(msg != NULL, "error string is null");
    
    msg = luxfhe_error_string(LUXFHE_ERR_NULL_POINTER);
    CHECK(msg != NULL, "error string is null");
    
    PASS();
}

void test_context(void) {
    TEST(context);
    
    LuxFHE_Context ctx = NULL;
    LuxFHE_Error err = luxfhe_context_new(LUXFHE_PARAMS_PN10QP27, &ctx);
    CHECK(err == LUXFHE_OK, "failed to create context");
    CHECK(ctx != NULL, "context is null");
    
    int n_lwe, n_br;
    uint64_t q_lwe, q_br;
    err = luxfhe_context_params(ctx, &n_lwe, &n_br, &q_lwe, &q_br);
    CHECK(err == LUXFHE_OK, "failed to get params");
    CHECK(n_lwe > 0, "n_lwe should be positive");
    CHECK(n_br > 0, "n_br should be positive");
    
    luxfhe_context_free(ctx);
    PASS();
}

void test_keygen(void) {
    TEST(keygen);
    
    LuxFHE_Context ctx = NULL;
    LuxFHE_Error err = luxfhe_context_new(LUXFHE_PARAMS_PN10QP27, &ctx);
    CHECK(err == LUXFHE_OK, "failed to create context");
    
    LuxFHE_SecretKey sk = NULL;
    LuxFHE_PublicKey pk = NULL;
    LuxFHE_BootstrapKey bsk = NULL;
    
    err = luxfhe_keygen_all(ctx, &sk, &pk, &bsk);
    CHECK(err == LUXFHE_OK, "failed to generate keys");
    CHECK(sk != NULL, "secret key is null");
    CHECK(pk != NULL, "public key is null");
    CHECK(bsk != NULL, "bootstrap key is null");
    
    luxfhe_secretkey_free(sk);
    luxfhe_publickey_free(pk);
    luxfhe_bootstrapkey_free(bsk);
    luxfhe_context_free(ctx);
    PASS();
}

void test_encrypt_decrypt_bool(void) {
    TEST(encrypt_decrypt_bool);
    
    LuxFHE_Context ctx = NULL;
    luxfhe_context_new(LUXFHE_PARAMS_PN10QP27, &ctx);
    
    LuxFHE_SecretKey sk = NULL;
    LuxFHE_PublicKey pk = NULL;
    LuxFHE_BootstrapKey bsk = NULL;
    luxfhe_keygen_all(ctx, &sk, &pk, &bsk);
    
    LuxFHE_Encryptor enc = NULL;
    LuxFHE_Decryptor dec = NULL;
    luxfhe_encryptor_new_sk(ctx, sk, &enc);
    luxfhe_decryptor_new(ctx, sk, &dec);
    
    // Test true
    LuxFHE_Ciphertext ct_true = NULL;
    LuxFHE_Error err = luxfhe_encrypt_bool(enc, true, &ct_true);
    CHECK(err == LUXFHE_OK, "failed to encrypt true");
    
    bool result;
    err = luxfhe_decrypt_bool(dec, ct_true, &result);
    CHECK(err == LUXFHE_OK, "failed to decrypt");
    CHECK(result == true, "expected true");
    
    // Test false
    LuxFHE_Ciphertext ct_false = NULL;
    err = luxfhe_encrypt_bool(enc, false, &ct_false);
    CHECK(err == LUXFHE_OK, "failed to encrypt false");
    
    err = luxfhe_decrypt_bool(dec, ct_false, &result);
    CHECK(err == LUXFHE_OK, "failed to decrypt");
    CHECK(result == false, "expected false");
    
    luxfhe_ciphertext_free(ct_true);
    luxfhe_ciphertext_free(ct_false);
    luxfhe_encryptor_free(enc);
    luxfhe_decryptor_free(dec);
    luxfhe_secretkey_free(sk);
    luxfhe_publickey_free(pk);
    luxfhe_bootstrapkey_free(bsk);
    luxfhe_context_free(ctx);
    PASS();
}

void test_gates(void) {
    TEST(gates);
    
    LuxFHE_Context ctx = NULL;
    luxfhe_context_new(LUXFHE_PARAMS_PN10QP27, &ctx);
    
    LuxFHE_SecretKey sk = NULL;
    LuxFHE_PublicKey pk = NULL;
    LuxFHE_BootstrapKey bsk = NULL;
    luxfhe_keygen_all(ctx, &sk, &pk, &bsk);
    
    LuxFHE_Encryptor enc = NULL;
    LuxFHE_Decryptor dec = NULL;
    LuxFHE_Evaluator eval = NULL;
    luxfhe_encryptor_new_sk(ctx, sk, &enc);
    luxfhe_decryptor_new(ctx, sk, &dec);
    luxfhe_evaluator_new(ctx, bsk, &eval);
    
    // Encrypt inputs
    LuxFHE_Ciphertext ct_true = NULL;
    LuxFHE_Ciphertext ct_false = NULL;
    luxfhe_encrypt_bool(enc, true, &ct_true);
    luxfhe_encrypt_bool(enc, false, &ct_false);
    
    // Test AND
    LuxFHE_Ciphertext ct_and = NULL;
    LuxFHE_Error err = luxfhe_and(eval, ct_true, ct_false, &ct_and);
    CHECK(err == LUXFHE_OK, "AND failed");
    bool result;
    luxfhe_decrypt_bool(dec, ct_and, &result);
    CHECK(result == false, "AND(true, false) should be false");
    
    // Test OR
    LuxFHE_Ciphertext ct_or = NULL;
    err = luxfhe_or(eval, ct_true, ct_false, &ct_or);
    CHECK(err == LUXFHE_OK, "OR failed");
    luxfhe_decrypt_bool(dec, ct_or, &result);
    CHECK(result == true, "OR(true, false) should be true");
    
    // Test NOT
    LuxFHE_Ciphertext ct_not = NULL;
    err = luxfhe_not(eval, ct_true, &ct_not);
    CHECK(err == LUXFHE_OK, "NOT failed");
    luxfhe_decrypt_bool(dec, ct_not, &result);
    CHECK(result == false, "NOT(true) should be false");
    
    // Cleanup
    luxfhe_ciphertext_free(ct_true);
    luxfhe_ciphertext_free(ct_false);
    luxfhe_ciphertext_free(ct_and);
    luxfhe_ciphertext_free(ct_or);
    luxfhe_ciphertext_free(ct_not);
    luxfhe_evaluator_free(eval);
    luxfhe_encryptor_free(enc);
    luxfhe_decryptor_free(dec);
    luxfhe_secretkey_free(sk);
    luxfhe_publickey_free(pk);
    luxfhe_bootstrapkey_free(bsk);
    luxfhe_context_free(ctx);
    PASS();
}

int main(void) {
    printf("LuxFHE C API Tests\n");
    printf("==================\n\n");
    
    test_version();
    test_error_strings();
    test_context();
    test_keygen();
    test_encrypt_decrypt_bool();
    test_gates();
    
    printf("\nAll tests passed!\n");
    return 0;
}
