// C++ compatibility test for LuxFHE
// Compile with: clang++ -std=c++17 -I../include -L../lib -lluxfhe cpp_test.cpp -o cpp_test

#include <iostream>
#include <cassert>
#include "luxfhe.h"

int main() {
    std::cout << "LuxFHE C++ Compatibility Test\n";
    std::cout << "==============================\n\n";
    
    // Get version info
    const char* version = luxfhe_version();
    std::cout << "Version: " << version << "\n\n";
    
    // Create context
    LuxFHE_Context ctx = nullptr;
    LuxFHE_Error err = luxfhe_context_new(LUXFHE_PARAMS_PN10QP27, &ctx);
    assert(err == LUXFHE_OK && "Context creation failed");
    std::cout << "✓ Context created\n";
    
    // Generate keys
    LuxFHE_SecretKey sk = nullptr;
    LuxFHE_PublicKey pk = nullptr;
    LuxFHE_BootstrapKey bsk = nullptr;
    
    err = luxfhe_keygen_secret(ctx, &sk);
    assert(err == LUXFHE_OK && "Secret key generation failed");
    std::cout << "✓ Secret key generated\n";
    
    err = luxfhe_keygen_public(ctx, sk, &pk);
    assert(err == LUXFHE_OK && "Public key generation failed");
    std::cout << "✓ Public key generated\n";
    
    err = luxfhe_keygen_bootstrap(ctx, sk, &bsk);
    assert(err == LUXFHE_OK && "Bootstrap key generation failed");
    std::cout << "✓ Bootstrap key generated\n";
    
    // Create encryptor with secret key
    LuxFHE_Encryptor enc_sk = nullptr;
    err = luxfhe_encryptor_new_sk(ctx, sk, &enc_sk);
    assert(err == LUXFHE_OK && "Secret key encryptor creation failed");
    std::cout << "✓ Secret key encryptor created\n";
    
    // Create encryptor with public key
    LuxFHE_Encryptor enc_pk = nullptr;
    err = luxfhe_encryptor_new_pk(ctx, pk, &enc_pk);
    assert(err == LUXFHE_OK && "Public key encryptor creation failed");
    std::cout << "✓ Public key encryptor created\n";
    
    // Create decryptor
    LuxFHE_Decryptor dec = nullptr;
    err = luxfhe_decryptor_new(ctx, sk, &dec);
    assert(err == LUXFHE_OK && "Decryptor creation failed");
    std::cout << "✓ Decryptor created\n";
    
    // Create evaluator
    LuxFHE_Evaluator eval = nullptr;
    err = luxfhe_evaluator_new(ctx, bsk, sk, &eval);
    assert(err == LUXFHE_OK && "Evaluator creation failed");
    std::cout << "✓ Evaluator created\n";
    
    // Encrypt booleans
    LuxFHE_Ciphertext ct_true = nullptr;
    LuxFHE_Ciphertext ct_false = nullptr;
    
    err = luxfhe_encrypt_bool(enc_sk, true, &ct_true);
    assert(err == LUXFHE_OK && "Encrypt true failed");
    
    err = luxfhe_encrypt_bool(enc_sk, false, &ct_false);
    assert(err == LUXFHE_OK && "Encrypt false failed");
    std::cout << "✓ Encrypted boolean values\n";
    
    // Decrypt and verify
    bool pt_true = false;
    bool pt_false = true;
    
    err = luxfhe_decrypt_bool(dec, ct_true, &pt_true);
    assert(err == LUXFHE_OK && "Decrypt true failed");
    assert(pt_true == true && "Decrypted value should be true");
    
    err = luxfhe_decrypt_bool(dec, ct_false, &pt_false);
    assert(err == LUXFHE_OK && "Decrypt false failed");
    assert(pt_false == false && "Decrypted value should be false");
    std::cout << "✓ Decryption verified\n";
    
    // Test public key encryption
    LuxFHE_Ciphertext ct_pk = nullptr;
    err = luxfhe_encrypt_bool(enc_pk, true, &ct_pk);
    assert(err == LUXFHE_OK && "PK encrypt failed");
    
    bool pt_pk = false;
    err = luxfhe_decrypt_bool(dec, ct_pk, &pt_pk);
    assert(err == LUXFHE_OK && "PK decrypt failed");
    assert(pt_pk == true && "PK decrypted value should be true");
    std::cout << "✓ Public key encryption verified\n";
    
    // Test gate operations
    LuxFHE_Ciphertext ct_and = nullptr;
    err = luxfhe_and(eval, ct_true, ct_false, &ct_and);
    assert(err == LUXFHE_OK && "AND gate failed");
    
    bool pt_and = true;
    err = luxfhe_decrypt_bool(dec, ct_and, &pt_and);
    assert(err == LUXFHE_OK && "Decrypt AND result failed");
    assert(pt_and == false && "AND(true, false) should be false");
    std::cout << "✓ AND gate verified\n";
    
    LuxFHE_Ciphertext ct_or = nullptr;
    err = luxfhe_or(eval, ct_true, ct_false, &ct_or);
    assert(err == LUXFHE_OK && "OR gate failed");
    
    bool pt_or = false;
    err = luxfhe_decrypt_bool(dec, ct_or, &pt_or);
    assert(err == LUXFHE_OK && "Decrypt OR result failed");
    assert(pt_or == true && "OR(true, false) should be true");
    std::cout << "✓ OR gate verified\n";
    
    // Cleanup
    luxfhe_ciphertext_free(ct_and);
    luxfhe_ciphertext_free(ct_or);
    luxfhe_ciphertext_free(ct_pk);
    luxfhe_ciphertext_free(ct_true);
    luxfhe_ciphertext_free(ct_false);
    luxfhe_evaluator_free(eval);
    luxfhe_decryptor_free(dec);
    luxfhe_encryptor_free(enc_pk);
    luxfhe_encryptor_free(enc_sk);
    luxfhe_bootstrapkey_free(bsk);
    luxfhe_publickey_free(pk);
    luxfhe_secretkey_free(sk);
    luxfhe_context_free(ctx);
    std::cout << "✓ Resources cleaned up\n";
    
    std::cout << "\n=== C++ Compatibility Test: ALL PASSED ===\n";
    return 0;
}
