// Integration tests for LuxFHE Rust bindings
// These tests require the C library to be available

use luxfhe::*;

#[test]
#[ignore] // Requires C library at runtime
fn test_context_creation() {
    let ctx = Context::new(ParamSet::PN10QP27).expect("Failed to create context");
    drop(ctx);
}

#[test]
#[ignore] // Requires C library at runtime
fn test_key_generation() {
    let ctx = Context::new(ParamSet::PN10QP27).expect("Failed to create context");
    let sk = ctx.keygen_secret().expect("Failed to generate secret key");
    let pk = ctx.keygen_public(&sk).expect("Failed to generate public key");
    let bk = ctx.keygen_bootstrap(&sk).expect("Failed to generate bootstrap key");
    
    drop(bk);
    drop(pk);
    drop(sk);
    drop(ctx);
}

#[test]
#[ignore] // Requires C library at runtime
fn test_encrypt_decrypt_bool() {
    let ctx = Context::new(ParamSet::PN10QP27).expect("Failed to create context");
    let sk = ctx.keygen_secret().expect("Failed to generate secret key");
    
    let enc = ctx.encryptor_sk(&sk).expect("Failed to create encryptor");
    let dec = ctx.decryptor(&sk).expect("Failed to create decryptor");
    
    // Test true
    let ct_true = enc.encrypt(true).expect("Failed to encrypt true");
    let pt_true = dec.decrypt(&ct_true).expect("Failed to decrypt");
    assert_eq!(pt_true, true);
    
    // Test false
    let ct_false = enc.encrypt(false).expect("Failed to encrypt false");
    let pt_false = dec.decrypt(&ct_false).expect("Failed to decrypt");
    assert_eq!(pt_false, false);
}

#[test]
#[ignore] // Requires C library at runtime
fn test_public_key_encryption() {
    let ctx = Context::new(ParamSet::PN10QP27).expect("Failed to create context");
    let sk = ctx.keygen_secret().expect("Failed to generate secret key");
    let pk = ctx.keygen_public(&sk).expect("Failed to generate public key");
    
    let enc = ctx.encryptor_pk(&pk).expect("Failed to create public encryptor");
    let dec = ctx.decryptor(&sk).expect("Failed to create decryptor");
    
    // Encrypt with public key, decrypt with secret key
    let ct = enc.encrypt(true).expect("Failed to encrypt");
    let pt = dec.decrypt(&ct).expect("Failed to decrypt");
    assert_eq!(pt, true);
}

#[test]
#[ignore] // Requires C library at runtime
fn test_gate_operations() {
    let ctx = Context::new(ParamSet::PN10QP27).expect("Failed to create context");
    let sk = ctx.keygen_secret().expect("Failed to generate secret key");
    let bk = ctx.keygen_bootstrap(&sk).expect("Failed to generate bootstrap key");
    
    let enc = ctx.encryptor_sk(&sk).expect("Failed to create encryptor");
    let dec = ctx.decryptor(&sk).expect("Failed to create decryptor");
    let eval = ctx.evaluator(&bk, &sk).expect("Failed to create evaluator");
    
    let ct_true = enc.encrypt(true).expect("Failed to encrypt");
    let ct_false = enc.encrypt(false).expect("Failed to encrypt");
    
    // Test AND gate
    let ct_and = eval.and(&ct_true, &ct_false).expect("AND failed");
    assert_eq!(dec.decrypt(&ct_and).unwrap(), false);
    
    // Test OR gate
    let ct_or = eval.or(&ct_true, &ct_false).expect("OR failed");
    assert_eq!(dec.decrypt(&ct_or).unwrap(), true);
    
    // Test XOR gate
    let ct_xor = eval.xor(&ct_true, &ct_false).expect("XOR failed");
    assert_eq!(dec.decrypt(&ct_xor).unwrap(), true);
    
    // Test NOT gate
    let ct_not = eval.not(&ct_true).expect("NOT failed");
    assert_eq!(dec.decrypt(&ct_not).unwrap(), false);
    
    // Test NAND gate
    let ct_nand = eval.nand(&ct_true, &ct_true).expect("NAND failed");
    assert_eq!(dec.decrypt(&ct_nand).unwrap(), false);
}

// Note: Byte operations require ByteCiphertext type
// Will be added when Integer/ByteCiphertext types are implemented
