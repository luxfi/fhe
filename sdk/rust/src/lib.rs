//! # LuxFHE - Rust Bindings for Fully Homomorphic Encryption
//!
//! This crate provides safe Rust bindings for the LuxFHE library,
//! enabling computation on encrypted data using TFHE (Threshold FHE).
//!
//! ## Example
//!
//! ```rust,no_run
//! use luxfhe::{Context, ParamSet};
//!
//! // Create context with standard parameters
//! let ctx = Context::new(ParamSet::PN10QP27).unwrap();
//!
//! // Generate keys
//! let (sk, pk, bsk) = ctx.keygen_all().unwrap();
//!
//! // Encrypt using public key
//! let enc = ctx.encryptor_pk(&pk).unwrap();
//! let ct_a = enc.encrypt(true).unwrap();
//! let ct_b = enc.encrypt(false).unwrap();
//!
//! // Evaluate AND gate on encrypted bits
//! let eval = ctx.evaluator(&bsk, &sk).unwrap();
//! let ct_result = eval.and(&ct_a, &ct_b).unwrap();
//!
//! // Decrypt with secret key
//! let dec = ctx.decryptor(&sk).unwrap();
//! let result = dec.decrypt(&ct_result).unwrap();
//! assert_eq!(result, false); // true AND false = false
//! ```

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

// std::ptr imported as needed by bindgen
use thiserror::Error;

// Include generated bindings
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

/// Error type for LuxFHE operations
#[derive(Error, Debug)]
pub enum LuxFHEError {
    #[error("Null pointer error")]
    NullPointer,
    #[error("Invalid parameter")]
    InvalidParam,
    #[error("Memory allocation failed")]
    Allocation,
    #[error("Library not initialized")]
    NotInitialized,
    #[error("Key not set")]
    KeyNotSet,
    #[error("Serialization error")]
    Serialization,
    #[error("Deserialization error")]
    Deserialization,
    #[error("Operation failed")]
    Operation,
    #[error("Type mismatch")]
    TypeMismatch,
    #[error("Value out of range")]
    OutOfRange,
    #[error("Unknown error: {0}")]
    Unknown(i32),
}

impl From<i32> for LuxFHEError {
    fn from(code: i32) -> Self {
        match code {
            -1 => LuxFHEError::NullPointer,
            -2 => LuxFHEError::InvalidParam,
            -3 => LuxFHEError::Allocation,
            -4 => LuxFHEError::NotInitialized,
            -5 => LuxFHEError::KeyNotSet,
            -6 => LuxFHEError::Serialization,
            -7 => LuxFHEError::Deserialization,
            -8 => LuxFHEError::Operation,
            -9 => LuxFHEError::TypeMismatch,
            -10 => LuxFHEError::OutOfRange,
            _ => LuxFHEError::Unknown(code),
        }
    }
}

pub type Result<T> = std::result::Result<T, LuxFHEError>;

fn check(code: i32) -> Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(LuxFHEError::from(code))
    }
}

/// TFHE parameter sets
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ParamSet {
    /// ~128-bit security, good performance (N=512, Q=12289)
    PN10QP27 = 0,
    /// ~128-bit security, higher precision (N=1024, Q=65537)
    PN11QP54 = 1,
}

/// TFHE Context - manages parameters and provides key generation
pub struct Context {
    handle: usize,
}

impl Context {
    /// Create a new context with the given parameter set
    pub fn new(params: ParamSet) -> Result<Self> {
        let mut handle: usize = 0;
        unsafe {
            check(luxfhe_context_new(params as u32, &mut handle as *mut usize as *mut _))?;
        }
        Ok(Context { handle })
    }

    /// Generate a secret key
    pub fn keygen_secret(&self) -> Result<SecretKey> {
        let mut handle: usize = 0;
        unsafe {
            check(luxfhe_keygen_secret(
                self.handle as *mut _,
                &mut handle as *mut usize as *mut _,
            ))?;
        }
        Ok(SecretKey { handle })
    }

    /// Generate a public key from a secret key
    pub fn keygen_public(&self, sk: &SecretKey) -> Result<PublicKey> {
        let mut handle: usize = 0;
        unsafe {
            check(luxfhe_keygen_public(
                self.handle as *mut _,
                sk.handle as *mut _,
                &mut handle as *mut usize as *mut _,
            ))?;
        }
        Ok(PublicKey { handle })
    }

    /// Generate a bootstrap key from a secret key
    pub fn keygen_bootstrap(&self, sk: &SecretKey) -> Result<BootstrapKey> {
        let mut handle: usize = 0;
        unsafe {
            check(luxfhe_keygen_bootstrap(
                self.handle as *mut _,
                sk.handle as *mut _,
                &mut handle as *mut usize as *mut _,
            ))?;
        }
        Ok(BootstrapKey { handle })
    }

    /// Generate all keys at once
    pub fn keygen_all(&self) -> Result<(SecretKey, PublicKey, BootstrapKey)> {
        let mut sk_handle: usize = 0;
        let mut pk_handle: usize = 0;
        let mut bsk_handle: usize = 0;
        unsafe {
            check(luxfhe_keygen_all(
                self.handle as *mut _,
                &mut sk_handle as *mut usize as *mut _,
                &mut pk_handle as *mut usize as *mut _,
                &mut bsk_handle as *mut usize as *mut _,
            ))?;
        }
        Ok((
            SecretKey { handle: sk_handle },
            PublicKey { handle: pk_handle },
            BootstrapKey { handle: bsk_handle },
        ))
    }

    /// Create an encryptor using a secret key
    pub fn encryptor_sk(&self, sk: &SecretKey) -> Result<Encryptor> {
        let mut handle: usize = 0;
        unsafe {
            check(luxfhe_encryptor_new_sk(
                self.handle as *mut _,
                sk.handle as *mut _,
                &mut handle as *mut usize as *mut _,
            ))?;
        }
        Ok(Encryptor { handle })
    }

    /// Create an encryptor using a public key
    pub fn encryptor_pk(&self, pk: &PublicKey) -> Result<Encryptor> {
        let mut handle: usize = 0;
        unsafe {
            check(luxfhe_encryptor_new_pk(
                self.handle as *mut _,
                pk.handle as *mut _,
                &mut handle as *mut usize as *mut _,
            ))?;
        }
        Ok(Encryptor { handle })
    }

    /// Create a decryptor
    pub fn decryptor(&self, sk: &SecretKey) -> Result<Decryptor> {
        let mut handle: usize = 0;
        unsafe {
            check(luxfhe_decryptor_new(
                self.handle as *mut _,
                sk.handle as *mut _,
                &mut handle as *mut usize as *mut _,
            ))?;
        }
        Ok(Decryptor { handle })
    }

    /// Create an evaluator (requires bootstrap key and secret key for key-switching)
    pub fn evaluator(&self, bsk: &BootstrapKey, sk: &SecretKey) -> Result<Evaluator> {
        let mut handle: usize = 0;
        unsafe {
            check(luxfhe_evaluator_new(
                self.handle as *mut _,
                bsk.handle as *mut _,
                sk.handle as *mut _,
                &mut handle as *mut usize as *mut _,
            ))?;
        }
        Ok(Evaluator { handle })
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe {
            luxfhe_context_free(self.handle as *mut _);
        }
    }
}

/// TFHE Secret Key
pub struct SecretKey {
    handle: usize,
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        unsafe {
            luxfhe_secretkey_free(self.handle as *mut _);
        }
    }
}

/// TFHE Public Key
pub struct PublicKey {
    handle: usize,
}

impl Drop for PublicKey {
    fn drop(&mut self) {
        unsafe {
            luxfhe_publickey_free(self.handle as *mut _);
        }
    }
}

/// TFHE Bootstrap Key (evaluation key)
pub struct BootstrapKey {
    handle: usize,
}

impl Drop for BootstrapKey {
    fn drop(&mut self) {
        unsafe {
            luxfhe_bootstrapkey_free(self.handle as *mut _);
        }
    }
}

/// Encrypted boolean value
pub struct Ciphertext {
    handle: usize,
}

impl Ciphertext {
    /// Clone the ciphertext
    pub fn try_clone(&self) -> Result<Self> {
        let mut handle: usize = 0;
        unsafe {
            check(luxfhe_ciphertext_clone(
                self.handle as *mut _,
                &mut handle as *mut usize as *mut _,
            ))?;
        }
        Ok(Ciphertext { handle })
    }
}

impl Clone for Ciphertext {
    fn clone(&self) -> Self {
        self.try_clone().expect("Failed to clone ciphertext")
    }
}

impl Drop for Ciphertext {
    fn drop(&mut self) {
        unsafe {
            luxfhe_ciphertext_free(self.handle as *mut _);
        }
    }
}

/// Encryptor for creating ciphertexts
pub struct Encryptor {
    handle: usize,
}

impl Encryptor {
    /// Encrypt a boolean value
    pub fn encrypt(&self, value: bool) -> Result<Ciphertext> {
        let mut handle: usize = 0;
        unsafe {
            check(luxfhe_encrypt_bool(
                self.handle as *mut _,
                value,
                &mut handle as *mut usize as *mut _,
            ))?;
        }
        Ok(Ciphertext { handle })
    }

    // Note: encrypt_byte requires ByteCiphertext type (8 encrypted bits)
    // Will be added when Integer/ByteCiphertext types are implemented
}


impl Drop for Encryptor {
    fn drop(&mut self) {
        unsafe {
            luxfhe_encryptor_free(self.handle as *mut _);
        }
    }
}

/// Decryptor for decrypting ciphertexts
pub struct Decryptor {
    handle: usize,
}

impl Decryptor {
    /// Decrypt a boolean ciphertext
    pub fn decrypt(&self, ct: &Ciphertext) -> Result<bool> {
        let mut value = false;
        unsafe {
            check(luxfhe_decrypt_bool(
                self.handle as *mut _,
                ct.handle as *mut _,
                &mut value,
            ))?;
        }
        Ok(value)
    }

    // Note: decrypt_byte requires ByteCiphertext type (8 encrypted bits)
    // Will be added when Integer/ByteCiphertext types are implemented
}

impl Drop for Decryptor {
    fn drop(&mut self) {
        unsafe {
            luxfhe_decryptor_free(self.handle as *mut _);
        }
    }
}

// Note: Integer type not yet exposed in C API
// Will be added when luxfhe_integer_* functions are implemented

/// Evaluator for homomorphic operations
pub struct Evaluator {
    handle: usize,
}

impl Evaluator {
    /// NOT gate
    pub fn not(&self, ct: &Ciphertext) -> Result<Ciphertext> {
        let mut handle: usize = 0;
        unsafe {
            check(luxfhe_not(
                self.handle as *mut _,
                ct.handle as *mut _,
                &mut handle as *mut usize as *mut _,
            ))?;
        }
        Ok(Ciphertext { handle })
    }

    /// AND gate
    pub fn and(&self, a: &Ciphertext, b: &Ciphertext) -> Result<Ciphertext> {
        let mut handle: usize = 0;
        unsafe {
            check(luxfhe_and(
                self.handle as *mut _,
                a.handle as *mut _,
                b.handle as *mut _,
                &mut handle as *mut usize as *mut _,
            ))?;
        }
        Ok(Ciphertext { handle })
    }

    /// OR gate
    pub fn or(&self, a: &Ciphertext, b: &Ciphertext) -> Result<Ciphertext> {
        let mut handle: usize = 0;
        unsafe {
            check(luxfhe_or(
                self.handle as *mut _,
                a.handle as *mut _,
                b.handle as *mut _,
                &mut handle as *mut usize as *mut _,
            ))?;
        }
        Ok(Ciphertext { handle })
    }

    /// XOR gate
    pub fn xor(&self, a: &Ciphertext, b: &Ciphertext) -> Result<Ciphertext> {
        let mut handle: usize = 0;
        unsafe {
            check(luxfhe_xor(
                self.handle as *mut _,
                a.handle as *mut _,
                b.handle as *mut _,
                &mut handle as *mut usize as *mut _,
            ))?;
        }
        Ok(Ciphertext { handle })
    }

    /// NAND gate
    pub fn nand(&self, a: &Ciphertext, b: &Ciphertext) -> Result<Ciphertext> {
        let mut handle: usize = 0;
        unsafe {
            check(luxfhe_nand(
                self.handle as *mut _,
                a.handle as *mut _,
                b.handle as *mut _,
                &mut handle as *mut usize as *mut _,
            ))?;
        }
        Ok(Ciphertext { handle })
    }

    /// NOR gate
    pub fn nor(&self, a: &Ciphertext, b: &Ciphertext) -> Result<Ciphertext> {
        let mut handle: usize = 0;
        unsafe {
            check(luxfhe_nor(
                self.handle as *mut _,
                a.handle as *mut _,
                b.handle as *mut _,
                &mut handle as *mut usize as *mut _,
            ))?;
        }
        Ok(Ciphertext { handle })
    }

    /// XNOR gate
    pub fn xnor(&self, a: &Ciphertext, b: &Ciphertext) -> Result<Ciphertext> {
        let mut handle: usize = 0;
        unsafe {
            check(luxfhe_xnor(
                self.handle as *mut _,
                a.handle as *mut _,
                b.handle as *mut _,
                &mut handle as *mut usize as *mut _,
            ))?;
        }
        Ok(Ciphertext { handle })
    }

    /// MUX gate (if sel then a else b)
    pub fn mux(&self, sel: &Ciphertext, a: &Ciphertext, b: &Ciphertext) -> Result<Ciphertext> {
        let mut handle: usize = 0;
        unsafe {
            check(luxfhe_mux(
                self.handle as *mut _,
                sel.handle as *mut _,
                a.handle as *mut _,
                b.handle as *mut _,
                &mut handle as *mut usize as *mut _,
            ))?;
        }
        Ok(Ciphertext { handle })
    }

    /// 3-input AND gate
    pub fn and3(&self, a: &Ciphertext, b: &Ciphertext, c: &Ciphertext) -> Result<Ciphertext> {
        let mut handle: usize = 0;
        unsafe {
            check(luxfhe_and3(
                self.handle as *mut _,
                a.handle as *mut _,
                b.handle as *mut _,
                c.handle as *mut _,
                &mut handle as *mut usize as *mut _,
            ))?;
        }
        Ok(Ciphertext { handle })
    }

    /// 3-input OR gate
    pub fn or3(&self, a: &Ciphertext, b: &Ciphertext, c: &Ciphertext) -> Result<Ciphertext> {
        let mut handle: usize = 0;
        unsafe {
            check(luxfhe_or3(
                self.handle as *mut _,
                a.handle as *mut _,
                b.handle as *mut _,
                c.handle as *mut _,
                &mut handle as *mut usize as *mut _,
            ))?;
        }
        Ok(Ciphertext { handle })
    }

    /// Majority gate (2 of 3)
    pub fn majority(&self, a: &Ciphertext, b: &Ciphertext, c: &Ciphertext) -> Result<Ciphertext> {
        let mut handle: usize = 0;
        unsafe {
            check(luxfhe_majority(
                self.handle as *mut _,
                a.handle as *mut _,
                b.handle as *mut _,
                c.handle as *mut _,
                &mut handle as *mut usize as *mut _,
            ))?;
        }
        Ok(Ciphertext { handle })
    }
}

impl Drop for Evaluator {
    fn drop(&mut self) {
        unsafe {
            luxfhe_evaluator_free(self.handle as *mut _);
        }
    }
}

/// Get library version
pub fn version() -> String {
    unsafe {
        let ptr = luxfhe_version();
        if ptr.is_null() {
            return String::from("unknown");
        }
        std::ffi::CStr::from_ptr(ptr)
            .to_string_lossy()
            .into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let ctx = Context::new(ParamSet::PN10QP27).unwrap();
        let (sk, pk, _bsk) = ctx.keygen_all().unwrap();

        // Test with public key encryptor
        let enc = ctx.encryptor_pk(&pk).unwrap();
        let dec = ctx.decryptor(&sk).unwrap();

        let ct_true = enc.encrypt(true).unwrap();
        let ct_false = enc.encrypt(false).unwrap();

        assert_eq!(dec.decrypt(&ct_true).unwrap(), true);
        assert_eq!(dec.decrypt(&ct_false).unwrap(), false);
    }

    #[test]
    fn test_and_gate() {
        let ctx = Context::new(ParamSet::PN10QP27).unwrap();
        let (sk, _pk, bsk) = ctx.keygen_all().unwrap();

        let enc = ctx.encryptor_sk(&sk).unwrap();
        let dec = ctx.decryptor(&sk).unwrap();
        let eval = ctx.evaluator(&bsk, &sk).unwrap();

        let ct_a = enc.encrypt(true).unwrap();
        let ct_b = enc.encrypt(false).unwrap();

        let result = eval.and(&ct_a, &ct_b).unwrap();
        assert_eq!(dec.decrypt(&result).unwrap(), false);
    }
}
