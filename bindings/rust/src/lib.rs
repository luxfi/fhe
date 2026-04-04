//! FFI bindings to libluxfhe — FHE boolean gates on encrypted data.
//!
//! One library, one implementation: libluxfhe (luxfi/lattice via Go).
//! Same FHE from Lux blockchain to AI agents.
//!
//! All Go objects are behind opaque `u64` handles. The Rust wrappers
//! provide safe, RAII-managed access — handles are freed on drop.
//!
//! # Example
//!
//! ```rust,ignore
//! use luxfhe_sys::Fhe;
//!
//! let params = Fhe::params_pn10qp27().unwrap();
//! let keygen = Fhe::keygen(&params).unwrap();
//! let sk = keygen.gen_secret_key().unwrap();
//! let bsk = keygen.gen_bootstrap_key(&sk).unwrap();
//!
//! let enc = Fhe::encryptor(&params, &sk).unwrap();
//! let dec = Fhe::decryptor(&params, &sk).unwrap();
//! let eval = Fhe::evaluator(&params, &bsk).unwrap();
//!
//! let ct_t = enc.encrypt(true).unwrap();
//! let ct_f = enc.encrypt(false).unwrap();
//!
//! let ct_and = eval.and(&ct_t, &ct_f).unwrap();
//! assert!(!dec.decrypt(&ct_and).unwrap());
//! ```

use std::os::raw::c_int;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FheError {
    #[error("libluxfhe operation failed: {0} (rc={1})")]
    FFIError(&'static str, i32),
}

pub type Result<T> = std::result::Result<T, FheError>;

// ── Raw FFI ──────────────────────────────────────────────────────────

extern "C" {
    fn lux_fhe_drop(handle: u64);

    // Parameters
    fn lux_fhe_params_pn10qp27(out: *mut u64) -> c_int;

    // KeyGenerator
    fn lux_fhe_keygen_new(params: u64, out: *mut u64) -> c_int;
    fn lux_fhe_keygen_gen_secret_key(kg: u64, out: *mut u64) -> c_int;
    fn lux_fhe_keygen_gen_public_key(kg: u64, sk: u64, out: *mut u64) -> c_int;
    fn lux_fhe_keygen_gen_keypair(kg: u64, sk_out: *mut u64, pk_out: *mut u64) -> c_int;
    fn lux_fhe_keygen_gen_bootstrap_key(kg: u64, sk: u64, out: *mut u64) -> c_int;

    // Encryptor
    fn lux_fhe_encryptor_new(params: u64, sk: u64, out: *mut u64) -> c_int;
    fn lux_fhe_encrypt(enc: u64, value: c_int, out: *mut u64) -> c_int;
    fn lux_fhe_encrypt_bit(enc: u64, bit: c_int, out: *mut u64) -> c_int;
    fn lux_fhe_encrypt_byte(enc: u64, b: u8, out: *mut u64) -> c_int;
    fn lux_fhe_encrypt_uint32(enc: u64, v: u32, out: *mut u64) -> c_int;
    fn lux_fhe_encrypt_uint64(enc: u64, v: u64, out: *mut u64) -> c_int;
    fn lux_fhe_encrypt_uint256(enc: u64, limbs: *const u64, out: *mut u64) -> c_int;

    // Decryptor
    fn lux_fhe_decryptor_new(params: u64, sk: u64, out: *mut u64) -> c_int;
    fn lux_fhe_decrypt(dec: u64, ct: u64, out: *mut c_int) -> c_int;
    fn lux_fhe_decrypt_bit(dec: u64, ct: u64, out: *mut c_int) -> c_int;
    fn lux_fhe_decrypt_byte(dec: u64, handles: *const u64, out: *mut u8) -> c_int;
    fn lux_fhe_decrypt_uint32(dec: u64, handles: *const u64, out: *mut u32) -> c_int;
    fn lux_fhe_decrypt_uint64(dec: u64, handles: *const u64, out: *mut u64) -> c_int;
    fn lux_fhe_decrypt_uint256(dec: u64, handles: *const u64, out: *mut u64) -> c_int;

    // Evaluator (gates)
    fn lux_fhe_evaluator_new(params: u64, bsk: u64, out: *mut u64) -> c_int;
    fn lux_fhe_eval_and(eval: u64, ct1: u64, ct2: u64, out: *mut u64) -> c_int;
    fn lux_fhe_eval_or(eval: u64, ct1: u64, ct2: u64, out: *mut u64) -> c_int;
    fn lux_fhe_eval_xor(eval: u64, ct1: u64, ct2: u64, out: *mut u64) -> c_int;
    fn lux_fhe_eval_not(eval: u64, ct: u64, out: *mut u64) -> c_int;
    fn lux_fhe_eval_nand(eval: u64, ct1: u64, ct2: u64, out: *mut u64) -> c_int;
}

// ── Handle wrapper (RAII) ────────────────────────────────────────────

/// Opaque handle to a Go-side FHE object. Freed on drop.
#[derive(Debug)]
struct Handle(u64);

impl Handle {
    fn id(&self) -> u64 {
        self.0
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe { lux_fhe_drop(self.0) };
        }
    }
}

// ── Public types ─────────────────────────────────────────────────────

/// FHE parameter set.
#[derive(Debug)]
pub struct Params(Handle);

/// FHE key generator.
#[derive(Debug)]
pub struct KeyGen(Handle);

/// FHE secret key.
#[derive(Debug)]
pub struct SecretKey(Handle);

/// FHE public key.
#[derive(Debug)]
pub struct PublicKey(Handle);

/// FHE bootstrap key (evaluation key).
#[derive(Debug)]
pub struct BootstrapKey(Handle);

/// FHE encryptor (requires secret key).
#[derive(Debug)]
pub struct Encryptor(Handle);

/// FHE decryptor (requires secret key).
#[derive(Debug)]
pub struct Decryptor(Handle);

/// FHE evaluator (requires bootstrap key, no secret key).
#[derive(Debug)]
pub struct Evaluator(Handle);

/// Encrypted bit (ciphertext).
#[derive(Debug)]
pub struct Ciphertext(Handle);

// ── Namespace ────────────────────────────────────────────────────────

/// Top-level FHE operations.
pub struct Fhe;

impl Fhe {
    /// Create PN10QP27 parameters (~128-bit security).
    pub fn params_pn10qp27() -> Result<Params> {
        let mut h: u64 = 0;
        let rc = unsafe { lux_fhe_params_pn10qp27(&mut h) };
        if rc != 0 {
            return Err(FheError::FFIError("lux_fhe_params_pn10qp27", rc));
        }
        Ok(Params(Handle(h)))
    }

    /// Create a key generator for the given parameters.
    pub fn keygen(params: &Params) -> Result<KeyGen> {
        let mut h: u64 = 0;
        let rc = unsafe { lux_fhe_keygen_new(params.0.id(), &mut h) };
        if rc != 0 {
            return Err(FheError::FFIError("lux_fhe_keygen_new", rc));
        }
        Ok(KeyGen(Handle(h)))
    }

    /// Create an encryptor (requires secret key).
    pub fn encryptor(params: &Params, sk: &SecretKey) -> Result<Encryptor> {
        let mut h: u64 = 0;
        let rc = unsafe { lux_fhe_encryptor_new(params.0.id(), sk.0.id(), &mut h) };
        if rc != 0 {
            return Err(FheError::FFIError("lux_fhe_encryptor_new", rc));
        }
        Ok(Encryptor(Handle(h)))
    }

    /// Create a decryptor (requires secret key).
    pub fn decryptor(params: &Params, sk: &SecretKey) -> Result<Decryptor> {
        let mut h: u64 = 0;
        let rc = unsafe { lux_fhe_decryptor_new(params.0.id(), sk.0.id(), &mut h) };
        if rc != 0 {
            return Err(FheError::FFIError("lux_fhe_decryptor_new", rc));
        }
        Ok(Decryptor(Handle(h)))
    }

    /// Create an evaluator (requires bootstrap key, no secret key needed).
    pub fn evaluator(params: &Params, bsk: &BootstrapKey) -> Result<Evaluator> {
        let mut h: u64 = 0;
        let rc = unsafe { lux_fhe_evaluator_new(params.0.id(), bsk.0.id(), &mut h) };
        if rc != 0 {
            return Err(FheError::FFIError("lux_fhe_evaluator_new", rc));
        }
        Ok(Evaluator(Handle(h)))
    }
}

// ── KeyGen ───────────────────────────────────────────────────────────

impl KeyGen {
    /// Generate a secret key.
    pub fn gen_secret_key(&self) -> Result<SecretKey> {
        let mut h: u64 = 0;
        let rc = unsafe { lux_fhe_keygen_gen_secret_key(self.0.id(), &mut h) };
        if rc != 0 {
            return Err(FheError::FFIError("lux_fhe_keygen_gen_secret_key", rc));
        }
        Ok(SecretKey(Handle(h)))
    }

    /// Generate a public key from a secret key.
    pub fn gen_public_key(&self, sk: &SecretKey) -> Result<PublicKey> {
        let mut h: u64 = 0;
        let rc = unsafe { lux_fhe_keygen_gen_public_key(self.0.id(), sk.0.id(), &mut h) };
        if rc != 0 {
            return Err(FheError::FFIError("lux_fhe_keygen_gen_public_key", rc));
        }
        Ok(PublicKey(Handle(h)))
    }

    /// Generate a key pair (secret key + public key).
    pub fn gen_keypair(&self) -> Result<(SecretKey, PublicKey)> {
        let mut sk_h: u64 = 0;
        let mut pk_h: u64 = 0;
        let rc = unsafe { lux_fhe_keygen_gen_keypair(self.0.id(), &mut sk_h, &mut pk_h) };
        if rc != 0 {
            return Err(FheError::FFIError("lux_fhe_keygen_gen_keypair", rc));
        }
        Ok((SecretKey(Handle(sk_h)), PublicKey(Handle(pk_h))))
    }

    /// Generate a bootstrap key from a secret key.
    pub fn gen_bootstrap_key(&self, sk: &SecretKey) -> Result<BootstrapKey> {
        let mut h: u64 = 0;
        let rc = unsafe { lux_fhe_keygen_gen_bootstrap_key(self.0.id(), sk.0.id(), &mut h) };
        if rc != 0 {
            return Err(FheError::FFIError("lux_fhe_keygen_gen_bootstrap_key", rc));
        }
        Ok(BootstrapKey(Handle(h)))
    }
}

// ── Encryptor ────────────────────────────────────────────────────────

impl Encryptor {
    /// Encrypt a boolean value.
    pub fn encrypt(&self, value: bool) -> Result<Ciphertext> {
        let mut h: u64 = 0;
        let rc = unsafe { lux_fhe_encrypt(self.0.id(), value as c_int, &mut h) };
        if rc != 0 {
            return Err(FheError::FFIError("lux_fhe_encrypt", rc));
        }
        Ok(Ciphertext(Handle(h)))
    }

    /// Encrypt a bit (0 or 1).
    pub fn encrypt_bit(&self, bit: i32) -> Result<Ciphertext> {
        let mut h: u64 = 0;
        let rc = unsafe { lux_fhe_encrypt_bit(self.0.id(), bit as c_int, &mut h) };
        if rc != 0 {
            return Err(FheError::FFIError("lux_fhe_encrypt_bit", rc));
        }
        Ok(Ciphertext(Handle(h)))
    }

    /// Encrypt a byte as 8 ciphertexts (LSB first).
    pub fn encrypt_byte(&self, b: u8) -> Result<Vec<Ciphertext>> {
        let mut handles = [0u64; 8];
        let rc = unsafe { lux_fhe_encrypt_byte(self.0.id(), b, handles.as_mut_ptr()) };
        if rc != 0 {
            return Err(FheError::FFIError("lux_fhe_encrypt_byte", rc));
        }
        Ok(handles.into_iter().map(|h| Ciphertext(Handle(h))).collect())
    }

    /// Encrypt a u32 as 32 ciphertexts (LSB first).
    pub fn encrypt_uint32(&self, v: u32) -> Result<Vec<Ciphertext>> {
        let mut handles = [0u64; 32];
        let rc = unsafe { lux_fhe_encrypt_uint32(self.0.id(), v, handles.as_mut_ptr()) };
        if rc != 0 {
            return Err(FheError::FFIError("lux_fhe_encrypt_uint32", rc));
        }
        Ok(handles.into_iter().map(|h| Ciphertext(Handle(h))).collect())
    }

    /// Encrypt a u64 as 64 ciphertexts (LSB first).
    pub fn encrypt_uint64(&self, v: u64) -> Result<Vec<Ciphertext>> {
        let mut handles = [0u64; 64];
        let rc = unsafe { lux_fhe_encrypt_uint64(self.0.id(), v, handles.as_mut_ptr()) };
        if rc != 0 {
            return Err(FheError::FFIError("lux_fhe_encrypt_uint64", rc));
        }
        Ok(handles.into_iter().map(|h| Ciphertext(Handle(h))).collect())
    }

    /// Encrypt a 256-bit value (4 u64 limbs, little-endian) as 256 ciphertexts.
    pub fn encrypt_uint256(&self, limbs: &[u64; 4]) -> Result<Vec<Ciphertext>> {
        let mut handles = [0u64; 256];
        let rc = unsafe {
            lux_fhe_encrypt_uint256(self.0.id(), limbs.as_ptr(), handles.as_mut_ptr())
        };
        if rc != 0 {
            return Err(FheError::FFIError("lux_fhe_encrypt_uint256", rc));
        }
        Ok(handles.into_iter().map(|h| Ciphertext(Handle(h))).collect())
    }
}

// ── Decryptor ────────────────────────────────────────────────────────

impl Decryptor {
    /// Decrypt a ciphertext to a boolean.
    pub fn decrypt(&self, ct: &Ciphertext) -> Result<bool> {
        let mut out: c_int = 0;
        let rc = unsafe { lux_fhe_decrypt(self.0.id(), ct.0.id(), &mut out) };
        if rc != 0 {
            return Err(FheError::FFIError("lux_fhe_decrypt", rc));
        }
        Ok(out != 0)
    }

    /// Decrypt a ciphertext to a bit (0 or 1).
    pub fn decrypt_bit(&self, ct: &Ciphertext) -> Result<i32> {
        let mut out: c_int = 0;
        let rc = unsafe { lux_fhe_decrypt_bit(self.0.id(), ct.0.id(), &mut out) };
        if rc != 0 {
            return Err(FheError::FFIError("lux_fhe_decrypt_bit", rc));
        }
        Ok(out)
    }

    /// Decrypt 8 ciphertexts to a byte.
    pub fn decrypt_byte(&self, cts: &[Ciphertext]) -> Result<u8> {
        if cts.len() != 8 {
            return Err(FheError::FFIError("decrypt_byte: expected 8 ciphertexts", -1));
        }
        let handles: Vec<u64> = cts.iter().map(|ct| ct.0.id()).collect();
        let mut out: u8 = 0;
        let rc = unsafe { lux_fhe_decrypt_byte(self.0.id(), handles.as_ptr(), &mut out) };
        if rc != 0 {
            return Err(FheError::FFIError("lux_fhe_decrypt_byte", rc));
        }
        Ok(out)
    }

    /// Decrypt 32 ciphertexts to a u32.
    pub fn decrypt_uint32(&self, cts: &[Ciphertext]) -> Result<u32> {
        if cts.len() != 32 {
            return Err(FheError::FFIError("decrypt_uint32: expected 32 ciphertexts", -1));
        }
        let handles: Vec<u64> = cts.iter().map(|ct| ct.0.id()).collect();
        let mut out: u32 = 0;
        let rc = unsafe { lux_fhe_decrypt_uint32(self.0.id(), handles.as_ptr(), &mut out) };
        if rc != 0 {
            return Err(FheError::FFIError("lux_fhe_decrypt_uint32", rc));
        }
        Ok(out)
    }

    /// Decrypt 64 ciphertexts to a u64.
    pub fn decrypt_uint64(&self, cts: &[Ciphertext]) -> Result<u64> {
        if cts.len() != 64 {
            return Err(FheError::FFIError("decrypt_uint64: expected 64 ciphertexts", -1));
        }
        let handles: Vec<u64> = cts.iter().map(|ct| ct.0.id()).collect();
        let mut out: u64 = 0;
        let rc = unsafe { lux_fhe_decrypt_uint64(self.0.id(), handles.as_ptr(), &mut out) };
        if rc != 0 {
            return Err(FheError::FFIError("lux_fhe_decrypt_uint64", rc));
        }
        Ok(out)
    }

    /// Decrypt 256 ciphertexts to 4 u64 limbs (little-endian).
    pub fn decrypt_uint256(&self, cts: &[Ciphertext]) -> Result<[u64; 4]> {
        if cts.len() != 256 {
            return Err(FheError::FFIError("decrypt_uint256: expected 256 ciphertexts", -1));
        }
        let handles: Vec<u64> = cts.iter().map(|ct| ct.0.id()).collect();
        let mut out = [0u64; 4];
        let rc = unsafe { lux_fhe_decrypt_uint256(self.0.id(), handles.as_ptr(), out.as_mut_ptr()) };
        if rc != 0 {
            return Err(FheError::FFIError("lux_fhe_decrypt_uint256", rc));
        }
        Ok(out)
    }
}

// ── Evaluator ────────────────────────────────────────────────────────

impl Evaluator {
    /// Homomorphic AND gate.
    pub fn and(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Result<Ciphertext> {
        let mut h: u64 = 0;
        let rc = unsafe { lux_fhe_eval_and(self.0.id(), ct1.0.id(), ct2.0.id(), &mut h) };
        if rc != 0 {
            return Err(FheError::FFIError("lux_fhe_eval_and", rc));
        }
        Ok(Ciphertext(Handle(h)))
    }

    /// Homomorphic OR gate.
    pub fn or(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Result<Ciphertext> {
        let mut h: u64 = 0;
        let rc = unsafe { lux_fhe_eval_or(self.0.id(), ct1.0.id(), ct2.0.id(), &mut h) };
        if rc != 0 {
            return Err(FheError::FFIError("lux_fhe_eval_or", rc));
        }
        Ok(Ciphertext(Handle(h)))
    }

    /// Homomorphic XOR gate.
    pub fn xor(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Result<Ciphertext> {
        let mut h: u64 = 0;
        let rc = unsafe { lux_fhe_eval_xor(self.0.id(), ct1.0.id(), ct2.0.id(), &mut h) };
        if rc != 0 {
            return Err(FheError::FFIError("lux_fhe_eval_xor", rc));
        }
        Ok(Ciphertext(Handle(h)))
    }

    /// Homomorphic NOT gate (free — no bootstrapping).
    pub fn not(&self, ct: &Ciphertext) -> Result<Ciphertext> {
        let mut h: u64 = 0;
        let rc = unsafe { lux_fhe_eval_not(self.0.id(), ct.0.id(), &mut h) };
        if rc != 0 {
            return Err(FheError::FFIError("lux_fhe_eval_not", rc));
        }
        Ok(Ciphertext(Handle(h)))
    }

    /// Homomorphic NAND gate.
    pub fn nand(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> Result<Ciphertext> {
        let mut h: u64 = 0;
        let rc = unsafe { lux_fhe_eval_nand(self.0.id(), ct1.0.id(), ct2.0.id(), &mut h) };
        if rc != 0 {
            return Err(FheError::FFIError("lux_fhe_eval_nand", rc));
        }
        Ok(Ciphertext(Handle(h)))
    }
}

// ── Ciphertext handle access ─────────────────────────────────────────

impl Ciphertext {
    /// Get the raw handle ID (for advanced FFI usage).
    pub fn handle_id(&self) -> u64 {
        self.0.id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_bool() {
        let params = Fhe::params_pn10qp27().unwrap();
        let keygen = Fhe::keygen(&params).unwrap();
        let sk = keygen.gen_secret_key().unwrap();

        let enc = Fhe::encryptor(&params, &sk).unwrap();
        let dec = Fhe::decryptor(&params, &sk).unwrap();

        let ct_t = enc.encrypt(true).unwrap();
        let ct_f = enc.encrypt(false).unwrap();

        assert!(dec.decrypt(&ct_t).unwrap());
        assert!(!dec.decrypt(&ct_f).unwrap());
    }

    #[test]
    fn test_encrypt_decrypt_byte() {
        let params = Fhe::params_pn10qp27().unwrap();
        let keygen = Fhe::keygen(&params).unwrap();
        let sk = keygen.gen_secret_key().unwrap();

        let enc = Fhe::encryptor(&params, &sk).unwrap();
        let dec = Fhe::decryptor(&params, &sk).unwrap();

        let cts = enc.encrypt_byte(0xA5).unwrap();
        let result = dec.decrypt_byte(&cts).unwrap();
        assert_eq!(result, 0xA5);
    }

    #[test]
    fn test_and_gate() {
        let params = Fhe::params_pn10qp27().unwrap();
        let keygen = Fhe::keygen(&params).unwrap();
        let sk = keygen.gen_secret_key().unwrap();
        let bsk = keygen.gen_bootstrap_key(&sk).unwrap();

        let enc = Fhe::encryptor(&params, &sk).unwrap();
        let dec = Fhe::decryptor(&params, &sk).unwrap();
        let eval = Fhe::evaluator(&params, &bsk).unwrap();

        let ct_t = enc.encrypt(true).unwrap();
        let ct_f = enc.encrypt(false).unwrap();

        // AND(true, true) = true
        let r = eval.and(&ct_t, &enc.encrypt(true).unwrap()).unwrap();
        assert!(dec.decrypt(&r).unwrap());

        // AND(true, false) = false
        let r = eval.and(&ct_t, &ct_f).unwrap();
        assert!(!dec.decrypt(&r).unwrap());
    }

    #[test]
    fn test_keypair() {
        let params = Fhe::params_pn10qp27().unwrap();
        let keygen = Fhe::keygen(&params).unwrap();
        let (sk, _pk) = keygen.gen_keypair().unwrap();

        let enc = Fhe::encryptor(&params, &sk).unwrap();
        let dec = Fhe::decryptor(&params, &sk).unwrap();

        let ct = enc.encrypt(true).unwrap();
        assert!(dec.decrypt(&ct).unwrap());
    }
}
