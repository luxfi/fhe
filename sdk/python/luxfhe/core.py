# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025, Lux Industries Inc
"""
Core LuxFHE Python bindings using cffi.
"""

from __future__ import annotations

import os
import sys
from enum import IntEnum
from pathlib import Path
from typing import Optional, Tuple, Union

from cffi import FFI

# Initialize FFI
ffi = FFI()

# C header declarations
ffi.cdef("""
    // Error codes
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

    // Parameter sets
    typedef enum {
        LUXFHE_PARAMS_PN10QP27 = 0,
        LUXFHE_PARAMS_PN11QP54 = 1,
    } LuxFHE_ParamSet;

    // Opaque handle types
    typedef void* LuxFHE_Context;
    typedef void* LuxFHE_SecretKey;
    typedef void* LuxFHE_PublicKey;
    typedef void* LuxFHE_BootstrapKey;
    typedef void* LuxFHE_Ciphertext;
    typedef void* LuxFHE_Integer;
    typedef void* LuxFHE_Encryptor;
    typedef void* LuxFHE_Decryptor;
    typedef void* LuxFHE_Evaluator;

    // Version
    const char* luxfhe_version(void);
    void luxfhe_version_info(int* major, int* minor, int* patch);
    const char* luxfhe_error_string(int err);

    // Context
    int luxfhe_context_new(int params, void** out);
    void luxfhe_context_free(void* ctx);
    int luxfhe_context_params(void* ctx, int* n_lwe, int* n_br, 
                              uint64_t* q_lwe, uint64_t* q_br);

    // Key generation
    int luxfhe_keygen_secret(void* ctx, void** out);
    int luxfhe_keygen_public(void* ctx, void* sk, void** out);
    int luxfhe_keygen_bootstrap(void* ctx, void* sk, void** out);
    int luxfhe_keygen_all(void* ctx, void** sk, void** pk, void** bsk);
    void luxfhe_secretkey_free(void* sk);
    void luxfhe_publickey_free(void* pk);
    void luxfhe_bootstrapkey_free(void* bsk);

    // Encryptor / Decryptor / Evaluator
    int luxfhe_encryptor_new_sk(void* ctx, void* sk, void** out);
    int luxfhe_encryptor_new_pk(void* ctx, void* pk, void** out);
    int luxfhe_decryptor_new(void* ctx, void* sk, void** out);
    int luxfhe_evaluator_new(void* ctx, void* bsk, void* sk, void** out);
    void luxfhe_encryptor_free(void* enc);
    void luxfhe_decryptor_free(void* dec);
    void luxfhe_evaluator_free(void* eval);

    // Boolean encryption/decryption
    int luxfhe_encrypt_bool(void* enc, bool value, void** out);
    int luxfhe_decrypt_bool(void* dec, void* ct, bool* out);
    void luxfhe_ciphertext_free(void* ct);
    int luxfhe_ciphertext_clone(void* ct, void** out);

    // Byte encryption/decryption
    int luxfhe_encrypt_byte(void* enc, uint8_t value, void** out);
    int luxfhe_decrypt_byte(void* dec, void* ct, uint8_t* out);
    void luxfhe_integer_free(void* ct);
    int luxfhe_integer_clone(void* ct, void** out);
    int luxfhe_integer_bitwidth(void* ct);

    // Boolean gates
    int luxfhe_not(void* eval, void* ct, void** out);
    int luxfhe_and(void* eval, void* ct1, void* ct2, void** out);
    int luxfhe_or(void* eval, void* ct1, void* ct2, void** out);
    int luxfhe_xor(void* eval, void* ct1, void* ct2, void** out);
    int luxfhe_nand(void* eval, void* ct1, void* ct2, void** out);
    int luxfhe_nor(void* eval, void* ct1, void* ct2, void** out);
    int luxfhe_xnor(void* eval, void* ct1, void* ct2, void** out);
    int luxfhe_mux(void* eval, void* sel, void* ct_true, void* ct_false, void** out);

    // Multi-input gates
    int luxfhe_and3(void* eval, void* ct1, void* ct2, void* ct3, void** out);
    int luxfhe_or3(void* eval, void* ct1, void* ct2, void* ct3, void** out);
    int luxfhe_majority(void* eval, void* ct1, void* ct2, void* ct3, void** out);

    // Serialization
    int luxfhe_secretkey_serialize(void* sk, uint8_t** data, size_t* len);
    int luxfhe_ciphertext_serialize(void* ct, uint8_t** data, size_t* len);
    void luxfhe_bytes_free(uint8_t* data);
""")

# Load the library
def _find_library() -> str:
    """Find the LuxFHE shared library."""
    # Check environment variable first
    lib_path = os.environ.get("LUXFHE_LIBRARY")
    if lib_path and os.path.exists(lib_path):
        return lib_path
    
    # Platform-specific library name
    if sys.platform == "darwin":
        lib_name = "libluxfhe.dylib"
    elif sys.platform == "win32":
        lib_name = "luxfhe.dll"
    else:
        lib_name = "libluxfhe.so"
    
    # Search paths
    search_paths = [
        Path(__file__).parent / "lib",
        Path(__file__).parent.parent / "lib",
        Path(__file__).parent.parent.parent / "c" / "lib",  # sdk/c/lib from sdk/python
        Path.home() / ".local" / "lib",
        Path("/usr/local/lib"),
        Path("/usr/lib"),
    ]
    
    for path in search_paths:
        lib_path = path / lib_name
        if lib_path.exists():
            return str(lib_path)
    
    raise ImportError(
        f"Could not find {lib_name}. "
        f"Set LUXFHE_LIBRARY environment variable or install the library."
    )

# Load library (lazy initialization)
_lib = None

def _get_lib():
    """Get the loaded library, loading it if necessary."""
    global _lib
    if _lib is None:
        _lib = ffi.dlopen(_find_library())
    return _lib


class LuxFHEError(Exception):
    """Exception raised for LuxFHE errors."""
    
    def __init__(self, code: int, message: str = None):
        self.code = code
        if message is None:
            message = ffi.string(_get_lib().luxfhe_error_string(code)).decode()
        super().__init__(f"LuxFHE error {code}: {message}")


def _check(code: int) -> None:
    """Check return code and raise exception if not OK."""
    if code != 0:
        raise LuxFHEError(code)


class ParamSet(IntEnum):
    """TFHE parameter sets."""
    
    # ~128-bit security, good performance
    PN10QP27 = 0
    
    # ~128-bit security, higher precision
    PN11QP54 = 1


def version() -> str:
    """Get library version string."""
    return ffi.string(_get_lib().luxfhe_version()).decode()


def version_info() -> Tuple[int, int, int]:
    """Get library version as (major, minor, patch) tuple."""
    major = ffi.new("int*")
    minor = ffi.new("int*")
    patch = ffi.new("int*")
    _get_lib().luxfhe_version_info(major, minor, patch)
    return (major[0], minor[0], patch[0])


class SecretKey:
    """TFHE secret key."""
    
    def __init__(self, handle):
        self._handle = handle
    
    def __del__(self):
        if hasattr(self, '_handle') and self._handle:
            _get_lib().luxfhe_secretkey_free(self._handle)
    
    def serialize(self) -> bytes:
        """Serialize the secret key to bytes."""
        data = ffi.new("uint8_t**")
        length = ffi.new("size_t*")
        _check(_get_lib().luxfhe_secretkey_serialize(self._handle, data, length))
        try:
            return bytes(ffi.buffer(data[0], length[0]))
        finally:
            _get_lib().luxfhe_bytes_free(data[0])


class PublicKey:
    """TFHE public key."""
    
    def __init__(self, handle):
        self._handle = handle
    
    def __del__(self):
        if hasattr(self, '_handle') and self._handle:
            _get_lib().luxfhe_publickey_free(self._handle)


class BootstrapKey:
    """TFHE bootstrap key (evaluation key)."""
    
    def __init__(self, handle):
        self._handle = handle
    
    def __del__(self):
        if hasattr(self, '_handle') and self._handle:
            _get_lib().luxfhe_bootstrapkey_free(self._handle)


class Ciphertext:
    """Encrypted boolean value."""
    
    def __init__(self, handle):
        self._handle = handle
    
    def __del__(self):
        if hasattr(self, '_handle') and self._handle:
            _get_lib().luxfhe_ciphertext_free(self._handle)
    
    def clone(self) -> "Ciphertext":
        """Create a copy of the ciphertext."""
        out = ffi.new("void**")
        _check(_get_lib().luxfhe_ciphertext_clone(self._handle, out))
        return Ciphertext(out[0])
    
    def serialize(self) -> bytes:
        """Serialize the ciphertext to bytes."""
        data = ffi.new("uint8_t**")
        length = ffi.new("size_t*")
        _check(_get_lib().luxfhe_ciphertext_serialize(self._handle, data, length))
        try:
            return bytes(ffi.buffer(data[0], length[0]))
        finally:
            _get_lib().luxfhe_bytes_free(data[0])


class Integer:
    """Encrypted integer value."""
    
    def __init__(self, handle):
        self._handle = handle
    
    def __del__(self):
        if hasattr(self, '_handle') and self._handle:
            _get_lib().luxfhe_integer_free(self._handle)
    
    @property
    def bitwidth(self) -> int:
        """Get the bit width of this integer."""
        return _get_lib().luxfhe_integer_bitwidth(self._handle)
    
    def clone(self) -> "Integer":
        """Create a copy of the integer."""
        out = ffi.new("void**")
        _check(_get_lib().luxfhe_integer_clone(self._handle, out))
        return Integer(out[0])


class Encryptor:
    """Encrypts plaintext values."""
    
    def __init__(self, handle):
        self._handle = handle
    
    def __del__(self):
        if hasattr(self, '_handle') and self._handle:
            _get_lib().luxfhe_encryptor_free(self._handle)
    
    def encrypt(self, value: bool) -> Ciphertext:
        """Encrypt a boolean value."""
        out = ffi.new("void**")
        _check(_get_lib().luxfhe_encrypt_bool(self._handle, value, out))
        return Ciphertext(out[0])
    
    def encrypt_byte(self, value: int) -> Integer:
        """Encrypt a byte (0-255)."""
        if not 0 <= value <= 255:
            raise ValueError("Value must be in range 0-255")
        out = ffi.new("void**")
        _check(_get_lib().luxfhe_encrypt_byte(self._handle, value, out))
        return Integer(out[0])


class Decryptor:
    """Decrypts ciphertext values."""
    
    def __init__(self, handle):
        self._handle = handle
    
    def __del__(self):
        if hasattr(self, '_handle') and self._handle:
            _get_lib().luxfhe_decryptor_free(self._handle)
    
    def decrypt(self, ct: Ciphertext) -> bool:
        """Decrypt a ciphertext to boolean."""
        out = ffi.new("bool*")
        _check(_get_lib().luxfhe_decrypt_bool(self._handle, ct._handle, out))
        return out[0]
    
    def decrypt_byte(self, ct: Integer) -> int:
        """Decrypt an encrypted byte."""
        out = ffi.new("uint8_t*")
        _check(_get_lib().luxfhe_decrypt_byte(self._handle, ct._handle, out))
        return out[0]


class Evaluator:
    """Evaluates homomorphic operations on ciphertexts."""
    
    def __init__(self, handle):
        self._handle = handle
    
    def __del__(self):
        if hasattr(self, '_handle') and self._handle:
            _get_lib().luxfhe_evaluator_free(self._handle)
    
    def not_gate(self, ct: Ciphertext) -> Ciphertext:
        """NOT gate."""
        out = ffi.new("void**")
        _check(_get_lib().luxfhe_not(self._handle, ct._handle, out))
        return Ciphertext(out[0])
    
    def and_gate(self, ct1: Ciphertext, ct2: Ciphertext) -> Ciphertext:
        """AND gate."""
        out = ffi.new("void**")
        _check(_get_lib().luxfhe_and(self._handle, ct1._handle, ct2._handle, out))
        return Ciphertext(out[0])
    
    def or_gate(self, ct1: Ciphertext, ct2: Ciphertext) -> Ciphertext:
        """OR gate."""
        out = ffi.new("void**")
        _check(_get_lib().luxfhe_or(self._handle, ct1._handle, ct2._handle, out))
        return Ciphertext(out[0])
    
    def xor_gate(self, ct1: Ciphertext, ct2: Ciphertext) -> Ciphertext:
        """XOR gate."""
        out = ffi.new("void**")
        _check(_get_lib().luxfhe_xor(self._handle, ct1._handle, ct2._handle, out))
        return Ciphertext(out[0])
    
    def nand_gate(self, ct1: Ciphertext, ct2: Ciphertext) -> Ciphertext:
        """NAND gate."""
        out = ffi.new("void**")
        _check(_get_lib().luxfhe_nand(self._handle, ct1._handle, ct2._handle, out))
        return Ciphertext(out[0])
    
    def nor_gate(self, ct1: Ciphertext, ct2: Ciphertext) -> Ciphertext:
        """NOR gate."""
        out = ffi.new("void**")
        _check(_get_lib().luxfhe_nor(self._handle, ct1._handle, ct2._handle, out))
        return Ciphertext(out[0])
    
    def xnor_gate(self, ct1: Ciphertext, ct2: Ciphertext) -> Ciphertext:
        """XNOR gate."""
        out = ffi.new("void**")
        _check(_get_lib().luxfhe_xnor(self._handle, ct1._handle, ct2._handle, out))
        return Ciphertext(out[0])
    
    def mux(self, sel: Ciphertext, ct_true: Ciphertext, ct_false: Ciphertext) -> Ciphertext:
        """Multiplexer: if sel then ct_true else ct_false."""
        out = ffi.new("void**")
        _check(_get_lib().luxfhe_mux(
            self._handle, sel._handle, ct_true._handle, ct_false._handle, out
        ))
        return Ciphertext(out[0])
    
    def and3(self, ct1: Ciphertext, ct2: Ciphertext, ct3: Ciphertext) -> Ciphertext:
        """3-input AND gate."""
        out = ffi.new("void**")
        _check(_get_lib().luxfhe_and3(
            self._handle, ct1._handle, ct2._handle, ct3._handle, out
        ))
        return Ciphertext(out[0])
    
    def or3(self, ct1: Ciphertext, ct2: Ciphertext, ct3: Ciphertext) -> Ciphertext:
        """3-input OR gate."""
        out = ffi.new("void**")
        _check(_get_lib().luxfhe_or3(
            self._handle, ct1._handle, ct2._handle, ct3._handle, out
        ))
        return Ciphertext(out[0])
    
    def majority(self, ct1: Ciphertext, ct2: Ciphertext, ct3: Ciphertext) -> Ciphertext:
        """Majority gate (2 of 3)."""
        out = ffi.new("void**")
        _check(_get_lib().luxfhe_majority(
            self._handle, ct1._handle, ct2._handle, ct3._handle, out
        ))
        return Ciphertext(out[0])


class Context:
    """TFHE context holding parameters and providing key generation."""
    
    def __init__(self, params: ParamSet = ParamSet.PN10QP27):
        """Create a new context with the given parameter set."""
        out = ffi.new("void**")
        _check(_get_lib().luxfhe_context_new(int(params), out))
        self._handle = out[0]
    
    def __del__(self):
        if hasattr(self, '_handle') and self._handle:
            _get_lib().luxfhe_context_free(self._handle)
    
    @property
    def params(self) -> dict:
        """Get parameter info."""
        n_lwe = ffi.new("int*")
        n_br = ffi.new("int*")
        q_lwe = ffi.new("uint64_t*")
        q_br = ffi.new("uint64_t*")
        _check(_get_lib().luxfhe_context_params(
            self._handle, n_lwe, n_br, q_lwe, q_br
        ))
        return {
            "n_lwe": n_lwe[0],
            "n_br": n_br[0],
            "q_lwe": q_lwe[0],
            "q_br": q_br[0],
        }
    
    def keygen_secret(self) -> SecretKey:
        """Generate a new secret key."""
        out = ffi.new("void**")
        _check(_get_lib().luxfhe_keygen_secret(self._handle, out))
        return SecretKey(out[0])
    
    def keygen_public(self, sk: SecretKey) -> PublicKey:
        """Generate a public key from a secret key."""
        out = ffi.new("void**")
        _check(_get_lib().luxfhe_keygen_public(self._handle, sk._handle, out))
        return PublicKey(out[0])
    
    def keygen_bootstrap(self, sk: SecretKey) -> BootstrapKey:
        """Generate a bootstrap key from a secret key."""
        out = ffi.new("void**")
        _check(_get_lib().luxfhe_keygen_bootstrap(self._handle, sk._handle, out))
        return BootstrapKey(out[0])
    
    def keygen_all(self) -> Tuple[SecretKey, PublicKey, BootstrapKey]:
        """Generate all keys at once."""
        sk_out = ffi.new("void**")
        pk_out = ffi.new("void**")
        bsk_out = ffi.new("void**")
        _check(_get_lib().luxfhe_keygen_all(
            self._handle, sk_out, pk_out, bsk_out
        ))
        return (
            SecretKey(sk_out[0]),
            PublicKey(pk_out[0]),
            BootstrapKey(bsk_out[0]),
        )
    
    def encryptor(self, key: Union[SecretKey, PublicKey]) -> Encryptor:
        """Create an encryptor using the given key."""
        out = ffi.new("void**")
        if isinstance(key, SecretKey):
            _check(_get_lib().luxfhe_encryptor_new_sk(self._handle, key._handle, out))
        elif isinstance(key, PublicKey):
            _check(_get_lib().luxfhe_encryptor_new_pk(self._handle, key._handle, out))
        else:
            raise TypeError("key must be SecretKey or PublicKey")
        return Encryptor(out[0])
    
    def decryptor(self, sk: SecretKey) -> Decryptor:
        """Create a decryptor using the secret key."""
        out = ffi.new("void**")
        _check(_get_lib().luxfhe_decryptor_new(self._handle, sk._handle, out))
        return Decryptor(out[0])
    
    def evaluator(self, bsk: BootstrapKey, sk: SecretKey) -> Evaluator:
        """Create an evaluator using the bootstrap key and secret key.
        
        The secret key is required for key-switching during bootstrapping.
        """
        out = ffi.new("void**")
        _check(_get_lib().luxfhe_evaluator_new(self._handle, bsk._handle, sk._handle, out))
        return Evaluator(out[0])
