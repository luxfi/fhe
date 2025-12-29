# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025, Lux Industries Inc
"""
Basic tests for LuxFHE Python bindings.
"""

import pytest
from luxfhe import (
    Context,
    ParamSet,
    version,
    version_info,
    LuxFHEError,
)


def test_version():
    """Test version functions."""
    v = version()
    assert v is not None
    assert len(v) > 0
    
    major, minor, patch = version_info()
    assert major == 1
    assert minor == 0
    assert patch == 0


def test_context_creation():
    """Test context creation."""
    ctx = Context(ParamSet.PN10QP27)
    assert ctx is not None
    
    params = ctx.params
    assert params["n_lwe"] > 0
    assert params["n_br"] > 0
    assert params["q_lwe"] > 0
    assert params["q_br"] > 0


def test_keygen():
    """Test key generation."""
    ctx = Context()
    sk, pk, bsk = ctx.keygen_all()
    
    assert sk is not None
    assert pk is not None
    assert bsk is not None


def test_encrypt_decrypt():
    """Test basic encryption and decryption."""
    ctx = Context()
    sk, pk, bsk = ctx.keygen_all()
    
    enc = ctx.encryptor(sk)
    dec = ctx.decryptor(sk)
    
    # Test true
    ct_true = enc.encrypt(True)
    assert dec.decrypt(ct_true) == True
    
    # Test false
    ct_false = enc.encrypt(False)
    assert dec.decrypt(ct_false) == False


def test_gates():
    """Test boolean gates."""
    ctx = Context()
    sk, pk, bsk = ctx.keygen_all()
    
    enc = ctx.encryptor(sk)
    dec = ctx.decryptor(sk)
    eval = ctx.evaluator(bsk, sk)
    
    ct_true = enc.encrypt(True)
    ct_false = enc.encrypt(False)
    
    # AND
    ct_and = eval.and_gate(ct_true, ct_false)
    assert dec.decrypt(ct_and) == False
    
    ct_and_tt = eval.and_gate(ct_true, ct_true)
    assert dec.decrypt(ct_and_tt) == True
    
    # OR
    ct_or = eval.or_gate(ct_true, ct_false)
    assert dec.decrypt(ct_or) == True
    
    ct_or_ff = eval.or_gate(ct_false, ct_false)
    assert dec.decrypt(ct_or_ff) == False
    
    # XOR
    ct_xor = eval.xor_gate(ct_true, ct_false)
    assert dec.decrypt(ct_xor) == True
    
    ct_xor_tt = eval.xor_gate(ct_true, ct_true)
    assert dec.decrypt(ct_xor_tt) == False
    
    # NOT
    ct_not = eval.not_gate(ct_true)
    assert dec.decrypt(ct_not) == False
    
    ct_not_f = eval.not_gate(ct_false)
    assert dec.decrypt(ct_not_f) == True


def test_mux():
    """Test multiplexer gate."""
    ctx = Context()
    sk, pk, bsk = ctx.keygen_all()
    
    enc = ctx.encryptor(sk)
    dec = ctx.decryptor(sk)
    eval = ctx.evaluator(bsk, sk)
    
    ct_true = enc.encrypt(True)
    ct_false = enc.encrypt(False)
    ct_sel_t = enc.encrypt(True)
    ct_sel_f = enc.encrypt(False)
    
    # MUX(true, true, false) = true
    result = eval.mux(ct_sel_t, ct_true, ct_false)
    assert dec.decrypt(result) == True
    
    # MUX(false, true, false) = false
    result = eval.mux(ct_sel_f, ct_true, ct_false)
    assert dec.decrypt(result) == False


def test_ciphertext_clone():
    """Test ciphertext cloning."""
    ctx = Context()
    sk, _, _ = ctx.keygen_all()
    
    enc = ctx.encryptor(sk)
    dec = ctx.decryptor(sk)
    
    ct = enc.encrypt(True)
    ct_clone = ct.clone()
    
    assert dec.decrypt(ct) == dec.decrypt(ct_clone)


def test_encrypt_byte():
    """Test byte encryption."""
    ctx = Context()
    sk, _, _ = ctx.keygen_all()
    
    enc = ctx.encryptor(sk)
    dec = ctx.decryptor(sk)
    
    ct = enc.encrypt_byte(42)
    result = dec.decrypt_byte(ct)
    
    assert result == 42


def test_encrypt_byte_bounds():
    """Test byte encryption bounds."""
    ctx = Context()
    sk, _, _ = ctx.keygen_all()
    
    enc = ctx.encryptor(sk)
    dec = ctx.decryptor(sk)
    
    # Min value
    ct_min = enc.encrypt_byte(0)
    assert dec.decrypt_byte(ct_min) == 0
    
    # Max value
    ct_max = enc.encrypt_byte(255)
    assert dec.decrypt_byte(ct_max) == 255
    
    # Out of range
    with pytest.raises(ValueError):
        enc.encrypt_byte(256)
    
    with pytest.raises(ValueError):
        enc.encrypt_byte(-1)


def test_public_key_encryption():
    """Test encryption with public key."""
    ctx = Context()
    sk, pk, bsk = ctx.keygen_all()
    
    # Encrypt with public key
    enc_pk = ctx.encryptor(pk)
    ct = enc_pk.encrypt(True)
    
    # Decrypt with secret key
    dec = ctx.decryptor(sk)
    assert dec.decrypt(ct) == True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
