# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025, Lux Industries Inc
"""
LuxFHE - Python bindings for the Lux TFHE library.

This package provides Python bindings for fully homomorphic encryption (FHE)
operations using the TFHE scheme. It enables computation on encrypted data
without decryption.

Example:
    >>> from luxfhe import Context, ParamSet
    >>> ctx = Context(ParamSet.PN10QP27)
    >>> sk, pk, bsk = ctx.keygen_all()
    >>> enc = ctx.encryptor(sk)
    >>> dec = ctx.decryptor(sk)
    >>> eval = ctx.evaluator(bsk)
    >>>
    >>> ct_a = enc.encrypt(True)
    >>> ct_b = enc.encrypt(False)
    >>> ct_and = eval.and_gate(ct_a, ct_b)
    >>> result = dec.decrypt(ct_and)  # False
"""

from .core import (
    Context,
    SecretKey,
    PublicKey,
    BootstrapKey,
    Ciphertext,
    Integer,
    Encryptor,
    Decryptor,
    Evaluator,
    ParamSet,
    LuxFHEError,
    version,
    version_info,
)

__version__ = "1.0.0"
__all__ = [
    "Context",
    "SecretKey",
    "PublicKey",
    "BootstrapKey",
    "Ciphertext",
    "Integer",
    "Encryptor",
    "Decryptor",
    "Evaluator",
    "ParamSet",
    "LuxFHEError",
    "version",
    "version_info",
]
