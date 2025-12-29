---
title: Security
description: Security model and guarantees
---

# Security

## Cryptographic Foundation

Lux TFHE is built on the **Learning With Errors (LWE)** problem, a lattice-based cryptographic assumption that is:

- **Classically secure**: No known polynomial-time classical algorithms
- **Quantum resistant**: No known polynomial-time quantum algorithms
- **Well-studied**: Extensively analyzed by the cryptographic community

## Security Level

The default parameter set provides **128-bit security** against both classical and quantum adversaries.

## Security Properties

### Semantic Security (IND-CPA)

Encryptions of identical plaintexts produce different ciphertexts. An adversary cannot distinguish between encryptions of any two messages.

### Correctness

Decryption always produces the correct result, assuming operations are performed correctly and noise doesn't overflow.

### Noise Management

Each operation adds "noise" to ciphertexts. Bootstrapping resets the noise level, allowing unlimited computation depth.

## Threat Model

### What TFHE Protects Against

- **Data exposure**: Servers never see plaintext values
- **Traffic analysis**: Ciphertext sizes are uniform
- **Side-channel attacks**: Operations are data-independent (constant-time)

### What TFHE Does NOT Protect Against

- **Access patterns**: The sequence of operations may leak information
- **Output size**: The number of output bits reveals information
- **Timing attacks on application logic**: Your higher-level code must be careful

## Key Management

### Secret Key

- **Never share** the secret key
- Store securely (HSM, secure enclave, encrypted at rest)
- Use key derivation functions for multi-user scenarios

### Public Key

- Safe to share publicly
- Users encrypt with this key
- Does not reveal any information about the secret key

### Bootstrap Key

- Large key (~80 MB)
- Required for homomorphic operations
- Safe to share with computation servers
- Does not reveal the secret key

## Best Practices

1. **Validate all inputs** before encryption
2. **Limit operation depth** to prevent noise overflow
3. **Use public key encryption** for user-submitted data
4. **Implement rate limiting** on FHE operations (they're expensive)
5. **Audit your circuits** for information leakage

## Implementation Security

### No Patented Techniques

Lux TFHE uses only pre-2020 techniques:

- Boolean circuit approach (Chillotti et al. 2016)
- GINX bootstrapping method
- Classic carry-propagate arithmetic

This avoids any potential patent issues with:
- LUT-based integer techniques
- Tree-based bootstrapping
- Programmable bootstrapping optimizations

### Constant-Time Operations

All cryptographic operations are implemented to run in constant time, preventing timing-based side-channel attacks.

### Memory Safety

Written in Go with automatic memory management, eliminating common C/C++ vulnerabilities:
- No buffer overflows
- No use-after-free
- No memory leaks

## Audits

[Contact us](mailto:security@lux.partners) for security audit reports.
