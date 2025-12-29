---
title: Overview
description: What is TFHE and how does it work?
---

# Overview

## What is TFHE?

**Threshold Fully Homomorphic Encryption (TFHE)** is a cryptographic technique that allows computation on encrypted data without decryption. The result of the computation is also encrypted, and only the holder of the secret key can decrypt it.

This enables privacy-preserving computation where:
- Users encrypt their data with a public key
- Servers perform computations on encrypted data
- Only the user can decrypt the final result

## How It Works

### 1. Key Generation

```go
params, _ := tfhe.NewParametersFromLiteral(tfhe.PN10QP27)
kg := tfhe.NewKeyGenerator(params)
sk, pk := kg.GenKeyPair()       // Secret key (private), Public key (shareable)
bsk := kg.GenBootstrapKey(sk)   // Bootstrap key (for server operations)
```

### 2. Encryption (User Side)

Users encrypt their data using the **public key** - they never need the secret key:

```go
pubEnc := tfhe.NewBitwisePublicEncryptor(params, pk)
encryptedValue := pubEnc.EncryptUint64(42, tfhe.FheUint8)
```

### 3. Computation (Server Side)

The server performs operations on encrypted data using the **bootstrap key**:

```go
eval := tfhe.NewBitwiseEvaluator(params, bsk, sk)
result, _ := eval.Add(encA, encB)  // Addition on encrypted data
```

### 4. Decryption (User Side)

Only the holder of the secret key can decrypt:

```go
dec := tfhe.NewBitwiseDecryptor(params, sk)
plaintext := dec.DecryptUint64(result)
```

## Boolean Circuit Approach

Lux TFHE uses a **boolean circuit approach** for integer operations:

1. Each integer is represented as a vector of encrypted bits
2. Operations are built from basic boolean gates (AND, OR, XOR, NOT)
3. Each boolean gate requires a "bootstrapping" operation to reduce noise

This approach is:
- **Patent-safe**: Uses pre-2020 techniques with no patented LUT methods
- **Flexible**: Supports arbitrary bit widths (4-256 bits)
- **Predictable**: Performance scales linearly with bit width

## Security

TFHE security is based on the **Learning With Errors (LWE)** problem, which is believed to be resistant to both classical and quantum computers.

Key security features:
- 128-bit security level
- Semantic security (identical plaintexts have different ciphertexts)
- IND-CPA secure encryption

## Use Cases

- **Confidential Smart Contracts**: Execute logic without revealing inputs
- **Privacy-Preserving DeFi**: Trade without exposing positions
- **Encrypted Voting**: Vote without revealing choices
- **Secure Auctions**: Bid without revealing amounts
- **Private Analytics**: Compute statistics on encrypted data
