# Lux TFHE

**Pure Go implementation of TFHE (Threshold Fully Homomorphic Encryption) for the Lux Network.**

[![Go Reference](https://pkg.go.dev/badge/github.com/luxfi/tfhe.svg)](https://pkg.go.dev/github.com/luxfi/tfhe)
[![CI](https://github.com/luxfi/tfhe/actions/workflows/ci.yml/badge.svg)](https://github.com/luxfi/tfhe/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE)

## Overview

Lux TFHE is a **production-ready**, **patent-safe** implementation of Threshold Fully Homomorphic Encryption written entirely in Go. It enables computation on encrypted data without ever decrypting it, making it ideal for privacy-preserving blockchain applications, confidential smart contracts, and secure multi-party computation.

## Key Advantages

### Pure Go - No CGO Required
- **Zero external dependencies** - compiles anywhere Go runs
- **Cross-platform** - Linux, macOS, Windows, ARM64
- **Deterministic builds** - critical for blockchain consensus
- **Easy deployment** - single static binary

### Patent-Safe Implementation
- Built on **classic boolean circuit approach** (pre-2020 techniques)
- No patented LUT-based integer techniques
- Uses peer-reviewed algorithms from published academic research
- Independent implementation from scratch

### Optimized for Blockchain
- **Public key encryption** - users encrypt without secret key
- **Deterministic RNG** - blockchain-compatible random numbers
- **Full serialization** - keys and ciphertexts
- **FheUint160** - native Ethereum address support
- **FheUint256** - native EVM word size support

### Performance (Apple M1 Max)

| Operation | Pure Go | OpenFHE (CGO) | Winner |
|-----------|---------|---------------|--------|
| Bootstrap Key Gen | 132 ms | 2,413 ms | **Go 18x faster** |
| Boolean Gate (AND) | 51 ms | 56 ms | **Go 1.10x** |
| Boolean Gate (XOR) | 51 ms | 56 ms | **Go 1.10x** |
| Encrypt Bit | 21 µs | 28 µs | Go 1.3x |
| NOT Gate | 1.2 µs | 1.4 µs | ~Same |

**Key Finding**: Our Pure Go implementation is faster than OpenFHE's C++ with CGO bindings for all boolean operations, with bootstrap key generation being **18x faster**.

See [BENCHMARKS.md](BENCHMARKS.md) for complete performance data.

## Installation

```bash
go get github.com/luxfi/tfhe
```

## Quick Start

```go
package main

import (
    "fmt"
    "github.com/luxfi/tfhe"
)

func main() {
    // Setup
    params, _ := tfhe.NewParametersFromLiteral(tfhe.PN10QP27)
    kg := tfhe.NewKeyGenerator(params)
    sk, pk := kg.GenKeyPair()
    bsk := kg.GenBootstrapKey(sk)

    // Encrypt with public key (user side - no secret key needed!)
    pubEnc := tfhe.NewBitwisePublicEncryptor(params, pk)
    ctA := pubEnc.EncryptUint64(5, tfhe.FheUint8)
    ctB := pubEnc.EncryptUint64(3, tfhe.FheUint8)

    // Compute on encrypted data (server/blockchain side)
    eval := tfhe.NewBitwiseEvaluator(params, bsk, sk)
    ctSum, _ := eval.Add(ctA, ctB)

    // Decrypt result
    dec := tfhe.NewBitwiseDecryptor(params, sk)
    result := dec.DecryptUint64(ctSum)
    fmt.Println("5 + 3 =", result) // Output: 5 + 3 = 8
}
```

## Supported Operations

### Integer Types

| Type | Bits | Use Case |
|------|------|----------|
| FheBool | 1 | Boolean flags, comparisons |
| FheUint4 | 4 | Small counters, nibbles |
| FheUint8 | 8 | Bytes, small values |
| FheUint16 | 16 | Short integers |
| FheUint32 | 32 | Standard integers |
| FheUint64 | 64 | Large integers |
| FheUint128 | 128 | UUIDs, large values |
| FheUint160 | 160 | **Ethereum addresses** |
| FheUint256 | 256 | **EVM word size** |

### Operations

**Arithmetic**
- `Add`, `Sub` - Addition, subtraction
- `ScalarAdd` - Add plaintext constant
- `Neg` - Negation

**Comparison**
- `Eq`, `Lt`, `Le`, `Gt`, `Ge` - All comparison operators
- `Min`, `Max` - Minimum/Maximum

**Bitwise**
- `And`, `Or`, `Xor`, `Not` - Bitwise operations
- `Shl`, `Shr` - Bit shifts

**Selection**
- `Select` - Encrypted if-then-else (MUX)
- `CastTo` - Type conversion

### Boolean Gates

| Gate | Time | Memory |
|------|------|--------|
| NOT | 1.2 µs | 8.9 KB |
| AND | 51 ms | 1.2 MB |
| OR | 52 ms | 1.2 MB |
| XOR | 51 ms | 1.2 MB |
| NAND | 52 ms | 1.2 MB |
| NOR | 52 ms | 1.2 MB |
| XNOR | 51 ms | 1.2 MB |
| MUX | 158 ms | 3.6 MB |

### Multi-Input Gates

| Gate | Time | Notes |
|------|------|-------|
| AND3 | 117 ms | 3-input AND |
| OR3 | 119 ms | 3-input OR |
| MAJORITY | 59 ms | **Optimized single bootstrap** |

## Architecture

```
github.com/luxfi/tfhe/
├── tfhe.go              # Parameters, key types, key generation
├── encryptor.go         # Boolean encryption (secret key)
├── decryptor.go         # Boolean decryption
├── evaluator.go         # Boolean gates (AND, OR, XOR, NOT, MUX)
├── bitwise_integers.go  # Integer operations + public key encryption
├── integers.go          # FheUintType, RadixCiphertext definitions
├── integer_ops.go       # Comparison, bitwise operations
├── serialization.go     # Key/ciphertext serialization
├── random.go            # FHE random number generation
├── server/              # HTTP server for FHE operations
└── gpu/                 # GPU acceleration (MLX/Metal, CUDA)
```

## Dependencies

- [`github.com/luxfi/lattice/v6`](https://github.com/luxfi/lattice) - Lattice cryptography primitives (RLWE, Ring, BlindRotation)

## Running Tests

```bash
# All tests
go test -v ./...

# With race detection
go test -race ./...

# Benchmarks
go test -bench=. -benchmem -run=^$
```

## License

**BSD-3-Clause + Patent Rights Reserved**

- **Lux Network**: Free to use on Lux mainnet and testnets
- **Research/Academic**: Free for non-commercial use
- **Commercial**: License required for use on other networks

Contact: licensing@lux.partners

See [LICENSE](LICENSE) for full terms.

## Implementation Notice

This is an **ORIGINAL implementation** of TFHE written from scratch in Go, based on published academic research:

- Built entirely on [`github.com/luxfi/lattice`](https://github.com/luxfi/lattice) (our own cryptographic primitives)
- Implements algorithms from peer-reviewed publications
- Contains novel optimizations developed independently

**Referenced Academic Works:**
- Chillotti et al. "TFHE: Fast Fully Homomorphic Encryption Over the Torus" (Journal of Cryptology, 2020)
- Ducas & Micciancio "FHEW: Bootstrapping Homomorphic Encryption in Less Than a Second" (EUROCRYPT 2015)

## Related Projects

- [luxfi/lattice](https://github.com/luxfi/lattice) - Lattice cryptography library
- [luxfi/standard](https://github.com/luxfi/standard) - fhEVM smart contracts (Solidity)
- [luxfi/mlx](https://github.com/luxfi/mlx) - GPU acceleration library

## Documentation

Full documentation available at [tfhe.lux.network](https://tfhe.lux.network)

## Contributing

Contributions welcome! Please ensure tests pass before submitting PRs:

```bash
go test -v ./...
go vet ./...
```
