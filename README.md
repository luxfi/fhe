# Lux FHE

**Fully Homomorphic Encryption for the Lux Network** — Pure Go with optional C++/CUDA acceleration.

[![Go Reference](https://pkg.go.dev/badge/github.com/luxfi/fhe.svg)](https://pkg.go.dev/github.com/luxfi/fhe)
[![CI](https://github.com/luxfi/fhe/actions/workflows/ci.yml/badge.svg)](https://github.com/luxfi/fhe/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE)

## Overview

Lux FHE is a production-ready implementation of Fully Homomorphic Encryption (FHE) that enables computation on encrypted data without decryption. Ideal for privacy-preserving blockchain applications, confidential smart contracts, and secure multi-party computation.

## Implementations

| Mode | Build Flag | Description |
|------|------------|-------------|
| **Pure Go** | `CGO_ENABLED=0` | Zero dependencies, compiles anywhere Go runs |
| **C++ Optimized** | `CGO_ENABLED=1` | High-performance [C++ backend](https://github.com/luxcpp/fhe) |
| **GPU Accelerated** | `CGO_ENABLED=1` + GPU | MLX (Apple Silicon), CUDA (NVIDIA) |

### Pure Go Mode
- **Zero external dependencies** — compiles anywhere Go runs
- **Cross-platform** — Linux, macOS, Windows, ARM64
- **Deterministic builds** — critical for blockchain consensus
- **Easy deployment** — single static binary

### C++/GPU Mode
For maximum performance, build with CGO enabled to use our optimized [C++ implementation](https://github.com/luxcpp/fhe):

```bash
CGO_ENABLED=1 go build ./...
```

See [luxcpp/fhe](https://github.com/luxcpp/fhe) for C++/CUDA/MLX implementation details.

## Blockchain Optimized

- **Public key encryption** — users encrypt without secret key access
- **Deterministic RNG** — blockchain-compatible random numbers
- **Full serialization** — keys and ciphertexts
- **FheUint160** — native Ethereum address support
- **FheUint256** — native EVM word size support

## Performance (Apple M1 Max)

| Operation | Pure Go | C++ (CGO) | GPU |
|-----------|---------|-----------|-----|
| Bootstrap Key Gen | 132 ms | 68 ms | 12 ms |
| Boolean Gate (AND) | 51 ms | 28 ms | 3 ms |
| 8-bit Addition | 5.0 s | 2.1 s | 180 ms |

See [BENCHMARKS.md](BENCHMARKS.md) for complete performance data.

## Installation

```bash
go get github.com/luxfi/fhe
```

## Quick Start

```go
package main

import (
    "fmt"
    fhe "github.com/luxfi/fhe"
)

func main() {
    // Setup
    params, _ := fhe.NewParametersFromLiteral(fhe.PN10QP27)
    kg := fhe.NewKeyGenerator(params)
    sk, pk := kg.GenKeyPair()
    bsk := kg.GenBootstrapKey(sk)

    // Encrypt with public key (user side - no secret key needed!)
    pubEnc := fhe.NewBitwisePublicEncryptor(params, pk)
    ctA, _ := pubEnc.EncryptUint64(5, fhe.FheUint8)
    ctB, _ := pubEnc.EncryptUint64(3, fhe.FheUint8)

    // Compute on encrypted data (server/blockchain side)
    eval := fhe.NewBitwiseEvaluator(params, bsk, sk)
    ctSum, _ := eval.Add(ctA, ctB)

    // Decrypt result
    dec := fhe.NewBitwiseDecryptor(params, sk)
    result := dec.DecryptUint64(ctSum)
    fmt.Println("5 + 3 =", result) // Output: 5 + 3 = 8
}
```

## Supported Types

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

## Operations

**Arithmetic**: `Add`, `Sub`, `ScalarAdd`, `Neg`

**Comparison**: `Eq`, `Lt`, `Le`, `Gt`, `Ge`, `Min`, `Max`

**Bitwise**: `And`, `Or`, `Xor`, `Not`, `Shl`, `Shr`

**Selection**: `Select` (encrypted if-then-else), `CastTo`

## Architecture

```
github.com/luxfi/fhe/
├── fhe.go               # Parameters, key types, key generation
├── encryptor.go         # Boolean encryption (secret key)
├── decryptor.go         # Boolean decryption
├── evaluator.go         # Boolean gates (AND, OR, XOR, NOT, MUX)
├── bitwise_integers.go  # Integer operations + public key encryption
├── integers.go          # FheUintType definitions
├── integer_ops.go       # Comparison, bitwise operations
├── serialization.go     # Key/ciphertext serialization
├── random.go            # FHE random number generation
├── server/              # HTTP server for benchmarking
└── gpu/                 # GPU acceleration stubs
```

## Dependencies

- [`github.com/luxfi/lattice/v6`](https://github.com/luxfi/lattice) — Lattice cryptography primitives

## Running Tests

```bash
# All tests (Pure Go)
CGO_ENABLED=0 go test -v ./...

# With C++ backend
CGO_ENABLED=1 go test -v ./...

# Benchmarks
go test -bench=. -benchmem -run=^$
```

## HTTP Benchmark Server

Both Go and C++ implementations include HTTP servers for head-to-head benchmarking:

```bash
# Go server
go run ./server -port 8080

# C++ server (see luxcpp/fhe)
./fhe-server --port 8081
```

## License

**BSD-3-Clause**

Lux FHE is open source software. Patent rights for novel optimizations are reserved by Lux Partners Limited.

- **Lux Network**: Free to use on Lux mainnet and testnets
- **Research/Academic**: Free for non-commercial use  
- **Commercial**: Contact licensing@lux.partners

See [LICENSE](LICENSE) for full terms.

## Implementation

Original implementation based on published academic research:

- Built on [`github.com/luxfi/lattice`](https://github.com/luxfi/lattice) (our cryptographic primitives)
- Implements peer-reviewed algorithms from academic publications
- Contains novel optimizations developed independently

**Academic References:**
- Chillotti et al. "FHE: Fast Fully Homomorphic Encryption Over the Torus" (Journal of Cryptology, 2020)
- Ducas & Micciancio "FHEW: Bootstrapping Homomorphic Encryption in Less Than a Second" (EUROCRYPT 2015)

## Related Projects

- [luxcpp/fhe](https://github.com/luxcpp/fhe) — C++/CUDA/MLX implementation
- [luxfi/lattice](https://github.com/luxfi/lattice) — Lattice cryptography library
- [luxfi/standard](https://github.com/luxfi/standard) — fhEVM smart contracts

## Contributing

Contributions welcome! Please ensure tests pass before submitting PRs:

```bash
CGO_ENABLED=0 go test -v ./...
go vet ./...
```
