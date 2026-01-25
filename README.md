# Lux FHE

[![Go Reference](https://pkg.go.dev/badge/github.com/luxfi/fhe.svg)](https://pkg.go.dev/github.com/luxfi/fhe)
[![CI](https://github.com/luxfi/fhe/actions/workflows/ci.yml/badge.svg)](https://github.com/luxfi/fhe/actions/workflows/ci.yml)

Fully Homomorphic Encryption (FHE) library for the Lux Network.

## Features

- **TFHE** - Fast Boolean operations on encrypted data
- **CKKS** - Approximate arithmetic on encrypted vectors
- **GPU Acceleration** - Metal and CUDA support via luxfi/gpu
- **Lazy Carry Propagation** - Efficient integer arithmetic
- **Multi-Party Computation** - Threshold decryption support

## Installation

```bash
go get github.com/luxfi/fhe
```

## Usage

### TFHE Boolean Gates

```go
import "github.com/luxfi/fhe"

// Generate keys
params := fhe.DefaultTFHEParams()
keys, _ := fhe.GenerateTFHEKeys(params)

// Encrypt bits
ct1, _ := fhe.TFHEEncrypt(keys, true)
ct2, _ := fhe.TFHEEncrypt(keys, false)

// Homomorphic operations
ctAnd, _ := fhe.TFHEAnd(keys, ct1, ct2)
ctOr, _ := fhe.TFHEOr(keys, ct1, ct2)
ctNot, _ := fhe.TFHENot(keys, ct1)

// Decrypt
result, _ := fhe.TFHEDecrypt(keys, ctAnd) // false
```

### Integer Operations

```go
import "github.com/luxfi/fhe"

// Encrypt integers
a, _ := fhe.EncryptInt(keys, 42, 8) // 8-bit integer
b, _ := fhe.EncryptInt(keys, 10, 8)

// Arithmetic
sum, _ := fhe.IntAdd(keys, a, b)
diff, _ := fhe.IntSub(keys, a, b)
prod, _ := fhe.IntMul(keys, a, b)

// Comparison
isGreater, _ := fhe.IntGreaterThan(keys, a, b)
```

### CKKS Approximate Arithmetic

```go
import "github.com/luxfi/fhe"

// Setup CKKS
params := fhe.DefaultCKKSParams()
keys, _ := fhe.GenerateCKKSKeys(params)

// Encrypt vectors
values := []float64{1.0, 2.0, 3.0, 4.0}
ct, _ := fhe.CKKSEncrypt(keys, values)

// Operations
scaled, _ := fhe.CKKSMulScalar(ct, 2.5)
rotated, _ := fhe.CKKSRotate(keys, ct, 1)

// Decrypt
result, _ := fhe.CKKSDecrypt(keys, scaled)
```

## API Reference

### Key Generation

| Function | Description |
|----------|-------------|
| `GenerateTFHEKeys(params)` | Generate TFHE key set |
| `GenerateCKKSKeys(params)` | Generate CKKS key set |

### TFHE Operations

| Function | Description |
|----------|-------------|
| `TFHEEncrypt(keys, bit)` | Encrypt a bit |
| `TFHEDecrypt(keys, ct)` | Decrypt a ciphertext |
| `TFHEAnd(keys, a, b)` | Homomorphic AND |
| `TFHEOr(keys, a, b)` | Homomorphic OR |
| `TFHENot(keys, a)` | Homomorphic NOT |
| `TFHENand(keys, a, b)` | Homomorphic NAND |
| `TFHEXor(keys, a, b)` | Homomorphic XOR |
| `TFHEBootstrap(keys, ct)` | Refresh ciphertext noise |

### Integer Operations

| Function | Description |
|----------|-------------|
| `EncryptInt(keys, value, bits)` | Encrypt integer |
| `DecryptInt(keys, ct)` | Decrypt integer |
| `IntAdd(keys, a, b)` | Addition |
| `IntSub(keys, a, b)` | Subtraction |
| `IntMul(keys, a, b)` | Multiplication |
| `IntGreaterThan(keys, a, b)` | Comparison |

### CKKS Operations

| Function | Description |
|----------|-------------|
| `CKKSEncrypt(keys, values)` | Encrypt vector |
| `CKKSDecrypt(keys, ct)` | Decrypt vector |
| `CKKSAdd(a, b)` | Vector addition |
| `CKKSMul(keys, a, b)` | Vector multiplication |
| `CKKSRotate(keys, ct, steps)` | Rotate slots |

## GPU Acceleration

Enable GPU acceleration via the luxfi/gpu package:

```go
import (
    "github.com/luxfi/fhe"
    "github.com/luxfi/gpu"
)

// Initialize GPU session
sess, _ := gpu.DefaultSession()

// Use GPU-accelerated FHE
fheOps := sess.FHE()
result, _ := fheOps.NTTForward(poly, modulus)
```

## Examples

See the `examples/` directory for complete examples:

- `examples/tfhe_basic/` - Basic TFHE operations
- `examples/integer_ops/` - Integer arithmetic
- `examples/ckks_ml/` - Machine learning on encrypted data
- `examples/multiparty/` - Threshold decryption

## Documentation

- [API Reference](https://pkg.go.dev/github.com/luxfi/fhe)
- [Workshop Materials](docs/workshop/)
- [Resources](docs/resources/)

## Testing

```bash
# Run all tests
go test ./...

# With GPU
CGO_ENABLED=1 go test ./...

# Benchmarks
go test -bench=. ./...
```

## Performance

Performance varies by operation and key parameters:

| Operation | Time (128-bit security) |
|-----------|-------------------------|
| TFHE Gate | ~10ms |
| Bootstrap | ~50ms |
| CKKS Add | <1ms |
| CKKS Mul | ~5ms |
| NTT (N=2^16) | ~1ms (GPU) |

## License

BSD 3-Clause. See [LICENSE](LICENSE).

## Links

- [Lux FHE Documentation](https://docs.luxfhe.ai)
- [Research Papers](docs/resources/README.md)
- [GitHub Issues](https://github.com/luxfi/fhe/issues)
