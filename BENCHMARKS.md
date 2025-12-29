# TFHE Benchmarks

Benchmarks for the Lux TFHE implementation on Apple M1 Max (ARM64).

## Summary Comparison

| Operation | Pure Go (Lattice) | OpenFHE (CGO) | Winner |
|-----------|-------------------|---------------|--------|
| SecretKey Gen | 41.7 µs | 14.4 µs | CGO 2.9x |
| BootstrapKey Gen | 131.9 ms | 2413 ms | **Go 18x** |
| Encrypt Bit | 20.8 µs | 27.7 µs | Go 1.3x |
| Decrypt Bit | 4.5 µs | 1.4 µs | CGO 3.2x |
| NOT | 1.2 µs | 1.4 µs | ~Same |
| AND | 51.3 ms | 56.2 ms | Go 1.10x |
| OR | 52.3 ms | 56.4 ms | Go 1.08x |
| XOR | 51.2 ms | 56.3 ms | **Go 1.10x** |
| NAND | 52.0 ms | 56.4 ms | Go 1.08x |
| NOR | 52.2 ms | 56.3 ms | Go 1.08x |
| XNOR | 51.0 ms | 57.6 ms | **Go 1.13x** |

**Key Findings:**
- Pure Go bootstrap key gen is **18x faster** than OpenFHE (132ms vs 2.4s)
- Pure Go is faster for ALL gates (~51ms vs ~56ms)
- **XOR/XNOR optimized** to use single bootstrap (matching OpenFHE algorithm)
- Decrypt is faster with OpenFHE (1.4µs vs 4.5µs)

---

## Pure Go (Lattice) Backend

### Key Operations

| Operation | Time | Memory | Allocs |
|-----------|------|--------|--------|
| SecretKey Gen | 41.7 µs | 15.6 KB | 21 |
| PublicKey Gen | 17.4 µs | 11.9 KB | 22 |
| BootstrapKey Gen | 131.9 ms | 82.4 MB | 151K |

### Boolean Gate Operations

| Operation | Time | Memory | Allocs |
|-----------|------|--------|--------|
| Encrypt Bit | 20.8 µs | 16.0 KB | 29 |
| Decrypt Bit | 4.5 µs | 4.7 KB | 8 |
| NOT | 1.2 µs | 8.9 KB | 11 |
| AND | 51.3 ms | 1.2 MB | 38K |
| OR | 52.3 ms | 1.2 MB | 38K |
| NAND | 52.0 ms | 1.2 MB | 38K |
| NOR | 52.2 ms | 1.2 MB | 38K |
| XOR | 51.2 ms | 1.2 MB | 38K |
| XNOR | 51.0 ms | 1.2 MB | 38K |
| MUX | 158.4 ms | 3.6 MB | 114K |

### Multi-Input Gate Operations

| Operation | Time | Memory | Allocs | Notes |
|-----------|------|--------|--------|-------|
| AND3 | 117.2 ms | 2.4 MB | 76K | 2 bootstraps |
| OR3 | 118.7 ms | 2.4 MB | 76K | 2 bootstraps |
| MAJORITY | 58.6 ms | 1.2 MB | 38K | **1 bootstrap** |

**MAJORITY optimization:** Uses single bootstrap since threshold at 0 correctly
separates 0-1 true inputs (negative sum) from 2-3 true inputs (positive sum).

### Integer Encryption/Decryption

| Operation | Time | Memory | Allocs |
|-----------|------|--------|--------|
| Encrypt 8-bit | 166.8 µs | 128 KB | 234 |
| Encrypt 16-bit | 326.6 µs | 256 KB | 466 |
| Encrypt 32-bit | 663.5 µs | 512 KB | 930 |
| Decrypt 8-bit | 36.5 µs | 37.9 KB | 64 |
| Decrypt 16-bit | 74.0 µs | 75.8 KB | 128 |

### Integer Arithmetic (8-bit)

| Operation | Time | Memory | Allocs |
|-----------|------|--------|--------|
| Add | 3.50 s | 81.2 MB | 2.6M |
| Sub | 5.20 s | 115.1 MB | 3.6M |
| ScalarAdd | 1.61 s | 36.2 MB | 1.1M |

### Integer Comparisons (8-bit)

| Operation | Time | Memory | Allocs |
|-----------|------|--------|--------|
| Eq | 1.74 s | 37.3 MB | 1.2M |
| Lt | 2.91 s | 64.0 MB | 2.0M |
| Le | 4.52 s | 102.8 MB | 3.2M |
| Gt | 2.78 s | 64.1 MB | 2.0M |
| Min | 4.00 s | 93.1 MB | 2.9M |
| Max | 4.01 s | 93.0 MB | 2.9M |

### Bitwise Operations (8-bit)

| Operation | Time | Memory | Allocs |
|-----------|------|--------|--------|
| AND | 420.5 ms | 9.7 MB | 306K |
| OR | 429.2 ms | 9.6 MB | 304K |
| XOR | 1.45 s | 29.0 MB | 916K |
| NOT | 10.5 µs | 71.0 KB | 90 |
| Shl | 9.9 µs | 35.4 KB | 42 |
| Shr | 9.6 µs | 35.4 KB | 42 |

### Other Operations

| Operation | Time | Memory | Allocs |
|-----------|------|--------|--------|
| Select (8-bit) | 1.27 s | 29.0 MB | 914K |
| CastTo (8→16) | 40.1 µs | 141.4 KB | 162 |
| PublicEncrypt 8-bit | 308.2 µs | 134.3 KB | 274 |
| PublicEncrypt 16-bit | 597.9 µs | 268.6 KB | 546 |

### Serialization

| Operation | Time | Memory | Allocs |
|-----------|------|--------|--------|
| Serialize Ciphertext | 14.4 µs | 34.9 KB | 98 |
| Deserialize Ciphertext | 20.3 µs | 28.6 KB | 255 |
| Serialize 8-bit Int | 126.8 µs | 430.8 KB | 800 |
| Serialize 16-bit Int | 255.9 µs | 873.8 KB | 1593 |

### RNG

| Operation | Time | Memory | Allocs |
|-----------|------|--------|--------|
| RandomUint 8-bit | 173.0 µs | 128.1 KB | 235 |
| RandomUint 16-bit | 340.9 µs | 256.1 KB | 467 |

---

## OpenFHE (CGO) Backend

Benchmarks from OpenFHE 1.2.x with GINX bootstrapping method.

### Key Operations

| Operation | Time | Memory | Allocs |
|-----------|------|--------|--------|
| SecretKey Gen | 14.4 µs | 8 B | 1 |
| BootstrapKey Gen | 2413 ms | 0 B | 0 |

### Boolean Gate Operations

| Operation | Time | Memory | Allocs |
|-----------|------|--------|--------|
| Encrypt Bit | 27.7 µs | 8 B | 1 |
| Decrypt Bit | 1.4 µs | 0 B | 0 |
| NOT | 1.4 µs | 8 B | 1 |
| AND | 56.2 ms | 8 B | 1 |
| OR | 56.4 ms | 8 B | 1 |
| XOR | 56.3 ms | 8 B | 1 |
| NAND | 56.4 ms | 8 B | 1 |
| NOR | 56.3 ms | 8 B | 1 |
| XNOR | 57.6 ms | 8 B | 1 |

---

## Running Benchmarks

### Pure Go Backend
```bash
cd /path/to/lux/tfhe

# All benchmarks
go test -bench=. -benchmem -run=^$ .

# Only lattice benchmarks
go test -bench=BenchmarkLattice -benchmem -run=^$ .

# With memory profiling
go test -bench=BenchmarkLatticeAdd8 -benchmem -memprofile=mem.prof -run=^$ .
```

### OpenFHE (CGO) Backend
```bash
cd /path/to/lux/fhe/go/tfhe

# Set OpenFHE paths
export CGO_CXXFLAGS='-I/path/to/openfhe/include -I/path/to/openfhe/include/openfhe -I/path/to/openfhe/include/openfhe/core'
export CGO_LDFLAGS='-L/path/to/openfhe/lib -lOPENFHEbinfhe -lOPENFHEcore -lOPENFHEpke -Wl,-rpath,/path/to/openfhe/lib'

go test -bench=. -benchmem -run=^$ .
```

---

## Performance Notes

1. **Bootstrap Key Generation**: Pure Go is 18x faster (132ms vs 2.4s). OpenFHE may use different parameter sets.
2. **All Boolean gates**: Pure Go is ~10% faster (~51ms vs ~56ms)
3. **XOR/XNOR optimized**: Now uses OpenFHE's `2*(ct1+ct2)` algorithm with single bootstrap
4. **NOT** is essentially free in both implementations (~1.4µs) - no bootstrapping needed
5. **Decrypt**: OpenFHE is faster (1.4µs vs 4.5µs)
6. **Memory**: OpenFHE uses ~8 bytes per op (pointer only), Go tracks more allocations

## Recommendations

| Use Case | Recommended Backend |
|----------|---------------------|
| Startup-sensitive (key gen) | Pure Go |
| All boolean circuits | Pure Go (faster) |
| No C++ dependencies needed | Pure Go |
| Maximum integer performance | OpenFHE (GPU future) |

## Hardware

- **CPU**: Apple M1 Max
- **Architecture**: ARM64
- **Cores**: 10 (8P + 2E)
- **Go Version**: 1.22+
- **OpenFHE Version**: 1.2.x

---

*Benchmarks run on December 27, 2024*
