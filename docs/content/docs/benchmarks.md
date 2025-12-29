---
title: Benchmarks
description: Performance characteristics of Lux TFHE
---

# Benchmarks

All benchmarks run on Apple M1 Max (ARM64).

## Summary Comparison

| Operation | Pure Go | OpenFHE (CGO) | Winner |
|-----------|---------|---------------|--------|
| SecretKey Gen | 41.7 µs | 14.4 µs | CGO 2.9x |
| BootstrapKey Gen | 131.9 ms | 2413 ms | **Go 18x** |
| Encrypt Bit | 20.8 µs | 27.7 µs | Go 1.3x |
| Decrypt Bit | 4.5 µs | 1.4 µs | CGO 3.2x |
| NOT | 1.2 µs | 1.4 µs | ~Same |
| AND | 51.3 ms | 56.2 ms | **Go 1.10x** |
| OR | 52.3 ms | 56.4 ms | **Go 1.08x** |
| XOR | 51.2 ms | 56.3 ms | **Go 1.10x** |
| NAND | 52.0 ms | 56.4 ms | **Go 1.08x** |
| NOR | 52.2 ms | 56.3 ms | **Go 1.08x** |
| XNOR | 51.0 ms | 57.6 ms | **Go 1.13x** |

**Key Findings:**
- Pure Go bootstrap key gen is **18x faster** than OpenFHE
- Pure Go is faster for **ALL gates** (~51ms vs ~56ms)
- XOR/XNOR optimized to use single bootstrap

## Boolean Gate Operations

| Operation | Time | Memory | Allocs |
|-----------|------|--------|--------|
| NOT | 1.2 µs | 8.9 KB | 11 |
| AND | 51.3 ms | 1.2 MB | 38K |
| OR | 52.3 ms | 1.2 MB | 38K |
| XOR | 51.2 ms | 1.2 MB | 38K |
| NAND | 52.0 ms | 1.2 MB | 38K |
| NOR | 52.2 ms | 1.2 MB | 38K |
| XNOR | 51.0 ms | 1.2 MB | 38K |
| MUX | 158.4 ms | 3.6 MB | 114K |

## Multi-Input Gates

| Operation | Time | Memory | Notes |
|-----------|------|--------|-------|
| AND3 | 117.2 ms | 2.4 MB | 2 bootstraps |
| OR3 | 118.7 ms | 2.4 MB | 2 bootstraps |
| MAJORITY | 58.6 ms | 1.2 MB | **1 bootstrap** |

## Integer Encryption/Decryption

| Operation | Time | Memory | Allocs |
|-----------|------|--------|--------|
| Encrypt 8-bit | 166.8 µs | 128 KB | 234 |
| Encrypt 16-bit | 326.6 µs | 256 KB | 466 |
| Encrypt 32-bit | 663.5 µs | 512 KB | 930 |
| Decrypt 8-bit | 36.5 µs | 37.9 KB | 64 |
| Decrypt 16-bit | 74.0 µs | 75.8 KB | 128 |

## Integer Arithmetic (8-bit)

| Operation | Time | Memory | Allocs |
|-----------|------|--------|--------|
| Add | 3.50 s | 81.2 MB | 2.6M |
| Sub | 5.20 s | 115.1 MB | 3.6M |
| ScalarAdd | 1.61 s | 36.2 MB | 1.1M |

## Integer Comparisons (8-bit)

| Operation | Time | Memory | Allocs |
|-----------|------|--------|--------|
| Eq | 1.74 s | 37.3 MB | 1.2M |
| Lt | 2.91 s | 64.0 MB | 2.0M |
| Le | 4.52 s | 102.8 MB | 3.2M |
| Gt | 2.78 s | 64.1 MB | 2.0M |
| Min | 4.00 s | 93.1 MB | 2.9M |
| Max | 4.01 s | 93.0 MB | 2.9M |

## Bitwise Operations (8-bit)

| Operation | Time | Memory | Allocs |
|-----------|------|--------|--------|
| AND | 420.5 ms | 9.7 MB | 306K |
| OR | 429.2 ms | 9.6 MB | 304K |
| XOR | 1.45 s | 29.0 MB | 916K |
| NOT | 10.5 µs | 71.0 KB | 90 |
| Shl | 9.9 µs | 35.4 KB | 42 |
| Shr | 9.6 µs | 35.4 KB | 42 |

## Running Benchmarks

```bash
# All benchmarks
go test -bench=. -benchmem -run=^$ .

# Only lattice benchmarks
go test -bench=BenchmarkLattice -benchmem -run=^$ .

# With memory profiling
go test -bench=BenchmarkLatticeAdd8 -benchmem -memprofile=mem.prof -run=^$ .
```

## Recommendations

| Use Case | Recommended Backend |
|----------|---------------------|
| Startup-sensitive (key gen) | Pure Go |
| All boolean circuits | Pure Go (faster) |
| No C++ dependencies needed | Pure Go |
| Maximum integer performance | OpenFHE (GPU future) |
