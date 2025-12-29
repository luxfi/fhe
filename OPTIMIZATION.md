# TFHE Optimization Guide

## Performance Optimization Strategies

This document describes the optimizations implemented in the Lux TFHE library and provides guidance for achieving maximum performance.

## Architecture Overview

```
                    +-----------------------+
                    |   High-Level API      |
                    |  (Boolean/Integer)    |
                    +-----------+-----------+
                                |
                    +-----------v-----------+
                    |    Evaluator          |
                    |  (Gate Evaluation)    |
                    +-----------+-----------+
                                |
            +-------------------+-------------------+
            |                                       |
+-----------v-----------+             +-------------v-------------+
|   CPU Backend         |             |    GPU Backend (MLX)      |
|   (lattice/v6)        |             |   (Metal/CUDA/CPU)        |
+-----------+-----------+             +-------------+-------------+
            |                                       |
+-----------v-----------+             +-------------v-------------+
|   NTT Engine          |             |   Batch Bootstrapping     |
|   (SIMD-optimized)    |             |   (Parallel PBS)          |
+-----------------------+             +---------------------------+
```

## Key Optimizations

### 1. NTT Optimization

The Number Theoretic Transform is the core operation in TFHE, used extensively in polynomial multiplication during bootstrapping.

**Cooley-Tukey NTT Algorithm**:
- O(N log N) complexity
- In-place computation with bit-reversal permutation
- Butterfly operations are SIMD-vectorizable

**Barrett Reduction**:
- Avoids expensive division in modular arithmetic
- Precomputes mu = floor(2^64 / Q)
- Reduces multiplication cost by 2-3x

```go
// Barrett reduction for a * b mod Q
func (e *NTTEngine) mulModBarrett(a, b uint64) uint64 {
    hi, lo := mul64(a, b)
    q := ((hi * e.barrettMu) >> 64) + ((lo * e.barrettMu) >> 32)
    r := lo - q*e.Q
    // At most 2 subtractions needed for correction
    if r >= e.Q { r -= e.Q }
    if r >= e.Q { r -= e.Q }
    return r
}
```

**Batch NTT**:
- Process multiple polynomials in parallel
- Optimal for GPU where batch size determines efficiency
- CPU version uses goroutine parallelism

### 2. GPU Bootstrapping Pipeline

The GPU engine implements a complete bootstrapping pipeline:

```
Input LWE → Batch NTT → External Products → Blind Rotation → INTT → Key Switch → Output LWE
```

**Key optimizations**:

1. **Structure of Arrays (SoA)**: All data stored for coalesced memory access
   ```
   // Bad: Array of Structures
   type LWE struct { a []uint64; b uint64 }
   ciphertexts []LWE  // Poor memory locality

   // Good: Structure of Arrays
   type LWEPool struct {
       A *mlx.Array  // [batch, n] - contiguous
       B *mlx.Array  // [batch]    - contiguous
   }
   ```

2. **Fused Kernels**: Combine multiple operations to reduce memory traffic
   - External product: decompose → multiply → accumulate in one pass
   - Blind rotation: all n external products batched

3. **Precomputed Data**: Twiddle factors and test polynomials computed once at initialization

### 3. Gate-Level Optimizations

**XOR/XNOR Optimization** (matching OpenFHE):
```
// Standard: 2 bootstraps for XOR
result = Bootstrap(a + b, TestPolyPositive) XOR Bootstrap(a + b, TestPolyNegative)

// Optimized: 1 bootstrap with doubling trick
doubled = 2 * (a + b)  // Causes (1,1) case to wrap to negative
result = Bootstrap(doubled, TestPolyXOR)
```

**MAJORITY Gate** (single bootstrap):
```
// 3-input MAJORITY with 1 bootstrap
sum = a + b + c
// Threshold at 0 separates:
//   0-1 true inputs (sum < 0) → FALSE
//   2-3 true inputs (sum > 0) → TRUE
result = Bootstrap(sum, TestPolyMAJORITY)
```

**NOT Gate** (free operation):
```
// NOT requires no bootstrap - just negate coefficients
NOT(ct) = -ct  // O(N) polynomial negation
```

### 4. Parameter Selection

| Parameter | PN10QP27 | PN11QP54 | Effect |
|-----------|----------|----------|--------|
| N (ring dimension) | 1024 | 2048 | Higher = more security, slower |
| Q (modulus) | 2^27 | 2^54 | Higher = more precision |
| n (LWE dimension) | 512 | 640 | Higher = more security |
| L (decomposition) | 4 | 5 | Higher = less noise, more compute |
| BaseLog | 7 | 10 | Higher = larger gadget, less noise |

**Choosing Parameters**:
- Use **PN10QP27** for most applications (128-bit security, balanced)
- Use **PN11QP54** when you need higher precision or longer circuits

**L (Decomposition Level) Tradeoff**:
```
L = 7 (original): Lower noise, but more computation
L = 4 (optimized): ~1.75x faster, still secure

External product cost = O(L × N × log N)
Reducing L from 7 to 4 gives ~1.75x speedup
```

### 5. Memory Optimization

**Bootstrap Key Size**:
```
BSK size = n × 2 × L × 2 × N × 8 bytes
         = 512 × 2 × 4 × 2 × 1024 × 8
         = 134 MB per user (with L=4)
```

**GPU Memory Budget** (per 8x H200 config):
- Total: 1.1 TB (141 GB × 8)
- Per GPU: 141 GB
- Users per GPU: ~1000 (with 134 MB BSK each)
- Total users: ~8000

### 6. Parallelization Strategies

**CPU**:
- Batch NTT uses goroutines (16 workers max)
- Gate evaluations can run in parallel with separate evaluators
- No lock contention on read-only bootstrap keys

**GPU**:
- Batch size determines efficiency (optimal: 4096+ for H200)
- Operations grouped by gate type for same test polynomial
- Multi-GPU with NVLink for user distribution

## Benchmarking

Run the full benchmark suite:

```bash
# All benchmarks
go test -bench=. -benchtime=5s ./...

# Specific benchmarks
go test -bench=BenchmarkBootstrap -benchtime=10s
go test -bench=BenchmarkNTT -benchtime=5s
go test -bench=BenchmarkBatch -benchtime=5s

# Memory allocation analysis
go test -bench=BenchmarkMemory -benchmem

# Generate performance report
go test -run=TestPerformanceReport -v
```

## Expected Performance (Apple M1 Max)

| Operation | Time | Notes |
|-----------|------|-------|
| Bootstrap Key Gen | 132 ms | 18x faster than OpenFHE |
| AND/OR/NAND/NOR | ~51 ms | Single bootstrap |
| XOR/XNOR | ~51 ms | Optimized single bootstrap |
| MAJORITY | ~59 ms | Single bootstrap |
| AND3/OR3 | ~117 ms | 2 bootstraps |
| MUX | ~170 ms | 3 bootstraps |
| NOT | 1.2 µs | Free (no bootstrap) |
| NTT (N=1024) | ~30 µs | Per transform |
| Batch NTT (32×) | ~14 µs/poly | Amortized |

## GPU Performance Targets

| Platform | Throughput | Latency |
|----------|------------|---------|
| M1 Max (Metal) | ~60K gates/sec | ~17 µs |
| H100 (CUDA) | ~180K gates/sec | ~5.5 µs |
| H200 (CUDA) | ~250K gates/sec | ~4 µs |
| 8× H200 (NVLink) | ~1.5M gates/sec | ~0.7 µs |

## Best Practices

1. **Batch Operations**: Always batch multiple gate operations together
2. **Reuse Keys**: Generate bootstrap key once, use for many operations
3. **Choose Right Parameters**: PN10QP27 for most use cases
4. **Use NOT Freely**: NOT is essentially free (no bootstrap)
5. **Minimize Circuit Depth**: Fewer sequential bootstraps = faster
6. **Prefer MAJORITY**: Single bootstrap for 3-input majority vote
7. **GPU for Batch**: GPU acceleration shines with 1000+ operations

## Future Optimizations

1. **AVX-512 NTT**: Assembly-optimized NTT for x86-64
2. **NEON NTT**: Assembly-optimized NTT for ARM64
3. **Metal Shaders**: Custom Metal kernels for NTT butterfly
4. **CUDA Kernels**: Custom CUDA kernels for H100/H200
5. **Circuit Compiler**: Automatic circuit optimization and batching
