---
title: GPU Acceleration
description: Multi-GPU TFHE acceleration with Metal (macOS) and CUDA (Linux/Windows)
---

# GPU Acceleration

Lux TFHE supports massively parallel bootstrapping on GPUs, providing 10-100x speedup for batch operations.

## Supported Backends

| Backend | Platform | Hardware | Status |
|---------|----------|----------|--------|
| Metal/MLX | macOS 13+ | Apple Silicon (M1/M2/M3) | ✅ Production |
| CUDA | Linux/Windows | NVIDIA GPU (Compute 7.0+) | 🚧 In Development |
| CPU | Any | Any | ✅ Fallback |

## macOS Setup (Metal/MLX)

Metal acceleration works out of the box on Apple Silicon Macs:

```go
import "github.com/luxfi/tfhe/gpu"

// Auto-detect Metal GPU
cfg := gpu.Config{
    Backends: []string{"metal", "cpu"}, // Fallback to CPU if Metal unavailable
}

engine, err := gpu.New(cfg)
if err != nil {
    log.Fatal(err)
}
defer engine.Close()

// Check what backend was selected
info := engine.Info()
fmt.Printf("Using: %s (%s)\n", info.Backend, info.DeviceName)
// Output: Using: metal (Apple M1 Max)
```

## Linux/Windows Setup (CUDA)

CUDA acceleration requires the NVIDIA CUDA Toolkit:

```bash
# Install CUDA Toolkit (Ubuntu/Debian)
sudo apt install nvidia-cuda-toolkit

# Or download from NVIDIA
# https://developer.nvidia.com/cuda-downloads
```

```go
cfg := gpu.Config{
    Backends: []string{"cuda", "cpu"},
}

engine, _ := gpu.New(cfg)
```

## Configuration Options

```go
type Config struct {
    // Backends in priority order
    // Options: "metal", "cuda", "cpu"
    Backends []string

    // Maximum ciphertexts per batch
    // Larger = more parallelism, more memory
    MaxBatchSize int // Default: 1024

    // GPU memory limit in bytes
    // 0 = use all available
    MemoryLimit int64 // Default: 0

    // Number of GPU streams (CUDA only)
    NumStreams int // Default: 4

    // Enable async execution
    Async bool // Default: true
}
```

## Batch Operations

The GPU engine excels at batch operations:

```go
// Single operation (minimal speedup)
result, _ := engine.Bootstrap(ct, bsk)

// Batch operation (10-100x speedup)
results, _ := engine.BatchBootstrap(ciphertexts, bsk)

// Boolean gates on encrypted integers
sumCts, _ := engine.BatchAdd(aInts, bInts, bsk)
```

## Performance Characteristics

### Batch Size vs Throughput

| Batch Size | M1 Max (Metal) | RTX 4090 (CUDA) |
|------------|----------------|-----------------|
| 1 | ~50 ms | ~40 ms |
| 10 | ~60 ms | ~45 ms |
| 100 | ~150 ms | ~100 ms |
| 1000 | ~500 ms | ~300 ms |
| 10000 | ~4 s | ~2.5 s |

*Throughput increases dramatically with batch size.*

### Memory Requirements

| Batch Size | GPU Memory |
|------------|------------|
| 100 | ~500 MB |
| 1000 | ~2 GB |
| 10000 | ~8 GB |

## Multi-GPU Support

For systems with multiple GPUs:

```go
cfg := gpu.Config{
    Backends:    []string{"cuda"},
    DeviceIndex: 0, // GPU 0
}
engine0, _ := gpu.New(cfg)

cfg.DeviceIndex = 1 // GPU 1
engine1, _ := gpu.New(cfg)

// Distribute work across GPUs
go engine0.BatchBootstrap(batch1, bsk)
go engine1.BatchBootstrap(batch2, bsk)
```

## Async Execution

For maximum throughput with streaming data:

```go
cfg := gpu.Config{
    Backends: []string{"metal"},
    Async:    true,
}
engine, _ := gpu.New(cfg)

// Submit work without blocking
future1 := engine.BatchBootstrapAsync(batch1, bsk)
future2 := engine.BatchBootstrapAsync(batch2, bsk)

// Do other work...

// Collect results
results1, _ := future1.Wait()
results2, _ := future2.Wait()
```

## Error Handling

```go
engine, err := gpu.New(cfg)
if err != nil {
    switch {
    case errors.Is(err, gpu.ErrNotSupported):
        // Platform doesn't support any GPU backend
        // Fall back to pure Go implementation
    case errors.Is(err, gpu.ErrOutOfMemory):
        // Not enough GPU memory
        // Reduce batch size or memory limit
    default:
        log.Fatal(err)
    }
}
```

## Benchmarking Your System

```bash
# Run GPU benchmarks
go test -bench=BenchmarkGPU -benchmem github.com/luxfi/tfhe/gpu

# Compare with CPU
go test -bench=BenchmarkLattice -benchmem github.com/luxfi/tfhe
```

## Platform-Specific Notes

### macOS (Metal/MLX)

- Requires macOS 13.0+ (Ventura or later)
- Works on Apple Silicon (M1, M2, M3 series)
- Intel Macs not supported (falls back to CPU)
- Uses MLX framework for optimal Metal performance

### Linux (CUDA)

- Requires CUDA Toolkit 11.0+
- NVIDIA GPU with Compute Capability 7.0+ (Volta or newer)
- Tested on: RTX 3090, RTX 4090, A100, H100

### Windows (CUDA)

- Same requirements as Linux
- CUDA Toolkit for Windows
- WSL2 also works with Linux CUDA backend

## Troubleshooting

### Metal not detected on macOS

```bash
# Check Metal support
system_profiler SPDisplaysDataType | grep Metal
```

### CUDA not detected on Linux

```bash
# Check CUDA installation
nvcc --version
nvidia-smi

# Check Go can find CUDA
export CGO_CFLAGS="-I/usr/local/cuda/include"
export CGO_LDFLAGS="-L/usr/local/cuda/lib64"
```

### Out of memory errors

Reduce batch size or set a memory limit:

```go
cfg := gpu.Config{
    MaxBatchSize: 256,           // Smaller batches
    MemoryLimit:  2 << 30,       // 2GB limit
}
```
