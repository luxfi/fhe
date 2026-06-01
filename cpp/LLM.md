# LuxNext FHE - CUDA/Multi-GPU Backend (Proprietary)

## Overview

This module provides NVIDIA GPU acceleration for Fully Homomorphic Encryption. The OSS version (`luxcpp/fhe`) includes Metal/Apple Silicon support. This proprietary module adds datacenter GPU support.

## Supported Hardware

| GPU | Architecture | Tensor Cores | FP64 TFLOPS |
|-----|-------------|--------------|-------------|
| H100 | Hopper (sm_90) | 456 | 34 |
| H200 | Hopper (sm_90) | 456 | 34 |
| HGX H100 | 8x H100 + NVSwitch | 3,648 | 272 |
| HGX H200 | 8x H200 + NVSwitch | 3,648 | 272 |

## Directory Structure

```
cpp/
├── src/
│   ├── core/
│   │   ├── include/math/hal/cuda/  # CUDA headers
│   │   └── lib/math/hal/cuda/      # CUDA kernels
│   └── gpu/
│       ├── server/                 # FHE GPU server
│       ├── include/                # GPU pipeline headers
│       └── src/                    # Multi-GPU orchestration
└── CMakeLists.txt
```

## Key Features

### Multi-GPU NTT
- Distributed NTT across 8 GPUs via NVLink
- Pipeline overlaps compute/transfer
- 40x speedup over single H100

### Batched Bootstrapping
- Parallel PBS across GPU cluster
- NCCL-based key distribution
- 100K+ gates/second

### Memory Management
- Unified memory with peer access
- Async prefetch for key materials
- Zero-copy between GPUs

## Build

```bash
mkdir build && cd build
cmake .. -DWITH_MULTI_GPU=ON -DWITH_NCCL=ON
make -j
```

## Integration with OSS

The CUDA backend links against `libFHEcore.dylib` from the OSS release:

```cmake
find_package(OpenFHE REQUIRED)
target_link_libraries(FHEcuda OpenFHE::FHEcore)
```

## Licensing

Proprietary - Lux Network internal use only.

---

*Last Updated: 2025-12-29*
