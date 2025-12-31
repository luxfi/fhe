# Lux FHE - Pure Go FHE Implementation

## Overview

Novel FHE implementation built on our own lattice cryptography stack (`luxfi/lattice`), designed for blockchain/EVM integration with multi-GPU acceleration.

**Key differentiators:**
- Pure Go implementation from first principles using `luxfi/lattice/v6` primitives
- Native blockchain integration (FheUint160 for addresses, FheUint256 for EVM words)
- Multi-GPU parallelism via luxfi/gpu backend (Metal/CUDA/CPU)
- 10,000+ concurrent user support with 100GB+ GPU memory
- Independent implementation - no external FHE library dependencies for core operations

## Architecture

```
luxfi/fhe (Pure Go FHE)
    │
    ├── Core Types
    │   ├── fhe.go            - Parameters, KeyGenerator, SecretKey, PublicKey
    │   ├── encryptor.go      - Bit/Boolean encryption
    │   ├── decryptor.go      - Bit/Boolean decryption
    │   └── evaluator.go      - Boolean gates (AND, OR, XOR, NOT, NAND, NOR, MUX)
    │
    ├── Integer Operations
    │   ├── integers.go       - FheUintType, Encryptor, Decryptor
    │   ├── bitwise_integers.go - BitCiphertext, BitwiseEncryptor, BitwiseEvaluator
    │   ├── integer_ops.go    - Add, Sub, Mul, Div, comparisons
    │   └── shortint.go       - Small integer optimizations
    │
    ├── Advanced Features
    │   ├── random.go         - FheRNG, FheRNGPublic (deterministic RNG)
    │   └── serialization.go  - Binary serialization for keys/ciphertexts
    │
    ├── CGO Backend (GPU-accelerated via luxcpp/fhe)
    │   └── cgo/
    │       ├── fhe.go        - OpenFHE bindings with Metal/CUDA GPU support
    │       ├── fhe_test.go   - Comprehensive tests
    │       └── tfhe_bridge.h - C header for C++ bridge
    │
    └── github.com/luxfi/lattice/v6  - Cryptographic primitives
        ├── core/rlwe         - Ring-LWE encryption
        ├── core/rgsw         - RGSW & blind rotation
        └── ring              - Polynomial ring operations
```

## Features

### Boolean Gates
- 2-input: AND, OR, XOR, NOT (free), NAND, NOR, XNOR, MUX
- 3-input: AND3, OR3, NAND3, NOR3, MAJORITY (single bootstrap)
- Full blind rotation with RGSW ciphertexts
- Programmable bootstrapping

### Integer Types
| Type | Bits | Use Case |
|------|------|----------|
| FheUint4 | 4 | Small values |
| FheUint8 | 8 | Bytes |
| FheUint16 | 16 | Short integers |
| FheUint32 | 32 | Standard integers |
| FheUint64 | 64 | Long integers |
| FheUint128 | 128 | Large values |
| FheUint160 | 160 | Ethereum addresses |
| FheUint256 | 256 | EVM words |

### Integer Operations
- Arithmetic: Add, Sub, Neg, ScalarAdd
- Comparisons: Eq, Lt, Le, Gt, Ge, Min, Max
- Bitwise: And, Or, Xor, Not
- Shifts: Shl, Shr
- Casting: CastTo

### Public Key Encryption
- Generate public key from secret key
- Encrypt with public key (no secret key needed)
- Decrypt with secret key

### Deterministic RNG
- FheRNG - secret key encryption
- FheRNGPublic - public key encryption
- SHA256-based deterministic PRNG
- Blockchain consensus compatible

## API Reference

### Quick Start

```go
import "github.com/luxfi/fhe"

// Create parameters and key generator
params, _ := fhe.NewParametersFromLiteral(fhe.PN10QP27)
kgen := fhe.NewKeyGenerator(params)

// Generate keys
sk := kgen.GenSecretKey()
pk := kgen.GenPublicKey(sk)
bsk := kgen.GenBootstrapKey(sk)

// Boolean operations
enc := fhe.NewEncryptor(params, sk)
dec := fhe.NewDecryptor(params, sk)
eval := fhe.NewEvaluator(params, bsk, sk)

ct1 := enc.Encrypt(true)
ct2 := enc.Encrypt(false)
result, _ := eval.AND(ct1, ct2)
value := dec.Decrypt(result) // false
```

### Integer Operations

```go
// Bitwise integer encryption
bitwiseEnc := fhe.NewBitwiseEncryptor(params, sk)
bitwiseDec := fhe.NewBitwiseDecryptor(params, sk)
bitwiseEval := fhe.NewBitwiseEvaluator(params, bsk, sk)

// Encrypt integers
ct1 := bitwiseEnc.EncryptUint64(42, fhe.FheUint8)
ct2 := bitwiseEnc.EncryptUint64(10, fhe.FheUint8)

// Operations
sum, _ := bitwiseEval.Add(ct1, ct2)
diff, _ := bitwiseEval.Sub(ct1, ct2)
eq, _ := bitwiseEval.Eq(ct1, ct2)

// Decrypt
result := bitwiseDec.DecryptUint64(sum) // 52
```

### Public Key Encryption

```go
// Generate public key
pk := kgen.GenPublicKey(sk)

// Encrypt with public key
pubEnc := fhe.NewBitwisePublicEncryptor(params, pk)
ct := pubEnc.EncryptUint64(42, fhe.FheUint8)

// Decrypt with secret key
result := bitwiseDec.DecryptUint64(ct) // 42
```

### Random Number Generation

```go
// Secret key RNG
seed := []byte("block_hash+tx_hash")
rng := fhe.NewFheRNG(params, sk, seed)
randomBit := rng.RandomBit()
randomUint := rng.RandomUint(fhe.FheUint8)

// Public key RNG
rngPub := fhe.NewFheRNGPublic(params, pk, seed)
randomPub := rngPub.RandomUint(fhe.FheUint8)

// Reseed
rng.Reseed(newSeed)
```

### Serialization

```go
// Serialize ciphertext
data, _ := ct.MarshalBinary()

// Deserialize
ct2 := new(fhe.BitCiphertext)
ct2.UnmarshalBinary(data)

// Public key serialization
pkData, _ := pk.MarshalBinary()
pkRestored := new(fhe.PublicKey)
pkRestored.UnmarshalBinary(pkData)
```

## Parameter Sets

| Name | Security | LWE N | Ring N | Use Case |
|------|----------|-------|--------|----------|
| PN10QP27 | 128-bit | 1024 | 512 | Default, balanced |
| PN11QP54 | 128-bit | 2048 | 1024 | Higher precision |

## Test Results

```
=== RUN   TestBitwiseEncryptDecrypt      --- PASS
=== RUN   TestBitwiseAdd                 --- PASS (6.50s)
=== RUN   TestBitwiseScalarAdd           --- PASS (2.74s)
=== RUN   TestBitwiseEq                  --- PASS (3.21s)
=== RUN   TestBitwiseLt                  --- PASS (6.53s)
=== RUN   TestBitwiseSub                 --- PASS (8.94s)
=== RUN   TestBitwiseBitOps              --- PASS (1.15s)
=== RUN   TestBitwiseShift               --- PASS (0.13s)
=== RUN   TestBitwiseCastTo              --- PASS (0.13s)
=== RUN   TestPublicKeyEncryption        --- PASS
=== RUN   TestPublicKeyWithOperations    --- PASS (1.71s)
=== RUN   TestPublicKeySerialization     --- PASS
=== RUN   TestFheRNG                     --- PASS (6 subtests)
=== RUN   TestFheRNGPublic               --- PASS (2 subtests)
PASS - ok  github.com/luxfi/fhe  35.876s
```

## Implementation Status

### Completed ✓
- [x] Boolean gates with blind rotation
- [x] Multi-input gates: AND3, OR3, NAND3, NOR3, MAJORITY
- [x] Integer types (FheUint4-256)
- [x] Arithmetic: Add, Sub, Neg, ScalarAdd
- [x] Comparisons: Eq, Lt, Le, Gt, Ge, Min, Max
- [x] Bitwise: And, Or, Xor, Not
- [x] Shifts: Shl, Shr
- [x] Type casting
- [x] Public key encryption
- [x] Deterministic RNG
- [x] Binary serialization
- [x] OpenFHE CGO backend (C++ bridge + Go bindings)
- [x] GitHub Actions CI workflow

### CGO Backend (Primary GPU Path)
The CGO backend provides GPU-accelerated FHE via C++ (`luxcpp/fhe`):
- `cgo/fhe.go` - ~1000 lines of thin CGO wrappers
- `cgo/tfhe_bridge.h` - C header for the C++ bridge
- Links to `libFHEbin`, `libFHEpke`, `libFHEcore` with Metal/CUDA support
- All gate operations run on GPU automatically

## Benchmark Comparison (Apple M1 Max)

| Operation | Pure Go | OpenFHE CGO | Notes |
|-----------|---------|-------------|-------|
| BootstrapKey Gen | 132 ms | 2413 ms | **Go 18x faster** |
| AND/OR/NAND/NOR | ~51 ms | ~56 ms | Go ~10% faster |
| XOR/XNOR | ~51 ms | ~56 ms | **Go ~10% faster** |
| NOT | 1.2 µs | 1.4 µs | Both free |
| Decrypt | 4.5 µs | 1.4 µs | CGO 3x faster |
| Add 8-bit | 3.5 s | - | Via gate composition |
| Lt 8-bit | 2.9 s | - | Via gate composition |
| MAJORITY | ~59 ms | - | **Single bootstrap** ✓ |
| AND3/OR3 | ~117 ms | - | 2 bootstraps (composition) |

**Key Insights:**
- Pure Go bootstrap key gen is dramatically faster (important for startup)
- **XOR/XNOR optimized** to match OpenFHE algorithm: `2*(ct1+ct2)` with single bootstrap
- **MAJORITY** uses single bootstrap (threshold at 0 separates 0-1 true from 2-3 true)
- AND3/OR3 use 2-bootstrap composition for correctness
- All 2-input gates now ~51ms (uniform performance)
- Pure Go wins for all gate operations

See `BENCHMARKS.md` for full results.

### Future Work
- [ ] Mul/Div operations (expensive)
- [x] OpenFHE backend benchmarking ✓
- [x] XOR/XNOR optimization (matching OpenFHE) ✓
- [x] FHE Server (cmd/fhe-server) ✓
- [ ] Multi-party threshold decryption (MPC protocol)
- [x] MLX GPU backend for OpenFHE fork ✓

## GPU Backend (OpenFHE Fork)

Apple Silicon GPU acceleration via luxfi/gpu framework in `~/work/lux/fhe`:

```bash
# Build with GPU support
cd ~/work/lux/fhe
mkdir build-gpu && cd build-gpu
cmake -DWITH_GPU=ON -DGPU_ROOT=../../luxfi/gpu -DCMAKE_BUILD_TYPE=Release ..
make -j8
```

### Architecture
```
lux/fhe (OpenFHE fork with GPU backend)
    └── src/core/
        ├── include/math/hal/gpu/gpu_backend.h
        └── lib/math/hal/gpu/
            ├── gpu_backend.cpp
            └── CMakeLists.txt
```

### Key Classes
- `GPUNTT` - NTT/INTT with batch operations
- `GPUPolyOps` - Polynomial arithmetic (add, sub, mult, automorphism)
- `GPUBlindRotation` - FHE bootstrapping infrastructure

### Design Decisions
1. **Integer NTT**: Uses exact modular arithmetic (uint64_t) - float64 not available on GPU
2. **Batch-First**: API designed for batch PBS (levelize circuits, process all gates at depth)
3. **RNS Path**: Integer/RNS approach preferred over FFT/float for exactness
4. **Custom Kernels (TODO)**: Hot loops (NTT butterfly, external product) need Metal/CUDA kernels

### Benchmarks (Apple M1 Max)
| Operation | Time | Notes |
|-----------|------|-------|
| NTT Forward (n=1024) | 30 µs | Per transform |
| Batch NTT (32 × n=512) | 14 µs/poly | Amortized |
| Throughput | 33K trans/s | Sequential |

### GPU Optimization Guidelines (FHE/PBS)
- Batch PBS aggressively (levelize circuits)
- Keep bootstrap key resident (avoid host/device churn)
- Use SoA layout for coalescing
- Fuse kernels (decomp → extprod → accumulate)
- Prefer RNS + NTT for exactness (float64 unsupported on GPU)

## GPU FHE Engine (Massive Parallelism)

Enterprise-grade GPU FHE for 1000+ concurrent users with 100GB+ GPU memory.

### Architecture
```
FHEEngine
    ├── UserSession[]           - Per-user isolated contexts
    │   ├── BootstrapKeyGPU     - BK resident on GPU [n, 2, L, 2, N]
    │   ├── KeySwitchKeyGPU     - KSK on GPU
    │   └── LWECiphertextGPU[]  - Ciphertext pools (SoA layout)
    │
    ├── BatchPBSScheduler       - Groups operations by gate type
    │   └── Auto-flush at threshold
    │
    └── Metal Kernels           - Fused GPU operations
        ├── batchNTTForward/Inverse
        ├── batchExternalProduct
        ├── batchBlindRotate
        ├── batchCMux
        └── batchKeySwitch
```

### Files
```
lux/fhe/src/core/
    ├── include/math/hal/gpu/fhe.h      - GPU FHE API
    └── lib/math/hal/gpu/
        ├── fhe.cpp                      - Implementation
        └── fhe_kernels.metal            - Metal shaders
```

### Key Optimizations
| Optimization | Impact |
|--------------|--------|
| **L=4 (vs L=7)** | ~1.75× speedup, BK fits L3 |
| **SoA Layout** | Coalesced GPU memory access |
| **Fused Kernels** | decompose→mul→acc in one pass |
| **Batch by Gate** | Same test poly for all ops |
| **User Isolation** | Per-user BK, no interference |

### API Usage
```cpp
#include "math/hal/mlx/fhe.h"
using namespace lbcrypto::gpu;

// Initialize engine
FHEConfig config;
config.N = 1024;
config.L = 4;  // Reduced!
config.maxUsers = 10000;
config.gpuMemoryBudget = 100ULL * 1024 * 1024 * 1024;  // 100GB

FHEEngine engine(config);
engine.initialize();

// Create users
uint64_t user1 = engine.createUser();
engine.uploadBootstrapKey(user1, bskData);
engine.allocateCiphertexts(user1, 1000);

// Batch operations
BatchedGateOp batch;
batch.gate = GateType::AND;
for (int i = 0; i < 10000; ++i) {
    batch.userIds.push_back(user1);
    batch.input1Indices.push_back(i);
    batch.input2Indices.push_back(i + 1);
    batch.outputIndices.push_back(i + 10000);
}
engine.executeBatchGates({batch});
engine.sync();
```

### Target Performance
| Metric | Target |
|--------|--------|
| Users | 10,000+ concurrent |
| Memory | 100GB+ GPU |
| Gate throughput | 100K+ gates/sec |
| Latency per gate | <1ms (amortized) |

### Memory Layout (SoA for Coalescing)
```
LWECiphertext batch [B ciphertexts]:
  a: [B, n]  - All a[0]s contiguous, then a[1]s, etc.
  b: [B]     - All body values contiguous

BootstrapKey [n RGSW ciphertexts]:
  data: [n, 2, L, 2, N]  - Digit-major for sequential extprod
```

## FHE Server

Standalone HTTP server for FHE operations, designed as a sidecar for the Solidity stack.

```bash
# Build
go build ./cmd/fhe-server

# Standard CPU mode
./fhe-server -addr :8448

# GPU-accelerated mode (Metal/CUDA via MLX)
./fhe-server -addr :8448 -gpu -batch 32

# Threshold mode
./fhe-server -addr :8448 -threshold -parties 5
```

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check (includes GPU status) |
| `/publickey` | GET | Get FHE public key |
| `/encrypt` | POST | Encrypt value |
| `/decrypt` | POST | Decrypt (non-threshold) |
| `/evaluate` | POST | Evaluate FHE operation |
| `/gpu/status` | GET | GPU engine status (memory, backend, device) |
| `/gpu/batch` | POST | Batch GPU operations |
| `/threshold/parties` | GET | List threshold parties |
| `/threshold/decrypt` | POST | Threshold decryption |
| `/verify` | POST | ZK verification |

### GPU Batch Operations

```bash
# Check GPU status
curl http://localhost:8448/gpu/status
# {"enabled":true,"backend":"Metal","device":"Apple M-series GPU","memory_gb":64}

# Batch operations
curl -X POST http://localhost:8448/gpu/batch \
  -H "Content-Type: application/json" \
  -d '{"operations": [
    {"id": "op1", "op": "add", "left": "<base64>", "right": "<base64>"},
    {"id": "op2", "op": "eq", "left": "<base64>", "right": "<base64>"}
  ]}'
```

### Command Line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-addr` | `:8448` | HTTP server address |
| `-gpu` | `false` | Enable GPU acceleration (Metal/CUDA) |
| `-batch` | `32` | Batch size for GPU operations |
| `-threshold` | `false` | Enable threshold FHE mode |
| `-parties` | `5` | Number of threshold parties |
| `-data` | `./data` | Data directory for keys |

### JavaScript SDK Integration

```typescript
import { LuxFHE } from '@luxfhe/sdk'

const fhe = new LuxFHE({
  serverUrl: 'http://localhost:8448',
  threshold: true,
})

const encrypted = await fhe.encrypt(42, 'uint8')
const result = await fhe.evaluate('add', encrypted, encrypted)
```

## fhEVM Integration

```go
import "github.com/luxfi/fhe"

type FHEPrecompile struct {
    params      fhe.Parameters
    bsk         *fhe.BootstrapKey
    bitwiseEval *fhe.BitwiseEvaluator
}

func (p *FHEPrecompile) Add(input []byte) ([]byte, error) {
    ct1 := new(fhe.BitCiphertext)
    ct1.UnmarshalBinary(input[:len(input)/2])
    ct2 := new(fhe.BitCiphertext)
    ct2.UnmarshalBinary(input[len(input)/2:])
    
    result, err := p.bitwiseEval.Add(ct1, ct2)
    if err != nil {
        return nil, err
    }
    return result.MarshalBinary()
}
```

## GPU Acceleration (C++ First Architecture)

GPU acceleration is handled entirely in C++ (`luxcpp/fhe`) with Go bindings via CGO.

### Architecture

```
luxcpp/
├── gpu/          ← Foundation (MLX/Metal/CUDA)
├── lattice/      ← NTT acceleration (uses gpu)
├── fhe/          ← TFHE/CKKS/BGV (uses lattice)
│   └── Metal Shaders:
│       ├── ntt_kernels.metal
│       ├── fhe_kernels.metal
│       ├── external_product_fused.metal
│       ├── four_step_ntt.metal
│       ├── bsk_prefetch.metal
│       └── scheme_switch.metal
│
└── crypto/       ← BLS pairings (uses gpu directly)

luxfi/fhe (Go)
└── cgo/          ← Thin CGO bindings to luxcpp/fhe
    ├── fhe.go    ← ~1000 lines of thin wrappers
    └── tfhe_bridge.h
```

### Key Points

1. **All GPU code in C++**: No Go GPU reimplementation - removed redundant `engine/` package
2. **Thin CGO bindings**: Go just wraps C++ calls, ~10-20ms per gate
3. **Metal + CUDA support**: Handled in C++ via luxcpp/gpu (MLX backend)
4. **Automatic backend detection**: C++ detects Metal (macOS) or CUDA (Linux)

### Performance (Apple M1 Max via CGO)

| Operation | Latency | Notes |
|-----------|---------|-------|
| Context creation | <1ms | Fast init |
| Key generation | 240ms | Bootstrap key included |
| AND/OR/NAND/NOR | ~10-20ms | GPU-accelerated |
| XOR/XNOR | ~10-20ms | GPU-accelerated |
| NOT | <1ms | Free operation |

### Usage

```go
import "github.com/luxfi/fhe/cgo"

// Create GPU-accelerated context
ctx, _ := cgo.NewContext(cgo.SecuritySTD128, cgo.MethodGINX)
defer ctx.Free()

// Generate keys (uses Metal/CUDA internally)
sk, _ := ctx.GenerateSecretKey()
ctx.GenerateBootstrapKey(sk)

// GPU-accelerated gate operations
ct1, _ := ctx.EncryptBit(sk, true)
ct2, _ := ctx.EncryptBit(sk, false)
result, _ := ctx.And(ct1, ct2)  // Runs on GPU

// Integer operations
int1, _ := ctx.EncryptInteger(sk, 42, 8)
int2, _ := ctx.EncryptInteger(sk, 10, 8)
sum, _ := ctx.Add(int1, int2)  // GPU-accelerated
```

### Build Requirements

```bash
# 1. Build MLX in luxcpp/gpu (foundation layer)
cd ~/work/luxcpp/gpu
mkdir build && cd build
cmake .. -DMLX_BUILD_TESTS=OFF
make -j$(sysctl -n hw.ncpu)
mkdir -p ../install/lib
cp libmlx.dylib mlx.metallib ../install/lib/

# 2. Build FHE library (links to MLX)
cd ~/work/luxcpp/fhe
mkdir build && cd build
cmake .. -DWITH_MLX=ON
make -j$(sysctl -n hw.ncpu)
make install  # Installs to luxcpp/fhe/install/

# 3. Go CGO bindings work automatically
cd ~/work/lux/fhe
CGO_ENABLED=1 go test ./cgo/...
```

### Library Dependency Chain

```
luxfi/fhe/cgo (Go)
    ↓ CGO links to
luxcpp/fhe/install/lib/libFHE*.dylib
    ↓ rpath links to
luxcpp/gpu/install/lib/libmlx.dylib
```

Install locations:
- `luxcpp/gpu/install/lib/` - MLX dylib + Metal shaders
- `luxcpp/fhe/install/lib/` - FHE libs (libFHEcore, libFHEbin, libFHEpke)

## Build

```bash
# Pure Go (default)
go build ./...
go test ./...

# With OpenFHE acceleration (optional)
CGO_ENABLED=1 go build -tags openfhe ./...

# GPU FHE (luxfi/gpu backend)
cd fhe && mkdir build-gpu && cd build-gpu
cmake .. -DWITH_GPU=ON -DGPU_ROOT=../../luxfi/gpu
make -j8 OPENFHEcore
```

## License

BSD-3-Clause - Lux Industries Inc
