# LuxFHE - Fully Homomorphic Encryption Stack

## Overview

LuxFHE (`github.com/luxfhe`) provides a complete FHE stack for Lux blockchain - JavaScript SDKs, Solidity contracts, Go/WASM backends, ML pipelines, and research implementations.

## Packages

| Package | Mode | Description |
|---------|------|-------------|
| `@luxfhe/v1-sdk` | Standard | Single-key TFHE - simpler, faster for trusted setups |
| `@luxfhe/v2-sdk` | Threshold | Network-based TFHE - decentralized decryption |
| `@luxfhe/wasm` | Bindings | TFHE WASM bindings (web + node via conditional exports) |
| `@luxfhe/kms` | Bindings | KMS bindings (web + node via conditional exports) |

**Canonical Contracts:** FHE contracts are published as part of `@luxfi/contracts` at `~/work/lux/standard`.

```
@luxfi/contracts/contracts/fhe/     # Canonical FHE contracts location
├── FHE.sol                         # Core FHE library
├── IFHE.sol                        # FHE interface and types
├── FheOS.sol                       # FHE OS precompiles
├── access/                         # Permissioned access control
├── config/                         # Network configuration
├── finance/                        # Vesting, DeFi primitives
├── gateway/                        # Gateway for decryption
├── governance/                     # Confidential voting
├── token/ERC20/                    # Confidential ERC20 tokens
└── utils/                          # Errors, debugging
```

**Sync workflow:** Development happens in `luxfhe/contracts/`, then sync to `lux/standard`:
```bash
cd luxfhe/contracts && pnpm sync  # Syncs to ~/work/lux/standard/contracts/fhe/
```

**Progression:** v1 → v2 shows evolution from centralized to decentralized FHE.

## Directory Structure

```
luxfhe/
├── js/                     # JavaScript SDKs
│   ├── v1-sdk/             # @luxfhe/v1-sdk - Standard TFHE
│   ├── v2-sdk/             # @luxfhe/v2-sdk - Threshold TFHE  
│   └── permit/             # Permit handling utilities
│
├── contracts/              # @luxfhe/contracts - Solidity FHE
│   └── contracts/
│       ├── access/         # Access control
│       ├── experimental/   # Experimental features
│       ├── finance/        # DeFi primitives
│       ├── governance/     # Voting/governance
│       ├── token/          # ERC20/721/1155 FHE variants
│       ├── utils/          # Utility contracts
│       ├── FHE.sol         # Core FHE operations
│       ├── FheOS.sol       # FHE OS interface
│       └── IFHE.sol        # FHE types and interface
│
├── core/                   # Core FHE implementations
│   ├── torus/           # TFHE compiler (Python to FHE)
│   ├── fhevm/              # Full-stack FHEVM framework
│   ├── fhevm-solidity/     # FHEVM Solidity library
│   ├── kms/                # Key Management System (Rust)
│   └── threshold/          # Threshold FHE library (Rust)
│
├── sdk/                    # Additional SDKs
│   ├── relayer/            # Relayer SDK for FHEVM protocol
│   └── fhe/              # CoFHE SDK monorepo
│
├── ml/                     # Machine Learning with FHE
│   ├── torus-ml/           # ML with FHE (Python)
│   ├── biometrics/         # FHE biometrics demo
│   └── extensions/         # Torus ML extensions
│
├── cmd/                    # Command-line applications
│   └── fhed/               # FHE daemon (standalone server)
│
├── go/                     # Go implementations
│   └── tfhe/               # Go TFHE bindings + server
│       └── cmd/            # CLI tools
│
├── wasm/                   # WebAssembly
│   └── tfhe/               # TFHE WASM bindings
│
├── examples/               # 25+ reference implementations
│   ├── blind-auction/      # [v1] Blind auction demo
│   ├── blind-auction-v2/   # [v2] Blind auction (threshold)
│   ├── binary-guessing/    # Binary number guessing game
│   ├── confidential-contracts/ # Confidential contract patterns
│   ├── confidential-voting/ # [v1] Private voting
│   ├── dapps/              # Multi-dapp monorepo
│   ├── demo-v2/            # v2 SDK demo (Nuxt)
│   ├── encrypto/           # Foundry-based FHE examples
│   ├── erc20-tutorial/     # [v1] FHE ERC20 tutorial
│   ├── fhe-voting/         # FHE voting implementation
│   ├── ios-demo/           # iOS FHE demo app
│   ├── kuhn-poker/         # FHE Kuhn poker variant
│   ├── playground/         # [v1] Interactive demo
│   ├── poker/              # [v1] FHE Kuhn poker
│   ├── redact/             # Data redaction example
│   ├── rng-game/           # [v1] Random number guessing
│   ├── rps-game/           # [v2] Rock-paper-scissors
│   ├── secret-santa/       # [v2] Secret Santa
│   ├── smart-wallet/       # [v1] Smart wallet POC
│   ├── ticket-manager/     # Ticket management (Nuxt)
│   ├── ticketing/          # Ticket contracts
│   ├── tickets/            # Ticket UI (Nuxt)
│   └── voting/             # FHE voting demo
│
├── templates/              # Project starters
│   ├── fhevm-hardhat/      # Hardhat + FHEVM
│   ├── foundry/            # Foundry template
│   ├── hardhat/            # Basic hardhat
│   ├── hardhat-starter/    # Hardhat quickstart
│   ├── miniapp/            # Mini-app template
│   ├── next/               # Next.js template
│   ├── nuxt/               # Nuxt.js template
│   ├── react/              # React template
│   ├── scaffold-eth/       # Scaffold-ETH2 + FHE
│   ├── ui/                 # UI component templates
│   └── vue/                # Vue.js template
│
├── plugins/                # Development plugins
│   ├── hardhat/            # Hardhat plugin
│   └── remix/              # Remix IDE plugin
│
├── mocks/                  # Mock contracts for testing
│   ├── fhe/              # CoFHE mock contracts
│   ├── fhevm/              # FHEVM mocks
│   └── foundry/            # Foundry mocks
│
├── research/               # Research implementations
│   ├── acm-threshold/      # ACM threshold paper code
│   ├── ocp-fhe/            # Open compute protocol FHE
│   ├── threshold-paper/    # Threshold FHE benchmarks
│   └── verifiable-fhe/     # Verifiable FHE proofs
│
├── proto/                  # Protocol buffers
│   └── decryption-oracle/  # Decryption oracle protos
│
├── docs/                   # Documentation
│   ├── fhe/              # Threshold FHE docs (Docusaurus)
│   ├── luxfhe/             # Legacy docs
│   ├── resources/          # Awesome FHE resources
│   └── workshop/           # Workshop materials
│
├── tests/                  # Test suites
│   └── fhevm-suite/        # FHEVM test suite
│
├── scaffold-eth/           # Scaffold-ETH2 integration
└── hardhat-plugin/         # Hardhat plugin monorepo
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         JavaScript Applications                         │
├────────────────────────────┬────────────────────────────────────────────┤
│   @luxfhe/v1-sdk           │         @luxfhe/v2-sdk                     │
│   (Standard TFHE)          │         (Threshold TFHE)                   │
│   - Single encryption key  │         - Distributed key shares (t-of-n) │
│   - Key holder decrypts    │         - Network consensus decryption    │
│   - Lower latency          │         - No single point of trust        │
│   - Trusted environments   │         - Public DeFi, trustless apps     │
├────────────────────────────┴────────────────────────────────────────────┤
│                          @luxfhe/contracts                              │
│                    Solidity FHE Smart Contracts                         │
│    FHE.sol · FheOS.sol · token/* · finance/* · governance/*            │
├─────────────────────────────────────────────────────────────────────────┤
│                         Core Components                                  │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐            │
│  │   torus/    │  │    fhevm/      │  │     kms/       │            │
│  │ TFHE Compiler  │  │ Full Stack VM  │  │ Key Management │            │
│  │   (Python)     │  │   (Solidity)   │  │    (Rust)      │            │
│  └────────────────┘  └────────────────┘  └────────────────┘            │
├─────────────────────────────────────────────────────────────────────────┤
│                    Backend Services                                      │
│  ┌───────────────────────────────┐  ┌───────────────────────────────┐  │
│  │   Go FHE Server               │  │   WASM Bindings               │  │
│  │   ~/work/lux/tfhe/cmd/        │  │   luxfhe/wasm/tfhe            │  │
│  │   /encrypt /decrypt /evaluate │  │   Browser-native FHE          │  │
│  └───────────────────────────────┘  └───────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────────────┤
│                    Cryptographic Foundations                             │
│     github.com/luxfi/tfhe (Pure Go)  ·  github.com/luxfi/lattice       │
└─────────────────────────────────────────────────────────────────────────┘
```

## SDK Comparison

### v1-sdk (Standard TFHE)
- Single encryption key
- Key holder performs decryption  
- Simpler architecture
- Lower latency
- Best for: Trusted environments, private apps

### v2-sdk (Threshold TFHE)
- Distributed key shares (t-of-n)
- Network consensus for decryption
- No single point of trust
- Requires FHE server network
- Best for: Public DeFi, trustless apps

## Examples by SDK

**v1-sdk examples** (single-key):
- blind-auction, confidential-voting, erc20-tutorial
- playground, poker, rng-game, smart-wallet

**v2-sdk examples** (threshold):
- blind-auction-v2, rps-game, secret-santa, demo-v2

**Framework-agnostic** (works with both):
- binary-guessing, confidential-contracts, dapps
- encrypto, fhe-voting, ios-demo, kuhn-poker
- redact, ticket-manager, ticketing, tickets, voting

## Core Components

### torus/ - TFHE Compiler
Python-to-FHE compiler. Converts Python code with numpy operations into FHE circuits.
- `frontends/` - Python frontend
- `compilers/` - FHE circuit compilers
- `backends/` - Execution backends (CPU, GPU)

### fhevm/ - Full-Stack FHEVM
Complete blockchain FHE framework:
- `coprocessor/` - FHE coprocessor
- `gateway-contracts/` - Gateway smart contracts
- `protocol-contracts/` - Protocol layer
- `sdk/` - TypeScript SDK
- `test-suite/` - Comprehensive tests

### kms/ - Key Management System
Rust-based threshold key management:
- `core/` - KMS core logic
- `core-client/` - Client library
- Docker compose files for centralized/threshold modes

### threshold/ - Threshold FHE Library
Rust implementation of threshold TFHE:
- `src/` - Core threshold logic
- `examples/` - Usage examples
- `benches/` - Performance benchmarks

## ML with FHE

### torus-ml/
Machine learning on encrypted data:
- `src/` - Core library
- `use_case_examples/` - Real-world ML examples
- `benchmarks/` - Performance benchmarks
- `docs/` - Comprehensive documentation

### biometrics/
FHE biometric verification demo:
- `client/` - Client-side processing
- `server/` - Server-side FHE operations
- `notebooks/` - Jupyter demos

### extensions/
Torus-ML extensions:
- `rust/` - Rust accelerations
- Additional ML operations

## FHE Daemon (fhed)

The `fhed` daemon provides a standalone FHE server for fully homomorphic encryption operations.

### Quick Start
```bash
# Install
go install github.com/luxfi/fhe/cmd/fhed@latest

# Start daemon (auto-generates keys on first run)
fhed start --http :8448

# Or with custom data directory
fhed start --http :8448 --data /path/to/keys

# Generate keys separately
fhed keygen --output ./keys --params PN10QP27
```

### Threshold Mode (t-of-n)
```bash
# Start in threshold mode with mDNS discovery
fhed start --mode threshold --threshold 2

# Generate 2-of-3 threshold keys
fhed keygen --threshold --t 2 --n 3 --output ./keys

# Reshare to new threshold/parties (LSSS)
fhed reshare --input ./keys --new-t 3 --new-n 5 --output ./reshared
```

### Features
- **HTTP API** for encrypt/decrypt/evaluate operations
- **Automatic key management** - generates keys on first start
- **Boolean gates** - AND, OR, XOR, NOT, NAND, NOR, XNOR, MUX, MAJORITY
- **Bit-by-bit encryption** - true TFHE with bootstrapping
- **Integer support** - uint32/uint64 as arrays of encrypted bits
- **mDNS discovery** - zero-config cluster formation via `github.com/luxfi/mdns`
- **LSSS resharing** - add/remove nodes without full key regeneration
- **Proactive security** - share refresh to invalidate compromised shares

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/fhe/health` | GET | Health check with params info |
| `/v1/fhe/publickey` | GET | Get public key (hex-encoded) |
| `/v1/fhe/encrypt` | POST | Encrypt bit or integer |
| `/v1/fhe/decrypt` | POST | Decrypt ciphertext(s) |
| `/v1/fhe/evaluate` | POST | Boolean gate evaluation |
| `/v1/fhe/cluster/status` | GET | Cluster state (threshold mode) |
| `/v1/fhe/cluster/peers` | GET | Discovered peers (threshold mode) |
| `/v1/fhe/cluster/reshare` | POST | Trigger reshare (threshold mode) |

### Parameters
- `PN10QP27` (default) - ~128-bit security, good performance
- `PN11QP54` - ~128-bit security, higher precision (Q=0x3FFFFFFFFED001, 54-bit prime)
- `STD128` - OpenFHE compatible

### Example Usage
```bash
# Encrypt a bit
curl -X POST http://localhost:8448/v1/fhe/encrypt \
  -H "Content-Type: application/json" \
  -d '{"bit": true}'

# Encrypt an integer
curl -X POST http://localhost:8448/v1/fhe/encrypt \
  -H "Content-Type: application/json" \
  -d '{"uint32": 42}'

# Boolean AND gate
curl -X POST http://localhost:8448/v1/fhe/evaluate \
  -H "Content-Type: application/json" \
  -d '{"operation": "and", "operands": ["<ct1>", "<ct2>"]}'

# Check cluster status (threshold mode)
curl http://localhost:8448/v1/fhe/cluster/status
```

## mDNS Discovery Package

Zero-config peer discovery for local networks: `github.com/luxfi/mdns`

```go
import "github.com/luxfi/mdns"

// Create discovery
disc := mdns.New("_fhed._tcp", "node-1", 8448,
    mdns.WithMetadata(map[string]string{"version": "1.0"}),
)

// Handle peer events
disc.OnPeer(func(peer *mdns.Peer, joined bool) {
    if joined {
        fmt.Printf("Peer: %s at %s\n", peer.NodeID, peer.Address())
    }
})

// Start/stop
disc.Start()
defer disc.Stop()

// Query peers
for _, peer := range disc.Peers() {
    fmt.Println(peer.NodeID, peer.Get("version"))
}
```

Used by: fhed, mpcd, and other Lux daemons for local cluster formation.

## Go & WASM

### go/tfhe/
Go bindings for TFHE with FHE server:
- `cmd/` - CLI tools and server
- `internal/` - Internal implementations
- `libtfhe-wrapper/` - C FFI bindings
- `wasm-cmd/` - WASM generation tools

### wasm/tfhe/
Browser-native FHE via WebAssembly:
- `wasm-code/` - Core WASM code
- `wasmer/` - Wasmer runtime
- `scripts/` - Build scripts

## Research

### ocp-fhe/
Open Compute Protocol for FHE - decentralized compute network:
- `chain/` - Blockchain integration
- `demo-frontend/` - Demo UI
- `ocf/` - OCF implementation

### threshold-paper/
Academic threshold TFHE paper implementation:
- `benchmarks/` - Performance data
- `src/` - Reference implementation

### verifiable-fhe/
Verifiable FHE proofs - proving correct FHE computation:
- `src/` - Proof generation/verification

## Quick Start

```bash
# Install SDK
pnpm add @luxfhe/v2-sdk  # or @luxfhe/v1-sdk

# Install contracts
pnpm add @luxfhe/contracts
```

```typescript
import { createFheClient } from '@luxfhe/v2-sdk'

const client = await createFheClient({
  provider: window.ethereum,
  networkUrl: 'https://fhe.lux.network'
})

// Encrypt a value
const encrypted = await client.encrypt_uint32(42)
```

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@luxfhe/contracts/FHE.sol";

contract ConfidentialToken {
    mapping(address => euint32) private _balances;
    
    function transfer(address to, euint32 amount) external {
        _balances[msg.sender] = FHE.sub(_balances[msg.sender], amount);
        _balances[to] = FHE.add(_balances[to], amount);
    }
}
```

## Backend (Go)

The FHE server lives at `~/work/lux/tfhe`:
- `cmd/fhe-server/` - HTTP server for FHE operations
- Supports both standard and threshold modes
- Endpoints: `/encrypt`, `/decrypt`, `/evaluate`, `/publickey`

## Development

### Building Examples
```bash
cd examples/playground
pnpm install
pnpm dev
```

### Running Tests
```bash
# Contracts
cd contracts && pnpm test

# SDK
cd js/v2-sdk && pnpm test

# Core
cd core/fhevm && npm test
```

### Using Templates
```bash
# Hardhat project
cp -r templates/hardhat my-fhe-project
cd my-fhe-project
pnpm install

# Next.js frontend
cp -r templates/next my-fhe-frontend
cd my-fhe-frontend
pnpm install && pnpm dev
```

## Native luxd Integration (2024-12-31)

### Architecture
The goal is for FHE to work natively with `luxd --dev` mode, eliminating the need for separate Docker containers:

```
luxd (single node, --dev mode)
├── C-Chain (EVM)
│   └── FHE Precompiles (precompiles/fhe/)
│       - FHEAdd, FHESub, FHEMul, FHEDiv, FHERem
│       - FHEEq, FHELt, FHEGt, FHELe, FHEGe
│       - FHEAnd, FHEOr, FHEXor, FHENot
│       - TrivialEncrypt, VerifyCiphertext
│       - Decrypt, Reencrypt
│
└── T-Chain (ThresholdVM)
    └── FHE RPC Service (vms/thresholdvm/fhe/)
        - GetPublicParams
        - RegisterCiphertext
        - RequestDecrypt / GetDecryptResult
        - CreatePermit / VerifyPermit
```

### SDK Connection

The `@luxfhe/sdk` currently connects to a standalone FHE server at `localhost:8448`. For native luxd:
- SDK should connect to luxd's RPC endpoint
- T-Chain provides FHE services via JSON-RPC at `/ext/bc/T/rpc`

### Unified FHE API (2025-01-01)

**One way to do everything - no backwards compatibility, forward perfection.**

#### Decryption Pattern
```solidity
// Step 1: Request async decryption
FHE.decrypt(encryptedValue);

// Step 2: Get result when ready
bool result = FHE.reveal(encryptedValue);         // Reverts if not ready
(bool result, bool ready) = FHE.revealSafe(encryptedValue);  // Safe version
```

#### Precompile Interface (IFHEDecrypt @ 0x0200...0083)
```solidity
function decrypt(bytes32 handle, uint8 ctType) external returns (bytes32 requestId);
function reveal(bytes32 requestId) external view returns (bytes memory result, bool ready);
```

### Examples Status (2025-01-01)

**✅ All Compiling (unified API):**
- binary-guessing, blind-auction, blind-auction-v2
- confidential-contracts, confidential-voting
- rng-game, rps-game, secret-santa, voting

**⚠️ Not using @luxfi/contracts:**
- `dapps/` - Uses `@fhevm/solidity` (lux's library)
- `poker/`, `kuhn-poker/` - Custom implementation
- `ticketing/`, `tickets/` - Package manager issues

### Key Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `@luxfi/contracts` | 1.4.0 | Solidity FHE library |
| `@luxfhe/sdk` | 0.5.0 | JavaScript SDK |

## Licenses

All code uses permissive licenses:
- MIT - Most components
- BSD-3-Clause - LuxFHE-derived code
- Apache-2.0 - Some Rust components

## Key Files

| Path | Purpose |
|------|---------|
| `contracts/contracts/FHE.sol` | Core FHE operations |
| `js/v2-sdk/src/index.ts` | v2 SDK entry point |
| `js/v1-sdk/src/index.ts` | v1 SDK entry point |
| `core/fhevm/sdk/` | FHEVM TypeScript SDK |
| `core/kms/core/` | KMS core logic |
| `go/tfhe/cmd/` | Go FHE server |
| `ml/torus-ml/src/` | ML with FHE |

## NTT (Go side, `ntt_simd.go` + `ntt_gpu.go`)

`fhe.NTTEngine` wraps a cached `subring.SubRing` keyed by `(N, Q)`. Two API tiers:

| Method | Path |
|--------|------|
| `NTTInPlace(coeffs)` / `INTTInPlace(coeffs)` | Single polynomial, CPU subring. |
| `NTTBatch(polys) / INTTBatch(polys)` | Batch dispatch — `luxfi/lattice/v7/gpu` (Metal/CUDA) when `gpu.GPUAvailable()` AND the engine's `(N,Q)` passes byte-equality probe; otherwise per-poly CPU. |
| `GPUNTTAvailable()` | Reports whether the GPU path serves this engine. |

CGo is the only build-tag axis. The byte-equality probe runs once per `(N, Q)`
and caches the result — a GPU context that disagrees with the CPU oracle is
rejected (never silently dispatched).

Tests: `ntt_gpu_test.go::TestNTTBatch_ByteEqualToInPlace`,
`TestINTTBatch_RoundTrip`.
