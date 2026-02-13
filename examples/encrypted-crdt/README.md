# Encrypted CRDT - Offline-First Privacy

FHE-encrypted Conflict-Free Replicated Data Types for privacy-preserving collaboration.

**Implements**: [PIP-0013](https://pips.pars.network/PIPs/pip-0013-encrypted-crdt) / [LP-6500](https://lps.lux.network/docs/lp-6500-fhecrdt-architecture)

## CRDT Types

| Type | Description | Merge Strategy |
|------|-------------|----------------|
| **LWW-Register** | Last-Writer-Wins Register | Higher timestamp wins, address tiebreak |
| **OR-Set** | Observed-Remove Set | Tag-based add/remove with tombstones |

## How It Works

1. **Write**: Encrypt your value with FHE, assign a Lamport timestamp, store on-chain
2. **Sync**: Peers exchange encrypted registers — values never revealed during sync
3. **Merge**: Deterministic conflict resolution (LWW) operates on encrypted values
4. **Read**: Request threshold decryption only when you need the plaintext

## Key Properties

- **Convergence**: All replicas converge to the same state after syncing all operations
- **Privacy**: Values encrypted end-to-end — even the chain only sees ciphertext
- **Offline-first**: Lamport timestamps enable conflict resolution after offline edits
- **Mesh-compatible**: Works over sneakernet, Bluetooth, or any transport

## Quick Start

```bash
npm install
npx hardhat compile
npx hardhat test

# Deploy
npx hardhat task:deploy-crdt

# Set a register
npx hardhat task:set-register --contract <addr> --doc myDoc --field title --value 42 --timestamp 1

# Read a register
npx hardhat task:get-register --contract <addr> --doc myDoc --field title

# Merge conflicting registers
npx hardhat task:merge-registers --contract <addr> --doc myDoc --field1 alice-title --field2 bob-title --result merged-title
```

## Related

- **Go implementation**: [github.com/luxfi/fhe/cmd/crdt](https://github.com/luxfi/fhe/tree/main/cmd/crdt) — Boolean-circuit LWW-Register with MUX selection
- **LP-6501**: DocReceipts (on-chain document update receipts)
- **LP-6502**: DAReceipts (data availability certificates)
