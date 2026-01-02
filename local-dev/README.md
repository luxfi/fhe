# LuxFHE Local Development

This directory contains tools for running LuxFHE locally for development.

## Quick Start (Recommended)

### Option 1: Using `lux dev` (Native)

The fastest way to get started - runs natively without Docker:

```bash
# 1. Start the local development environment
./start-local.sh

# 2. Run tests in any example
cd ../examples/blind-auction
npm install
npm run test
```

This starts:
- **Lux dev node** on port 8545 (C-Chain RPC)
- **FHE server** on port 8448

### Option 2: Using Docker Compose

For a more isolated environment:

```bash
# Start FHE server + Anvil for contracts
docker compose --profile contracts up -d

# Or for threshold mode (multi-party FHE)
docker compose --profile threshold up -d
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| C-Chain RPC | 8545 | EVM JSON-RPC endpoint |
| C-Chain WS | 8546 | WebSocket endpoint |
| FHE Server | 8448 | FHE encryption/decryption |
| Faucet | 42069 | Test token faucet |

## FHE Precompile Addresses

| Precompile | Address |
|------------|---------|
| FHEOS | `0x0200000000000000000000000000000000000080` |
| ACL | `0x0200000000000000000000000000000000000081` |
| Verifier | `0x0200000000000000000000000000000000000082` |
| Gateway | `0x0200000000000000000000000000000000000083` |

## Example Hardhat Configuration

```typescript
// hardhat.config.ts
import "@luxfhe/hardhat-plugin";

const config: HardhatUserConfig = {
  solidity: "0.8.31",
  defaultNetwork: "localluxfhe",
  networks: {
    localluxfhe: {
      url: "http://localhost:8545/ext/bc/C/rpc",
      chainId: 1337,
      accounts: {
        mnemonic: "test test test test test test test test test test test junk",
      },
    },
  },
  luxfhePlugin: {
    fheServerUrl: "http://localhost:8448",
    autoFaucet: true,
  },
};
```

## Commands

```bash
# Start all services
./start-local.sh

# Start only node
./start-local.sh --node

# Start only FHE server
./start-local.sh --fhe

# Stop all services
./start-local.sh --stop
```

## Logs

Logs are stored in `~/.lux/dev/logs/`:
- `lux-dev.log` - Lux node logs
- `fhe-server.log` - FHE server logs

## Troubleshooting

### FHE server not starting
```bash
# Check if FHE server is built
ls ~/work/luxcpp/fhe/server/build/bin/fhe_server

# If not, build it:
cd ~/work/luxcpp/fhe
mkdir -p build && cd build
cmake .. && make
```

### Node not starting
```bash
# Check if lux CLI is installed
which lux

# Install if missing:
go install github.com/luxfi/cli@latest
```

### Port already in use
```bash
# Check what's using the port
lsof -i :8545
lsof -i :8448

# Kill the process or use different ports:
NODE_PORT=9650 FHE_PORT=8449 ./start-local.sh
```
