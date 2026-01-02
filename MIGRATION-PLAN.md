# Lux FHE Repository Migration Plan

## Overview

Restructure `/Users/z/work/luxfhe` monorepo into separate top-level repos under `github.com/luxfhe/` organization.

## Current Structure -> Target Repos

| Current Directory | Target Repo | Package Name | Description |
|-------------------|-------------|--------------|-------------|
| `contracts/` | `luxfhe/contracts` | `@luxfhe/contracts` | Core FHE Solidity contracts |
| `js/v1-sdk/` | `luxfhe/v1-sdk` | `@luxfhe/v1-sdk` | Standard TFHE SDK (single-key) |
| `js/v2-sdk/` | `luxfhe/v2-sdk` | `@luxfhe/v2-sdk` | Threshold TFHE SDK (network) |
| `js/permit/` | `luxfhe/permit` | `@luxfhe/permit` | Permit signing utilities |
| `mocks/` | `luxfhe/mocks` | `@luxfhe/mocks` | Mock contracts for testing |
| `examples/` | `luxfhe/examples` | - | Example applications (monorepo) |
| `templates/` | `luxfhe/templates` | - | Project starter templates |
| `docs/` | `luxfhe/docs` | - | Documentation sites |
| `research/` | `luxfhe/research` | - | Research projects |
| `scaffold-eth/` | `luxfhe/scaffold-eth` | - | Scaffold-ETH integration |
| `wasm/` | `luxfhe/wasm-sdk` | `@luxfhe/wasm-sdk` | Rust WASM SDK |
| `proto/` | `luxfhe/proto` | - | Protocol buffer definitions |
| `plugins/hardhat/` | `luxfhe/hardhat-plugin` | `@luxfhe/hardhat-plugin` | Hardhat plugin (CoFHE) |
| `plugins/remix/` | `luxfhe/remix-plugin` | `@luxfhe/remix-plugin` | Remix IDE plugin |
| `hardhat-plugin/` | (merge into hardhat-plugin) | - | Duplicate hardhat plugin root |
| `sdk/fhe/` | `luxfhe/fhe-sdk` | `@luxfhe/fhe-sdk` | CoFHE SDK monorepo |
| `sdk/relayer/` | `luxfhe/relayer` | `@luxfhe/relayer` | Transaction relayer |
| `ml/` | `luxfhe/ml` | - | FHE ML extensions |
| `tests/` | (distribute to each repo) | - | E2E test suites |

## Dependency Graph

```
                    @luxfhe/contracts
                          |
            +-------------+-------------+
            |             |             |
      @luxfhe/v1-sdk  @luxfhe/v2-sdk  @luxfhe/permit
            |             |             |
            +------+------+             |
                   |                    |
            @luxfhe/hardhat-plugin -----+
                   |
            @luxfhe/mocks
```

### Core Dependencies (shared)

1. **@luxfhe/contracts** (no internal deps)
   - External: @openzeppelin/contracts, hardhat

2. **@luxfhe/v1-sdk** (no internal deps)
   - External: ethers, node-tfhe, tfhe, node-tkms, tkms

3. **@luxfhe/v2-sdk** (no internal deps)
   - External: ethers, node-tfhe, tfhe, zustand, zod

4. **@luxfhe/permit** (no internal deps)
   - External: ethers, node-tfhe, tweetnacl

5. **@luxfhe/hardhat-plugin**
   - Internal: @luxfhe/contracts (via peerDeps), @luxfhe/v1-sdk or v2-sdk
   - External: hardhat, ethers

6. **@luxfhe/mocks**
   - Internal: @luxfhe/contracts
   - External: hardhat, foundry

## Package.json Changes Required

### 1. contracts/package.json
```diff
- "repository": { "url": "https://github.com/luxfhe/contracts.git" }
+ "repository": { "url": "https://github.com/luxfhe/contracts.git" }
  // Already correct
```

### 2. js/v1-sdk/package.json
```diff
- "repository": { "url": "git+https://github.com/luxfhe/v1-sdk.git" }
+ "repository": { "url": "https://github.com/luxfhe/v1-sdk.git" }
  // Minor URL normalization
```

### 3. js/v2-sdk/package.json
```diff
  // Already correctly configured for standalone repo
```

### 4. js/permit/package.json
```diff
- "name": "fhe-permit"
+ "name": "@luxfhe/permit"
- "repository": { "url": "git+https://github.com/luxfheProtocol/fhe.git" }
+ "repository": { "url": "https://github.com/luxfhe/permit.git" }
```

### 5. plugins/hardhat/package.json
```diff
- "name": "fhe-hardhat-plugin"
+ "name": "@luxfhe/hardhat-plugin"
- "repository": "github:luxfheProtocol/fhe-hardhat-plugin"
+ "repository": { "url": "https://github.com/luxfhe/hardhat-plugin.git" }
- "@luxfhe/fhe-contracts": "0.0.13"
+ "@luxfhe/contracts": "^0.5.0"
- "@luxfhe/fhe-mock-contracts": "^0.3.0"
+ "@luxfhe/mocks": "^0.5.0"
```

### 6. proto/decryption-oracle/go.mod
```diff
- module github.com/fhenixprotocol/decryption-oracle-proto
+ module github.com/luxfhe/proto
```

## Import Path Changes

### Solidity Imports
```diff
- import "@fhenixprotocol/contracts/FHE.sol";
+ import "@luxfhe/contracts/FHE.sol";

- import "fhe/contracts/...";
+ import "@luxfhe/contracts/...";
```

### JavaScript/TypeScript Imports
```diff
- import { ... } from "fhe";
+ import { ... } from "@luxfhe/v2-sdk";

- import { ... } from "@fhenixprotocol/v1-sdk";
+ import { ... } from "@luxfhe/v1-sdk";

- import { ... } from "fhe-permit";
+ import { ... } from "@luxfhe/permit";
```

### Go Imports
```diff
- import "github.com/fhenixprotocol/decryption-oracle-proto"
+ import "github.com/luxfhe/proto"
```

## Migration Order (Dependency-Aware)

1. **Phase 1 - Core (no internal deps)**
   - contracts
   - v1-sdk
   - v2-sdk
   - permit
   - proto
   - wasm-sdk

2. **Phase 2 - Dependent packages**
   - mocks (depends on contracts)
   - hardhat-plugin (depends on contracts, sdk)
   - remix-plugin

3. **Phase 3 - Applications**
   - examples
   - templates
   - scaffold-eth
   - docs

4. **Phase 4 - Research/Internal**
   - research
   - ml
   - fhe-sdk
   - relayer

## Files to Create in Each Repo

Each new repo needs:
- `README.md` - Project-specific documentation
- `LICENSE` - BSD-3-Clause or MIT (match current)
- `.gitignore` - Language-appropriate ignores
- `CHANGELOG.md` - Version history
- `.github/workflows/` - CI/CD pipelines (optional, add later)

## Notes

1. **hardhat-plugin/ vs plugins/hardhat/**: These appear to be duplicates. Merge into single `luxfhe/hardhat-plugin`.

2. **sdk/fhe/**: This is a Turborepo monorepo with multiple packages. Consider whether to flatten or keep as monorepo.

3. **tests/**: Distribute e2e tests to relevant repos rather than keeping separate.

4. **Git History**: Use `git filter-repo` or `git subtree split` to preserve commit history if important.

5. **NPM Publishing**: All `@luxfhe/*` packages should use `publishConfig.access: "public"`.
