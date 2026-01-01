# @luxfhe/contracts

**Thin wrapper package** - Re-exports FHE (Fully Homomorphic Encryption) contracts from `@luxfi/contracts`.

## Installation

```bash
npm install @luxfhe/contracts
# or
pnpm add @luxfhe/contracts
```

## Usage

```solidity
// Option 1: Import from @luxfhe/contracts (this package)
import "@luxfhe/contracts/fhe/FHE.sol";

// Option 2: Import directly from @luxfi/contracts (canonical source)
import "@luxfi/contracts/fhe/FHE.sol";
```

Both paths resolve to the same contracts.

## What's Included

This package re-exports:

- `FHE.sol` - Core FHE library with encrypted types and operations
- `IFHE.sol` - Interfaces and struct definitions

For the full FHE library including access control, tokens, and governance:

```solidity
// Access control
import "@luxfi/contracts/fhe/access/Permissioned.sol";

// Confidential tokens
import "@luxfi/contracts/fhe/token/ConfidentialERC20.sol";

// Governance
import "@luxfi/contracts/fhe/governance/ConfidentialGovernorAlpha.sol";
```

## Canonical Source

All FHE contracts are maintained in `@luxfi/contracts`:
- GitHub: https://github.com/luxfi/standard
- npm: https://www.npmjs.com/package/@luxfi/contracts

This package (`@luxfhe/contracts`) exists for convenience and backwards compatibility.

## Version History

- **v1.1.0** - Clean import paths (`@luxfhe/contracts/fhe/FHE.sol`)
- **v1.0.0** - Initial release

## License

MIT
