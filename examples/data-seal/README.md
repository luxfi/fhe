# Data Seal - Verifiable Data Integrity

FHE-encrypted tamper-proof document sealing with three seal modes.

**Implements**: [PIP-0010](https://pips.pars.network/PIPs/pip-0010-data-integrity-seal) / [LP-0535](https://lps.lux.network/docs/lp-0535-verifiable-data-integrity-seal)

## Seal Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| **Public** | Transparent, anyone verifies | Journalism, open records |
| **ZK** | Content hidden, properties provable | Trade secrets, proprietary models |
| **Private** | FHE-encrypted, selective disclosure | Whistleblower evidence, medical records |

## How It Works

1. **Seal**: Hash your document, encrypt an integrity tag with FHE, store on-chain
2. **Verify**: Submit an encrypted challenge tag — homomorphic comparison reveals match/mismatch without exposing the original tag
3. **Batch**: Seal thousands of documents in one transaction

## Quick Start

```bash
npm install
npx hardhat compile
npx hardhat test

# Deploy
npx hardhat task:deploy-seal

# Create a seal
npx hardhat task:seal --contract <address> --hash 0xabc...

# Verify a seal
npx hardhat task:verify-seal --contract <address> --id 0 --tag 42

# Batch seal
npx hardhat task:batch-seal --contract <address> --count 10
```

## Related

- **Go implementation**: [github.com/luxfi/fhe/cmd/seal](https://github.com/luxfi/fhe/tree/main/cmd/seal) — Boolean-circuit FHE seal using XNOR+AND chain
- **LP-0530**: Z-Chain Receipt Registry (Poseidon2 Merkle accumulator)
- **LP-3658**: Poseidon2 Precompile (ZK-friendly hashing)
