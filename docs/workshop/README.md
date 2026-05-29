# Lux FHEVM Workshop

> **Status:** under construction. The previous workshop bundled
> upstream tooling that is no longer part of the Lux stack
> (`fhevmjs`, `fhevm-tfhe-cli`). The replacement uses the
> **Torus** compiler and the Lux FHE Coprocessor and is being
> ported as those land.

## What this workshop will cover

Building an encrypted ERC-20 token end to end:

- Solidity contract using Lux FHE precompiles via `FHE.sol`
- Off-chain compilation of the encrypted client with the Torus
  framework (`github.com/luxfi/torus`)
- Reencrypt-for-user EIP-712 flow using `eip712-reencrypt.sol`
- Submission through the Lux FHE Coprocessor
  (`github.com/luxfi/fhe-coprocessor`)

The Solidity sources in this directory (`erc20.sol`,
`eip712-reencrypt.sol`) are stable and continue to be the canonical
contract examples. Only the client tooling changed.

## Environment (when the client tooling lands)

Lux FHE Devnet in MetaMask:

- Network name: Lux FHE Devnet
- RPC URL: https://devnet.luxfhe.ai
- Chain ID: 8009
- Currency symbol: LUX
- Block explorer: https://main.explorer.luxfhe.ai/

## Tracking

See the canonical naming and product map under
`Lux FHE` / `Torus` (compiler / framework) — the workshop will
follow that hierarchy.
