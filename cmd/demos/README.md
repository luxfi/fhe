# FHE Demo Programs

Runnable demos demonstrating Fully Homomorphic Encryption use cases for digital securities and encrypted compliance. Seven server-mode demos (dark pool, compliance, marketmaker, auction, voting, nav, proof) plus two CLI-mode demos that exercise the FHE ↔ precompile bridge (encrypted-loan-approval, encrypted-compliance).

## Prerequisites

```bash
cd ~/work/lux/fhe
go build ./...   # verify the fhe package compiles
```

## Demos

### 1. Dark Pool (Encrypted Order Matching)

Traders submit encrypted limit orders. The matching engine compares bids against asks homomorphically. Only matched fills are decrypted.

```bash
go run ./cmd/demos/darkpool
```

### 2. Programmable Compliance

Verifies SEC diversification rules on an encrypted portfolio: no single position > 25%, total exposure < 80%. Only the boolean compliance result is revealed.

```bash
go run ./cmd/demos/compliance
```

### 3. Private Market Making

Three market makers submit encrypted bid/ask quotes. Best bid (highest) and best ask (lowest) are selected via encrypted comparisons. Losing quotes stay private.

```bash
go run ./cmd/demos/marketmaker
```

### 4. Encrypted Sealed-Bid Auction

Five participants submit encrypted bids. The winner is determined via tournament-style max comparisons. Only the winning bid is decrypted.

```bash
go run ./cmd/demos/auction
```

### 5. Private Shareholder Voting

100 shareholders vote encrypted yes/no. Votes are tallied using a ripple-carry adder (XOR + AND gates). Only the final count is decrypted.

```bash
go run ./cmd/demos/voting
go run ./cmd/demos/voting -voters 50 -yes 30
```

### 6. Confidential NAV

An ETF's encrypted holdings (10 positions with share counts and prices) are used to compute NAV = sum(shares * price) / totalShares. Only the final NAV is revealed.

```bash
go run ./cmd/demos/nav
```

### 7. Compliance Proof

Proves two conditions on an encrypted portfolio: max position < 25% and no sanctioned counterparty. Outputs plaintext booleans while inputs stay encrypted.

```bash
go run ./cmd/demos/proof
```

### 8. Encrypted Loan Approval (CLI + FHE ↔ Precompile bridge)

Standalone CLI: encrypts two 8-bit inputs (credit score and debt-to-income), evaluates `score >= min` AND `dti < max` homomorphically, threshold-decrypts only the final boolean.

```bash
go run ./cmd/demos/encrypted-loan-approval
go run ./cmd/demos/encrypted-loan-approval -score 210 -dti 35
go run ./cmd/demos/encrypted-loan-approval -score 120 -dti 42 -min-score 180 -max-dti 45
```

### 9. Encrypted Compliance (CLI) + Solidity bridge

Off-chain Go harness paired with an illustrative Solidity interface in the same directory. Runs the same gates against `luxfi/fhe` directly that the Solidity contract would call through the luxfi/precompile FHE address space.

```bash
go run ./cmd/demos/encrypted-compliance
```

See `cmd/demos/encrypted-compliance/solidity_interface.sol` for the on-chain analogue.

## Run All

```bash
for d in darkpool compliance marketmaker auction voting nav proof \
         encrypted-loan-approval encrypted-compliance; do
  echo "=== $d ==="
  go run ./cmd/demos/$d
  echo
done
```

## Architecture

All demos use the `github.com/luxfi/fhe` package with boolean circuit evaluation:

- **Parameters**: `PN10QP27` (128-bit security, N=1024)
- **Boolean gates**: `Evaluator` with `AND`, `OR`, `XOR`, `NOT`, `ANDNY`, `MAJORITY` + bootstrapping
- **Encryption**: `Encryptor.Encrypt(bool)` encrypts individual bits
- **Decryption**: `Decryptor.Decrypt(*Ciphertext)` decodes bits (secret key holder only)
- **Integers**: 8-bit values represented as `[8]*Ciphertext` (bit-decomposed, LSB first)
- **Comparison**: MSB-first bitwise less-than circuit using `ANDNY` + `XOR` + `AND` + `OR`
- **Addition**: Ripple-carry full adder using `XOR` + `MAJORITY`

FHE operations run without the secret key. The evaluator uses bootstrap keys (public) for noise management via programmable bootstrapping after each gate.

## Performance (Apple M-series, PN10QP27)

- **Key generation**: ~600ms-1s (one-time)
- **Encryption**: ~5ms per 8-bit value (8 bit encryptions)
- **Single gate** (AND, OR, XOR): ~400-600ms per gate
- **8-bit comparison** (lt/gt/ge): ~12-16s (24 gates: 8x ANDNY + 8x XOR + 7x AND + 7x OR)
- **8-bit addition**: ~10-13s per add (24 gates: 8x XOR + 8x XOR + 8x MAJORITY)
- **Vote tally** (1 ballot): ~5.8s (14 gates: 7x XOR + 7x AND for 7-bit accumulator)

## FHE ↔ Precompile Bridge

The existing seven demos stop at the `luxfi/fhe` Go API boundary — they show encrypted computation works, but leave the reader to imagine how the same gates run under the EVM. The two CLI demos close that loop:

| Demo | Off-chain (`luxfi/fhe` Go call) | On-chain (`luxfi/precompile`) |
|------|---------------------------------|------------------------------|
| `encrypted-loan-approval` | `geEncrypted`, `ltEncrypted`, `eval.AND` | `FHEGe`, `FHELt`, `FHEAnd` |
| `encrypted-compliance`    | `geEncrypted`, `neEncrypted`, `eval.AND` | `FHEGe`, `FHENe`, `FHEAnd` |
| threshold decrypt         | `dec.Decrypt(ebool)`                     | `IFHEDecrypt.decrypt` + `.reveal` at `0x02000000...0083` |

Both demos use parameter set `PN10QP27` (N=1024, ~128-bit classical, same as every other demo in this directory) so the ciphertext layouts shipped to the on-chain precompile match what the Go demo generates.

`cmd/demos/encrypted-compliance/solidity_interface.sol` is the illustrative on-chain twin of `encrypted-compliance/main.go`. It reproduces the `IFHEPrecompile` signatures needed for the three gates (`ge`, `ne`, `and_`, `trivialEncrypt8`, `decrypt`, `reveal`) and a thin `EncryptedCompliance` contract that wires them together. It is not meant to deploy as-is — the actual `@luxfi/contracts/contracts/fhe/FHE.sol` library already provides a richer surface and different low-byte conventions. The point is to let a reader read both files side-by-side and see the symmetry.

### Why CLI, not HTTP, for these two?

The other seven demos are server-mode so they can be driven from a Next.js or hardhat fixture. The bridge demos are single-shot: they exist to show one end-to-end computation with timing, not to expose an API. CLI mode means a reviewer can `go run` one command and read the gate-by-gate timing in their terminal without setting up a client.
