# FHE Demo Programs

Seven runnable demos demonstrating Fully Homomorphic Encryption use cases for digital securities.

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

## Run All

```bash
for d in darkpool compliance marketmaker auction voting nav proof; do
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
