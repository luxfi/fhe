# Encrypted Loan + Compliance demos (`cmd/demos/`)

Two new runnable demos that close the loop between the off-chain Go FHE
library (`luxfi/fhe`) and the on-chain EVM FHE precompiles
(`luxfi/precompile`, per [LP-167](https://github.com/luxfi/lps/blob/main/LPs/lp-167.md)).

| Demo | Story | Wall-time (CPU) |
|------|-------|-----------------|
| [`encrypted-loan-approval/`](./encrypted-loan-approval) | Borrower encrypts `(credit_score, debt_to_income)`. Lender homomorphically evaluates a 2-clause approval policy. Borrower decrypts the verdict. | ~7 s |
| [`encrypted-compliance/`](./encrypted-compliance) | Same shape as `loan`, but pairs the Go demo with an illustrative Solidity contract (`solidity_interface.sol`) that calls the FHE precompile surface gate-for-gate. | ~7 s |

Both run end-to-end in one command, no Docker, no HTTP server, no
external dependency beyond `github.com/luxfi/fhe` itself:

```bash
go run ./cmd/demos/encrypted-loan-approval                # default vectors
go run ./cmd/demos/encrypted-loan-approval -score 120 -dti 45   # rejected
go run ./cmd/demos/encrypted-compliance -risk 4 -balance 200    # approved
go run ./cmd/demos/encrypted-compliance -risk 50 -balance 10    # rejected
```

Parameter set: `PN10QP27` (1024-coefficient ring, ~134M ciphertext
modulus, 128-bit classical security) — same as the rest of the
`luxfi/fhe` demos.

---

## FHE ↔ Precompile Bridge

The point of these two demos is to make one symmetry undeniable: **every
gate the Go demo evaluates off-chain is the same gate a smart contract
would invoke through a precompile on-chain**. Same LWE ciphertext shape,
same bootstrap key, same operation, same noise budget.

### Gate map

| Demo step (Go) | Gate | EVM precompile (per `LLM.md` § Native luxd Integration) |
|----------------|------|---------------------------------------------------------|
| `enc.Encrypt(bit)`                            | LWE encrypt   | `TrivialEncrypt`  @ `0x0200…0080` |
| `unsignedGe8(eval, a, b)` (bit-cascade)       | `FHEGe`       | `0x0200…008C` |
| `unsignedLe8(eval, a, b)` ≡ `Ge(b, a)`        | `FHELe`       | `0x0200…008B` |
| `eval.AND(scoreOK, dtiOK)`                    | `FHEAnd`      | `0x0200…008F` |
| `eval.XNOR(a, b)`                             | `FHEEq` (bit) | `0x0200…0084` |
| `eval.OR(x, y)`                               | `FHEOr`       | `0x0200…0090` |
| `eval.NOT(x)`                                 | `FHENot`      | `0x0200…0092` |
| `dec.Decrypt(approved)`                       | `IFHEDecrypt` | `0x0200…0083` (async; see `solidity_interface.sol::requestVerdict`) |

The final-byte assignments are owner-controlled in `luxfi/precompile`;
the addresses above are illustrative and reflect the order in the
LP-167 reference. The bridge is structural, not address-literal — the
point is that there is a 1:1 mapping between a Go gate call and an EVM
precompile call on the same ciphertext.

### What's real vs. what's illustrative

| Piece | Status |
|-------|--------|
| Off-chain FHE evaluation in Go (`cmd/demos/encrypted-{loan-approval,compliance}/main.go`) | **Real, runs end-to-end.** Uses the `luxfi/fhe` boolean Evaluator (`AND`/`OR`/`XNOR`/`ANDYN`/`NOT`) to build an 8-bit unsigned ripple comparator. Every bootstrap is real. |
| `solidity_interface.sol` | **Illustrative.** Shows the precompile call shape the EVM contract would use. Bodies are commented `staticcall` sketches, not deployable. The Go demo is the executable half of the bridge. |
| Precompile addresses (`0x0200…008X`) | **Illustrative.** Final addresses are owner-set in `luxfi/precompile`. The mapping (one precompile per gate) is structural and stable. |
| Async decrypt flow (`requestVerdict` / `readVerdict`) | **Illustrative.** The Go demo decrypts synchronously because the demo process holds `sk`. On-chain, decryption is brokered by the T-Chain threshold-decryption committee (`@luxfhe/sdk` flow). |

### Why a bit-level cascade, not `IntegerEvaluator.Ge`?

`luxfi/fhe` ships a higher-level radix-encrypted `IntegerEvaluator` API
(`Ge`, `Le`, `Eq`, `Lt`, `Gt`) over `FheUint8` / `FheUint16` / … . In
development we tried wiring the demo to that path first — it would have
been ~5 lines of code. On `PN10QP27` with `blockBits=2` the radix
comparators decrypted to nondeterministic results across our test
vectors (e.g. `Lt(12, 12) = true`, `Ge(100, 150) = true`), which
suggests a noise-budget or LUT-encoding issue somewhere in the
radix → boolean conversion in `integer_ops.go`. The fused `CMPCOMBINE`
gate exhibited similar nondeterminism when chained across 8 bits.

The single-gate boolean primitives (`AND`/`OR`/`XOR`/`XNOR`/`ANDYN`/
`NOT`) are correct in isolation — every one of them decrypts as
expected on every input. The demos therefore use the boolean Evaluator
directly and build a textbook MSB-to-LSB comparator out of it. This
also happens to be a clearer pedagogical fit for the bridge story,
since the EVM precompile internally implements the same cascade.

If the higher-level radix path is fixed in a follow-up, swapping
`unsignedGe8` for `intEval.Ge` is a 4-line change.

### Scope guardrails honoured

- No changes to any TFHE core file (`fhe.go`, `encryptor.go`,
  `decryptor.go`, `evaluator.go`, `integers.go`, `integer_ops.go`,
  `shortint.go`, `lazy_carry.go`, `ntt_*.go`, `security.go`).
- No changes to the seven existing demo binaries.
- No new top-level dependencies — `go.mod` is unchanged.
- Total addition: 3 files (~500 LOC), all under `cmd/demos/`.
