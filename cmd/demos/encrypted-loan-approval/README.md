# encrypted-loan-approval

Runnable FHE demo: a lender approves or rejects a loan application
based on the borrower's credit score and debt-to-income ratio without
ever seeing the underlying numbers.

```bash
go run ./cmd/demos/encrypted-loan-approval                       # approved (defaults)
go run ./cmd/demos/encrypted-loan-approval -score 120 -dti 30    # rejected (low score)
go run ./cmd/demos/encrypted-loan-approval -score 180 -dti 50    # rejected (high DTI)
```

## Flow

1. **Borrower (client-side)** locally encrypts each 8-bit input
   (`credit_score`, `debt_to_income`) bit-by-bit under their FHE secret
   key. Plaintext never leaves the borrower's machine.
2. **Lender (evaluator)** holds only the public bootstrap key. It
   evaluates the policy entirely on ciphertexts:

   ```
   scoreOK  = unsignedGe8(credit_score,    min_score)   // FHEGe
   dtiOK    = unsignedLe8(debt_to_income,  max_dti)     // FHELe
   approved = scoreOK AND dtiOK                          // FHEAnd
   ```

   Each comparator is a 30-gate cascade (8 XNOR + 8 ANDYN +
   7 AND + 7 OR + 1 NOT) implementing a textbook MSB-to-LSB unsigned
   ripple comparator. Every gate is bootstrapped, so the result can be
   composed indefinitely.

3. **Borrower** receives the ciphertext of the approval bit and
   decrypts it. The lender still holds only ciphertext.

## Sample output

```
=== Encrypted Loan Approval (FHE) ===

Policy (public):
  approved = (credit_score >= 150) AND (debt_to_income <= 35)

Borrower's plaintext inputs (NEVER sent in cleartext to the lender):
  credit_score        = 180
  debt_to_income (%)  = 28

[1/5] Initialising FHE (PN10QP27)…              done in 270ms
[2/5] Borrower encrypts (score, dti) …          done in 0s
[3/5] Lender evaluates: score >= min_score …    done in 2.7s
[4/5] Lender evaluates: dti <= max_dti …        done in 2.7s
[5/5] Lender combines: scoreOK AND dtiOK …      done in 90ms

Borrower decrypts the verdict (lender still holds only ciphertext):
  scoreOK  (private)  = true
  dtiOK    (private)  = true
  APPROVED            = true

Total FHE wall-time: 7.0s
```

## Bridge story

See [`../README.md`](../README.md) for the full off-chain ↔ on-chain
gate map. Short version: every gate this demo invokes
(`AND`/`OR`/`XNOR`/`ANDYN`/`NOT`) is exposed by `luxfi/precompile` as
an EVM precompile (`FHEAnd`/`FHEOr`/`FHEEq`/`FHELt`/`FHENot`). The Go
evaluation here and the on-chain precompile evaluation operate on the
same LWE ciphertext shape.

The companion demo `../encrypted-compliance/` ships a Solidity
contract (`solidity_interface.sol`) that mirrors this exact flow on
the EVM precompile surface — useful as a side-by-side reference.

## Parameters & timing

- Parameter set: `PN10QP27` (128-bit classical security)
- ~62 bootstrapped gates total
- Wall-time: ~7 s on Apple M-series CPU, single-threaded
