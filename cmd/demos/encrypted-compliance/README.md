# encrypted-compliance

Runnable FHE compliance gate paired with an illustrative Solidity
contract that mirrors the Go evaluation gate-for-gate against the
`luxfi/precompile` FHE surface.

```bash
go run ./cmd/demos/encrypted-compliance                      # approved (defaults)
go run ./cmd/demos/encrypted-compliance -risk 50 -balance 200    # rejected (risk too high)
go run ./cmd/demos/encrypted-compliance -risk 4 -balance 10      # rejected (balance too low)
```

## What it shows

A compliance engine evaluates:

```
approved = (risk_score <= max_risk) AND (balance >= min_balance)
```

with encrypted inputs. The Go demo prints, for each gate it evaluates,
the **exact Solidity precompile call** the on-chain version would make.
See `./solidity_interface.sol` for the matching contract.

Sample run:

```
setup            270ms
encrypt          0s    // sol: TrivialEncrypt @ 0x0200…0080
FHELe(risk,max)  3.35s // sol: FHE.le(risk, maxRisk)
FHEGe(bal,min)   3.34s // sol: FHE.ge(balance, minBalance)
FHEAnd           90ms  // sol: FHE.and(riskOK, balanceOK)

riskOK    = true
balanceOK = true
APPROVED  = true
```

## Files

| File | Role |
|------|------|
| `main.go`                | Runnable Go demo — does the FHE evaluation end-to-end. |
| `solidity_interface.sol` | Documentation artefact — illustrative on-chain mirror that calls FHE precompiles for each Go gate. Not deployable. |

## Bridge story

See [`../README.md`](../README.md) for the full off-chain ↔ on-chain
gate map.
