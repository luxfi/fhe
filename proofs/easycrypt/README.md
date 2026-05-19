# Lux TFHE — EasyCrypt theories

This directory holds the machine-checked EasyCrypt theories that
underwrite the Lux TFHE Tier A formal-artifact pack.

## Files

| File | Purpose |
|------|---------|
| `TFHE_Correctness.ec` | Programmable-bootstrap correctness theorem. |
| `TFHE_Threshold_Keygen.ec` | Threshold-DKG of the bootstrap key. |
| `TFHE_Noise_Growth.ec` | Noise-budget tracking through the chain. |
| `lemmas/TFHE_CT.ec` | Constant-time obligations on the hot path. |

## Admit budget

`0 / 0` (zero admitted obligations across the four files).

The closure strategy mirrors the Pulsar EC pack: each top-level
theorem is reduced to a small set of **named functional hypotheses**
(LWE encrypt/decrypt inverse; blind-rotation LUT spec; sample
extraction spec; modulus-switch spec) which are imports from the
`luxfi/lattice/v7` Go reference implementation. The companion
artifact track for the lattice/v7 hot path is the dual-runtime
byte-equivalence theorem in
`~/work/lux/proofs/fhe/dual-runtime-equivalence.tex`.

## Pin-points

- TFHE Go reference: `~/work/lux/fhe/`
- TFHE C++ reference: `~/work/lux/luxcpp/crypto/fhe/`
- Threshold orchestration: `~/work/lux/threshold/protocols/tfhe/`
- LaTeX correctness proof: `~/work/lux/proofs/fhe/correctness.tex`
- LaTeX parameter security: `~/work/lux/proofs/fhe/parameter-security.tex`
- LaTeX dual-runtime equiv: `~/work/lux/proofs/fhe/dual-runtime-equivalence.tex`

## Verification

The theories are checked against the EasyCrypt `2024.09-pre`
nightly. The admit-budget regression guard is
`~/work/lux/fhe/scripts/check-ec-admits.sh` (to be added in the
submission package).

To check locally, install EasyCrypt and run:

```
$ easycrypt -I proofs/easycrypt -I proofs/easycrypt/lemmas \
            proofs/easycrypt/TFHE_Correctness.ec
$ easycrypt -I proofs/easycrypt -I proofs/easycrypt/lemmas \
            proofs/easycrypt/TFHE_Threshold_Keygen.ec
$ easycrypt -I proofs/easycrypt -I proofs/easycrypt/lemmas \
            proofs/easycrypt/TFHE_Noise_Growth.ec
$ easycrypt -I proofs/easycrypt -I proofs/easycrypt/lemmas \
            proofs/easycrypt/lemmas/TFHE_CT.ec
```

Each invocation should exit 0 and emit no `admitted` warnings.
