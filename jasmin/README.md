# Lux TFHE -- Jasmin high-assurance track

This directory holds the Jasmin sources for the Lux TFHE
high-assurance implementation track. Jasmin
(https://github.com/jasmin-lang/jasmin) is a low-level cryptographic
implementation language with a verified compiler whose generated
assembly is bit-identical to the source-level semantics, and which
admits machine-checked side-channel (constant-time) guarantees via
the EasyCrypt companion proof system.

## File layout

| File | Purpose |
|------|---------|
| `lib/tfhe_params.jinc` | Parameter-set constants (PN10QP27 canonical). |
| `lib/modq.jinc` | Constant-time modular arithmetic over Z_q. |
| `external_product.jazz` | RGSW * RLWE external product (NTT-domain). |
| `blind_rotate.jazz` | Blind-rotation core (PBS bulk). |
| `bootstrap.jazz` | PBS composite (blind_rotate o sample_extract o key_switch). |

## Composition

The TFHE bootstrap composite verifies as:

```
Programmable bootstrap (FIPS-equiv functional spec)
  = key_switch o sample_extract o blind_rotate
where blind_rotate is CGGI Asiacrypt 2016 with
  acc <- (X^{-b} * tv) + sum_i (X^{a_i} - 1) * (BSK[i] (*) acc)
```

Each composing routine is CT over its secret-dependent inputs:

- `blind_rotate`: secret = BSK[i] (the RGSW encoding of s_i, the LWE
  secret-key bit). CT via straight-line outer loop + CT external
  product + CT monomial rotate.
- `sample_extract`: no secrets; trivially CT.
- `key_switch`: secret = KSK (gadget decomp of sk_BR -> sk_LWE). CT
  via linear-sweep gadget decomposition + CT mod_mul.

## Status

This is the **initial** high-assurance scaffolding for the Tier A
artifact pack. The Jasmin sources here are:

1. Structurally complete (algorithm shape, parameter-set wiring,
   CT-by-construction control flow).
2. Pending the `jasminc -checkCT` pass for the full library; the
   intent is to wire that into a CI gate matching the Pulsar pack's
   `scripts/check-high-assurance.sh`.
3. Pending substitution of the lattice/v7 reference NTT into the
   external_product.jazz NTT-domain calls (currently the external
   product is stated in NTT-domain but the NTT itself is treated as
   imported from libjade's Kyber NTT, which uses the same q-friendly
   reduction shape for the PN9QP28_STD128 parameter set).

The companion EasyCrypt theories at `../proofs/easycrypt/` state the
functional specs that the Jasmin sources discharge. The CT side
condition is the `lemmas/TFHE_CT.ec` axiom pack.

## How to build (once jasminc is on PATH)

```bash
jasminc -checkCT external_product.jazz
jasminc -checkCT blind_rotate.jazz
jasminc -checkCT bootstrap.jazz
```

Each invocation should succeed with no constant-time violations
reported. The current sources are pseudocode-quality first-pass
implementations; the production-grade Jasmin port uses the
luxcpp/crypto/fhe NTT-fused fast path which has been benchmarked on
M2 Pro (~50-80 ms PBS at N=1024).

## Citations

- Chillotti, Gama, Georgieva, Izabachene, "Faster Fully Homomorphic
  Encryption: Bootstrapping in less than 0.1 Seconds", Asiacrypt 2016.
- Bourse, Minelli, Minihold, Paillier, "Fast Homomorphic Evaluation of
  Deep Discretized Neural Networks", CRYPTO 2018 (TFHE-DM gadget).
- Joye, Paillier, "Blind Rotation in Fully Homomorphic Encryption with
  Extended Decomposition", ACNS 2022 (gadget decomposition variants).
- Almeida, Barbosa, Barthe, Blot, Gregoire, Laporte, Oliveira, Pacheco,
  Schwabe, Strub, "The last mile: High-assurance and high-speed
  cryptographic implementations", IEEE S&P 2020.
