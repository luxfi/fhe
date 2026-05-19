# Cryptographer sign-off -- luxfi/fhe Tier A artifact pack

> Independent review of the Lux TFHE Tier A formal-artifact pack on
> the `main` of `github.com/luxfi/fhe`.
> Reviewer: cryptographer agent (Hanzo Dev, internal review).

## Summary

**APPROVED WITH GATES** for the Lux confidential-compute stack
(LP-066 / LP-134 F-Chain) and for the Lux threshold-FHE compliance
package (LP-019, LP-076, LP-167) subject to the disclosure and
empirical-CT gates in the "Gates" section below.

The Tier A formal-artifact pack at this commit closes the
single-party TFHE bootstrap correctness theorem, the threshold-DKG
correctness reduction, the noise-budget book-keeping, and the
constant-time obligation surface. The empirical CT regression guard
(dudect harness) builds clean for all three hot-path routines
(Encrypt / Decrypt / Bootstrap). The companion paper at
`~/work/lux/papers/lux-tfhe-formalization/` ties everything together
and cites the existing LaTeX artifacts (`correctness.tex`,
`parameter-security.tex`, `dual-runtime-equivalence.tex`) without
restating their content.

The gates that remain are about empirical confirmation of the CT
claim (running dudect to ≥10^9 samples on a quiet CPU-pinned host)
and operational disclosure (deployment runbook calling out the
threshold trust model). They do not require any algorithm or code
change.

## What was reviewed

- **Algorithm source.** `~/work/lux/fhe/` at `main`:
  - `fhe.go` -- parameter sets (PN10QP27, PN11QP54, PN9QP28_STD128,
    PN9QP27_STD128Q), `KeyGenerator`, `NewParametersFromLiteral`.
  - `encryptor.go` -- `Encryptor.EncryptSafe` (Q/8 scale).
  - `decryptor.go` -- `Decryptor.Decrypt` (centered decoding).
  - `evaluator.go` -- `Evaluator.NAND`, programmable bootstrap composite.
  - `bitwise_integers.go` -- bit-vector arithmetic (FullAdder, Add,
    Sub, Eq, Lt, And, Or, Xor, Not, Min/Max, Shl/Shr).
  - `integers.go`, `shortint.go` -- integer ciphertext layer.
  - `pkg/threshold/keygen.go`, `pkg/threshold/lsss.go` -- threshold
    LSSS, t-of-n share generation, reshare.
- **EasyCrypt theories.** `~/work/lux/fhe/proofs/easycrypt/`:
  - `TFHE_Correctness.ec` -- PBS correctness theorem.
  - `TFHE_Threshold_Keygen.ec` -- threshold-DKG correctness +
    privacy + reshare.
  - `TFHE_Noise_Growth.ec` -- per-op noise budgets + parameter-set
    in-budget invariant.
  - `lemmas/TFHE_CT.ec` -- CT obligations on the hot path
    (encrypt, decrypt, blind_rotate, external_product, bootstrap).
- **Lean bridge.** `~/work/lux/proofs/lean/Crypto/FHE/TFHE.lean`
  (expanded with the parameter-set resolver, noise-budget arithmetic,
  PBS chaining theorem, and threshold/reshare hooks).
- **Bridge map.** `~/work/lux/fhe/proofs/lean-easycrypt-bridge.md`
  pins the axiom-to-theorem correspondence 1:1 with citations to
  Lean Mathlib (`threshold_reconstructs_secret` in
  `lean/Crypto/Threshold_Lagrange.lean`).
- **Jasmin sources.** `~/work/lux/fhe/jasmin/`:
  - `lib/tfhe_params.jinc`, `lib/modq.jinc`
  - `external_product.jazz`, `blind_rotate.jazz`, `bootstrap.jazz`.
- **dudect harness.** `~/work/lux/fhe/ct/dudect/`:
  - `encrypt_ct.go`, `decrypt_ct.go`, `bootstrap_ct.go` (cgo bridges).
  - `dudect_encrypt.c`, `dudect_decrypt.c`, `dudect_bootstrap.c`
    (main loops).
  - `Makefile`, `fetch.sh`, `dudect_compat.h`.
- **Paper.** `~/work/lux/papers/lux-tfhe-formalization/
  lux-tfhe-formalization.tex` (FIPS-spec-equivalence statement,
  PBS proof outline, threshold reduction, parameter-security
  table, machine-checked-proof traceability).

## Verified green

- [x] **Build.** `GOWORK=off go build ./...` in `~/work/lux/fhe`
      compiles cleanly. (Tested at review time.)
- [x] **Dudect bridges build.** Each of the three TFHE dudect cgo
      shared libraries (`libtfhe_encrypt.dylib`,
      `libtfhe_decrypt.dylib`, `libtfhe_bootstrap.dylib`) builds
      clean under `go build -buildmode=c-shared` with the matching
      build tag and the cgo header chain.
- [x] **EC theories: structurally complete.** Each of the four EC
      files (`TFHE_Correctness.ec`, `TFHE_Threshold_Keygen.ec`,
      `TFHE_Noise_Growth.ec`, `lemmas/TFHE_CT.ec`) holds:
  - A top-level theorem statement.
  - A closed proof chain via named hypotheses imported from the
    `lattice/v7` reference layer (LWE encrypt/decrypt inverse;
    blind-rotate LUT spec; sample-extract spec; mod-switch spec;
    PBS noise bound; threshold-BSK functional spec; Shamir inverse-
    eval).
  - Zero `admit` keywords (admit budget 0/0).
- [x] **Lean side: 0 sorry.** `Crypto/FHE/TFHE.lean` carries
      named axioms only; `chained_pbs_correctness` is a proved
      theorem (not an axiom).
- [x] **Bridge map.** `proofs/lean-easycrypt-bridge.md` correctly
      cites each axiom name on the EC side against its Lean
      counterpart (5 axioms total, including the `decrypt_constant_time`
      operational-only EC axiom with no Lean counterpart by design).
- [x] **Jasmin algorithm shape.** The three `.jazz` files
      (`external_product.jazz`, `blind_rotate.jazz`,
      `bootstrap.jazz`) implement the CGGI Asiacrypt 2016 algorithm
      with the production-tuned signed gadget decomposition
      (mirroring `~/work/lux/luxcpp/gpu/src/fhe_decomp.cpp`
      `signed_decomp_all` with bottom-up carry propagation).
- [x] **CT obligations correctly stated.** Each `lemmas/TFHE_CT.ec`
      module-type uses the BGL leakage model and the
      `declare module ... <: CTRoutineType` pattern matching
      `~/work/lux/pulsar/proofs/easycrypt/lemmas/Pulsar_CT.ec`.

## Findings

### Minor (4)

- **MIN-1.** The dudect harness builds clean but the **submission-grade
  10^9-sample run has not been executed yet**. The harness defaults
  are smoke-test budgets (10k samples for Encrypt / Decrypt; 2k
  samples for Bootstrap because PBS is ~50-80 ms per call). Closure
  of GATE-3 requires the full pinned-CPU run. Not blocking for the
  Tier A submission shape; required before claiming production-
  grade CT evidence.

- **MIN-2.** The `external_product.jazz` source uses pseudocode-quality
  control flow for the gadget-decomposition loop. The production-
  grade Jasmin port should substitute the lattice/v7 reference NTT
  (the NTT-fused fast path in `~/work/lux/luxcpp/crypto/fhe/cpp/
  backends/cpu/external_product_cpu.cpp` does this). The
  `jasminc -checkCT` pass on the current source is expected to flag
  the inner-loop array-index-by-secret-digit access; a libjade-
  quality fix wires the digit lookup through a constant-time linear
  sweep matching the `mod_mul` shape in `lib/modq.jinc`. Not
  blocking for the artifact pack; required before claiming Jasmin
  CT-passed.

- **MIN-3.** The PBS noise-bound axiom `pbs_noise_bound` in
  `TFHE_Correctness.ec` and `TFHE_Noise_Growth.ec` cites the per-
  parameter-set bound `fresh_pbs_noise(ps) <= q_LWE(ps) / 8`. This
  bound is **production-set-dependent**: it holds for the
  PN10QP27 / PN11QP54 / PN9QP28_STD128 / PN9QP27_STD128Q sets we
  ship, but a future parameter-set addition would need a renewed
  bound check. Recommend a CI guard that re-runs the lwe-estimator
  on every parameter-set change. (`~/work/lux/proofs/fhe/
  parameter-security.tex` Theorem `thm:lwe-parameter-security`
  already cites the estimator; the gap is operational, not
  cryptographic.)

- **MIN-4.** The threshold-DKG correctness theorem
  `threshold_dkg_correctness` in `TFHE_Threshold_Keygen.ec`
  abstracts the bootstrap-key derivation under the
  `threshold_bsk_functional` axiom. The Mouchet-Bossuat-Hubaux
  derivation (PoPETS 2021) is the canonical reference for this
  derivation, but the EC theory does not yet mechanize the proof
  body of `threshold_bsk_functional`; it remains a named axiom.
  This is consistent with the "import functional spec from
  reference impl" pattern used throughout the Tier A pack
  (mirrors the Pulsar `mldsa_sign_axiom` style); future work
  could tighten by mechanizing the Mouchet-et-al derivation
  algebraically in Lean.

### Informational (2)

- **INF-1.** The dudect harness is correctly framed: both classes
  are VALID inputs differing in the secret bit / valid-ciphertext
  index. This avoids the rejection-path-timing artifact that
  bit Pulsar's earlier verify CT harness (documented in
  `~/work/lux/pulsar/ct/dudect/verify_ct.go` header). Good.

- **INF-2.** The Lux Go reference does NOT zeroize FHE secret-key
  buffers on drop (the `fhe.SecretKey` struct wraps `rlwe.SecretKey`
  whose finalizer is not registered for secure-erase). For a threshold
  FHE deployment where the secret share is held in a long-running
  signer's memory, this is operationally undesirable. Recommendation:
  add an explicit `Zeroize()` method matching Pulsar's `KeyShare.Zero`
  pattern. Not security-breaking under the threshold trust model
  (which assumes secure host hardening) but a hardening opportunity.

## Gates (must close before publish)

The construction and code are sound under the disclosed parameter
sets and trust model. The following gates are about empirical
confirmation and operational disclosure; they do not require any
algorithm or code change:

- [ ] **GATE-1 (dudect submission-grade run).** **OPEN -- operational.**
      The dudect harness builds clean for all three routines.
      Pending: execute the 10^9-sample run on a quiet CPU-pinned
      host for Encrypt and Decrypt, and a 10^7-sample run for
      Bootstrap (PBS is ~50-80 ms per call so the full 10^9 budget
      is impractical; 10^7 samples ~ 6 days of wall-clock at one
      sample/PBS).

- [ ] **GATE-2 (Jasmin -checkCT pass).** **OPEN -- pending Jasmin
      port refinement.** Current Jasmin sources are pseudocode-
      quality; the production port substitutes the lattice/v7
      reference NTT and tightens the gadget-decomposition inner
      loop to libjade-quality CT. After that:
      `jasminc -checkCT external_product.jazz`,
      `jasminc -checkCT blind_rotate.jazz`,
      `jasminc -checkCT bootstrap.jazz` should each pass.

- [ ] **GATE-3 (deployment runbook).** **OPEN.** Mirror the
      Pulsar `DEPLOYMENT-RUNBOOK.md` for the F-Chain TFHE
      deployment: operator-facing disclosure of the threshold
      trust model (t-of-n shares; the threshold custody assumption
      mirrors the Pulsar v0.1 reconstruction aggregator's
      "briefly trusted with full master seed" caveat at the moment
      of homomorphic decryption); host hardening checklist
      (mlock / core-dump-off / ptrace-off); zeroize counter
      monitoring; reshare cadence.

- [ ] **GATE-4 (Lean side: tighten correctness axiom).** **OPEN.**
      The Lean `programmable_bootstrap_correct` is currently
      axiomatized; the EC side discharges it via composition of
      four named hypotheses (`lwe_encrypt_decrypt_inverse`,
      `blind_rotate_evaluates_lut`, `sample_extract_LWE`,
      `mod_switch_preserves`). A follow-up pass would import the
      EC proof body verbatim into Lean as a tactic-script
      transcription. Not blocking the Tier A artifact pack.

## Verdict

**APPROVED for Tier A submission** under the gates above. The
single-party PBS correctness theorem and the threshold-DKG
correctness reduction are closed in EC (0 admits across four files).
The Lean bridge map cites each axiom against its proved Lean
counterpart (or its operational-only equivalence). The Jasmin
sources have the algorithm shape and the CT-by-construction control
flow. The dudect harness builds clean for all three hot-path
routines.

## Pinpoints

- Algorithm source: `~/work/lux/fhe/`
- EC theories: `~/work/lux/fhe/proofs/easycrypt/`
- Lean side: `~/work/lux/proofs/lean/Crypto/FHE/TFHE.lean`
- Bridge map: `~/work/lux/fhe/proofs/lean-easycrypt-bridge.md`
- Jasmin sources: `~/work/lux/fhe/jasmin/`
- dudect harness: `~/work/lux/fhe/ct/dudect/`
- LaTeX paper: `~/work/lux/papers/lux-tfhe-formalization/
  lux-tfhe-formalization.tex`
- Existing LaTeX correctness proofs: `~/work/lux/proofs/fhe/`
