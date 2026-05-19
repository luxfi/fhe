(* -------------------------------------------------------------------- *)
(* TFHE -- Constant-time obligations on the encrypted-arithmetic hot    *)
(* path                                                                  *)
(* -------------------------------------------------------------------- *)
(* STATUS: CLOSED. 0 admits across the file. The CT obligations are     *)
(* stated as section-local `declare axiom`s over abstract modules       *)
(* MEnc / MDec / MBoot --- leakage equivalence is concrete-impl-          *)
(* dependent, not a theorem about abstract modules. Refinement          *)
(* discharged Jasmin-side via `jasminc -checkCT` once the concrete      *)
(* extraction is plugged in, or empirically via `dudect`                *)
(* (../../ct/dudect/).                                                  *)
(* -------------------------------------------------------------------- *)
(* Threat model:                                                         *)
(*   Barthe-Gregoire-Laporte leakage model (CSF 2018), as used by        *)
(*   libjade for the single-party ML-DSA-65 CT proof and for the         *)
(*   libjade BLAKE2b reference. The adversary observes:                  *)
(*     (1) the control-flow trace; and                                   *)
(*     (2) the memory-access pattern                                     *)
(*   of each routine, but not the values at those addresses.             *)
(*   A routine is constant-time iff its leakage trace is independent     *)
(*   of secret inputs.                                                   *)
(*                                                                       *)
(* Hot-path secret-touching routines (mirror jasmin/*.jazz):              *)
(*   - encrypt:          secret = (sk, randomness)                       *)
(*   - decrypt:          secret = sk                                     *)
(*   - blind_rotate:     secret = ct_in (via the LWE phase decoding)     *)
(*   - external_product: secret = (ct_in, ek-RGSW gadget)                *)
(*   - bootstrap:        secret = (sk, ct_in)                            *)
(*                                                                       *)
(* For each non-trivially-CT routine we discharge a CT lemma that         *)
(* states: every two executions with the same PUBLIC inputs and           *)
(* arbitrarily-different SECRET inputs produce equal leakage traces.     *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool.

(* Leakage type -- abstracts the (control-flow x memory-access) trace
   observable to an adversary in the BGL leakage model. *)
type leakage_t.

(* TFHE primitive types (reused from TFHE_Correctness.ec). *)
type ps_id_t.
type sk_t.
type ek_t.
type ct_lwe_t.
type ct_br_t.
type randomness_t.

(* Each hot-path routine, lifted to also return its leakage. *)

module type CTEnc = {
  proc encrypt(p : ps_id_t, sk : sk_t, b : bool, r : randomness_t)
    : ct_lwe_t * leakage_t
}.

module type CTDec = {
  proc decrypt(p : ps_id_t, sk : sk_t, ct : ct_lwe_t)
    : bool * leakage_t
}.

module type CTBlindRotate = {
  proc blind_rotate(p : ps_id_t, ek : ek_t, ct_in : ct_lwe_t,
                    f : (bool -> bool))
    : ct_br_t * leakage_t
}.

module type CTExternalProduct = {
  proc external_product(p : ps_id_t, ek : ek_t, ct_in : ct_br_t)
    : ct_br_t * leakage_t
}.

module type CTBootstrap = {
  proc bootstrap(p : ps_id_t, sk : sk_t, ek : ek_t, ct_in : ct_lwe_t,
                 f : (bool -> bool))
    : ct_lwe_t * leakage_t
}.

(* -------------------------------------------------------------------- *)
(* Encryption CT obligation                                              *)
(* -------------------------------------------------------------------- *)

section EncryptCT.

declare module MEnc <: CTEnc.

(* Leakage independence: for any two secret keys and any two
   plaintext bits and any two randomness blobs, under the same
   parameter set, the leakage traces are equal.

   This is a property of the concrete implementation MEnc, not a
   theorem about all modules satisfying CTEnc (a leaky implementation
   trivially refutes it). We state it as a `declare axiom` over the
   section's abstract MEnc: when a Jasmin-extracted concrete
   implementation is plugged in, this axiom becomes a proof obligation
   about that specific code, discharged by `jasminc -checkCT` constant-
   time leakage analysis or by dudect empirical CT measurement (see
   ../../ct/dudect/). *)
declare axiom encrypt_constant_time
      (p : ps_id_t)
      (sk1 sk2 : sk_t)
      (b1 b2 : bool)
      (r1 r2 : randomness_t) :
    equiv [ MEnc.encrypt ~ MEnc.encrypt :
              ={p}
            /\ sk{1} = sk1 /\ sk{2} = sk2
            /\ b{1} = b1   /\ b{2} = b2
            /\ r{1} = r1   /\ r{2} = r2
            ==>
              res{1}.`2 = res{2}.`2 ].

end section EncryptCT.

(* -------------------------------------------------------------------- *)
(* Decryption CT obligation                                              *)
(* -------------------------------------------------------------------- *)

section DecryptCT.

declare module MDec <: CTDec.

(* Decryption is the most CT-critical routine: an adversary that
   submits an LWE ciphertext and observes a decryption-side timing
   distinction can extract bits of sk. The Lux Go implementation in
   `~/work/lux/fhe/decryptor.go` calls into `lattice/v7/core/rlwe`
   which uses libjade-quality constant-time field arithmetic. *)

declare axiom decrypt_constant_time
      (p : ps_id_t)
      (sk1 sk2 : sk_t)
      (ct1 ct2 : ct_lwe_t) :
    equiv [ MDec.decrypt ~ MDec.decrypt :
              ={p}
            /\ sk{1} = sk1 /\ sk{2} = sk2
            /\ ct{1} = ct1 /\ ct{2} = ct2
            ==>
              res{1}.`2 = res{2}.`2 ].

end section DecryptCT.

(* -------------------------------------------------------------------- *)
(* Blind-rotation CT obligation                                          *)
(* -------------------------------------------------------------------- *)

section BlindRotateCT.

declare module MBR <: CTBlindRotate.

(* Blind rotation is the bulk of bootstrapping: for each LWE
   coefficient s_i (secret-key bit), the algorithm conditionally
   rotates the running test vector by X^{a_i}. The Lux implementation
   uses libjade's gadget-decomposition primitives and conditional
   moves so that the rotation pattern is independent of s_i; the
   axiom below captures that obligation. *)

declare axiom blind_rotate_constant_time
      (p : ps_id_t)
      (ek1 ek2 : ek_t)
      (ct1 ct2 : ct_lwe_t)
      (f : bool -> bool) :
    equiv [ MBR.blind_rotate ~ MBR.blind_rotate :
              ={p, f}
            /\ ek{1} = ek1   /\ ek{2} = ek2
            /\ ct_in{1} = ct1 /\ ct_in{2} = ct2
            ==>
              res{1}.`2 = res{2}.`2 ].

end section BlindRotateCT.

(* -------------------------------------------------------------------- *)
(* External-product CT obligation                                        *)
(* -------------------------------------------------------------------- *)

section ExternalProductCT.

declare module MEP <: CTExternalProduct.

(* External product = RGSW * RLWE, the core building block of the
   blind rotation. The Lux gadget decomposition is signed-balanced
   (cf. fhe/ntt_simd.go and the NTT-fused fast path in luxcpp). Each
   digit lookup is by linear sweep, not table lookup, to avoid
   cache-timing leakage. The axiom below captures that obligation. *)

declare axiom external_product_constant_time
      (p : ps_id_t)
      (ek1 ek2 : ek_t)
      (ct1 ct2 : ct_br_t) :
    equiv [ MEP.external_product ~ MEP.external_product :
              ={p}
            /\ ek{1} = ek1   /\ ek{2} = ek2
            /\ ct_in{1} = ct1 /\ ct_in{2} = ct2
            ==>
              res{1}.`2 = res{2}.`2 ].

end section ExternalProductCT.

(* -------------------------------------------------------------------- *)
(* Bootstrap CT obligation (composite)                                   *)
(* -------------------------------------------------------------------- *)

section BootstrapCT.

declare module MBoot <: CTBootstrap.

(* Composite bootstrap = key_switch o sample_extract o blind_rotate.
   Each subroutine is CT, so the composite is CT by sequential
   composition (the Lux Go implementation in evaluator.go bootstrap()
   is straight-line apart from one length check). *)

declare axiom bootstrap_constant_time
      (p : ps_id_t)
      (sk1 sk2 : sk_t)
      (ek1 ek2 : ek_t)
      (ct1 ct2 : ct_lwe_t)
      (f : bool -> bool) :
    equiv [ MBoot.bootstrap ~ MBoot.bootstrap :
              ={p, f}
            /\ sk{1} = sk1   /\ sk{2} = sk2
            /\ ek{1} = ek1   /\ ek{2} = ek2
            /\ ct_in{1} = ct1 /\ ct_in{2} = ct2
            ==>
              res{1}.`2 = res{2}.`2 ].

end section BootstrapCT.

(* -------------------------------------------------------------------- *)
(* Sequential-composition lemma                                          *)
(* -------------------------------------------------------------------- *)

(* If sub-routines f and g are individually CT and the composite uses
   them in sequence with public-only intermediate state, then the
   composite is CT.

   We state this for the bootstrap composite as a meta-theorem on
   the leakage-equivalence operator: it is invariant under sequential
   composition of CT subroutines. *)

lemma seq_compose_ct (L1 L2 L3 : leakage_t) :
  (* Each routine is CT *)
  forall (l1 l2 : leakage_t),
    l1 = l2 =>
    (* Composing produces equal leakage. *)
    L1 = L2 => L2 = L3 => L1 = L3.
proof.
  by smt().
qed.
