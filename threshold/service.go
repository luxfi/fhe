// Service interfaces for the threshold FHE layer.
//
// Three roles, one wire shape:
//
//   PartialDecryptService.PartialDecrypt   — party-side: produce a share.
//   ShareVerifyService.VerifyShare         — peer-side or aggregator-side.
//   ShareAggregateService.Aggregate        — aggregator-side: combine ≥t shares.
//
// All three are stateless w.r.t. the network: callers pass in the keys
// and ciphertexts they have, and the service does the protocol work and
// emits canonical output. Network plumbing (RPC fan-out, TLS, retries)
// lives one level up in luxfi/mpc — see RealThresholdDecryptor in
// pkg/policy/fhe_verifier.go.
//
// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause
package threshold

import "context"

// PartialDecryptService produces a single party's contribution to a
// threshold decryption.
//
// MPCVM v0.62 four-kernel template applied to partial decryption:
//
//	apply           — decompose the ciphertext into per-party operands
//	                  (extract the (a, b) LWE pair; reduce mod q).
//	sweep           — sample noise e_i from the prescribed distribution;
//	                  update the Fiat-Shamir transcript with sessionID,
//	                  partyID, ciphertextID, share commitment.
//	compute_leaves  — emit the per-party share share_i = b · sk_i + e_i
//	                  (mod q) and the noise proof tying e_i to the
//	                  transcript.
//	compose_root    — keccak the canonical encoding (ShareData || PartyID
//	                  || CiphertextID || SessionID) and write ShareRoot.
//
// Implementations MUST be deterministic given (partyKey, ciphertext,
// sessionID) for a fixed noise-sampling seed — the Fiat-Shamir
// transcript bytes are byte-equal across primary and private modes.
// Determinism is what allows peer auditors to re-run any party's
// PartialDecrypt and check the output.
type PartialDecryptService interface {
	PartialDecrypt(
		ctx context.Context,
		partyKey KeyShare,
		ciphertext FHECiphertext,
		sessionID [32]byte,
	) (FHEThresholdShare, error)
}

// ShareVerifyService independently checks a share without aggregating.
//
// Verification re-derives ShareRoot from the share fields, replays the
// Fiat-Shamir transcript against the noise commitment in NoiseProof,
// and verifies the proof against the party's public key.
//
// VerifyShare returns (false, error) on cryptographic failure and
// (false, nil) on a clean negative verdict — callers that need to
// distinguish should branch on the error. The boolean alone is a safe
// drop-in for any check that just wants "include this share or not".
type ShareVerifyService interface {
	VerifyShare(
		ctx context.Context,
		share FHEThresholdShare,
		ciphertext FHECiphertext,
		partyPubKey PublicKey,
		sessionID [32]byte,
	) (bool, error)
}

// ShareAggregateService combines ≥threshold shares into the plaintext.
//
// The aggregator MUST re-verify every share before combining (defence
// against a malicious party producing a share whose noise proof
// passed at the producer but was tampered in transit). Implementations
// short-circuit on the first invalid share by emitting the appropriate
// FHEStatus in the result; the plaintext returned in that case is nil
// and callers MUST not use it.
//
// The plaintext output is returned separately from FHEThresholdResult
// so the result roots can be anchored (M-Chain or WORM) without
// disclosing the plaintext. The plaintext follows the data-handling
// rules of the calling deployment mode.
type ShareAggregateService interface {
	Aggregate(
		ctx context.Context,
		ciphertext FHECiphertext,
		shares []FHEThresholdShare,
		threshold uint32,
		sessionID [32]byte,
	) (FHEThresholdResult, []byte /* plaintext */, error)
}
