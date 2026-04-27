// Share verification — peer-side and aggregator-side.
//
// Verification is the cheap, fail-closed gate before aggregation. It
// catches:
//
//   - tampered ShareData (ShareRoot mismatch)
//   - wrong-ciphertext shares (CiphertextID mismatch)
//   - replay across sessions (sessionID baked into ShareRoot)
//   - unverifiable noise (placeholder proof) — this is the gap closed
//     by the production CDS proof.
//
// The verifier does NOT need the producer's KeyShare: the placeholder
// noise proof binds to the share data and transcript, so the verifier
// only needs the share + ciphertext + sessionID + (optionally) the
// party's PublicKey. The peer-mode path that DOES carry the KeyShare
// is exposed via VerifyShareWithKey for committee self-checks.
//
// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause
package threshold

import (
	"context"
	"errors"
)

// ErrShareRootMismatch indicates the canonical encoding of the share's
// fields does not hash to the declared ShareRoot.
var ErrShareRootMismatch = errors.New("threshold: share root mismatch")

// ErrCiphertextIDMismatch indicates the share's CiphertextID does not
// equal the supplied ciphertext's ID.
var ErrCiphertextIDMismatch = errors.New("threshold: ciphertext id mismatch")

// ErrPartyIDMismatch indicates the share's PartyID does not match the
// supplied PublicKey.PartyID. Caught early so the aggregator never
// dispatches a verification with the wrong key.
var ErrPartyIDMismatch = errors.New("threshold: party id mismatch")

// ErrNoiseProofVerify indicates the noise proof did not verify against
// the share + transcript. With the placeholder this means a structural
// failure; with the production CDS proof it means the noise was out of
// bound or the proof transcript did not match.
var ErrNoiseProofVerify = errors.New("threshold: noise proof verification failed")

// ShareVerifier is the default in-process ShareVerifyService.
type ShareVerifier struct{}

// NewShareVerifier returns a default ShareVerifier.
func NewShareVerifier() *ShareVerifier {
	return &ShareVerifier{}
}

// VerifyShare runs the public-input verification path. The boolean
// return is false on any failure; the error carries the diagnostic.
//
// Sequence:
//
//  1. PartyID consistency between share and pubKey.
//  2. CiphertextID consistency between share and supplied ciphertext.
//  3. ShareRoot re-derivation from canonical encoding.
//  4. Noise proof verification (public-key path).
//
// With the placeholder proof the public-key verification step fails
// closed; the committee path uses VerifyShareWithKey instead.
func (v *ShareVerifier) VerifyShare(
	ctx context.Context,
	share FHEThresholdShare,
	ciphertext FHECiphertext,
	partyPubKey PublicKey,
	sessionID [32]byte,
) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	if share.PartyID != partyPubKey.PartyID {
		return false, ErrPartyIDMismatch
	}
	if share.CiphertextID != ciphertext.ID {
		return false, ErrCiphertextIDMismatch
	}
	expected := computeShareRoot(share, sessionID)
	if expected != share.ShareRoot {
		return false, ErrShareRootMismatch
	}
	if !verifyNoiseProofPublic(partyPubKey, share, sessionID) {
		// Public-key noise verification is a no-op until CDS proof
		// ships; production deployments MUST use VerifyShareWithKey
		// during committee assembly. Returning the typed error keeps
		// the diagnostic visible without short-circuiting upstream
		// callers that already accept a placeholder.
		return false, ErrNoiseProofVerify
	}
	return true, nil
}

// VerifyShareWithKey runs the symmetric-key verification path used by
// committee peers that hold the producer's KeyShare (e.g. self-checks
// across replicated MPC nodes).
//
// This path is the only one that succeeds against the placeholder
// noise proof. The CDS proof, when shipped, will collapse this back
// into the public-key path.
func (v *ShareVerifier) VerifyShareWithKey(
	ctx context.Context,
	share FHEThresholdShare,
	ciphertext FHECiphertext,
	partyKey KeyShare,
	sessionID [32]byte,
) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if share.PartyID != partyKey.PartyID {
		return false, ErrPartyIDMismatch
	}
	if share.CiphertextID != ciphertext.ID {
		return false, ErrCiphertextIDMismatch
	}
	expected := computeShareRoot(share, sessionID)
	if expected != share.ShareRoot {
		return false, ErrShareRootMismatch
	}
	if !verifyNoiseProof(partyKey, share, sessionID) {
		return false, ErrNoiseProofVerify
	}
	return true, nil
}
