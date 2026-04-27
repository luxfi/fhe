// Noise proof for threshold partial decryption.
//
// Production deployments of threshold FHE require a zero-knowledge proof
// that the noise term e_i sampled by party i during partial decryption
// was drawn from the prescribed distribution within the protocol-
// mandated bound. Without this proof a malicious party can inject an
// out-of-bound noise term to bias the aggregate decryption (a "noise
// flooding" attack against threshold security).
//
// The standard construction is the CDS (Cramer-Damgard-Schoenmakers)
// disjunctive sigma protocol made non-interactive via Fiat-Shamir over
// the same transcript that produced ShareRoot. This package ships a
// transcript-bound HMAC commitment as a placeholder that:
//
//   - is byte-equal across producer and verifier (deterministic given
//     the share material and the transcript), and
//
//   - lets the rest of the threshold pipeline run end-to-end.
//
// PRODUCTION REQUIRES replacing NoiseProof with a real CDS sigma
// protocol over Z_q (BFV/CKKS) or Z_2 (TFHE). The interface in this
// file is what the real proof plugs into; only the body of buildProof
// + verifyProof changes. Verification consumers — ShareVerifyService
// and ShareAggregateService — already enforce length and transcript
// binding.
//
// References:
//   - Cramer/Damgard/Schoenmakers 1994 — proofs of partial knowledge.
//   - Boudgoust/Scholl 2023 — "Threshold FHE: New Constructions and
//     Applications" — §3.2 noise-bound proof for the sum-then-round
//     decryption.
//   - VeloFHE 2025 — threshold TFHE noise smudging proofs.
//
// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause
package threshold

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

// NoiseProofVersion is the on-wire version. Bumping this invalidates
// every existing share — by design, since changing the proof system
// requires a coordinated upgrade.
const NoiseProofVersion uint32 = 1

// noiseProofKey returns the per-share HMAC key the placeholder proof
// uses. It is derived from the same transcript material that
// canonicalShare hashes — so the proof bytes are the only payload, and
// verifiers re-derive the key from public inputs.
//
// In a production CDS proof the equivalent of this key is the witness
// commitment; the structure of that commitment is what makes the proof
// zero-knowledge in the noise distribution.
func noiseProofKey(partyKey KeyShare, ctID [32]byte, sessionID [32]byte) []byte {
	const domain = "LUX/FHE/THRESHOLD/NOISE-PROOF-KEY/v1"
	mac := hmac.New(sha256.New, partyKey.Bytes)
	mac.Write([]byte(domain))
	mac.Write(ctID[:])
	mac.Write(sessionID[:])
	var pid [4]byte
	binary.BigEndian.PutUint32(pid[:], partyKey.PartyID)
	mac.Write(pid[:])
	return mac.Sum(nil)
}

// buildNoiseProof produces the placeholder noise proof for a share.
//
// Encoding:
//
//	version       uint32 BE
//	partyID       uint32 BE
//	hmac          32 bytes  =  HMAC-SHA256(noiseProofKey,
//	                              "LUX/FHE/THRESHOLD/NOISE-PROOF/v1"
//	                              || sessionID || ctID || shareData)
//
// PRODUCTION REQUIRES replacing the hmac field with the CDS sigma
// transcript (commitment, challenge, response). The version tag exists
// so that a future "v2" proof can be deployed without ambiguity.
func buildNoiseProof(
	partyKey KeyShare,
	ctID [32]byte,
	sessionID [32]byte,
	shareData []byte,
) []byte {
	key := noiseProofKey(partyKey, ctID, sessionID)
	mac := hmac.New(sha256.New, key)
	const domain = "LUX/FHE/THRESHOLD/NOISE-PROOF/v1"
	mac.Write([]byte(domain))
	mac.Write(sessionID[:])
	mac.Write(ctID[:])
	mac.Write(shareData)
	tag := mac.Sum(nil)

	out := make([]byte, 0, 4+4+len(tag))
	var u32 [4]byte
	binary.BigEndian.PutUint32(u32[:], NoiseProofVersion)
	out = append(out, u32[:]...)
	binary.BigEndian.PutUint32(u32[:], partyKey.PartyID)
	out = append(out, u32[:]...)
	out = append(out, tag...)
	return out
}

// verifyNoiseProof rebuilds the proof bytes from public inputs +
// the producer's KeyShare and compares. Verifiers that do not have the
// KeyShare rely on a peer-side proof — this is exactly the gap the
// production CDS proof closes.
//
// The interface here is what the production proof consumes: the share
// passes through unchanged, only the body changes when CDS replaces
// the placeholder.
func verifyNoiseProof(
	partyKey KeyShare,
	share FHEThresholdShare,
	sessionID [32]byte,
) bool {
	if len(share.NoiseProof) < 8 {
		return false
	}
	gotVersion := binary.BigEndian.Uint32(share.NoiseProof[0:4])
	if gotVersion != NoiseProofVersion {
		return false
	}
	gotPartyID := binary.BigEndian.Uint32(share.NoiseProof[4:8])
	if gotPartyID != share.PartyID {
		return false
	}
	expected := buildNoiseProof(partyKey, share.CiphertextID, sessionID, share.ShareData)
	return hmac.Equal(expected, share.NoiseProof)
}

// verifyNoiseProofPublic is the public-key path: the verifier does not
// hold the producer's KeyShare. The placeholder cannot satisfy this —
// HMAC requires the symmetric key — and the function returns
// (false, errPlaceholderNoiseProofPublic). Production CDS proofs are
// publicly verifiable from the party's PublicKey alone, which is
// exactly why the placeholder must be replaced before mainnet.
//
// Until the CDS proof ships, peer-side verification runs in the
// committee path where each peer has its own KeyShare and verifies
// only its own outbound shares; cross-party verification is deferred
// to the aggregator that holds the combined view.
func verifyNoiseProofPublic(
	pubKey PublicKey,
	share FHEThresholdShare,
	sessionID [32]byte,
) bool {
	_ = pubKey
	_ = share
	_ = sessionID
	// Placeholder cannot verify from a public key. See package note.
	return false
}
