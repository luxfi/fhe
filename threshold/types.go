// Package threshold implements the t-of-n threshold FHE service layer
// — partial decryption, share verification, and aggregate decryption —
// composed on top of luxfi/fhe primitives (NTT, blind rotation, key
// switching).
//
// The package is independent of any single FHE scheme: the service
// interfaces accept opaque ciphertext bytes and party-keyed share
// material, and the concrete implementations in this package target the
// TFHE/FHEW path used by F-Chain. Other schemes (BFV, CKKS, BGV) plug in
// by implementing the same interfaces.
//
// Design discipline:
//
//   - Every wire object — share, transcript, aggregate — carries a
//     canonical sha256 root of its inputs. Verification and aggregation
//     re-derive these roots; mismatches fail closed with a typed status.
//
//   - Partial decryption follows the MPCVM v0.62 four-kernel template:
//     `apply` decomposes the ciphertext into per-party operands;
//     `sweep` samples per-share noise and updates the Fiat-Shamir
//     transcript; `compute_leaves` produces the per-party share + noise
//     proof; `compose_root` keccaks the canonical encoding and emits the
//     ShareRoot. Each step has a single, unambiguous shape.
//
//   - The package targets the dual-mode MPC dispatcher (sibling #115):
//     primary mode anchors the ThresholdTranscriptRoot to M-Chain; private
//     mode anchors to local WORM. The service emits the root either way;
//     the caller decides where it lands.
//
// Reference: LP-137-FHE-THRESHOLD.md.
//
// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause
package threshold

// FHEStatus is the verdict status emitted by the threshold service for
// every share, transcript, and aggregate result. Wire stable: enum
// values are fixed and MUST NOT be reordered. Add new statuses by
// appending.
type FHEStatus uint32

const (
	// StatusOK is the success status. The result fields are valid and the
	// plaintext (where present) is the correct decryption.
	StatusOK FHEStatus = 0

	// StatusInsufficientShares indicates fewer than `Threshold` valid
	// shares were collected before aggregation. The result is undefined.
	StatusInsufficientShares FHEStatus = 1

	// StatusNoiseProofFailed indicates a share's noise proof did not
	// verify against the Fiat-Shamir transcript. The share has been
	// rejected; the aggregate excludes it.
	StatusNoiseProofFailed FHEStatus = 2

	// StatusShareRootMismatch indicates the canonical encoding of a
	// share's data does not match its declared ShareRoot. Indicates
	// tampering or serialization drift.
	StatusShareRootMismatch FHEStatus = 3

	// StatusReplay indicates a sessionID has already been used for
	// partial decryption. The service refuses to re-issue a share for
	// the same (party, ciphertext, sessionID) tuple.
	StatusReplay FHEStatus = 4

	// StatusUnknownParty indicates a share carried a PartyID outside
	// the configured set. The aggregator rejects it before verification.
	StatusUnknownParty FHEStatus = 5

	// StatusInvalidCiphertext indicates the input ciphertext failed
	// scheme-level structural validation (header drift, length mismatch,
	// modulus mismatch).
	StatusInvalidCiphertext FHEStatus = 6
)

// String returns a stable, human-readable name for the status.
func (s FHEStatus) String() string {
	switch s {
	case StatusOK:
		return "OK"
	case StatusInsufficientShares:
		return "InsufficientShares"
	case StatusNoiseProofFailed:
		return "NoiseProofFailed"
	case StatusShareRootMismatch:
		return "ShareRootMismatch"
	case StatusReplay:
		return "Replay"
	case StatusUnknownParty:
		return "UnknownParty"
	case StatusInvalidCiphertext:
		return "InvalidCiphertext"
	default:
		return "Unknown"
	}
}

// FHEThresholdShare is a single party's contribution to a threshold
// decryption (or partial evaluation). It is the wire object produced by
// PartialDecryptService.PartialDecrypt and consumed by both
// ShareVerifyService.VerifyShare and ShareAggregateService.Aggregate.
//
// The ShareRoot field binds (PartyID, CiphertextID, ShareData) to a
// single sha256 hash so downstream verifiers can detect replay,
// reordering, and field-level tampering with a single comparison.
type FHEThresholdShare struct {
	// PartyID is the 1-indexed party identifier. Party indices are part
	// of the keygen ceremony — every share for a given ciphertext must
	// carry a distinct PartyID.
	PartyID uint32

	// CiphertextID is the sha256 of the canonical encoding of the
	// ciphertext this share decrypts. Allows the aggregator to reject
	// mismatched-ciphertext shares without re-decoding.
	CiphertextID [32]byte

	// ShareData is the scheme-specific share payload — for TFHE this is
	// (b · sk_i + e_i) mod q packed as the canonical scheme bytes; for
	// BFV/CKKS this is the partial-decrypt polynomial. The threshold
	// package does not interpret the bytes; the FHEScheme bound at the
	// service layer does.
	ShareData []byte

	// NoiseProof is the proof that the noise added during partial
	// decryption was sampled from the prescribed distribution within
	// the protocol-mandated bound. Production systems use a CDS-style
	// sigma-of-knowledge proof; see noise_proof.go for the reference
	// transcript construction.
	NoiseProof []byte

	// ShareRoot is sha256(canonical(ShareData || PartyID || CiphertextID
	// || SessionID)). Verifiers MUST re-derive and compare; aggregators
	// MUST reject any share whose ShareRoot does not match.
	ShareRoot [32]byte
}

// FHEThresholdResult is the aggregate of a threshold decryption: the
// roots that flow into FHEPrecompileArtifact.ThresholdTranscriptRoot,
// the party count and threshold actually realized, and the verdict
// status.
//
// The aggregate plaintext (when Status == StatusOK) is returned out of
// band by the aggregate service so callers can decide whether to log,
// audit, or deliver it. The result struct itself only carries the roots
// — those are the values bound into the precompile artifact and the
// audit dispatcher.
type FHEThresholdResult struct {
	// CiphertextRoot is sha256(canonical(input ciphertexts in canonical
	// order)). For single-ciphertext decrypts this is sha256 of the
	// ciphertext bytes; for multi-ciphertext aggregates (e.g. a vector
	// decrypt) it is the Merkle root.
	CiphertextRoot [32]byte

	// ShareRoot is the Merkle root over all share roots used in the
	// aggregation, in canonical (ascending PartyID) order.
	ShareRoot [32]byte

	// AggregateRoot is sha256(canonical(plaintext bytes || PartyCount ||
	// Threshold)). Callers anchoring to M-Chain or WORM use this as the
	// commitment to the aggregate output without revealing the plaintext.
	AggregateRoot [32]byte

	// PartyCount is the number of valid shares actually combined.
	PartyCount uint32

	// Threshold is the t value the protocol was configured for.
	Threshold uint32

	// Status is the final verdict. StatusOK means the aggregate is valid
	// and the out-of-band plaintext bytes are the true decryption.
	Status FHEStatus
}

// KeyShare is a single party's secret share of the threshold key. The
// Bytes field is the scheme-specific encoding; the threshold package
// does not interpret it. PartyID matches FHEThresholdShare.PartyID.
type KeyShare struct {
	PartyID uint32
	Bytes   []byte
}

// PublicKey is the per-party public verification material. For TFHE
// threshold this is the party's public commitment to its secret share;
// for BFV/CKKS it is the public part of the partial-decrypt key.
type PublicKey struct {
	PartyID uint32
	Bytes   []byte
}

// FHECiphertext is the opaque wire form of an FHE ciphertext. The
// threshold package treats it as immutable bytes plus a 32-byte ID; the
// scheme-specific decoder is plugged in via the service constructor.
type FHECiphertext struct {
	// ID is sha256 of Bytes. Computed once at construction; aggregators
	// re-check before use.
	ID [32]byte

	// Bytes is the canonical scheme-specific encoding.
	Bytes []byte
}
