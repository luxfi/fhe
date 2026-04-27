// Canonical encoding + transcript-root construction for the threshold
// FHE service.
//
// Two roots flow through the protocol:
//
//   ShareRoot             = sha256(canonicalShare(share, sessionID))
//   ThresholdTranscriptRoot = keccak256(canonicalTranscript(...))
//
// Both encodings are length-prefixed, fixed-byte-order, and reject
// trailing data. Determinism across CPU/Metal/CUDA/Go/C++ implementations
// is exactly the byte-equivalence of these encodings — the same input
// MUST produce the same root on every backend. This is the
// `compose_root` step of the MPCVM four-kernel template.
//
// The keccak256 used for the transcript root matches the EVM/Quasar
// keccak shape so the FHEPrecompileArtifact.ThresholdTranscriptRoot
// field can be checked inside the cevm precompile dispatcher without
// converting hash families.
//
// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause
package threshold

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sort"

	"golang.org/x/crypto/sha3"
)

// ErrCanonical is returned when canonical encoding fails. Indicates a
// caller-side bug (over-large field, nil pointer) — never a wire-side
// failure.
var ErrCanonical = errors.New("threshold: canonical encoding failed")

// canonicalShare encodes a share + sessionID into the byte slice that
// is sha256'd to produce ShareRoot.
//
// Layout (length-prefixed, big-endian):
//
//	domain    "LUX/FHE/THRESHOLD/SHARE/v1" (26 bytes)
//	partyID    uint32 BE                   (4 bytes)
//	ctID       fixed 32 bytes              (32 bytes)
//	sessionID  fixed 32 bytes              (32 bytes)
//	shareLen   uint32 BE                   (4 bytes)
//	shareData  shareLen bytes
//
// NoiseProof is intentionally NOT in the share root: the noise proof
// commits to the same transcript and is verified independently. Mixing
// it into ShareRoot would force aggregators to re-encode the entire
// proof to verify a single share's identity — wasteful and brittle.
func canonicalShare(s FHEThresholdShare, sessionID [32]byte) []byte {
	const domain = "LUX/FHE/THRESHOLD/SHARE/v1"
	out := make([]byte, 0, len(domain)+4+32+32+4+len(s.ShareData))
	out = append(out, domain...)
	out = appendU32(out, s.PartyID)
	out = append(out, s.CiphertextID[:]...)
	out = append(out, sessionID[:]...)
	out = appendU32(out, uint32(len(s.ShareData)))
	out = append(out, s.ShareData...)
	return out
}

// computeShareRoot returns sha256(canonicalShare(share, sessionID)).
func computeShareRoot(s FHEThresholdShare, sessionID [32]byte) [32]byte {
	return sha256.Sum256(canonicalShare(s, sessionID))
}

// canonicalTranscript encodes the full threshold-decryption transcript
// into the byte slice that is keccak256'd to produce
// ThresholdTranscriptRoot.
//
// Layout:
//
//	domain        "LUX/FHE/THRESHOLD/TRANSCRIPT/v1" (31 bytes)
//	sessionID     fixed 32 bytes
//	ctRoot        fixed 32 bytes (CiphertextRoot from result)
//	partyCount    uint32 BE
//	threshold     uint32 BE
//	shareCount    uint32 BE
//	shareRoots    shareCount × 32 bytes (ascending PartyID order)
//	aggregateRoot fixed 32 bytes
//	statusU32     uint32 BE
//
// The sort-on-PartyID step is what makes the transcript byte-equal
// across nodes that may receive shares in different network orders.
func canonicalTranscript(
	sessionID [32]byte,
	result FHEThresholdResult,
	shareRoots [][32]byte,
) []byte {
	const domain = "LUX/FHE/THRESHOLD/TRANSCRIPT/v1"
	out := make([]byte, 0, len(domain)+32+32+4+4+4+len(shareRoots)*32+32+4)
	out = append(out, domain...)
	out = append(out, sessionID[:]...)
	out = append(out, result.CiphertextRoot[:]...)
	out = appendU32(out, result.PartyCount)
	out = appendU32(out, result.Threshold)
	out = appendU32(out, uint32(len(shareRoots)))
	for _, sr := range shareRoots {
		out = append(out, sr[:]...)
	}
	out = append(out, result.AggregateRoot[:]...)
	out = appendU32(out, uint32(result.Status))
	return out
}

// ComputeTranscriptRoot returns keccak256(canonicalTranscript(...)).
//
// This is the value that flows into
// FHEPrecompileArtifact.ThresholdTranscriptRoot and is anchored by the
// audit dispatcher (M-Chain in primary mode, local WORM in private
// mode).
func ComputeTranscriptRoot(
	sessionID [32]byte,
	result FHEThresholdResult,
	shares []FHEThresholdShare,
) [32]byte {
	roots := make([][32]byte, len(shares))
	idxs := make([]int, len(shares))
	for i := range shares {
		idxs[i] = i
	}
	sort.Slice(idxs, func(a, b int) bool {
		return shares[idxs[a]].PartyID < shares[idxs[b]].PartyID
	})
	for i, idx := range idxs {
		roots[i] = shares[idx].ShareRoot
	}
	h := sha3.NewLegacyKeccak256()
	h.Write(canonicalTranscript(sessionID, result, roots))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// merkleShareRoot computes the Merkle root over share roots in
// ascending PartyID order. Used to populate
// FHEThresholdResult.ShareRoot. Pure sha256-of-pairs; matches the
// gpukit transcript_root primitive's CPU oracle.
func merkleShareRoot(shares []FHEThresholdShare) [32]byte {
	if len(shares) == 0 {
		return [32]byte{}
	}
	idxs := make([]int, len(shares))
	for i := range shares {
		idxs[i] = i
	}
	sort.Slice(idxs, func(a, b int) bool {
		return shares[idxs[a]].PartyID < shares[idxs[b]].PartyID
	})
	leaves := make([][32]byte, len(idxs))
	for i, idx := range idxs {
		leaves[i] = shares[idx].ShareRoot
	}
	for len(leaves) > 1 {
		next := make([][32]byte, 0, (len(leaves)+1)/2)
		for i := 0; i < len(leaves); i += 2 {
			var pair [64]byte
			copy(pair[:32], leaves[i][:])
			if i+1 < len(leaves) {
				copy(pair[32:], leaves[i+1][:])
			} else {
				copy(pair[32:], leaves[i][:])
			}
			next = append(next, sha256.Sum256(pair[:]))
		}
		leaves = next
	}
	return leaves[0]
}

// ciphertextRoot computes sha256 of the ciphertext bytes — the value
// stored on FHECiphertext.ID at construction and reused as
// FHEThresholdResult.CiphertextRoot for single-input decrypts.
func ciphertextRoot(ct FHECiphertext) [32]byte {
	return sha256.Sum256(ct.Bytes)
}

// canonicalAggregate encodes the plaintext + party-count + threshold
// into the byte slice that is sha256'd to produce AggregateRoot. Used
// by the aggregator to commit to the output without revealing it
// upstream.
func canonicalAggregate(plaintext []byte, partyCount, threshold uint32) []byte {
	const domain = "LUX/FHE/THRESHOLD/AGGREGATE/v1"
	out := make([]byte, 0, len(domain)+4+len(plaintext)+4+4)
	out = append(out, domain...)
	out = appendU32(out, uint32(len(plaintext)))
	out = append(out, plaintext...)
	out = appendU32(out, partyCount)
	out = appendU32(out, threshold)
	return out
}

// computeAggregateRoot returns sha256(canonicalAggregate(...)).
func computeAggregateRoot(plaintext []byte, partyCount, threshold uint32) [32]byte {
	return sha256.Sum256(canonicalAggregate(plaintext, partyCount, threshold))
}

func appendU32(b []byte, v uint32) []byte {
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], v)
	return append(b, tmp[:]...)
}
