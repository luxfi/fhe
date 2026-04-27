// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package types

import (
	"crypto/sha256"
	"encoding/binary"
)

// FHEPrecompileArtifact is the fixed-size record produced by an FHE
// precompile invocation. It is the unit of evidence consumed by the
// QuasarGPU integration layer (LP-132) and the FChainTFHE cert lane
// (LP-013, LP-020 §3.0).
//
// All *Root fields are 32-byte SHA-256 digests over the canonical encoding
// of the corresponding payload. Zero (all-zero bytes) signals "not
// applicable for this artifact" and must be accepted by the verifier as
// long as the corresponding feature was not requested.
//
// Layout is byte-stable across Go and C++. Total size: 232 bytes.
type FHEPrecompileArtifact struct {
	// ParamsHash binds the artifact to a specific FHE parameter set.
	// 32 bytes, offset 0.
	ParamsHash [32]byte

	// KeyRoot is the digest of the public/evaluation-key material used.
	// 32 bytes, offset 32.
	KeyRoot [32]byte

	// InputCiphertextRoot is a Merkle / hash-list digest of all input
	// ciphertext headers consumed by this precompile call.
	// 32 bytes, offset 64.
	InputCiphertextRoot [32]byte

	// OutputCiphertextRoot is the digest of the output ciphertext headers
	// produced by this precompile call.
	// 32 bytes, offset 96.
	OutputCiphertextRoot [32]byte

	// CircuitRoot is the digest of the circuit / policy program executed.
	// 32 bytes, offset 128.
	CircuitRoot [32]byte

	// ThresholdTranscriptRoot is the digest of the threshold-decryption
	// transcript when this artifact is part of a threshold round.
	// All-zero if not threshold.
	// 32 bytes, offset 160.
	ThresholdTranscriptRoot [32]byte

	// AttestationRoot is the digest of the GPU attestation chain proving
	// the precompile ran on attested hardware (LP-127).
	// All-zero if confidential attestation was not requested.
	// 32 bytes, offset 192.
	AttestationRoot [32]byte

	// OpCount is the number of FHE operations (gates, mults, rotations)
	// charged to this artifact.
	// 4 bytes, offset 224.
	OpCount uint32

	// FailedCount is the number of operations that failed validation
	// (e.g. domain mismatch rejected at the boundary). Non-zero values
	// mean the artifact is observable evidence of a misconfigured caller.
	// 4 bytes, offset 228.
	FailedCount uint32
}

// canonicalEncoding returns the deterministic byte representation used for
// hashing.
func (a *FHEPrecompileArtifact) canonicalEncoding() []byte {
	buf := make([]byte, 232)
	copy(buf[0:32], a.ParamsHash[:])
	copy(buf[32:64], a.KeyRoot[:])
	copy(buf[64:96], a.InputCiphertextRoot[:])
	copy(buf[96:128], a.OutputCiphertextRoot[:])
	copy(buf[128:160], a.CircuitRoot[:])
	copy(buf[160:192], a.ThresholdTranscriptRoot[:])
	copy(buf[192:224], a.AttestationRoot[:])
	binary.LittleEndian.PutUint32(buf[224:228], a.OpCount)
	binary.LittleEndian.PutUint32(buf[228:232], a.FailedCount)
	return buf
}

// Digest returns SHA-256 of the canonical encoding. This value is the
// `fchain_fhe_root` contribution from this precompile call.
func (a *FHEPrecompileArtifact) Digest() [32]byte {
	return sha256.Sum256(a.canonicalEncoding())
}

// IsThreshold reports whether this artifact participated in a threshold
// decryption round.
func (a *FHEPrecompileArtifact) IsThreshold() bool {
	return a.ThresholdTranscriptRoot != [32]byte{}
}

// IsAttested reports whether this artifact was produced under hardware
// attestation.
func (a *FHEPrecompileArtifact) IsAttested() bool {
	return a.AttestationRoot != [32]byte{}
}
