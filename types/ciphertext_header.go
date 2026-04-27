// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package types

import (
	"crypto/sha256"
	"encoding/binary"

	lattice "github.com/luxfi/lattice/v7/types"
)

// FHECiphertextHeader wraps every FHE buffer with the metadata required for
// safe dispatch.
//
// Without this header, two ciphertexts produced under different parameter
// sets, evaluation keys, or domains can be combined silently and produce
// either undecryptable ciphertexts or an outright privacy break (key
// reuse across circuits).
//
// Layout is byte-stable across Go and C++. Field order MUST NOT change
// without updating the C++ mirror and matching layout tests.
//
// Total size: 144 bytes.
type FHECiphertextHeader struct {
	// ParamsHash is the SHA-256 of the canonical encoding of the full
	// parameter set (q, p, N, log_p, sigma, dnum, etc.).
	// 32 bytes, offset 0.
	ParamsHash [32]byte

	// KeyID is the SHA-256 of the public/evaluation-key material that
	// produced or will operate on this ciphertext.
	// 32 bytes, offset 32.
	KeyID [32]byte

	// CircuitID is the SHA-256 of the circuit / policy program under
	// which this ciphertext was produced. Used to bind ciphertexts to
	// their authorised computation set.
	// 32 bytes, offset 64.
	CircuitID [32]byte

	// Scheme identifies the FHE scheme.
	// 4 bytes, offset 96.
	Scheme FHEScheme

	// Level is the modulus-switching level (multiplicative depth budget).
	// 4 bytes, offset 100.
	Level uint32

	// N is the polynomial ring degree.
	// 4 bytes, offset 104.
	N uint32

	// ModulusCount is the number of RNS moduli currently active.
	// 4 bytes, offset 108.
	ModulusCount uint32

	// Domain is the polynomial domain the ciphertext data lives in.
	// 1 byte, offset 112.
	Domain lattice.PolyDomain

	// _pad pads to the next 8-byte boundary so the trailing 32-byte
	// fields stay aligned at offsets that are multiples of 8.
	// 7 bytes, offset 113.
	_pad [7]uint8

	// Reserved provides 24 bytes for forward-compatible extension fields
	// (e.g. attestation hashes, transcript pointers). Initialised to zero
	// and ignored by Digest() unless promoted to a named field.
	// 24 bytes, offset 120.
	Reserved [24]byte
}

// canonicalEncoding returns the deterministic byte representation used for
// hashing. Field order matches struct layout; integers use little-endian.
func (h *FHECiphertextHeader) canonicalEncoding() []byte {
	buf := make([]byte, 144)
	copy(buf[0:32], h.ParamsHash[:])
	copy(buf[32:64], h.KeyID[:])
	copy(buf[64:96], h.CircuitID[:])
	binary.LittleEndian.PutUint32(buf[96:100], uint32(h.Scheme))
	binary.LittleEndian.PutUint32(buf[100:104], h.Level)
	binary.LittleEndian.PutUint32(buf[104:108], h.N)
	binary.LittleEndian.PutUint32(buf[108:112], h.ModulusCount)
	buf[112] = uint8(h.Domain)
	// bytes 113..119 are pad, fixed zero
	copy(buf[120:144], h.Reserved[:])
	return buf
}

// Digest returns the SHA-256 of the canonical encoding of the header.
//
// Determinism: same field values always yield the same digest, across
// processes and runs. This is the value bound into precompile artifacts and
// threshold transcripts.
func (h *FHECiphertextHeader) Digest() [32]byte {
	return sha256.Sum256(h.canonicalEncoding())
}

// MatchesContext reports whether this ciphertext header is compatible with
// the given NTTContext, i.e. the polynomial degree and domain agree.
//
// Use this at the kernel boundary BEFORE dispatching a forward/inverse NTT
// or a pointwise multiply: if the ciphertext is in PolyDomainNTTMontgomery
// but the kernel's OutputDomain is PolyDomainNTTStandard, the dispatch is
// silently corrupting and must be rejected.
func (h *FHECiphertextHeader) MatchesContext(ctx *lattice.NTTContext) bool {
	if ctx == nil {
		return false
	}
	if h.N != ctx.N {
		return false
	}
	// The header's Domain describes the *current* domain of the buffer.
	// A kernel with InputDomain == h.Domain accepts this ciphertext.
	return h.Domain == ctx.InputDomain
}
