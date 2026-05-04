// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package wire is fhe's wire-format hardening boundary.
//
// LP-107 Phase 5: fhe consumes luxfi/math/codec for bounded
// decoding of FHE ciphertext / key / param-pack frames. FHE wire
// formats nest more deeply than pulsar's lattice frames (a CKKS
// ciphertext is a Vec<Poly> over an RNS chain of Vec<u64>; an
// EvaluationKey is a tuple of those), so the bounded depth + size
// caps in luxfi/math/codec are essential.
package wire

import (
	"bytes"
	"fmt"

	"github.com/luxfi/math/codec"
)

// MaxFHESliceLen — FHE caps. PN11QP54 ring is 2048 coeffs/poly with
// up to ~10 levels in the RNS chain; 4096 is generous headroom.
const MaxFHESliceLen = 4096

// FHEWireLimits is the codec.Limits configuration FHE uses for
// every untrusted-input frame.
var FHEWireLimits = codec.Limits{
	MaxFrameBytes:     32 * 1024 * 1024, // 32 MiB — accommodates EvaluationKey
	MaxUint16SliceLen: MaxFHESliceLen,
	MaxUint32SliceLen: MaxFHESliceLen,
	MaxUint64SliceLen: MaxFHESliceLen,
	MaxDepth:          5, // Vec<Poly> + Poly + RNS-Vec<u64> + scheme + chain
}

// ValidateCiphertextFrame walks the outer length prefix of an FHE
// ciphertext wire frame. Returns an error wrapping codec.ErrLimitExceeded
// when the cap is exceeded.
//
// The bounded reader rejects the lattice issue #4 attack input class
// (huge varint length) before any allocation, sharing the substrate's
// hardening with pulsar and lens.
func ValidateCiphertextFrame(frame []byte) error {
	r, err := codec.NewReader(bytes.NewReader(frame), FHEWireLimits)
	if err != nil {
		return fmt.Errorf("fhe/wire: NewReader: %w", err)
	}
	if _, err := r.ReadUint64Slice(); err != nil {
		return fmt.Errorf("fhe/wire: outer length: %w", err)
	}
	return nil
}
