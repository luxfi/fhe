// FHECiphertext constructor and helpers.
//
// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause
package threshold

// NewFHECiphertext wraps raw scheme bytes in an FHECiphertext with a
// canonical sha256 ID. The ID is the value that flows into every
// share's CiphertextID and into FHEThresholdResult.CiphertextRoot for
// single-input decryptions.
func NewFHECiphertext(bytes []byte) FHECiphertext {
	cp := make([]byte, len(bytes))
	copy(cp, bytes)
	return FHECiphertext{
		ID:    ciphertextRoot(FHECiphertext{Bytes: cp}),
		Bytes: cp,
	}
}
