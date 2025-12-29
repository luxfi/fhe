//go:build !cgo

// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package gpu

// BatchLWE holds a batch of LWE ciphertexts (stub)
type BatchLWE struct {
	Count int
}

// BatchRLWE holds a batch of RLWE ciphertexts (stub)
type BatchRLWE struct {
	Count int
}

// RLWECiphertext represents a single RLWE ciphertext (stub)
type RLWECiphertext struct{}

// GPUBootstrapKey holds bootstrap key data (stub)
type GPUBootstrapKey struct {
	n       int
	L       int
	N       int
	Base    uint64
	BaseLog int
}
