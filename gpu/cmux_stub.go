//go:build !cgo

// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package gpu

// RGSW represents an RGSW ciphertext (stub)
type RGSW struct {
	L       int
	N       int
	Base    uint64
	BaseLog int
}

// RLWE represents an RLWE ciphertext (stub)
type RLWE struct {
	N int
}
