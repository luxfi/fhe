// Package types defines the FHE-GPU ciphertext header and precompile artifact
// types. These wrap every FHE buffer with the minimal metadata required to
// reject domain mismatches, parameter mismatches, and key/circuit drift at
// the kernel boundary.
//
// Reference: LP-137-FHE-TYPING.md.
//
// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause
package types

// FHEScheme identifies which FHE scheme produced or consumes a ciphertext.
//
// Wire stable: enum values are fixed and MUST NOT be reordered. Add new
// schemes by appending.
type FHEScheme uint32

const (
	// FHESchemeTFHE is the TFHE/FHEW boolean-circuit family with blind
	// rotation bootstrap, as implemented by luxfi/fhe over luxfi/lattice.
	FHESchemeTFHE FHEScheme = 0

	// FHESchemeFHEW is the FHEW variant (kept distinct from TFHE for
	// parameter-set hashing even though the kernel path can be shared).
	FHESchemeFHEW FHEScheme = 1

	// FHESchemeCKKS is approximate-arithmetic CKKS (real/complex).
	FHESchemeCKKS FHEScheme = 2

	// FHESchemeBFV is exact-arithmetic BFV (integer).
	FHESchemeBFV FHEScheme = 3

	// FHESchemeBGV is exact-arithmetic BGV (integer).
	FHESchemeBGV FHEScheme = 4
)

// String returns a stable, human-readable name for the scheme.
func (s FHEScheme) String() string {
	switch s {
	case FHESchemeTFHE:
		return "TFHE"
	case FHESchemeFHEW:
		return "FHEW"
	case FHESchemeCKKS:
		return "CKKS"
	case FHESchemeBFV:
		return "BFV"
	case FHESchemeBGV:
		return "BGV"
	default:
		return "Unknown"
	}
}
