// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// security_profile.go — strict-PQ adapter for the FHE parameter set.
//
// FHE chains have one decision to make at boot: which OpenFHE
// ParametersLiteral binds the security target. A classical
// ParametersLiteral is ~128-bit classical security (broken by Shor);
// a PQ ParametersLiteral lands in NIST FIPS 203 / 204 territory
// (LMKCDEY bootstrapping, lattice problem hardness preserved against
// quantum adversaries).
//
// This file plugs that single decision into the canonical pq.Mode
// gate so audit + chain-config code uses the same vocabulary as
// warp, dex, evm, zap:
//
//   mode, _ := pq.ModeFromString(cfg.FHEProfile)
//   params := fhe.DefaultParamsForMode(mode)
//
// Strict-PQ ⇒ PN9QP27_STD128Q (the only PQ literal currently
// published). Classical / hybrid fall back to PN10QP27 — there's no
// classical FHE ciphertext to refuse at the parameter layer, so the
// gate is selection, not refusal.

package fhe

import "github.com/luxfi/pq"

// DefaultParamsForMode is the single seam every Liquid FHE chain
// boot routes through to pick a ParametersLiteral. Picking
// parameters directly (e.g. fhe.PN10QP27) anywhere in a Liquid FHE
// chain's boot path is a bug — it bypasses the mode gate and can
// silently weaken the chain to classical-only security.
//
// Strict-PQ ⇒ PN9QP27_STD128Q (NIST FIPS 203 / 204 LMKCDEY).
// Classical / hybrid ⇒ PN10QP27 (~128-bit classical, dev-only).
func DefaultParamsForMode(mode pq.Mode) ParametersLiteral {
	if mode.IsPostQuantum() {
		return PN9QP27_STD128Q
	}
	return PN10QP27
}
