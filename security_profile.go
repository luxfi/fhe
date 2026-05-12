// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

// SecurityProfile is the security profile a Liquid FHE chain pins.
// There is no relaxed-PQ middle ground: a chain is strict-PQ or it
// isn't.
//
// The profile maps onto a specific ParametersLiteral so callers
// don't pick parameters at random and accidentally weaken the chain.
// DefaultParamsForProfile is the single seam every Liquid FHE chain
// boot routes through; direct references to PN10QP27 / PN11QP54 /
// PN9QP27_STD128Q in chain-config code are a bug (they bypass the
// profile gate).
type SecurityProfile int

const (
	// ProfileClassical128 selects PN10QP27 — ~128-bit *classical*
	// security. Acceptable for dev / regression testing only; a
	// strict-PQ Liquid chain MUST NOT boot under this profile.
	ProfileClassical128 SecurityProfile = iota

	// ProfileStrictPQ selects PN9QP27_STD128Q — 128-bit *quantum*
	// security via OpenFHE's STD128Q_LMKCDEY parameter set (NIST
	// FIPS 203 / 204 family alignment, LMKCDEY bootstrapping).
	// This is the canonical Liquid FHE chain profile.
	ProfileStrictPQ

	// ProfileStrictPQHighValue is reserved for the high-value tier
	// (treasury, governance roots) once STD192Q_LMKCDEY-aligned
	// ParametersLiterals land. For now it returns the same PQ
	// literal as ProfileStrictPQ so consumers can wire
	// IsPostQuantum()==true chains without holding for the
	// high-value tier.
	ProfileStrictPQHighValue
)

// String renders the canonical wire name. Audit pipelines match on
// these strings; renaming here breaks every downstream consumer.
func (p SecurityProfile) String() string {
	switch p {
	case ProfileClassical128:
		return "classical-128"
	case ProfileStrictPQ:
		return "strict-pq"
	case ProfileStrictPQHighValue:
		return "strict-pq-high-value"
	default:
		return "unknown"
	}
}

// IsPostQuantum reports whether this profile selects a parameter
// set whose security target is quantum-secure (NIST PQ alignment).
// ProfileClassical128 returns false; strict-PQ profiles return true.
func (p SecurityProfile) IsPostQuantum() bool {
	return p == ProfileStrictPQ || p == ProfileStrictPQHighValue
}

// DefaultParamsForProfile is the single seam every Liquid FHE chain
// boot routes through to pick a ParametersLiteral. Picking
// parameters directly (e.g. fhe.PN10QP27) anywhere in a Liquid FHE
// chain's boot path is a bug — it bypasses the profile gate and can
// silently weaken the chain to classical-only security.
//
// Strict-PQ profiles return PN9QP27_STD128Q (the only PQ
// ParametersLiteral currently published by this package). Once
// STD192Q_LMKCDEY-aligned literals land, ProfileStrictPQHighValue
// will return them; today both strict-PQ profiles return the same
// PQ literal.
func DefaultParamsForProfile(p SecurityProfile) ParametersLiteral {
	switch p {
	case ProfileStrictPQ, ProfileStrictPQHighValue:
		return PN9QP27_STD128Q
	case ProfileClassical128:
		fallthrough
	default:
		return PN10QP27
	}
}

// ProfileFromPQFlag maps a chain-config "pq" boolean (as written by
// liquidity/operator into /data/configs/chains/<id>/config.json) to
// a SecurityProfile. true → ProfileStrictPQ; false →
// ProfileClassical128. Reading via this helper means a misnamed
// flag (e.g. "PQ" with capitals, "post_quantum") that bypasses the
// JSON tag silently degrades to ProfileClassical128 — and the
// calling chain boot rejects the boot if it expected strict-PQ.
func ProfileFromPQFlag(pq bool) SecurityProfile {
	if pq {
		return ProfileStrictPQ
	}
	return ProfileClassical128
}
