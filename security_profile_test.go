// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import "testing"

func TestSecurityProfile_String(t *testing.T) {
	for _, tc := range []struct {
		profile SecurityProfile
		want    string
	}{
		{ProfileClassical128, "classical-128"},
		{ProfileStrictPQ, "strict-pq"},
		{ProfileStrictPQHighValue, "strict-pq-high-value"},
		{SecurityProfile(99), "unknown"},
	} {
		if got := tc.profile.String(); got != tc.want {
			t.Errorf("SecurityProfile(%d).String() = %q, want %q",
				tc.profile, got, tc.want)
		}
	}
}

func TestSecurityProfile_IsPostQuantum(t *testing.T) {
	for _, tc := range []struct {
		profile SecurityProfile
		want    bool
	}{
		{ProfileClassical128, false},
		{ProfileStrictPQ, true},
		{ProfileStrictPQHighValue, true},
	} {
		if got := tc.profile.IsPostQuantum(); got != tc.want {
			t.Errorf("%s.IsPostQuantum() = %t, want %t",
				tc.profile, got, tc.want)
		}
	}
}

// TestDefaultParamsForProfile_StrictPQReturnsPQLiteral pins the
// security guarantee: a strict-PQ profile MUST return a PQ
// ParametersLiteral, never a classical one. A regression that
// pointed ProfileStrictPQ at PN10QP27 would silently weaken every
// Liquid FHE chain. The test asserts byte-identity, not just "some
// PQ literal", so swapping the underlying PQ literal name requires
// an explicit test update.
func TestDefaultParamsForProfile_StrictPQReturnsPQLiteral(t *testing.T) {
	for _, p := range []SecurityProfile{ProfileStrictPQ, ProfileStrictPQHighValue} {
		got := DefaultParamsForProfile(p)
		if got != PN9QP27_STD128Q {
			t.Errorf("DefaultParamsForProfile(%s) = %+v, want PN9QP27_STD128Q",
				p, got)
		}
	}
}

// TestDefaultParamsForProfile_ClassicalReturnsClassicalLiteral pins
// the converse: classical profile returns the classical literal.
// Default-case fall-through (unknown profile) also returns
// classical so a typo in the consumer cannot accidentally promote
// to PQ params (whose keygen is ~10x slower and would surface as a
// boot-time hang rather than a clear error).
func TestDefaultParamsForProfile_ClassicalReturnsClassicalLiteral(t *testing.T) {
	for _, p := range []SecurityProfile{ProfileClassical128, SecurityProfile(99)} {
		got := DefaultParamsForProfile(p)
		if got != PN10QP27 {
			t.Errorf("DefaultParamsForProfile(%s) = %+v, want PN10QP27",
				p, got)
		}
	}
}

func TestProfileFromPQFlag(t *testing.T) {
	if got := ProfileFromPQFlag(true); got != ProfileStrictPQ {
		t.Errorf("ProfileFromPQFlag(true) = %s, want strict-pq", got)
	}
	if got := ProfileFromPQFlag(false); got != ProfileClassical128 {
		t.Errorf("ProfileFromPQFlag(false) = %s, want classical-128", got)
	}
}
