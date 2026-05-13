// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhe

import (
	"testing"

	"github.com/luxfi/pq"
)

// TestDefaultParamsForMode_StrictPQReturnsPQLiteral pins the
// security guarantee: pq.ModeStrictPQ MUST return a PQ
// ParametersLiteral, never a classical one. A regression that
// pointed strict-PQ at PN10QP27 would silently weaken every Liquid
// FHE chain. The test asserts byte-identity, not just "some PQ
// literal", so swapping the underlying PQ literal name requires an
// explicit test update.
func TestDefaultParamsForMode_StrictPQReturnsPQLiteral(t *testing.T) {
	got := DefaultParamsForMode(pq.ModeStrictPQ)
	if got != PN9QP27_STD128Q {
		t.Errorf("DefaultParamsForMode(StrictPQ) = %+v, want PN9QP27_STD128Q", got)
	}
}

// TestDefaultParamsForMode_ClassicalReturnsClassicalLiteral pins
// the converse: classical mode returns the classical literal.
// Hybrid also returns classical params — the gate is selection, not
// refusal, and FHE parameter sets don't have a hybrid mid-tier.
func TestDefaultParamsForMode_ClassicalReturnsClassicalLiteral(t *testing.T) {
	for _, m := range []pq.Mode{pq.ModeClassical, pq.ModeHybrid} {
		got := DefaultParamsForMode(m)
		if got != PN10QP27 {
			t.Errorf("DefaultParamsForMode(%s) = %+v, want PN10QP27", m, got)
		}
	}
}
