// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package fhe

import "testing"

// TestBootstrapKey_MarshalRoundTrip proves a BootstrapKey survives a
// MarshalBinary/UnmarshalBinary round trip. The BRK field is an interface whose
// concrete type must be gob-registered; this test pins that the registration is
// in place (regression guard for the BRK decode path).
func TestBootstrapKey_MarshalRoundTrip(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	kg := NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)

	data, err := bsk.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("marshal produced no bytes")
	}

	got := new(BootstrapKey)
	if err := got.UnmarshalBinary(data); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.BRK == nil {
		t.Fatal("BRK is nil after round trip")
	}
	for name, p := range map[string]interface{}{
		"TestPolyAND":  got.TestPolyAND,
		"TestPolyOR":   got.TestPolyOR,
		"TestPolyNAND": got.TestPolyNAND,
		"TestPolyNOR":  got.TestPolyNOR,
	} {
		if p == nil {
			t.Fatalf("%s is nil after round trip", name)
		}
	}
}
