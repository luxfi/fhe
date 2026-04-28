// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package fhe

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// TestNewKeyGeneratorFromSeed_Deterministic verifies that the same seed
// produces byte-identical secret keys across independent invocations.
// This is the consensus invariant: every validator must derive the same
// key from the same network seed.
func TestNewKeyGeneratorFromSeed_Deterministic(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	seed := []byte("LUX_FHE_KEYGEN_v1:test-seed-1")

	kg1, err := NewKeyGeneratorFromSeed(params, seed)
	if err != nil {
		t.Fatalf("NewKeyGeneratorFromSeed #1: %v", err)
	}
	kg2, err := NewKeyGeneratorFromSeed(params, seed)
	if err != nil {
		t.Fatalf("NewKeyGeneratorFromSeed #2: %v", err)
	}

	sk1 := kg1.GenSecretKey()
	sk2 := kg2.GenSecretKey()

	b1, err := sk1.SKBR.MarshalBinary()
	if err != nil {
		t.Fatalf("sk1 marshal: %v", err)
	}
	b2, err := sk2.SKBR.MarshalBinary()
	if err != nil {
		t.Fatalf("sk2 marshal: %v", err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatalf("same seed produced different SKBR: len1=%d len2=%d", len(b1), len(b2))
	}

	if params.N() != params.NBR() {
		bL1, err := sk1.SKLWE.MarshalBinary()
		if err != nil {
			t.Fatalf("sk1 LWE marshal: %v", err)
		}
		bL2, err := sk2.SKLWE.MarshalBinary()
		if err != nil {
			t.Fatalf("sk2 LWE marshal: %v", err)
		}
		if !bytes.Equal(bL1, bL2) {
			t.Fatalf("same seed produced different SKLWE")
		}
	}
}

// TestNewKeyGeneratorFromSeed_DifferentSeeds verifies distinct seeds yield
// distinct secret keys. This catches accidental constant-output bugs.
func TestNewKeyGeneratorFromSeed_DifferentSeeds(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	kgA, err := NewKeyGeneratorFromSeed(params, []byte("seed-A"))
	if err != nil {
		t.Fatalf("kgA: %v", err)
	}
	kgB, err := NewKeyGeneratorFromSeed(params, []byte("seed-B"))
	if err != nil {
		t.Fatalf("kgB: %v", err)
	}

	skA := kgA.GenSecretKey()
	skB := kgB.GenSecretKey()

	bA, _ := skA.SKBR.MarshalBinary()
	bB, _ := skB.SKBR.MarshalBinary()
	if bytes.Equal(bA, bB) {
		t.Fatalf("distinct seeds produced identical secret key (degenerate sampler)")
	}
}

// TestNewKeyGeneratorFromSeed_GoldenVector pins the SHA-256 of the marshalled
// secret key for a known seed under PN10QP27. Any change to the derivation
// pipeline (HKDF salt, info strings, sampler order, NTT/Montgomery form,
// underlying lattice library) will break this vector and must be reviewed
// as a network-breaking change.
func TestNewKeyGeneratorFromSeed_GoldenVector(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}

	// Fixed network seed used for the golden vector.
	seed := []byte("LUX_FHE_KEYGEN_v1:golden:0001")

	kg, err := NewKeyGeneratorFromSeed(params, seed)
	if err != nil {
		t.Fatalf("NewKeyGeneratorFromSeed: %v", err)
	}
	sk := kg.GenSecretKey()
	raw, err := sk.SKBR.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	digest := sha256.Sum256(raw)
	got := hex.EncodeToString(digest[:])

	// Cross-process golden vector. Updating this requires explicit network
	// review: any change here invalidates all keys derived under prior versions.
	const goldenDigest = "75becea8a116b6f04469ba39bbcfe9ecbbe893c3fbedcc50f30c653a2004ec73"
	if got != goldenDigest {
		t.Fatalf("golden vector drift:\n  want %s\n  got  %s", goldenDigest, got)
	}
	t.Logf("PN10QP27 SKBR sha256(seed=%q) = %s", seed, got)

	// Determinism check — same seed, fresh generator, same digest.
	kg2, _ := NewKeyGeneratorFromSeed(params, seed)
	sk2 := kg2.GenSecretKey()
	raw2, _ := sk2.SKBR.MarshalBinary()
	digest2 := sha256.Sum256(raw2)
	if !bytes.Equal(digest[:], digest2[:]) {
		t.Fatalf("re-derivation differs:\n  first  %x\n  second %x", digest, digest2)
	}
}

// TestNewKeyGeneratorFromSeed_EmptySeed asserts the empty-seed guard.
func TestNewKeyGeneratorFromSeed_EmptySeed(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral: %v", err)
	}
	if _, err := NewKeyGeneratorFromSeed(params, nil); err == nil {
		t.Fatalf("expected error for empty seed")
	}
}
