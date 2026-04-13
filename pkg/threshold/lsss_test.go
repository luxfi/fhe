// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package threshold

import (
	"math/big"
	"testing"
)

func TestSplitAndRecombine(t *testing.T) {
	secret := big.NewInt(42)
	ss, err := SplitSecret(secret, 3, 5)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	got, err := RecombineShares(ss.Shares, 3)
	if err != nil {
		t.Fatalf("recombine: %v", err)
	}
	if got.Cmp(secret) != 0 {
		t.Fatalf("expected %s, got %s", secret, got)
	}
}

func TestSplitAndRecombine_SubsetOfShares(t *testing.T) {
	secret := big.NewInt(1234567890)
	ss, err := SplitSecret(secret, 3, 5)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	// Use shares 2,4,5 (any t=3 subset).
	subset := []*Share{ss.Shares[1], ss.Shares[3], ss.Shares[4]}
	got, err := RecombineShares(subset, 3)
	if err != nil {
		t.Fatalf("recombine: %v", err)
	}
	if got.Cmp(secret) != 0 {
		t.Fatalf("expected %s, got %s", secret, got)
	}
}

func TestReshare_RoundTrip(t *testing.T) {
	secret := big.NewInt(999)
	oldSS, err := SplitSecret(secret, 2, 3)
	if err != nil {
		t.Fatalf("split: %v", err)
	}

	// Reshare from 2-of-3 to 3-of-5.
	newSS, err := Reshare(oldSS.Shares, 2, 3, 5)
	if err != nil {
		t.Fatalf("reshare: %v", err)
	}

	// New shares must reconstruct the same secret.
	got, err := RecombineShares(newSS.Shares, 3)
	if err != nil {
		t.Fatalf("recombine: %v", err)
	}
	if got.Cmp(secret) != 0 {
		t.Fatalf("reshare broke secret: expected %s, got %s", secret, got)
	}
}

func TestReshare_SecretNotInReturnValues(t *testing.T) {
	secret := big.NewInt(12345)
	oldSS, err := SplitSecret(secret, 2, 3)
	if err != nil {
		t.Fatalf("split: %v", err)
	}

	newSS, err := Reshare(oldSS.Shares, 2, 2, 4)
	if err != nil {
		t.Fatalf("reshare: %v", err)
	}

	// The secret itself must not appear as any share value.
	for _, s := range newSS.Shares {
		if s.Value.Cmp(secret) == 0 {
			t.Fatalf("secret leaked as share value at index %d", s.Index)
		}
	}
}

func TestReshare_SameThreshold(t *testing.T) {
	secret := big.NewInt(7777)
	ss, err := SplitSecret(secret, 3, 5)
	if err != nil {
		t.Fatalf("split: %v", err)
	}

	newSS, err := Reshare(ss.Shares, 3, 3, 5)
	if err != nil {
		t.Fatalf("reshare: %v", err)
	}

	got, err := RecombineShares(newSS.Shares, 3)
	if err != nil {
		t.Fatalf("recombine: %v", err)
	}
	if got.Cmp(secret) != 0 {
		t.Fatalf("expected %s, got %s", secret, got)
	}
}

func TestRefreshShares_PreservesSecret(t *testing.T) {
	secret := big.NewInt(555)
	ss, err := SplitSecret(secret, 2, 3)
	if err != nil {
		t.Fatalf("split: %v", err)
	}

	refreshed, err := RefreshShares(ss)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}

	got, err := RecombineShares(refreshed.Shares, 2)
	if err != nil {
		t.Fatalf("recombine: %v", err)
	}
	if got.Cmp(secret) != 0 {
		t.Fatalf("refresh broke secret: expected %s, got %s", secret, got)
	}
}

func TestAddShare(t *testing.T) {
	secret := big.NewInt(100)
	ss, err := SplitSecret(secret, 2, 3)
	if err != nil {
		t.Fatalf("split: %v", err)
	}

	newShare, err := AddShare(ss.Shares, 2, 10)
	if err != nil {
		t.Fatalf("add share: %v", err)
	}

	// Combine original share 1 + new share at index 10.
	combined := []*Share{ss.Shares[0], newShare}
	got, err := RecombineShares(combined, 2)
	if err != nil {
		t.Fatalf("recombine: %v", err)
	}
	if got.Cmp(secret) != 0 {
		t.Fatalf("expected %s, got %s", secret, got)
	}
}

// Finding 10: Generator must be in order-q subgroup.
func TestGenerator_IsQuadraticResidue(t *testing.T) {
	// For safe prime p = 2q+1, q = (p-1)/2.
	q := new(big.Int).Sub(Prime, big.NewInt(1))
	q.Div(q, big.NewInt(2))

	// Generator^q mod p must equal 1 (element of order q).
	result := new(big.Int).Exp(Generator, q, Prime)
	if result.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("Generator^q mod p = %s, expected 1", result)
	}

	// Generator itself must not be 1.
	if Generator.Cmp(big.NewInt(1)) == 0 {
		t.Fatal("Generator is trivial (1)")
	}
}

func TestFeldmanVSS_VerifyShare(t *testing.T) {
	secret := big.NewInt(77)

	// Build a known polynomial for verification.
	coeffs := make([]*big.Int, 3)
	coeffs[0] = new(big.Int).Set(secret)
	// Derive coefficients from 3 shares via matrix inversion (for test only).
	// Instead, just verify that ComputeCommitments + VerifyShare is consistent
	// by creating a known polynomial.
	coeffs[1] = big.NewInt(13)
	coeffs[2] = big.NewInt(7)

	shares := make([]*Share, 5)
	for i := 0; i < 5; i++ {
		x := big.NewInt(int64(i + 1))
		shares[i] = &Share{Index: i + 1, Value: evaluatePolynomial(coeffs, x)}
	}

	commitment := ComputeCommitments(coeffs)

	for _, s := range shares {
		if !VerifyShare(s, commitment) {
			t.Fatalf("share %d failed verification", s.Index)
		}
	}

	// Tampered share should fail.
	tampered := &Share{Index: 1, Value: new(big.Int).Add(shares[0].Value, big.NewInt(1))}
	if VerifyShare(tampered, commitment) {
		t.Fatal("tampered share passed verification")
	}
}

func TestSplitSecret_InvalidParams(t *testing.T) {
	_, err := SplitSecret(big.NewInt(1), 0, 3)
	if err == nil {
		t.Fatal("expected error for threshold=0")
	}
	_, err = SplitSecret(big.NewInt(1), 4, 3)
	if err == nil {
		t.Fatal("expected error for threshold > total")
	}
}
