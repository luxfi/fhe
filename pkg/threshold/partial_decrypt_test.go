// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package threshold

import (
	"testing"

	"github.com/luxfi/fhe"
	"github.com/luxfi/lattice/v7/utils/sampling"
)

// TestPartialDecrypt_RoundTrip_2of3 verifies that the canonical 2-of-3
// flow recovers the plaintext bit. This is the smoke test: real shares,
// real partials, real Lagrange combine, real bit decoding.
func TestPartialDecrypt_RoundTrip_2of3(t *testing.T) {
	for _, value := range []bool{false, true} {
		runRoundTrip(t, fhe.PN10QP27, 2, 3, value)
	}
}

// TestPartialDecrypt_RoundTrip_5of9 covers an asymmetric setup. Uses
// PN11QP54 because PN10QP27's modulus is too small to support t=5 with
// secure noise flooding (Λ_max · σ · √t · 6 > Q/16 at PN10).
func TestPartialDecrypt_RoundTrip_5of9(t *testing.T) {
	for _, value := range []bool{false, true} {
		runRoundTrip(t, fhe.PN11QP54, 5, 9, value)
	}
}

// TestPartialDecrypt_RoundTrip_11of21 covers a larger committee — the
// canonical Bendlin-Damgård benchmark setting. PN11QP54 (Q ≈ 2^54)
// suffices for t=11. Skipped under -short (keygen is slow).
func TestPartialDecrypt_RoundTrip_11of21(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 11-of-21 round-trip under -short")
	}
	for _, value := range []bool{false, true} {
		runRoundTrip(t, fhe.PN11QP54, 11, 21, value)
	}
}

func runRoundTrip(t *testing.T, lit fhe.ParametersLiteral, threshold, total int, value bool) {
	t.Helper()
	params, err := fhe.NewParametersFromLiteral(lit)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	kgen := fhe.NewKeyGenerator(params)
	sk, _ := kgen.GenKeyPair()

	// Distribute shares.
	shares, err := ShareLWESecretKeyFHE(sk, params, threshold, total)
	if err != nil {
		t.Fatalf("share: %v", err)
	}
	if got, want := len(shares), total; got != want {
		t.Fatalf("share count: got %d want %d", got, want)
	}

	// Encrypt with the master key (collective public key in the
	// production flow; either yields the same threshold-decryptable
	// ciphertext).
	enc := fhe.NewEncryptor(params, sk)
	ct := enc.Encrypt(value)

	// Each party in a chosen subset of size `threshold` produces a
	// partial. We choose the *last* t parties to avoid lucky alignment
	// with the first-t shares carrying obviously-small Lagrange weights.
	subset := shares[total-threshold:]
	partials := make([]*LWEPartialDecryption, threshold)
	for i, share := range subset {
		share := share
		prng, err := sampling.NewPRNG()
		if err != nil {
			t.Fatalf("prng: %v", err)
		}
		p, err := PartialDecryptFHE(&share, ct, params, threshold, prng)
		if err != nil {
			t.Fatalf("partial[%d]: %v", i, err)
		}
		if p.Index != share.Index {
			t.Fatalf("partial index mismatch: got %d want %d", p.Index, share.Index)
		}
		partials[i] = p
	}

	got, err := CombineFHE(ct, partials, params)
	if err != nil {
		t.Fatalf("combine: %v", err)
	}
	if got != value {
		t.Fatalf("round trip: got %v want %v (subset of %d, threshold %d)", got, value, total, threshold)
	}
}

// TestPartialDecrypt_BelowThresholdFails_2of3 confirms that 1 of 3
// partials cannot recover the plaintext (negative correctness test).
//
// Note: this is a *correctness* property — a single partial is exactly
// c_1·s_j + e_j, and adding it to c_0 yields a polynomial whose
// constant term is c_0 + c_1·s_j + e_j, far from the m + e of the
// honest decryption. We test that the decoded bit is wrong w.h.p.;
// security is a separate semantic statement covered by the simulation
// argument (not testable from black-box).
func TestPartialDecrypt_BelowThresholdFails_2of3(t *testing.T) {
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	kgen := fhe.NewKeyGenerator(params)
	sk, _ := kgen.GenKeyPair()
	shares, err := ShareLWESecretKeyFHE(sk, params, 2, 3)
	if err != nil {
		t.Fatalf("share: %v", err)
	}
	enc := fhe.NewEncryptor(params, sk)
	ct := enc.Encrypt(true)

	prng, _ := sampling.NewPRNG()
	share := shares[0]
	p, err := PartialDecryptFHE(&share, ct, params, 1, prng)
	if err != nil {
		t.Fatalf("partial: %v", err)
	}

	// Try to "combine" with 1 partial — Lagrange basis for {x_0} at 0
	// is identity, so this reduces to c_0 + (c_1·s_0 + e_0), which is
	// not the master decryption. Statistically the decoded bit is wrong
	// with probability ~1/2. We sample multiple plaintexts and check
	// that disagreement is non-negligible.
	disagreements := 0
	trials := 32
	for i := 0; i < trials; i++ {
		value := i&1 == 0
		ct2 := enc.Encrypt(value)
		prng2, _ := sampling.NewPRNG()
		p2, err := PartialDecryptFHE(&share, ct2, params, 1, prng2)
		if err != nil {
			t.Fatalf("partial[%d]: %v", i, err)
		}
		got, err := CombineFHE(ct2, []*LWEPartialDecryption{p2}, params)
		if err != nil {
			t.Fatalf("combine[%d]: %v", i, err)
		}
		if got != value {
			disagreements++
		}
	}
	_ = p
	if disagreements == 0 {
		t.Fatalf("below-threshold combine should disagree with plaintext; got 0/%d disagreements", trials)
	}
}

// TestShareLWESecretKey_NoMasterKeyLeak_2of3 verifies that no party's
// stored share equals the master secret key polynomial.
func TestShareLWESecretKey_NoMasterKeyLeak_2of3(t *testing.T) {
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	kgen := fhe.NewKeyGenerator(params)
	sk, _ := kgen.GenKeyPair()
	shares, err := ShareLWESecretKeyFHE(sk, params, 2, 3)
	if err != nil {
		t.Fatalf("share: %v", err)
	}

	// Lift sk to standard form to compare against shares (the share
	// representation).
	ringQ := params.ParamsLWE().RingQ()
	skStd := ringQ.NewPoly()
	ringQ.IMForm(sk.SKLWE.Value.Q, skStd)
	ringQ.INTT(skStd, skStd)

	for _, share := range shares {
		for i := 0; i < ringQ.N(); i++ {
			if share.Coeffs[i] == skStd.Coeffs[0][i] && share.Coeffs[i] != 0 {
				// A single coordinate matching is statistically possible.
				// We only flag if the entire vector matches.
			}
		}
		match := true
		for i := 0; i < ringQ.N(); i++ {
			if share.Coeffs[i] != skStd.Coeffs[0][i] {
				match = false
				break
			}
		}
		if match {
			t.Fatalf("share at index %d equals master secret coefficients", share.Index)
		}
	}
}

// TestCombineLWE_DuplicateIndexRejected verifies the dedup guard.
func TestCombineLWE_DuplicateIndexRejected(t *testing.T) {
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	kgen := fhe.NewKeyGenerator(params)
	sk, _ := kgen.GenKeyPair()
	shares, err := ShareLWESecretKeyFHE(sk, params, 2, 3)
	if err != nil {
		t.Fatalf("share: %v", err)
	}
	enc := fhe.NewEncryptor(params, sk)
	ct := enc.Encrypt(true)
	prng, _ := sampling.NewPRNG()
	share := shares[0]
	p, err := PartialDecryptFHE(&share, ct, params, 1, prng)
	if err != nil {
		t.Fatalf("partial: %v", err)
	}

	// Pass the same partial twice — should error before combining.
	if _, err := CombineLWE(ct.Ciphertext, []*LWEPartialDecryption{p, p}, params.ParamsLWE()); err == nil {
		t.Fatal("expected duplicate-index error")
	}
}

// TestCombineLWE_MismatchedQRejected guards against cross-parameter mixing.
func TestCombineLWE_MismatchedQRejected(t *testing.T) {
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	kgen := fhe.NewKeyGenerator(params)
	sk, _ := kgen.GenKeyPair()
	shares, err := ShareLWESecretKeyFHE(sk, params, 2, 3)
	if err != nil {
		t.Fatalf("share: %v", err)
	}
	enc := fhe.NewEncryptor(params, sk)
	ct := enc.Encrypt(true)
	prng, _ := sampling.NewPRNG()
	share := shares[0]
	p, err := PartialDecryptFHE(&share, ct, params, 1, prng)
	if err != nil {
		t.Fatalf("partial: %v", err)
	}
	p.Q = p.Q ^ 1
	if _, err := CombineLWE(ct.Ciphertext, []*LWEPartialDecryption{p}, params.ParamsLWE()); err == nil {
		t.Fatal("expected q-mismatch error")
	}
}

// TestPartialDecrypt_Deterministic_SameShares_SameOutput verifies that
// running the combine on the SAME partials yields the SAME plaintext.
// (PartialDecrypt is non-deterministic due to fresh noise; combine is
// deterministic in its inputs.)
func TestPartialDecrypt_Deterministic_SameShares_SameOutput(t *testing.T) {
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	kgen := fhe.NewKeyGenerator(params)
	sk, _ := kgen.GenKeyPair()
	shares, err := ShareLWESecretKeyFHE(sk, params, 2, 3)
	if err != nil {
		t.Fatalf("share: %v", err)
	}
	enc := fhe.NewEncryptor(params, sk)
	ct := enc.Encrypt(true)

	prng1, _ := sampling.NewPRNG()
	prng2, _ := sampling.NewPRNG()
	share0 := shares[0]
	share1 := shares[1]
	p0, err := PartialDecryptFHE(&share0, ct, params, 2, prng1)
	if err != nil {
		t.Fatalf("partial 0: %v", err)
	}
	p1, err := PartialDecryptFHE(&share1, ct, params, 2, prng2)
	if err != nil {
		t.Fatalf("partial 1: %v", err)
	}

	// Run combine twice on the same partials.
	got1, err := CombineFHE(ct, []*LWEPartialDecryption{p0, p1}, params)
	if err != nil {
		t.Fatalf("combine 1: %v", err)
	}
	got2, err := CombineFHE(ct, []*LWEPartialDecryption{p0, p1}, params)
	if err != nil {
		t.Fatalf("combine 2: %v", err)
	}
	if got1 != got2 {
		t.Fatalf("combine non-deterministic in inputs: %v vs %v", got1, got2)
	}
	if !got1 {
		t.Fatalf("plaintext recovery failed: got false want true")
	}
}
