// Tests for the threshold FHE service layer.
//
// Coverage:
//
//   - 2-of-3 partial decrypt + aggregate, byte-identical replay.
//   - 3-of-5 same.
//   - Insufficient shares (1 of 3 with t=2).
//   - Bad noise proof (tampered NoiseProof bytes).
//   - Tampered share data (after ShareRoot computed).
//   - Replay protection: same sessionID twice for one party.
//   - Wrong-ciphertext share is rejected.
//   - Cross-party verification with PartyKeys (committee self-check).
//   - Transcript root determinism across share reorderings.
//
// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause
package threshold

import (
	"context"
	"crypto/rand"
	"testing"
)

// makeCommittee returns n KeyShares with deterministic-looking bytes
// keyed off PartyID. The bytes are per-party 32-byte secrets — the toy
// scheme XORs them across t parties to recover the masked plaintext.
func makeCommittee(t *testing.T, n uint32) ([]KeyShare, []PublicKey) {
	t.Helper()
	keys := make([]KeyShare, n)
	pubs := make([]PublicKey, n)
	for i := uint32(1); i <= n; i++ {
		b := make([]byte, 32)
		// deterministic by partyID so tests are repeatable
		for j := range b {
			b[j] = byte(i)*0x11 ^ byte(j)
		}
		keys[i-1] = KeyShare{PartyID: i, Bytes: b}
		// pubkey is sha-of-key (placeholder; production uses real
		// per-party verifier material)
		pubs[i-1] = PublicKey{PartyID: i, Bytes: append([]byte("pub:"), b...)}
	}
	return keys, pubs
}

// freshSession returns a 32-byte sessionID drawn from crypto/rand.
func freshSession(t *testing.T) [32]byte {
	t.Helper()
	var s [32]byte
	if _, err := rand.Read(s[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return s
}

func TestPartialDecrypt_Deterministic(t *testing.T) {
	keys, _ := makeCommittee(t, 3)
	ct := NewFHECiphertext([]byte("ciphertext-bytes-toy-1"))
	sess := freshSession(t)

	pd1 := NewPartialDecrypter()
	pd2 := NewPartialDecrypter()
	share1, err := pd1.PartialDecrypt(context.Background(), keys[0], ct, sess)
	if err != nil {
		t.Fatalf("PartialDecrypt 1: %v", err)
	}
	share2, err := pd2.PartialDecrypt(context.Background(), keys[0], ct, sess)
	if err != nil {
		t.Fatalf("PartialDecrypt 2: %v", err)
	}
	if share1.ShareRoot != share2.ShareRoot {
		t.Fatalf("nondeterministic ShareRoot: %x vs %x", share1.ShareRoot, share2.ShareRoot)
	}
	if string(share1.ShareData) != string(share2.ShareData) {
		t.Fatalf("nondeterministic ShareData")
	}
}

func TestPartialDecrypt_Replay(t *testing.T) {
	keys, _ := makeCommittee(t, 3)
	ct := NewFHECiphertext([]byte("ciphertext-bytes-toy-2"))
	sess := freshSession(t)

	pd := NewPartialDecrypter()
	if _, err := pd.PartialDecrypt(context.Background(), keys[0], ct, sess); err != nil {
		t.Fatalf("first PartialDecrypt: %v", err)
	}
	if _, err := pd.PartialDecrypt(context.Background(), keys[0], ct, sess); err == nil {
		t.Fatalf("expected replay error on second PartialDecrypt")
	}
}

func TestAggregate_2of3(t *testing.T) {
	keys, _ := makeCommittee(t, 3)
	ct := NewFHECiphertext([]byte("ciphertext-bytes-2of3"))
	sess := freshSession(t)

	shares := make([]FHEThresholdShare, 0, 3)
	for i := 0; i < 3; i++ {
		pd := NewPartialDecrypter()
		s, err := pd.PartialDecrypt(context.Background(), keys[i], ct, sess)
		if err != nil {
			t.Fatalf("PartialDecrypt[%d]: %v", i, err)
		}
		shares = append(shares, s)
	}

	pkMap := make(map[uint32]KeyShare)
	for _, k := range keys {
		pkMap[k.PartyID] = k
	}
	agg := NewShareAggregator()
	agg.PartyKeys = pkMap

	res, plaintext, err := agg.Aggregate(context.Background(), ct, shares[:2], 2, sess)
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if res.Status != StatusOK {
		t.Fatalf("Status = %s, want OK", res.Status)
	}
	if res.PartyCount != 2 {
		t.Fatalf("PartyCount = %d, want 2", res.PartyCount)
	}
	if res.Threshold != 2 {
		t.Fatalf("Threshold = %d, want 2", res.Threshold)
	}
	if len(plaintext) == 0 {
		t.Fatalf("empty plaintext")
	}
	if res.CiphertextRoot != ct.ID {
		t.Fatalf("CiphertextRoot mismatch")
	}
	if res.AggregateRoot == ([32]byte{}) {
		t.Fatalf("AggregateRoot empty")
	}
}

func TestAggregate_3of5(t *testing.T) {
	keys, _ := makeCommittee(t, 5)
	ct := NewFHECiphertext([]byte("ciphertext-bytes-3of5"))
	sess := freshSession(t)

	shares := make([]FHEThresholdShare, 0, 5)
	for i := 0; i < 5; i++ {
		pd := NewPartialDecrypter()
		s, err := pd.PartialDecrypt(context.Background(), keys[i], ct, sess)
		if err != nil {
			t.Fatalf("PartialDecrypt[%d]: %v", i, err)
		}
		shares = append(shares, s)
	}
	pkMap := make(map[uint32]KeyShare)
	for _, k := range keys {
		pkMap[k.PartyID] = k
	}
	agg := NewShareAggregator()
	agg.PartyKeys = pkMap

	// Provide 4 shares but require threshold 3 — aggregator MUST take
	// the first t in canonical order.
	res, plaintext, err := agg.Aggregate(context.Background(), ct, shares[:4], 3, sess)
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if res.Status != StatusOK {
		t.Fatalf("Status = %s", res.Status)
	}
	if res.PartyCount != 3 {
		t.Fatalf("PartyCount = %d, want 3", res.PartyCount)
	}
	if len(plaintext) == 0 {
		t.Fatalf("empty plaintext")
	}
}

func TestAggregate_InsufficientShares(t *testing.T) {
	keys, _ := makeCommittee(t, 3)
	ct := NewFHECiphertext([]byte("ciphertext-bytes-insufficient"))
	sess := freshSession(t)

	pd := NewPartialDecrypter()
	share, err := pd.PartialDecrypt(context.Background(), keys[0], ct, sess)
	if err != nil {
		t.Fatalf("PartialDecrypt: %v", err)
	}
	pkMap := map[uint32]KeyShare{keys[0].PartyID: keys[0]}
	agg := NewShareAggregator()
	agg.PartyKeys = pkMap

	res, plaintext, err := agg.Aggregate(context.Background(), ct, []FHEThresholdShare{share}, 2, sess)
	if err != ErrTooFewShares {
		t.Fatalf("err = %v, want ErrTooFewShares", err)
	}
	if res.Status != StatusInsufficientShares {
		t.Fatalf("Status = %s, want InsufficientShares", res.Status)
	}
	if plaintext != nil {
		t.Fatalf("expected nil plaintext on insufficient shares")
	}
}

func TestAggregate_TamperedShareData(t *testing.T) {
	keys, _ := makeCommittee(t, 3)
	ct := NewFHECiphertext([]byte("ciphertext-bytes-tampered-share"))
	sess := freshSession(t)

	pd := NewPartialDecrypter()
	share, err := pd.PartialDecrypt(context.Background(), keys[0], ct, sess)
	if err != nil {
		t.Fatalf("PartialDecrypt: %v", err)
	}
	// Tamper after ShareRoot was computed.
	if len(share.ShareData) > 0 {
		share.ShareData[0] ^= 0xff
	}

	pkMap := map[uint32]KeyShare{keys[0].PartyID: keys[0]}
	agg := NewShareAggregator()
	agg.PartyKeys = pkMap

	res, _, err := agg.Aggregate(context.Background(), ct, []FHEThresholdShare{share}, 1, sess)
	if err != ErrShareRootMismatch {
		t.Fatalf("err = %v, want ErrShareRootMismatch", err)
	}
	if res.Status != StatusShareRootMismatch {
		t.Fatalf("Status = %s, want ShareRootMismatch", res.Status)
	}
}

func TestAggregate_BadNoiseProof(t *testing.T) {
	keys, _ := makeCommittee(t, 3)
	ct := NewFHECiphertext([]byte("ciphertext-bytes-bad-noise"))
	sess := freshSession(t)

	pd := NewPartialDecrypter()
	share, err := pd.PartialDecrypt(context.Background(), keys[0], ct, sess)
	if err != nil {
		t.Fatalf("PartialDecrypt: %v", err)
	}
	// Tamper noise proof — but RECOMPUTE the share root to bypass the
	// root-mismatch check, so the noise-proof check is what catches
	// the failure.
	if len(share.NoiseProof) > 0 {
		share.NoiseProof[len(share.NoiseProof)-1] ^= 0x01
	}
	share.ShareRoot = computeShareRoot(share, sess)

	pkMap := map[uint32]KeyShare{keys[0].PartyID: keys[0]}
	agg := NewShareAggregator()
	agg.PartyKeys = pkMap

	_, _, err = agg.Aggregate(context.Background(), ct, []FHEThresholdShare{share}, 1, sess)
	if err != ErrNoiseProofVerify {
		t.Fatalf("err = %v, want ErrNoiseProofVerify", err)
	}
}

func TestAggregate_DuplicatePartyID(t *testing.T) {
	keys, _ := makeCommittee(t, 3)
	ct := NewFHECiphertext([]byte("ciphertext-bytes-dup"))
	sess := freshSession(t)
	pd := NewPartialDecrypter()
	s1, err := pd.PartialDecrypt(context.Background(), keys[0], ct, sess)
	if err != nil {
		t.Fatalf("PartialDecrypt: %v", err)
	}
	pd2 := NewPartialDecrypter()
	s2, err := pd2.PartialDecrypt(context.Background(), keys[0], ct, sess)
	if err != nil {
		t.Fatalf("PartialDecrypt 2: %v", err)
	}

	agg := NewShareAggregator()
	_, _, err = agg.Aggregate(context.Background(), ct, []FHEThresholdShare{s1, s2}, 2, sess)
	if err != ErrDuplicatePartyID {
		t.Fatalf("err = %v, want ErrDuplicatePartyID", err)
	}
}

func TestAggregate_WrongCiphertext(t *testing.T) {
	keys, _ := makeCommittee(t, 3)
	ct1 := NewFHECiphertext([]byte("ciphertext-1"))
	ct2 := NewFHECiphertext([]byte("ciphertext-2"))
	sess := freshSession(t)

	pd := NewPartialDecrypter()
	share, err := pd.PartialDecrypt(context.Background(), keys[0], ct1, sess)
	if err != nil {
		t.Fatalf("PartialDecrypt: %v", err)
	}
	// Aggregate against the wrong ciphertext.
	pkMap := map[uint32]KeyShare{keys[0].PartyID: keys[0]}
	agg := NewShareAggregator()
	agg.PartyKeys = pkMap

	_, _, err = agg.Aggregate(context.Background(), ct2, []FHEThresholdShare{share}, 1, sess)
	if err != ErrCiphertextIDMismatch {
		t.Fatalf("err = %v, want ErrCiphertextIDMismatch", err)
	}
}

func TestVerifyShareWithKey_HappyPath(t *testing.T) {
	keys, _ := makeCommittee(t, 3)
	ct := NewFHECiphertext([]byte("ciphertext-verify"))
	sess := freshSession(t)

	pd := NewPartialDecrypter()
	share, err := pd.PartialDecrypt(context.Background(), keys[0], ct, sess)
	if err != nil {
		t.Fatalf("PartialDecrypt: %v", err)
	}
	v := NewShareVerifier()
	ok, err := v.VerifyShareWithKey(context.Background(), share, ct, keys[0], sess)
	if err != nil || !ok {
		t.Fatalf("VerifyShareWithKey: ok=%v err=%v", ok, err)
	}
}

func TestVerifyShare_PublicPathFailsWithoutCDS(t *testing.T) {
	// Documentation test: until the CDS proof ships, the public-key
	// verification path returns ErrNoiseProofVerify. This test
	// guards against accidental success — if it ever turns green
	// without a CDS implementation, the verifier has been weakened.
	keys, pubs := makeCommittee(t, 3)
	ct := NewFHECiphertext([]byte("ciphertext-public-verify"))
	sess := freshSession(t)
	pd := NewPartialDecrypter()
	share, err := pd.PartialDecrypt(context.Background(), keys[0], ct, sess)
	if err != nil {
		t.Fatalf("PartialDecrypt: %v", err)
	}
	v := NewShareVerifier()
	ok, err := v.VerifyShare(context.Background(), share, ct, pubs[0], sess)
	if err != ErrNoiseProofVerify || ok {
		t.Fatalf("VerifyShare: ok=%v err=%v, want false + ErrNoiseProofVerify", ok, err)
	}
}

func TestComputeTranscriptRoot_OrderInvariant(t *testing.T) {
	keys, _ := makeCommittee(t, 3)
	ct := NewFHECiphertext([]byte("ciphertext-transcript"))
	sess := freshSession(t)

	shares := make([]FHEThresholdShare, 3)
	for i := 0; i < 3; i++ {
		pd := NewPartialDecrypter()
		s, err := pd.PartialDecrypt(context.Background(), keys[i], ct, sess)
		if err != nil {
			t.Fatalf("PartialDecrypt[%d]: %v", i, err)
		}
		shares[i] = s
	}
	pkMap := make(map[uint32]KeyShare)
	for _, k := range keys {
		pkMap[k.PartyID] = k
	}
	agg := NewShareAggregator()
	agg.PartyKeys = pkMap

	res1, _, err := agg.Aggregate(context.Background(), ct, shares, 3, sess)
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	root1 := ComputeTranscriptRoot(sess, res1, shares)

	// Reorder shares — transcript root MUST be byte-equal because the
	// transcript canonicalizes by ascending PartyID.
	reordered := []FHEThresholdShare{shares[2], shares[0], shares[1]}
	res2, _, err := agg.Aggregate(context.Background(), ct, reordered, 3, sess)
	if err != nil {
		t.Fatalf("Aggregate reordered: %v", err)
	}
	root2 := ComputeTranscriptRoot(sess, res2, reordered)
	if root1 != root2 {
		t.Fatalf("transcript root not order-invariant:\n  %x\n  %x", root1, root2)
	}
}

func TestNoiseProof_VersionTagged(t *testing.T) {
	keys, _ := makeCommittee(t, 1)
	ct := NewFHECiphertext([]byte("ciphertext-version"))
	sess := freshSession(t)
	pd := NewPartialDecrypter()
	share, err := pd.PartialDecrypt(context.Background(), keys[0], ct, sess)
	if err != nil {
		t.Fatalf("PartialDecrypt: %v", err)
	}
	if len(share.NoiseProof) < 8 {
		t.Fatalf("noise proof too short")
	}
	// Bump version → verification fails.
	share.NoiseProof[3] = 0xff
	share.ShareRoot = computeShareRoot(share, sess)
	if verifyNoiseProof(keys[0], share, sess) {
		t.Fatalf("expected version mismatch to fail verification")
	}
}

func TestStatus_String(t *testing.T) {
	cases := []struct {
		s    FHEStatus
		want string
	}{
		{StatusOK, "OK"},
		{StatusInsufficientShares, "InsufficientShares"},
		{StatusNoiseProofFailed, "NoiseProofFailed"},
		{StatusShareRootMismatch, "ShareRootMismatch"},
		{StatusReplay, "Replay"},
		{StatusUnknownParty, "UnknownParty"},
		{StatusInvalidCiphertext, "InvalidCiphertext"},
		{FHEStatus(255), "Unknown"},
	}
	for _, c := range cases {
		if got := c.s.String(); got != c.want {
			t.Errorf("FHEStatus(%d).String() = %q, want %q", c.s, got, c.want)
		}
	}
}
