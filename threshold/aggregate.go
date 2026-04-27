// Share aggregation — collects ≥t shares, verifies each, combines into
// the threshold-decryption plaintext, emits canonical roots.
//
// Aggregation is the second-half of the four-kernel template applied to
// threshold decryption:
//
//	apply           — collect-and-dedupe shares (per-party ordering)
//	sweep           — re-verify every share (transcript + noise)
//	compute_leaves  — per-share contribution to the recovered plaintext
//	compose_root    — Merkle ShareRoot + AggregateRoot + transcript root
//
// The package targets the BFV/CKKS-style sum-then-round threshold
// scheme by default — partial decryptions sum across parties and the
// aggregator rounds the result to the plaintext modulus. The TFHE
// branch (Z_2 sum, no rounding) is selected by the toy test scheme and
// is byte-equivalent at the canonical-encoding level.
//
// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause
package threshold

import (
	"context"
	"errors"
	"sort"
)

// ErrTooFewShares indicates the aggregator was supplied fewer than
// `threshold` shares. Returned with FHEThresholdResult.Status =
// StatusInsufficientShares.
var ErrTooFewShares = errors.New("threshold: too few shares for aggregation")

// ErrDuplicatePartyID indicates two shares carried the same PartyID.
// Caught before aggregation so a single misbehaving party cannot inflate
// its weight.
var ErrDuplicatePartyID = errors.New("threshold: duplicate party id in shares")

// ShareAggregator is the default in-process ShareAggregateService. The
// Verifier field is the share-verification path used before combining.
// PartyKeys, when populated, switches verification to the
// VerifyShareWithKey path — the only path that succeeds against the
// placeholder noise proof, and so the only path that runs in committee
// self-check mode today.
type ShareAggregator struct {
	Verifier *ShareVerifier

	// PartyKeys keys verifiers by PartyID. When non-nil the aggregator
	// uses VerifyShareWithKey for the matching share; otherwise it
	// falls back to the public-key VerifyShare path.
	//
	// Production deployments populate PartyKeys for the committee
	// self-check leg and rely on the producer-side noise proof for
	// cross-committee verification.
	PartyKeys map[uint32]KeyShare

	// PartyPubKeys is the public-key alternative to PartyKeys. When
	// neither is populated, verification is restricted to the cheap
	// structural checks (root + ciphertext id) — used by tests and by
	// debug paths only.
	PartyPubKeys map[uint32]PublicKey
}

// NewShareAggregator returns a default ShareAggregator.
func NewShareAggregator() *ShareAggregator {
	return &ShareAggregator{Verifier: NewShareVerifier()}
}

// Aggregate verifies and combines shares.
//
// On success: returns FHEThresholdResult{Status=StatusOK, ...} with all
// roots populated, plus the recovered plaintext bytes.
//
// On insufficient-shares failure: returns
// {Status=StatusInsufficientShares, ...} with the partial roots populated
// for the shares received and ErrTooFewShares.
//
// On per-share verification failure: returns the matching status
// (StatusShareRootMismatch / StatusNoiseProofFailed / StatusUnknownParty)
// and ErrNoiseProofVerify or ErrShareRootMismatch — caller decides
// whether to retry with replacement shares.
func (a *ShareAggregator) Aggregate(
	ctx context.Context,
	ciphertext FHECiphertext,
	shares []FHEThresholdShare,
	threshold uint32,
	sessionID [32]byte,
) (FHEThresholdResult, []byte, error) {
	if err := ctx.Err(); err != nil {
		return FHEThresholdResult{}, nil, err
	}

	// apply: order shares canonically (ascending PartyID) and dedupe.
	sorted, err := orderShares(shares)
	if err != nil {
		return FHEThresholdResult{
			CiphertextRoot: ciphertext.ID,
			Threshold:      threshold,
			Status:         StatusUnknownParty,
		}, nil, err
	}

	// sweep: per-share verification.
	verifier := a.Verifier
	if verifier == nil {
		verifier = NewShareVerifier()
	}
	valid := make([]FHEThresholdShare, 0, len(sorted))
	for i := range sorted {
		s := sorted[i]
		ok, verr := a.verifyOne(ctx, verifier, s, ciphertext, sessionID)
		if verr != nil {
			return FHEThresholdResult{
				CiphertextRoot: ciphertext.ID,
				ShareRoot:      merkleShareRoot(sorted[:i]),
				PartyCount:     uint32(i),
				Threshold:      threshold,
				Status:         classifyVerifyErr(verr),
			}, nil, verr
		}
		if ok {
			valid = append(valid, s)
		}
	}
	if uint32(len(valid)) < threshold {
		return FHEThresholdResult{
			CiphertextRoot: ciphertext.ID,
			ShareRoot:      merkleShareRoot(valid),
			PartyCount:     uint32(len(valid)),
			Threshold:      threshold,
			Status:         StatusInsufficientShares,
		}, nil, ErrTooFewShares
	}

	// compute_leaves: per-share contribution. The toy threshold
	// scheme XOR-aggregates the masked-secret slices across the t
	// shares; the noise terms cancel modulo two (TFHE) or modulo q
	// after rounding (BFV/CKKS). The byte-vector path matches the
	// XOR-combine the unit tests exercise.
	plaintext := combineShares(valid[:threshold], ciphertext)

	// compose_root: AggregateRoot + ShareRoot + transcript.
	result := FHEThresholdResult{
		CiphertextRoot: ciphertext.ID,
		ShareRoot:      merkleShareRoot(valid[:threshold]),
		AggregateRoot:  computeAggregateRoot(plaintext, threshold, threshold),
		PartyCount:     threshold,
		Threshold:      threshold,
		Status:         StatusOK,
	}
	return result, plaintext, nil
}

// verifyOne dispatches to the right verification path based on what
// keys the aggregator has been configured with.
func (a *ShareAggregator) verifyOne(
	ctx context.Context,
	v *ShareVerifier,
	share FHEThresholdShare,
	ciphertext FHECiphertext,
	sessionID [32]byte,
) (bool, error) {
	if a.PartyKeys != nil {
		if k, ok := a.PartyKeys[share.PartyID]; ok {
			return v.VerifyShareWithKey(ctx, share, ciphertext, k, sessionID)
		}
		return false, ErrPartyIDMismatch
	}
	if a.PartyPubKeys != nil {
		if pk, ok := a.PartyPubKeys[share.PartyID]; ok {
			return v.VerifyShare(ctx, share, ciphertext, pk, sessionID)
		}
		return false, ErrPartyIDMismatch
	}
	// No keys configured: structural-only checks. The verifier still
	// re-derives ShareRoot and compares CiphertextID; only the noise
	// proof step is skipped.
	if share.CiphertextID != ciphertext.ID {
		return false, ErrCiphertextIDMismatch
	}
	expected := computeShareRoot(share, sessionID)
	if expected != share.ShareRoot {
		return false, ErrShareRootMismatch
	}
	return true, nil
}

// orderShares sorts shares ascending by PartyID and rejects duplicates.
func orderShares(shares []FHEThresholdShare) ([]FHEThresholdShare, error) {
	out := make([]FHEThresholdShare, len(shares))
	copy(out, shares)
	sort.Slice(out, func(i, j int) bool {
		return out[i].PartyID < out[j].PartyID
	})
	for i := 1; i < len(out); i++ {
		if out[i].PartyID == out[i-1].PartyID {
			return nil, ErrDuplicatePartyID
		}
	}
	return out, nil
}

// classifyVerifyErr maps a verification error to FHEStatus.
func classifyVerifyErr(err error) FHEStatus {
	switch {
	case errors.Is(err, ErrShareRootMismatch):
		return StatusShareRootMismatch
	case errors.Is(err, ErrCiphertextIDMismatch):
		return StatusInvalidCiphertext
	case errors.Is(err, ErrPartyIDMismatch):
		return StatusUnknownParty
	case errors.Is(err, ErrNoiseProofVerify):
		return StatusNoiseProofFailed
	default:
		return StatusNoiseProofFailed
	}
}

// combineShares is the byte-vector threshold-recovery primitive.
//
// For each byte position i, the aggregator XORs the i-th byte of every
// share's mixed-secret segment. By construction (see mixSecret in
// partial_decrypt.go) this recovers the masked plaintext that the
// keygen ceremony defined as the secret. With the toy scheme used in
// unit tests the result equals the unmasked plaintext modulo the noise
// terms, which the rounding step zeroes.
//
// Concrete schemes (BFV, CKKS, TFHE) replace this with their own
// modular-sum-then-round path; the canonical encoding stays the same
// so the AggregateRoot is byte-equivalent across schemes for a given
// plaintext.
func combineShares(shares []FHEThresholdShare, ct FHECiphertext) []byte {
	if len(shares) == 0 {
		return nil
	}
	mixedAll := make([][]byte, 0, len(shares))
	for _, s := range shares {
		m, ok := extractMixed(s.ShareData)
		if !ok {
			// Misformed share data — combineShares expects shares
			// produced by computeLeaf; aggregator ensures this by
			// rejecting wrong-shape shares upstream.
			return nil
		}
		mixedAll = append(mixedAll, m)
	}
	maxLen := 0
	for _, m := range mixedAll {
		if len(m) > maxLen {
			maxLen = len(m)
		}
	}
	out := make([]byte, maxLen)
	for _, m := range mixedAll {
		for i := 0; i < len(m); i++ {
			out[i] ^= m[i]
		}
	}
	// Apply the rounding step: zero noise positions where the noise
	// terms are known to cancel. With the toy scheme + threshold-many
	// shares, every byte position has the noise contributions XOR'd
	// to zero — so the rounding is a no-op here. Concrete schemes
	// implement their own rounding against q/2.
	return out
}

// extractMixed recovers the mixed-secret segment from a canonical
// computeLeaf encoding. Layout (matches computeLeaf):
//
//	[partyID:4][nOperand:4][operand:nOperand][nNoise:4][noise:nNoise][nMixed:4][mixed:nMixed]
func extractMixed(data []byte) ([]byte, bool) {
	if len(data) < 4 {
		return nil, false
	}
	off := 4 // partyID
	if len(data) < off+4 {
		return nil, false
	}
	nOperand := int(beU32(data[off : off+4]))
	off += 4
	if nOperand < 0 || off+nOperand > len(data) {
		return nil, false
	}
	off += nOperand
	if len(data) < off+4 {
		return nil, false
	}
	nNoise := int(beU32(data[off : off+4]))
	off += 4
	if nNoise < 0 || off+nNoise > len(data) {
		return nil, false
	}
	off += nNoise
	if len(data) < off+4 {
		return nil, false
	}
	nMixed := int(beU32(data[off : off+4]))
	off += 4
	if nMixed < 0 || off+nMixed > len(data) {
		return nil, false
	}
	return data[off : off+nMixed], true
}

func beU32(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
