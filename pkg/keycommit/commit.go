// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keycommit

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"math/big"

	"github.com/luxfi/fhe"
)

// KeyCommitment represents a party's share of the FHE secret key
type KeyCommitment struct {
	PartyIndex int    // 1-based party index
	SessionID  string // Keygen session identifier

	// LSSS shares of the key components
	SKLWEShare *Share // Share of the LWE secret key seed
	SKBRShare  *Share // Share of the BR secret key seed

	// Public information (same for all parties)
	Threshold int
	Total     int
	PublicKey *fhe.PublicKey
	Params    fhe.Parameters
}

// CommitResult is the result of distributed key generation
type CommitResult struct {
	SessionID    string
	Threshold    int
	Total        int
	PublicKey    *fhe.PublicKey
	BootstrapKey *fhe.BootstrapKey
	Params       fhe.Parameters
	Shares       []*KeyCommitment // One per party
}

// CommitKey generates a keypair in one process and Shamir-splits the SHA-256
// hash of each secret-key component. The resulting shares are shares of a hash
// and cannot perform threshold decryption.
//
// Deprecated: for threshold custody use
// github.com/luxfi/threshold/protocols/tfhe.
func CommitKey(params fhe.Parameters, threshold, total int, sessionID string) (*CommitResult, error) {
	if threshold > total {
		return nil, fmt.Errorf("threshold %d exceeds total %d", threshold, total)
	}

	// Generate regular FHE keys first
	keygen := fhe.NewKeyGenerator(params)
	sk, pk := keygen.GenKeyPair()
	bsk := keygen.GenBootstrapKey(sk)

	// Derive secrets from the key components for sharing
	// We hash the serialized keys to get field elements
	skLWEBytes, err := serializeRLWESecretKey(sk.SKLWE)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize SKLWE: %w", err)
	}
	skLWESeed := hashToFieldElement(skLWEBytes)

	skBRBytes, err := serializeRLWESecretKey(sk.SKBR)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize SKBR: %w", err)
	}
	skBRSeed := hashToFieldElement(skBRBytes)

	// Split secrets using LSSS
	lweSharings, err := SplitSecret(skLWESeed, threshold, total)
	if err != nil {
		return nil, fmt.Errorf("failed to split SKLWE: %w", err)
	}

	brSharings, err := SplitSecret(skBRSeed, threshold, total)
	if err != nil {
		return nil, fmt.Errorf("failed to split SKBR: %w", err)
	}

	// Create key shares for each party
	shares := make([]*KeyCommitment, total)
	for i := 0; i < total; i++ {
		shares[i] = &KeyCommitment{
			PartyIndex: i + 1,
			SessionID:  sessionID,
			SKLWEShare: lweSharings.Shares[i],
			SKBRShare:  brSharings.Shares[i],
			Threshold:  threshold,
			Total:      total,
			PublicKey:  pk,
			Params:     params,
		}
	}

	return &CommitResult{
		SessionID:    sessionID,
		Threshold:    threshold,
		Total:        total,
		PublicKey:    pk,
		BootstrapKey: bsk,
		Params:       params,
		Shares:       shares,
	}, nil
}

// ReshareCommitment performs LSSS resharing to change threshold or add/remove parties
func ReshareCommitment(oldShares []*KeyCommitment, newThreshold, newTotal int, newSessionID string) (*CommitResult, error) {
	if len(oldShares) == 0 {
		return nil, fmt.Errorf("no shares provided")
	}

	oldThreshold := oldShares[0].Threshold
	if len(oldShares) < oldThreshold {
		return nil, fmt.Errorf("not enough shares: have %d, need %d", len(oldShares), oldThreshold)
	}

	// Extract LSSS shares
	lweShares := make([]*Share, len(oldShares))
	brShares := make([]*Share, len(oldShares))
	for i, ks := range oldShares {
		lweShares[i] = ks.SKLWEShare
		brShares[i] = ks.SKBRShare
	}

	// Reshare to new parameters
	newLWEShares, err := Reshare(lweShares, oldThreshold, newThreshold, newTotal)
	if err != nil {
		return nil, fmt.Errorf("failed to reshare SKLWE: %w", err)
	}

	newBRShares, err := Reshare(brShares, oldThreshold, newThreshold, newTotal)
	if err != nil {
		return nil, fmt.Errorf("failed to reshare SKBR: %w", err)
	}

	// Create new key shares (public key remains the same)
	newShares := make([]*KeyCommitment, newTotal)
	for i := 0; i < newTotal; i++ {
		newShares[i] = &KeyCommitment{
			PartyIndex: i + 1,
			SessionID:  newSessionID,
			SKLWEShare: newLWEShares.Shares[i],
			SKBRShare:  newBRShares.Shares[i],
			Threshold:  newThreshold,
			Total:      newTotal,
			PublicKey:  oldShares[0].PublicKey, // Same public key
			Params:     oldShares[0].Params,
		}
	}

	return &CommitResult{
		SessionID:    newSessionID,
		Threshold:    newThreshold,
		Total:        newTotal,
		PublicKey:    oldShares[0].PublicKey,
		BootstrapKey: nil, // Would need to regenerate or share
		Params:       oldShares[0].Params,
		Shares:       newShares,
	}, nil
}

// AddParty adds a new party by computing their share
func AddParty(existingShares []*KeyCommitment, newPartyIndex int, newSessionID string) (*KeyCommitment, error) {
	if len(existingShares) == 0 {
		return nil, fmt.Errorf("no shares provided")
	}

	threshold := existingShares[0].Threshold
	if len(existingShares) < threshold {
		return nil, fmt.Errorf("not enough shares: have %d, need %d", len(existingShares), threshold)
	}

	// Extract LSSS shares
	lweShares := make([]*Share, len(existingShares))
	brShares := make([]*Share, len(existingShares))
	for i, ks := range existingShares {
		lweShares[i] = ks.SKLWEShare
		brShares[i] = ks.SKBRShare
	}

	// Compute new share
	newLWEShare, err := AddShare(lweShares, threshold, newPartyIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to add SKLWE share: %w", err)
	}

	newBRShare, err := AddShare(brShares, threshold, newPartyIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to add SKBR share: %w", err)
	}

	return &KeyCommitment{
		PartyIndex: newPartyIndex,
		SessionID:  newSessionID,
		SKLWEShare: newLWEShare,
		SKBRShare:  newBRShare,
		Threshold:  threshold,
		Total:      existingShares[0].Total + 1,
		PublicKey:  existingShares[0].PublicKey,
		Params:     existingShares[0].Params,
	}, nil
}

// RefreshCommitments refreshes all shares to provide proactive security
func RefreshCommitments(shares []*KeyCommitment, newSessionID string) ([]*KeyCommitment, error) {
	if len(shares) == 0 {
		return nil, fmt.Errorf("no shares provided")
	}

	threshold := shares[0].Threshold
	total := len(shares)

	// Collect current shares
	lweSet := &ShareSet{
		Threshold: threshold,
		Total:     total,
		Shares:    make([]*Share, total),
	}
	brSet := &ShareSet{
		Threshold: threshold,
		Total:     total,
		Shares:    make([]*Share, total),
	}

	for i, ks := range shares {
		lweSet.Shares[i] = ks.SKLWEShare
		brSet.Shares[i] = ks.SKBRShare
	}

	// Refresh shares
	newLWESet, err := RefreshShares(lweSet)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh SKLWE: %w", err)
	}

	newBRSet, err := RefreshShares(brSet)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh SKBR: %w", err)
	}

	// Create new key shares
	newShares := make([]*KeyCommitment, total)
	for i := 0; i < total; i++ {
		newShares[i] = &KeyCommitment{
			PartyIndex: shares[i].PartyIndex,
			SessionID:  newSessionID,
			SKLWEShare: newLWESet.Shares[i],
			SKBRShare:  newBRSet.Shares[i],
			Threshold:  threshold,
			Total:      total,
			PublicKey:  shares[0].PublicKey,
			Params:     shares[0].Params,
		}
	}

	return newShares, nil
}

// Helpers

func hashToFieldElement(data []byte) *big.Int {
	hash := sha256.Sum256(data)
	n := new(big.Int).SetBytes(hash[:])
	return n.Mod(n, Prime)
}

func serializeRLWESecretKey(sk interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(sk); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// MarshalCommitment serializes a key share
func MarshalCommitment(ks *KeyCommitment) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(ks); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalCommitment deserializes a key share
func UnmarshalCommitment(data []byte) (*KeyCommitment, error) {
	dec := gob.NewDecoder(bytes.NewReader(data))
	var ks KeyCommitment
	if err := dec.Decode(&ks); err != nil {
		return nil, err
	}
	return &ks, nil
}
