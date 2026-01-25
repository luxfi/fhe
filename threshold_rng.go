// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package fhe

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
)

// ThresholdRNGProvider is an interface for threshold randomness providers.
// Implementations typically connect to a threshold network (e.g., T-Chain)
// to generate verifiable random values.
type ThresholdRNGProvider interface {
	// RequestRandomness requests random bytes from the threshold network.
	RequestRandomness(ctx context.Context, numBytes int) ([]byte, error)

	// IsAvailable returns true if the threshold network is reachable.
	IsAvailable(ctx context.Context) bool
}

// ThresholdRNGConfig configures the threshold RNG behavior.
type ThresholdRNGConfig struct {
	// Provider is the threshold randomness source.
	Provider ThresholdRNGProvider

	// FallbackEnabled allows local PRNG fallback when threshold network is unavailable.
	FallbackEnabled bool

	// MinThreshold is the minimum number of parties required for threshold operations.
	MinThreshold int
}

// ThresholdRNG generates encrypted random numbers using threshold randomness.
// It combines threshold network randomness with FHE encryption.
type ThresholdRNG struct {
	params   Parameters
	sk       *SecretKey
	pk       *PublicKey
	config   *ThresholdRNGConfig
	enc      *BitwiseEncryptor
	pubEnc   *BitwisePublicEncryptor
	state    [32]byte
	counter  uint64
	fallback bool
}

// NewThresholdRNG creates a new threshold RNG instance.
// If sk is provided, uses secret key encryption; otherwise uses public key encryption.
func NewThresholdRNG(params Parameters, sk *SecretKey, pk *PublicKey, config *ThresholdRNGConfig) *ThresholdRNG {
	rng := &ThresholdRNG{
		params:  params,
		sk:      sk,
		pk:      pk,
		config:  config,
		counter: 0,
	}

	if sk != nil {
		rng.enc = NewBitwiseEncryptor(params, sk)
	}
	if pk != nil {
		rng.pubEnc = NewBitwisePublicEncryptor(params, pk)
	}

	return rng
}

// reseed gets new randomness from the threshold network or falls back to local PRNG.
func (rng *ThresholdRNG) reseed(ctx context.Context, seed []byte) {
	// Use provided seed if available
	if len(seed) > 0 {
		rng.state = sha256.Sum256(seed)
		return
	}

	// Try threshold network
	if rng.config != nil && rng.config.Provider != nil && rng.config.Provider.IsAvailable(ctx) {
		if randomBytes, err := rng.config.Provider.RequestRandomness(ctx, 32); err == nil && len(randomBytes) >= 32 {
			copy(rng.state[:], randomBytes[:32])
			rng.fallback = false
			return
		}
	}

	// Fallback to counter-based state if enabled
	if rng.config == nil || rng.config.FallbackEnabled {
		var data [8]byte
		binary.LittleEndian.PutUint64(data[:], rng.counter)
		rng.state = sha256.Sum256(data[:])
		rng.fallback = true
	}
}

// advance advances the PRNG state
func (rng *ThresholdRNG) advance() [32]byte {
	var data [40]byte
	copy(data[:32], rng.state[:])
	binary.LittleEndian.PutUint64(data[32:], rng.counter)
	rng.counter++
	rng.state = sha256.Sum256(data[:])
	return rng.state
}

// RandomBit generates an encrypted random bit using threshold randomness.
func (rng *ThresholdRNG) RandomBit(ctx context.Context, seed []byte) (*Ciphertext, error) {
	rng.reseed(ctx, seed)
	random := rng.advance()
	bit := (random[0] & 1) == 1

	if rng.enc != nil {
		return rng.enc.enc.Encrypt(bit), nil
	}
	if rng.pubEnc != nil {
		return rng.pubEnc.Encrypt(bit)
	}
	return nil, nil
}

// RandomUint generates an encrypted random integer using threshold randomness.
func (rng *ThresholdRNG) RandomUint(ctx context.Context, t FheUintType, seed []byte) (*BitCiphertext, error) {
	rng.reseed(ctx, seed)
	numBits := t.NumBits()
	bits := make([]*Ciphertext, numBits)

	for i := 0; i < numBits; i++ {
		random := rng.advance()
		bit := (random[0] & 1) == 1
		if rng.enc != nil {
			bits[i] = rng.enc.enc.Encrypt(bit)
		} else if rng.pubEnc != nil {
			ct, err := rng.pubEnc.Encrypt(bit)
			if err != nil {
				return nil, err
			}
			bits[i] = ct
		}
	}

	return &BitCiphertext{
		bits:    bits,
		numBits: numBits,
		fheType: t,
	}, nil
}

// IsThresholdAvailable checks if the threshold network is available.
func (rng *ThresholdRNG) IsThresholdAvailable(ctx context.Context) bool {
	if rng.config == nil || rng.config.Provider == nil {
		return false
	}
	return rng.config.Provider.IsAvailable(ctx)
}

// IsFallback returns true if the RNG is using fallback (local) randomness.
func (rng *ThresholdRNG) IsFallback() bool {
	return rng.fallback
}

// CalculateThreshold calculates the minimum threshold for t-of-n threshold schemes.
// Uses the standard formula: t = floor(n/2) + 1 for honest majority.
func CalculateThreshold(n int) int {
	if n <= 0 {
		return 0
	}
	return n/2 + 1
}
