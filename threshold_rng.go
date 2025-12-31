// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package fhe

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

// ThresholdRNGProvider defines the interface for threshold randomness.
// Implementations connect to the T-Chain threshold network.
type ThresholdRNGProvider interface {
	// RequestRandomness requests threshold-generated randomness.
	// The request is processed by t-of-n threshold parties.
	// Returns a 32-byte random value after threshold decryption.
	RequestRandomness(ctx context.Context, seed []byte) ([]byte, error)

	// RequestRandomBits requests specific number of random bits.
	RequestRandomBits(ctx context.Context, numBits int, seed []byte) ([]byte, error)

	// IsAvailable checks if threshold network is reachable.
	IsAvailable(ctx context.Context) bool

	// GetThreshold returns the current threshold (t of n).
	GetThreshold() (t, n int)
}

// ThresholdRNGConfig configures the threshold RNG.
type ThresholdRNGConfig struct {
	// Provider is the threshold randomness provider (T-Chain client).
	Provider ThresholdRNGProvider

	// Timeout for threshold operations.
	Timeout time.Duration

	// FallbackEnabled allows falling back to deterministic PRNG
	// when threshold network is unavailable.
	FallbackEnabled bool

	// FallbackSeed is used when falling back to deterministic mode.
	// Should be derived from consensus state for determinism.
	FallbackSeed []byte
}

// DefaultThresholdRNGConfig returns default configuration.
func DefaultThresholdRNGConfig() *ThresholdRNGConfig {
	return &ThresholdRNGConfig{
		Timeout:         30 * time.Second,
		FallbackEnabled: true,
	}
}

// ThresholdRNG generates encrypted random numbers using T-Chain threshold network.
// This ensures randomness cannot be predicted by any single party.
type ThresholdRNG struct {
	params   Parameters
	enc      *BitwiseEncryptor
	pubEnc   *BitwisePublicEncryptor
	provider ThresholdRNGProvider
	config   *ThresholdRNGConfig

	// Fallback state
	fallbackMu      sync.Mutex
	fallbackState   [32]byte
	fallbackCounter uint64

	// Cache for recent randomness requests
	cacheMu sync.RWMutex
	cache   map[string][]byte
}

// NewThresholdRNG creates a new threshold RNG.
// If provider is nil and fallback is enabled, uses deterministic mode.
func NewThresholdRNG(params Parameters, sk *SecretKey, pk *PublicKey, cfg *ThresholdRNGConfig) *ThresholdRNG {
	if cfg == nil {
		cfg = DefaultThresholdRNGConfig()
	}

	rng := &ThresholdRNG{
		params:   params,
		provider: cfg.Provider,
		config:   cfg,
		cache:    make(map[string][]byte),
	}

	if sk != nil {
		rng.enc = NewBitwiseEncryptor(params, sk)
	}
	if pk != nil {
		rng.pubEnc = NewBitwisePublicEncryptor(params, pk)
	}

	// Initialize fallback state
	if cfg.FallbackSeed != nil {
		rng.fallbackState = sha256.Sum256(cfg.FallbackSeed)
	}

	return rng
}

// RandomBytes generates random bytes using threshold network.
func (rng *ThresholdRNG) RandomBytes(ctx context.Context, numBytes int, seed []byte) ([]byte, error) {
	if rng.provider != nil && rng.provider.IsAvailable(ctx) {
		return rng.thresholdRandomBytes(ctx, numBytes, seed)
	}

	if rng.config.FallbackEnabled {
		return rng.fallbackRandomBytes(numBytes, seed)
	}

	return nil, errors.New("threshold network unavailable and fallback disabled")
}

// thresholdRandomBytes gets randomness from threshold network.
func (rng *ThresholdRNG) thresholdRandomBytes(ctx context.Context, numBytes int, seed []byte) ([]byte, error) {
	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, rng.config.Timeout)
	defer cancel()

	// Check cache first
	cacheKey := string(sha256Hash(append(seed, byte(numBytes))))
	rng.cacheMu.RLock()
	if cached, ok := rng.cache[cacheKey]; ok {
		rng.cacheMu.RUnlock()
		return cached, nil
	}
	rng.cacheMu.RUnlock()

	// Request from threshold network
	numBits := numBytes * 8
	randomBits, err := rng.provider.RequestRandomBits(ctx, numBits, seed)
	if err != nil {
		// Try fallback if enabled
		if rng.config.FallbackEnabled {
			return rng.fallbackRandomBytes(numBytes, seed)
		}
		return nil, err
	}

	// Cache result
	rng.cacheMu.Lock()
	rng.cache[cacheKey] = randomBits
	rng.cacheMu.Unlock()

	return randomBits, nil
}

// fallbackRandomBytes generates deterministic random bytes.
func (rng *ThresholdRNG) fallbackRandomBytes(numBytes int, seed []byte) ([]byte, error) {
	rng.fallbackMu.Lock()
	defer rng.fallbackMu.Unlock()

	result := make([]byte, 0, numBytes)

	// Mix in the seed
	if len(seed) > 0 {
		var mixData [64]byte
		copy(mixData[:32], rng.fallbackState[:])
		seedHash := sha256.Sum256(seed)
		copy(mixData[32:], seedHash[:])
		rng.fallbackState = sha256.Sum256(mixData[:])
	}

	// Generate bytes
	for len(result) < numBytes {
		var data [40]byte
		copy(data[:32], rng.fallbackState[:])
		binary.LittleEndian.PutUint64(data[32:], rng.fallbackCounter)
		rng.fallbackCounter++

		rng.fallbackState = sha256.Sum256(data[:])
		result = append(result, rng.fallbackState[:]...)
	}

	return result[:numBytes], nil
}

// RandomBit generates a single encrypted random bit using threshold network.
func (rng *ThresholdRNG) RandomBit(ctx context.Context, seed []byte) (*Ciphertext, error) {
	randomBytes, err := rng.RandomBytes(ctx, 1, seed)
	if err != nil {
		return nil, err
	}

	bit := (randomBytes[0] & 1) == 1

	if rng.enc != nil {
		return rng.enc.enc.Encrypt(bit), nil
	}
	if rng.pubEnc != nil {
		return rng.pubEnc.Encrypt(bit)
	}

	return nil, errors.New("no encryptor available")
}

// RandomUint generates an encrypted random integer using threshold network.
func (rng *ThresholdRNG) RandomUint(ctx context.Context, t FheUintType, seed []byte) (*BitCiphertext, error) {
	numBits := t.NumBits()
	bytesNeeded := (numBits + 7) / 8

	randomBytes, err := rng.RandomBytes(ctx, bytesNeeded, seed)
	if err != nil {
		return nil, err
	}

	bits := make([]*Ciphertext, numBits)
	for i := 0; i < numBits; i++ {
		byteIdx := i / 8
		bitIdx := i % 8
		bit := (randomBytes[byteIdx] >> bitIdx) & 1

		var ct *Ciphertext
		var encErr error
		if rng.enc != nil {
			ct = rng.enc.enc.Encrypt(bit == 1)
		} else if rng.pubEnc != nil {
			ct, encErr = rng.pubEnc.Encrypt(bit == 1)
			if encErr != nil {
				return nil, encErr
			}
		} else {
			return nil, errors.New("no encryptor available")
		}
		bits[i] = ct
	}

	return &BitCiphertext{
		bits:    bits,
		numBits: numBits,
		fheType: t,
	}, nil
}

// RandomUint256 generates an encrypted random 256-bit integer.
func (rng *ThresholdRNG) RandomUint256(ctx context.Context, seed []byte) (*BitCiphertext, error) {
	return rng.RandomUint(ctx, FheUint256, seed)
}

// IsThresholdAvailable checks if threshold network is available.
func (rng *ThresholdRNG) IsThresholdAvailable(ctx context.Context) bool {
	if rng.provider == nil {
		return false
	}
	return rng.provider.IsAvailable(ctx)
}

// GetThreshold returns the current threshold parameters.
func (rng *ThresholdRNG) GetThreshold() (t, n int, err error) {
	if rng.provider == nil {
		return 0, 0, errors.New("no threshold provider")
	}
	t, n = rng.provider.GetThreshold()
	return t, n, nil
}

// ClearCache clears the randomness cache.
func (rng *ThresholdRNG) ClearCache() {
	rng.cacheMu.Lock()
	rng.cache = make(map[string][]byte)
	rng.cacheMu.Unlock()
}

// sha256Hash is a helper for hashing.
func sha256Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// DefaultThresholdPercent is the default threshold percentage (69%).
// This matches Lux mainnet/testnet 5-node validator sets.
const DefaultThresholdPercent = 69

// DefaultNumParties is the default number of parties (5-node network).
const DefaultNumParties = 5

// DefaultThreshold is 4-of-5 (which satisfies 69% requirement: 4/5 = 80% >= 69%).
const DefaultThreshold = 4

// CalculateThreshold returns the minimum threshold for a given percentage and party count.
// For example: CalculateThreshold(69, 5) returns 4 (since ceil(5 * 0.69) = 4).
func CalculateThreshold(percentRequired int, numParties int) int {
	required := (numParties*percentRequired + 99) / 100 // Ceiling division
	if required < 1 {
		return 1
	}
	if required > numParties {
		return numParties
	}
	return required
}

// LocalThresholdProvider is a mock provider for testing/development.
// In production, use TChainThresholdProvider to connect to T-Chain.
type LocalThresholdProvider struct {
	threshold  int
	numParties int
	seed       []byte
	mu         sync.Mutex
	counter    uint64
}

// NewLocalThresholdProvider creates a local mock provider.
func NewLocalThresholdProvider(threshold, numParties int, seed []byte) *LocalThresholdProvider {
	return &LocalThresholdProvider{
		threshold:  threshold,
		numParties: numParties,
		seed:       seed,
	}
}

// RequestRandomness implements ThresholdRNGProvider.
func (p *LocalThresholdProvider) RequestRandomness(ctx context.Context, seed []byte) ([]byte, error) {
	return p.RequestRandomBits(ctx, 256, seed)
}

// RequestRandomBits implements ThresholdRNGProvider.
func (p *LocalThresholdProvider) RequestRandomBits(ctx context.Context, numBits int, seed []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	numBytes := (numBits + 7) / 8
	result := make([]byte, 0, numBytes)

	// Combine provider seed with request seed
	var combined [64]byte
	if len(p.seed) >= 32 {
		copy(combined[:32], p.seed[:32])
	}
	if len(seed) > 0 {
		seedHash := sha256.Sum256(seed)
		copy(combined[32:], seedHash[:])
	}

	state := sha256.Sum256(combined[:])

	// Generate bytes
	for len(result) < numBytes {
		var data [40]byte
		copy(data[:32], state[:])
		binary.LittleEndian.PutUint64(data[32:], p.counter)
		p.counter++
		state = sha256.Sum256(data[:])
		result = append(result, state[:]...)
	}

	return result[:numBytes], nil
}

// IsAvailable implements ThresholdRNGProvider.
func (p *LocalThresholdProvider) IsAvailable(ctx context.Context) bool {
	return true
}

// GetThreshold implements ThresholdRNGProvider.
func (p *LocalThresholdProvider) GetThreshold() (t, n int) {
	return p.threshold, p.numParties
}
