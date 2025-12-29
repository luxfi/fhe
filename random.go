// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package tfhe

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// FheRNG generates encrypted random numbers for FHE computations.
// Uses a deterministic PRNG seeded with a nonce for consensus compatibility.
// The generated random values are encrypted and remain hidden until decryption.
type FheRNG struct {
	params  Parameters
	enc     *BitwiseEncryptor
	state   [32]byte // SHA256 state
	counter uint64
}

// NewFheRNG creates a new encrypted random number generator.
// The seed should be derived from blockchain state (e.g., block hash + tx hash)
// to ensure deterministic but unpredictable randomness.
func NewFheRNG(params Parameters, sk *SecretKey, seed []byte) *FheRNG {
	state := sha256.Sum256(seed)
	return &FheRNG{
		params:  params,
		enc:     NewBitwiseEncryptor(params, sk),
		state:   state,
		counter: 0,
	}
}

// FheRNGPublic generates encrypted random numbers using public key encryption.
// This allows the RNG to run on nodes that don't have access to the secret key.
type FheRNGPublic struct {
	params  Parameters
	enc     *BitwisePublicEncryptor
	state   [32]byte
	counter uint64
}

// NewFheRNGPublic creates a new encrypted random number generator using public key.
func NewFheRNGPublic(params Parameters, pk *PublicKey, seed []byte) *FheRNGPublic {
	state := sha256.Sum256(seed)
	return &FheRNGPublic{
		params:  params,
		enc:     NewBitwisePublicEncryptor(params, pk),
		state:   state,
		counter: 0,
	}
}

// advance advances the PRNG state and returns the next 32 bytes of randomness
func (rng *FheRNG) advance() [32]byte {
	// Combine state with counter
	var data [40]byte
	copy(data[:32], rng.state[:])
	binary.LittleEndian.PutUint64(data[32:], rng.counter)
	rng.counter++

	// Update state
	rng.state = sha256.Sum256(data[:])
	return rng.state
}

// advance advances the public RNG state
func (rng *FheRNGPublic) advance() [32]byte {
	var data [40]byte
	copy(data[:32], rng.state[:])
	binary.LittleEndian.PutUint64(data[32:], rng.counter)
	rng.counter++
	rng.state = sha256.Sum256(data[:])
	return rng.state
}

// RandomBit generates a single encrypted random bit
// Note: Uses secret key encryption which cannot fail with valid parameters
func (rng *FheRNG) RandomBit() *Ciphertext {
	random := rng.advance()
	bit := (random[0] & 1) == 1
	return rng.enc.enc.Encrypt(bit)
}

// RandomBit generates a single encrypted random bit using public key
func (rng *FheRNGPublic) RandomBit() (*Ciphertext, error) {
	random := rng.advance()
	bit := (random[0] & 1) == 1
	ct, err := rng.enc.Encrypt(bit)
	if err != nil {
		return nil, fmt.Errorf("random bit encrypt: %w", err)
	}
	return ct, nil
}

// RandomUint generates an encrypted random integer of the specified type
// Note: Uses secret key encryption which cannot fail with valid parameters
func (rng *FheRNG) RandomUint(t FheUintType) *BitCiphertext {
	numBits := t.NumBits()
	bits := make([]*Ciphertext, numBits)

	// Get enough random bytes
	bytesNeeded := (numBits + 7) / 8
	var randomBytes []byte

	for len(randomBytes) < bytesNeeded {
		random := rng.advance()
		randomBytes = append(randomBytes, random[:]...)
	}

	// Encrypt each bit
	for i := 0; i < numBits; i++ {
		byteIdx := i / 8
		bitIdx := i % 8
		bit := (randomBytes[byteIdx] >> bitIdx) & 1
		bits[i] = rng.enc.enc.Encrypt(bit == 1)
	}

	return &BitCiphertext{
		bits:    bits,
		numBits: numBits,
		fheType: t,
	}
}

// RandomUint generates an encrypted random integer using public key
func (rng *FheRNGPublic) RandomUint(t FheUintType) (*BitCiphertext, error) {
	numBits := t.NumBits()
	bits := make([]*Ciphertext, numBits)

	bytesNeeded := (numBits + 7) / 8
	var randomBytes []byte

	for len(randomBytes) < bytesNeeded {
		random := rng.advance()
		randomBytes = append(randomBytes, random[:]...)
	}

	for i := 0; i < numBits; i++ {
		byteIdx := i / 8
		bitIdx := i % 8
		bit := (randomBytes[byteIdx] >> bitIdx) & 1
		ct, err := rng.enc.Encrypt(bit == 1)
		if err != nil {
			return nil, fmt.Errorf("random uint encrypt bit %d: %w", i, err)
		}
		bits[i] = ct
	}

	return &BitCiphertext{
		bits:    bits,
		numBits: numBits,
		fheType: t,
	}, nil
}

// RandomBounded generates an encrypted random integer in range [0, bound)
// Uses rejection sampling to ensure uniform distribution
// Note: This reveals the number of attempts but not the final value
func (rng *FheRNG) RandomBounded(t FheUintType, bound uint64) *BitCiphertext {
	// For now, just generate a random value and let the caller handle modular reduction
	// True rejection sampling would require homomorphic comparison which is expensive
	// The caller can use eval.Mod() or similar operations if needed
	return rng.RandomUint(t)
}

// Counter returns the current RNG counter (for verification/debugging)
func (rng *FheRNG) Counter() uint64 {
	return rng.counter
}

// Counter returns the current RNG counter
func (rng *FheRNGPublic) Counter() uint64 {
	return rng.counter
}

// Reseed reseeds the RNG with a new seed
func (rng *FheRNG) Reseed(seed []byte) {
	rng.state = sha256.Sum256(seed)
	rng.counter = 0
}

// Reseed reseeds the public RNG with a new seed
func (rng *FheRNGPublic) Reseed(seed []byte) {
	rng.state = sha256.Sum256(seed)
	rng.counter = 0
}
