// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024-2025, Lux Industries Inc
//
// Go bindings for Lux FHE library
// Wraps unified MLX/CUDA/CPU backend with GPU acceleration
//
// For enterprise licensing: fhe@lux.network

//go:build cgo && luxfhe

package cgo

/*
#cgo CXXFLAGS: -std=c++17 -O3 -I${SRCDIR}/../../mlx/fhe
#cgo darwin LDFLAGS: -L${SRCDIR}/../../mlx/build/lib -lluxfhe -framework Metal -framework MetalPerformanceShaders
#cgo linux LDFLAGS: -L${SRCDIR}/../../mlx/build/lib -lluxfhe -lcuda -lcudart
#cgo LDFLAGS: -lstdc++

#include "luxfhe_bridge.h"
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"runtime"
	"sync"
	"unsafe"
)

// =============================================================================
// Types
// =============================================================================

// Backend represents the computation backend
type Backend int

const (
	BackendAuto Backend = iota
	BackendMLX
	BackendCUDA
	BackendCPU
)

// Mode represents the FHE operation mode (DMAFHE)
type Mode int

const (
	ModeAuto   Mode = iota
	ModeUTXO64      // 64-bit optimized for UTXO
	ModeEVM256      // 256-bit optimized for EVM
)

// Security represents the security level
type Security int

const (
	Security128 Security = iota
	Security192
	Security256
)

// TrustLevel represents validator trust level (VAFHE)
type TrustLevel int

const (
	TrustPublic       TrustLevel = 1 // Consumer GPU
	TrustPrivate      TrustLevel = 2 // SGX/A100
	TrustConfidential TrustLevel = 3 // H100+TDX
	TrustSovereign    TrustLevel = 4 // Blackwell
)

// AttestationType represents hardware attestation type
type AttestationType int

const (
	AttestSGX AttestationType = iota
	AttestTDX
	AttestSEV
	AttestNVTrust
	AttestARMCCA
)

// EVMOpcode represents EVM arithmetic opcodes
type EVMOpcode uint8

const (
	EVMAdd    EVMOpcode = 0x01
	EVMMul    EVMOpcode = 0x02
	EVMSub    EVMOpcode = 0x03
	EVMDiv    EVMOpcode = 0x04
	EVMMod    EVMOpcode = 0x06
	EVMAddMod EVMOpcode = 0x08
	EVMMulMod EVMOpcode = 0x09
	EVMExp    EVMOpcode = 0x0a
	EVMLt     EVMOpcode = 0x10
	EVMGt     EVMOpcode = 0x11
	EVMEq     EVMOpcode = 0x14
	EVMAnd    EVMOpcode = 0x16
	EVMOr     EVMOpcode = 0x17
	EVMXor    EVMOpcode = 0x18
	EVMNot    EVMOpcode = 0x19
	EVMShl    EVMOpcode = 0x1b
	EVMShr    EVMOpcode = 0x1c
	EVMSar    EVMOpcode = 0x1d
)

// Chain IDs
const (
	ChainLUX   = 96369
	ChainZOO   = 200200
	ChainHANZO = 36963
)

// =============================================================================
// Engine
// =============================================================================

// Engine manages FHE operations with GPU acceleration
type Engine struct {
	ptr    C.LuxFHEEngine
	mu     sync.RWMutex
	params *Params
	bsk    *BootstrapKey
}

// NewEngine creates a new FHE engine with the specified backend
func NewEngine(backend Backend) (*Engine, error) {
	e := &Engine{}
	e.ptr = C.luxfhe_engine_create(C.LuxFHEBackend(backend))
	if e.ptr == nil {
		return nil, errors.New("failed to create FHE engine")
	}
	runtime.SetFinalizer(e, (*Engine).Free)
	return e, nil
}

// NewDefaultEngine creates an engine with auto-detected backend
func NewDefaultEngine() (*Engine, error) {
	e := &Engine{}
	e.ptr = C.luxfhe_engine_create_default()
	if e.ptr == nil {
		return nil, errors.New("failed to create FHE engine")
	}
	runtime.SetFinalizer(e, (*Engine).Free)
	return e, nil
}

// Free releases the engine
func (e *Engine) Free() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ptr != nil {
		C.luxfhe_engine_free(e.ptr)
		e.ptr = nil
	}
}

// SetMode sets the operation mode (DMAFHE)
func (e *Engine) SetMode(mode Mode) {
	e.mu.Lock()
	defer e.mu.Unlock()
	C.luxfhe_engine_set_mode(e.ptr, C.LuxFHEMode(mode))
}

// GetMode returns the current mode
func (e *Engine) GetMode() Mode {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return Mode(C.luxfhe_engine_get_mode(e.ptr))
}

// GetBackend returns the active backend
func (e *Engine) GetBackend() Backend {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return Backend(C.luxfhe_engine_get_backend(e.ptr))
}

// =============================================================================
// Parameters
// =============================================================================

// Params holds TFHE parameters
type Params struct {
	ptr C.LuxFHEParams
}

// NewParams creates TFHE parameters
func NewParams(security Security, mode Mode) (*Params, error) {
	p := &Params{}
	p.ptr = C.luxfhe_params_create(C.LuxFHESecurity(security), C.LuxFHEMode(mode))
	if p.ptr == nil {
		return nil, errors.New("failed to create parameters")
	}
	runtime.SetFinalizer(p, (*Params).Free)
	return p, nil
}

// Free releases parameters
func (p *Params) Free() {
	if p.ptr != nil {
		C.luxfhe_params_free(p.ptr)
		p.ptr = nil
	}
}

// GetN returns LWE dimension
func (p *Params) GetN() int {
	return int(C.luxfhe_params_get_n(p.ptr))
}

// GetRingDimension returns ring dimension N
func (p *Params) GetRingDimension() int {
	return int(C.luxfhe_params_get_N(p.ptr))
}

// =============================================================================
// Keys
// =============================================================================

// SecretKey holds the secret key
type SecretKey struct {
	ptr    C.LuxFHESecretKey
	engine *Engine
}

// PublicKey holds the public key
type PublicKey struct {
	ptr    C.LuxFHEPublicKey
	engine *Engine
}

// BootstrapKey holds the bootstrapping key
type BootstrapKey struct {
	ptr    C.LuxFHEBootstrapKey
	engine *Engine
}

// KeySwitchKey holds the key switching key
type KeySwitchKey struct {
	ptr    C.LuxFHEKeySwitchKey
	engine *Engine
}

// GenerateSecretKey generates a new secret key
func (e *Engine) GenerateSecretKey(params *Params) (*SecretKey, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	
	sk := &SecretKey{engine: e}
	sk.ptr = C.luxfhe_keygen_secret(e.ptr, params.ptr)
	if sk.ptr == nil {
		return nil, errors.New("failed to generate secret key")
	}
	runtime.SetFinalizer(sk, (*SecretKey).Free)
	return sk, nil
}

// Free releases the secret key
func (sk *SecretKey) Free() {
	if sk.ptr != nil {
		C.luxfhe_secretkey_free(sk.ptr)
		sk.ptr = nil
	}
}

// GeneratePublicKey generates a public key
func (e *Engine) GeneratePublicKey(params *Params, sk *SecretKey) (*PublicKey, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	
	pk := &PublicKey{engine: e}
	pk.ptr = C.luxfhe_keygen_public(e.ptr, params.ptr, sk.ptr)
	if pk.ptr == nil {
		return nil, errors.New("failed to generate public key")
	}
	runtime.SetFinalizer(pk, (*PublicKey).Free)
	return pk, nil
}

// Free releases the public key
func (pk *PublicKey) Free() {
	if pk.ptr != nil {
		C.luxfhe_publickey_free(pk.ptr)
		pk.ptr = nil
	}
}

// GenerateBootstrapKey generates the bootstrapping key (GPU-accelerated)
func (e *Engine) GenerateBootstrapKey(params *Params, sk *SecretKey) (*BootstrapKey, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	
	bsk := &BootstrapKey{engine: e}
	bsk.ptr = C.luxfhe_keygen_bootstrap(e.ptr, params.ptr, sk.ptr)
	if bsk.ptr == nil {
		return nil, errors.New("failed to generate bootstrap key")
	}
	e.bsk = bsk
	runtime.SetFinalizer(bsk, (*BootstrapKey).Free)
	return bsk, nil
}

// Free releases the bootstrap key
func (bsk *BootstrapKey) Free() {
	if bsk.ptr != nil {
		C.luxfhe_bootstrapkey_free(bsk.ptr)
		bsk.ptr = nil
	}
}

// GenerateKeySwitchKey generates the key switching key
func (e *Engine) GenerateKeySwitchKey(params *Params, sk *SecretKey) (*KeySwitchKey, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	
	ksk := &KeySwitchKey{engine: e}
	ksk.ptr = C.luxfhe_keygen_keyswitch(e.ptr, params.ptr, sk.ptr)
	if ksk.ptr == nil {
		return nil, errors.New("failed to generate key switch key")
	}
	runtime.SetFinalizer(ksk, (*KeySwitchKey).Free)
	return ksk, nil
}

// Free releases the key switch key
func (ksk *KeySwitchKey) Free() {
	if ksk.ptr != nil {
		C.luxfhe_keyswitchkey_free(ksk.ptr)
		ksk.ptr = nil
	}
}

// =============================================================================
// Ciphertext (Boolean)
// =============================================================================

// Ciphertext holds an encrypted bit
type Ciphertext struct {
	ptr    C.LuxFHECiphertext
	engine *Engine
}

// EncryptBit encrypts a boolean value
func (e *Engine) EncryptBit(sk *SecretKey, bit bool) (*Ciphertext, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	var b C.int = 0
	if bit {
		b = 1
	}
	
	ct := &Ciphertext{engine: e}
	ct.ptr = C.luxfhe_encrypt_bit(e.ptr, sk.ptr, b)
	if ct.ptr == nil {
		return nil, errors.New("failed to encrypt bit")
	}
	runtime.SetFinalizer(ct, (*Ciphertext).Free)
	return ct, nil
}

// EncryptBitPublic encrypts with public key
func (e *Engine) EncryptBitPublic(pk *PublicKey, bit bool) (*Ciphertext, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	var b C.int = 0
	if bit {
		b = 1
	}
	
	ct := &Ciphertext{engine: e}
	ct.ptr = C.luxfhe_encrypt_bit_public(e.ptr, pk.ptr, b)
	if ct.ptr == nil {
		return nil, errors.New("failed to encrypt bit with public key")
	}
	runtime.SetFinalizer(ct, (*Ciphertext).Free)
	return ct, nil
}

// DecryptBit decrypts a boolean value
func (e *Engine) DecryptBit(sk *SecretKey, ct *Ciphertext) (bool, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	result := C.luxfhe_decrypt_bit(e.ptr, sk.ptr, ct.ptr)
	return result != 0, nil
}

// Free releases the ciphertext
func (ct *Ciphertext) Free() {
	if ct.ptr != nil {
		C.luxfhe_ciphertext_free(ct.ptr)
		ct.ptr = nil
	}
}

// Clone creates a copy of the ciphertext
func (ct *Ciphertext) Clone() (*Ciphertext, error) {
	newCt := &Ciphertext{engine: ct.engine}
	newCt.ptr = C.luxfhe_ciphertext_clone(ct.ptr)
	if newCt.ptr == nil {
		return nil, errors.New("failed to clone ciphertext")
	}
	runtime.SetFinalizer(newCt, (*Ciphertext).Free)
	return newCt, nil
}

// =============================================================================
// Boolean Gates
// =============================================================================

// And performs AND gate with bootstrapping
func (e *Engine) And(bsk *BootstrapKey, a, b *Ciphertext) (*Ciphertext, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	ct := &Ciphertext{engine: e}
	ct.ptr = C.luxfhe_and(e.ptr, bsk.ptr, a.ptr, b.ptr)
	if ct.ptr == nil {
		return nil, errors.New("AND gate failed")
	}
	runtime.SetFinalizer(ct, (*Ciphertext).Free)
	return ct, nil
}

// Or performs OR gate
func (e *Engine) Or(bsk *BootstrapKey, a, b *Ciphertext) (*Ciphertext, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	ct := &Ciphertext{engine: e}
	ct.ptr = C.luxfhe_or(e.ptr, bsk.ptr, a.ptr, b.ptr)
	if ct.ptr == nil {
		return nil, errors.New("OR gate failed")
	}
	runtime.SetFinalizer(ct, (*Ciphertext).Free)
	return ct, nil
}

// Xor performs XOR gate
func (e *Engine) Xor(bsk *BootstrapKey, a, b *Ciphertext) (*Ciphertext, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	ct := &Ciphertext{engine: e}
	ct.ptr = C.luxfhe_xor(e.ptr, bsk.ptr, a.ptr, b.ptr)
	if ct.ptr == nil {
		return nil, errors.New("XOR gate failed")
	}
	runtime.SetFinalizer(ct, (*Ciphertext).Free)
	return ct, nil
}

// Not performs NOT gate (no bootstrapping needed)
func (e *Engine) Not(ct *Ciphertext) (*Ciphertext, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	result := &Ciphertext{engine: e}
	result.ptr = C.luxfhe_not(e.ptr, ct.ptr)
	if result.ptr == nil {
		return nil, errors.New("NOT gate failed")
	}
	runtime.SetFinalizer(result, (*Ciphertext).Free)
	return result, nil
}

// Nand performs NAND gate
func (e *Engine) Nand(bsk *BootstrapKey, a, b *Ciphertext) (*Ciphertext, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	ct := &Ciphertext{engine: e}
	ct.ptr = C.luxfhe_nand(e.ptr, bsk.ptr, a.ptr, b.ptr)
	if ct.ptr == nil {
		return nil, errors.New("NAND gate failed")
	}
	runtime.SetFinalizer(ct, (*Ciphertext).Free)
	return ct, nil
}

// Mux performs multiplexer: if sel then a else b
func (e *Engine) Mux(bsk *BootstrapKey, sel, a, b *Ciphertext) (*Ciphertext, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	ct := &Ciphertext{engine: e}
	ct.ptr = C.luxfhe_mux(e.ptr, bsk.ptr, sel.ptr, a.ptr, b.ptr)
	if ct.ptr == nil {
		return nil, errors.New("MUX gate failed")
	}
	runtime.SetFinalizer(ct, (*Ciphertext).Free)
	return ct, nil
}

// =============================================================================
// Integer (64-bit - UTXO mode)
// =============================================================================

// Integer holds an encrypted 64-bit integer
type Integer struct {
	ptr    C.LuxFHEInteger
	engine *Engine
}

// EncryptU64 encrypts a 64-bit unsigned integer
func (e *Engine) EncryptU64(sk *SecretKey, value uint64) (*Integer, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	i := &Integer{engine: e}
	i.ptr = C.luxfhe_encrypt_u64(e.ptr, sk.ptr, C.uint64_t(value))
	if i.ptr == nil {
		return nil, errors.New("failed to encrypt integer")
	}
	runtime.SetFinalizer(i, (*Integer).Free)
	return i, nil
}

// EncryptU64Public encrypts with public key
func (e *Engine) EncryptU64Public(pk *PublicKey, value uint64) (*Integer, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	i := &Integer{engine: e}
	i.ptr = C.luxfhe_encrypt_u64_public(e.ptr, pk.ptr, C.uint64_t(value))
	if i.ptr == nil {
		return nil, errors.New("failed to encrypt integer with public key")
	}
	runtime.SetFinalizer(i, (*Integer).Free)
	return i, nil
}

// DecryptU64 decrypts a 64-bit integer
func (e *Engine) DecryptU64(sk *SecretKey, ct *Integer) (uint64, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	return uint64(C.luxfhe_decrypt_u64(e.ptr, sk.ptr, ct.ptr)), nil
}

// Free releases the integer
func (i *Integer) Free() {
	if i.ptr != nil {
		C.luxfhe_integer_free(i.ptr)
		i.ptr = nil
	}
}

// Clone creates a copy
func (i *Integer) Clone() (*Integer, error) {
	newI := &Integer{engine: i.engine}
	newI.ptr = C.luxfhe_integer_clone(i.ptr)
	if newI.ptr == nil {
		return nil, errors.New("failed to clone integer")
	}
	runtime.SetFinalizer(newI, (*Integer).Free)
	return newI, nil
}

// =============================================================================
// Integer Arithmetic
// =============================================================================

// AddU64 adds two encrypted integers
func (e *Engine) AddU64(bsk *BootstrapKey, a, b *Integer) (*Integer, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	i := &Integer{engine: e}
	i.ptr = C.luxfhe_add_u64(e.ptr, bsk.ptr, a.ptr, b.ptr)
	if i.ptr == nil {
		return nil, errors.New("addition failed")
	}
	runtime.SetFinalizer(i, (*Integer).Free)
	return i, nil
}

// SubU64 subtracts two encrypted integers
func (e *Engine) SubU64(bsk *BootstrapKey, a, b *Integer) (*Integer, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	i := &Integer{engine: e}
	i.ptr = C.luxfhe_sub_u64(e.ptr, bsk.ptr, a.ptr, b.ptr)
	if i.ptr == nil {
		return nil, errors.New("subtraction failed")
	}
	runtime.SetFinalizer(i, (*Integer).Free)
	return i, nil
}

// MulU64 multiplies two encrypted integers
func (e *Engine) MulU64(bsk *BootstrapKey, a, b *Integer) (*Integer, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	i := &Integer{engine: e}
	i.ptr = C.luxfhe_mul_u64(e.ptr, bsk.ptr, a.ptr, b.ptr)
	if i.ptr == nil {
		return nil, errors.New("multiplication failed")
	}
	runtime.SetFinalizer(i, (*Integer).Free)
	return i, nil
}

// AddScalarU64 adds a plaintext scalar
func (e *Engine) AddScalarU64(a *Integer, scalar uint64) (*Integer, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	i := &Integer{engine: e}
	i.ptr = C.luxfhe_add_scalar_u64(e.ptr, a.ptr, C.uint64_t(scalar))
	if i.ptr == nil {
		return nil, errors.New("scalar addition failed")
	}
	runtime.SetFinalizer(i, (*Integer).Free)
	return i, nil
}

// =============================================================================
// Comparisons (ULFHE - PAT-FHE-011)
// =============================================================================

// Lt tests a < b with O(1) bootstrapping
func (e *Engine) Lt(bsk *BootstrapKey, a, b *Integer) (*Ciphertext, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	ct := &Ciphertext{engine: e}
	ct.ptr = C.luxfhe_lt(e.ptr, bsk.ptr, a.ptr, b.ptr)
	if ct.ptr == nil {
		return nil, errors.New("less-than comparison failed")
	}
	runtime.SetFinalizer(ct, (*Ciphertext).Free)
	return ct, nil
}

// Le tests a <= b
func (e *Engine) Le(bsk *BootstrapKey, a, b *Integer) (*Ciphertext, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	ct := &Ciphertext{engine: e}
	ct.ptr = C.luxfhe_le(e.ptr, bsk.ptr, a.ptr, b.ptr)
	if ct.ptr == nil {
		return nil, errors.New("less-equal comparison failed")
	}
	runtime.SetFinalizer(ct, (*Ciphertext).Free)
	return ct, nil
}

// Gt tests a > b
func (e *Engine) Gt(bsk *BootstrapKey, a, b *Integer) (*Ciphertext, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	ct := &Ciphertext{engine: e}
	ct.ptr = C.luxfhe_gt(e.ptr, bsk.ptr, a.ptr, b.ptr)
	if ct.ptr == nil {
		return nil, errors.New("greater-than comparison failed")
	}
	runtime.SetFinalizer(ct, (*Ciphertext).Free)
	return ct, nil
}

// Ge tests a >= b
func (e *Engine) Ge(bsk *BootstrapKey, a, b *Integer) (*Ciphertext, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	ct := &Ciphertext{engine: e}
	ct.ptr = C.luxfhe_ge(e.ptr, bsk.ptr, a.ptr, b.ptr)
	if ct.ptr == nil {
		return nil, errors.New("greater-equal comparison failed")
	}
	runtime.SetFinalizer(ct, (*Ciphertext).Free)
	return ct, nil
}

// Eq tests a == b
func (e *Engine) Eq(bsk *BootstrapKey, a, b *Integer) (*Ciphertext, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	ct := &Ciphertext{engine: e}
	ct.ptr = C.luxfhe_eq(e.ptr, bsk.ptr, a.ptr, b.ptr)
	if ct.ptr == nil {
		return nil, errors.New("equality comparison failed")
	}
	runtime.SetFinalizer(ct, (*Ciphertext).Free)
	return ct, nil
}

// InRange checks if value is in [min, max] range
func (e *Engine) InRange(bsk *BootstrapKey, value *Integer, min, max uint64) (*Ciphertext, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	ct := &Ciphertext{engine: e}
	ct.ptr = C.luxfhe_in_range(e.ptr, bsk.ptr, value.ptr, C.uint64_t(min), C.uint64_t(max))
	if ct.ptr == nil {
		return nil, errors.New("range check failed")
	}
	runtime.SetFinalizer(ct, (*Ciphertext).Free)
	return ct, nil
}

// =============================================================================
// uint256 (EVM256PP - PAT-FHE-012)
// =============================================================================

// Uint256 holds an encrypted 256-bit integer (4 limbs)
type Uint256 struct {
	ptr    C.LuxFHEUint256
	engine *Engine
}

// EncryptU256 encrypts a uint256 from 4 limbs
func (e *Engine) EncryptU256(sk *SecretKey, limbs [4]uint64) (*Uint256, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	cLimbs := (*C.uint64_t)(unsafe.Pointer(&limbs[0]))
	u := &Uint256{engine: e}
	u.ptr = C.luxfhe_encrypt_u256(e.ptr, sk.ptr, cLimbs)
	if u.ptr == nil {
		return nil, errors.New("failed to encrypt uint256")
	}
	runtime.SetFinalizer(u, (*Uint256).Free)
	return u, nil
}

// EncryptU256Public encrypts with public key
func (e *Engine) EncryptU256Public(pk *PublicKey, limbs [4]uint64) (*Uint256, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	cLimbs := (*C.uint64_t)(unsafe.Pointer(&limbs[0]))
	u := &Uint256{engine: e}
	u.ptr = C.luxfhe_encrypt_u256_public(e.ptr, pk.ptr, cLimbs)
	if u.ptr == nil {
		return nil, errors.New("failed to encrypt uint256 with public key")
	}
	runtime.SetFinalizer(u, (*Uint256).Free)
	return u, nil
}

// DecryptU256 decrypts a uint256 to 4 limbs
func (e *Engine) DecryptU256(sk *SecretKey, ct *Uint256) ([4]uint64, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	var limbs [4]uint64
	C.luxfhe_decrypt_u256(e.ptr, sk.ptr, ct.ptr, (*C.uint64_t)(unsafe.Pointer(&limbs[0])))
	return limbs, nil
}

// Free releases uint256
func (u *Uint256) Free() {
	if u.ptr != nil {
		C.luxfhe_uint256_free(u.ptr)
		u.ptr = nil
	}
}

// AddU256 adds two encrypted uint256
func (e *Engine) AddU256(a, b *Uint256) (*Uint256, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	u := &Uint256{engine: e}
	u.ptr = C.luxfhe_add_u256(e.ptr, a.ptr, b.ptr)
	if u.ptr == nil {
		return nil, errors.New("uint256 addition failed")
	}
	runtime.SetFinalizer(u, (*Uint256).Free)
	return u, nil
}

// SubU256 subtracts two encrypted uint256
func (e *Engine) SubU256(a, b *Uint256) (*Uint256, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	u := &Uint256{engine: e}
	u.ptr = C.luxfhe_sub_u256(e.ptr, a.ptr, b.ptr)
	if u.ptr == nil {
		return nil, errors.New("uint256 subtraction failed")
	}
	runtime.SetFinalizer(u, (*Uint256).Free)
	return u, nil
}

// MulU256 multiplies two encrypted uint256
func (e *Engine) MulU256(bsk *BootstrapKey, a, b *Uint256) (*Uint256, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	u := &Uint256{engine: e}
	u.ptr = C.luxfhe_mul_u256(e.ptr, bsk.ptr, a.ptr, b.ptr)
	if u.ptr == nil {
		return nil, errors.New("uint256 multiplication failed")
	}
	runtime.SetFinalizer(u, (*Uint256).Free)
	return u, nil
}

// AndU256 performs bitwise AND
func (e *Engine) AndU256(a, b *Uint256) (*Uint256, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	u := &Uint256{engine: e}
	u.ptr = C.luxfhe_and_u256(e.ptr, a.ptr, b.ptr)
	if u.ptr == nil {
		return nil, errors.New("uint256 AND failed")
	}
	runtime.SetFinalizer(u, (*Uint256).Free)
	return u, nil
}

// ShlU256 shifts left
func (e *Engine) ShlU256(a *Uint256, shift uint32) (*Uint256, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	u := &Uint256{engine: e}
	u.ptr = C.luxfhe_shl_u256(e.ptr, a.ptr, C.uint32_t(shift))
	if u.ptr == nil {
		return nil, errors.New("uint256 shift left failed")
	}
	runtime.SetFinalizer(u, (*Uint256).Free)
	return u, nil
}

// =============================================================================
// EVM Execution
// =============================================================================

// EVMExecute executes an EVM opcode on encrypted operands
func (e *Engine) EVMExecute(bsk *BootstrapKey, opcode EVMOpcode, a, b *Uint256) (*Uint256, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	u := &Uint256{engine: e}
	u.ptr = C.luxfhe_evm_execute(e.ptr, bsk.ptr, C.LuxFHEEVMOpcode(opcode), a.ptr, b.ptr)
	if u.ptr == nil {
		return nil, errors.New("EVM execution failed")
	}
	runtime.SetFinalizer(u, (*Uint256).Free)
	return u, nil
}

// =============================================================================
// Cross-Chain Bridge (XCFHE - PAT-FHE-013)
// =============================================================================

// Bridge handles cross-chain re-encryption
type Bridge struct {
	ptr C.LuxFHEBridgeContext
}

// NewBridge creates a bridge context
func NewBridge(sourceChain, destChain uint64) (*Bridge, error) {
	b := &Bridge{}
	b.ptr = C.luxfhe_bridge_create(C.uint64_t(sourceChain), C.uint64_t(destChain))
	if b.ptr == nil {
		return nil, errors.New("failed to create bridge")
	}
	runtime.SetFinalizer(b, (*Bridge).Free)
	return b, nil
}

// Free releases the bridge
func (b *Bridge) Free() {
	if b.ptr != nil {
		C.luxfhe_bridge_free(b.ptr)
		b.ptr = nil
	}
}

// Reencrypt re-encrypts a ciphertext for the destination chain
func (b *Bridge) Reencrypt(ct *Ciphertext, destPubkey []byte) (*Ciphertext, error) {
	if len(destPubkey) == 0 {
		return nil, errors.New("empty destination public key")
	}
	
	newCt := &Ciphertext{engine: ct.engine}
	newCt.ptr = C.luxfhe_bridge_reencrypt(b.ptr, ct.ptr, 
		(*C.uint8_t)(unsafe.Pointer(&destPubkey[0])), C.size_t(len(destPubkey)))
	if newCt.ptr == nil {
		return nil, errors.New("re-encryption failed")
	}
	runtime.SetFinalizer(newCt, (*Ciphertext).Free)
	return newCt, nil
}

// Verify verifies a re-encryption proof
func (b *Bridge) Verify(proof []byte) bool {
	if len(proof) == 0 {
		return false
	}
	return bool(C.luxfhe_bridge_verify(b.ptr, (*C.uint8_t)(unsafe.Pointer(&proof[0])), C.size_t(len(proof))))
}

// =============================================================================
// Validator Session (VAFHE - PAT-FHE-014)
// =============================================================================

// ValidatorSession manages validator attestation and work tracking
type ValidatorSession struct {
	ptr    C.LuxFHEValidatorSession
	engine *Engine
}

// NewValidatorSession creates a validator session
func (e *Engine) NewValidatorSession(attestType AttestationType) (*ValidatorSession, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	
	vs := &ValidatorSession{engine: e}
	vs.ptr = C.luxfhe_validator_create(e.ptr, C.LuxFHEAttestationType(attestType))
	if vs.ptr == nil {
		return nil, errors.New("failed to create validator session")
	}
	runtime.SetFinalizer(vs, (*ValidatorSession).Free)
	return vs, nil
}

// Free releases the session
func (vs *ValidatorSession) Free() {
	if vs.ptr != nil {
		C.luxfhe_validator_free(vs.ptr)
		vs.ptr = nil
	}
}

// Attest submits an attestation quote
func (vs *ValidatorSession) Attest(quote []byte) bool {
	if len(quote) == 0 {
		return false
	}
	return bool(C.luxfhe_validator_attest(vs.ptr, (*C.uint8_t)(unsafe.Pointer(&quote[0])), C.size_t(len(quote))))
}

// TrustLevel returns the current trust level
func (vs *ValidatorSession) TrustLevel() TrustLevel {
	return TrustLevel(C.luxfhe_validator_trust_level(vs.ptr))
}

// RecordWork records operations and returns credits earned
func (vs *ValidatorSession) RecordWork(operations uint64) uint64 {
	return uint64(C.luxfhe_validator_record_work(vs.ptr, C.uint64_t(operations)))
}

// =============================================================================
// Performance Statistics
// =============================================================================

// Stats holds performance metrics
type Stats struct {
	NTTTimeMs        float64
	BootstrapTimeMs  float64
	KeygenTimeMs     float64
	EncryptTimeMs    float64
	DecryptTimeMs    float64
	OperationsCount  uint64
	ThroughputOpsSec float64
	MemoryUsedBytes  uint64
	GPUMemoryBytes   uint64
}

// GetStats returns performance statistics
func (e *Engine) GetStats() Stats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	cStats := C.luxfhe_get_stats(e.ptr)
	return Stats{
		NTTTimeMs:        float64(cStats.ntt_time_ms),
		BootstrapTimeMs:  float64(cStats.bootstrap_time_ms),
		KeygenTimeMs:     float64(cStats.keygen_time_ms),
		EncryptTimeMs:    float64(cStats.encrypt_time_ms),
		DecryptTimeMs:    float64(cStats.decrypt_time_ms),
		OperationsCount:  uint64(cStats.operations_count),
		ThroughputOpsSec: float64(cStats.throughput_ops_sec),
		MemoryUsedBytes:  uint64(cStats.memory_used_bytes),
		GPUMemoryBytes:   uint64(cStats.gpu_memory_used_bytes),
	}
}

// ResetStats clears the statistics
func (e *Engine) ResetStats() {
	e.mu.Lock()
	defer e.mu.Unlock()
	C.luxfhe_reset_stats(e.ptr)
}

// =============================================================================
// Serialization
// =============================================================================

// Serialize serializes a ciphertext to bytes
func (ct *Ciphertext) Serialize() ([]byte, error) {
	var size C.size_t
	data := C.luxfhe_serialize_ciphertext(ct.ptr, &size)
	if data == nil {
		return nil, errors.New("serialization failed")
	}
	defer C.luxfhe_free_bytes(data)
	return C.GoBytes(unsafe.Pointer(data), C.int(size)), nil
}

// DeserializeCiphertext deserializes a ciphertext
func (e *Engine) DeserializeCiphertext(data []byte) (*Ciphertext, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}
	
	ct := &Ciphertext{engine: e}
	ct.ptr = C.luxfhe_deserialize_ciphertext(e.ptr, (*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
	if ct.ptr == nil {
		return nil, errors.New("deserialization failed")
	}
	runtime.SetFinalizer(ct, (*Ciphertext).Free)
	return ct, nil
}

// Serialize serializes an integer to bytes
func (i *Integer) Serialize() ([]byte, error) {
	var size C.size_t
	data := C.luxfhe_serialize_integer(i.ptr, &size)
	if data == nil {
		return nil, errors.New("serialization failed")
	}
	defer C.luxfhe_free_bytes(data)
	return C.GoBytes(unsafe.Pointer(data), C.int(size)), nil
}

// DeserializeInteger deserializes an integer
func (e *Engine) DeserializeInteger(data []byte) (*Integer, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}
	
	i := &Integer{engine: e}
	i.ptr = C.luxfhe_deserialize_integer(e.ptr, (*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
	if i.ptr == nil {
		return nil, errors.New("deserialization failed")
	}
	runtime.SetFinalizer(i, (*Integer).Free)
	return i, nil
}

// =============================================================================
// Utility Functions
// =============================================================================

// Version returns the library version
func Version() string {
	return C.GoString(C.luxfhe_version())
}

// BackendType returns the active backend name
func BackendType() string {
	return C.GoString(C.luxfhe_backend_type())
}

// HasGPU returns true if GPU is available
func HasGPU() bool {
	return bool(C.luxfhe_has_gpu())
}
