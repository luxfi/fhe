// Copyright (c) 2024 The Lux Authors
// Use of this source code is governed by a BSD 3-Clause
// license that can be found in the LICENSE file.

//go:build cgo

package cgo

/*
#cgo pkg-config: lux-fhe
#cgo CXXFLAGS: -std=c++17 -O3
#cgo darwin LDFLAGS: -framework Accelerate -framework Metal -framework MetalPerformanceShaders -lstdc++
#cgo linux LDFLAGS: -lstdc++
#cgo windows LDFLAGS: -lstdc++

#include "tfhe_bridge.h"
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"runtime"
	"sync"
	"unsafe"
)

// SecurityLevel represents the security strength
type SecurityLevel int

const (
	SecuritySTD128 SecurityLevel = iota
	SecuritySTD192
	SecuritySTD256
)

// Method represents the FHE method/variant
type Method int

const (
	MethodAP      Method = iota // Alperin-Sheriff-Peikert
	MethodGINX                  // GINX bootstrapping
	MethodLMKCDEY               // LMKCDEY bootstrapping
)

// Context holds OpenFHE FHE context
type Context struct {
	ptr C.TfheContext
	mu  sync.RWMutex
}

// SecretKey holds the secret key
type SecretKey struct {
	ptr C.TfheSecretKey
	ctx *Context
}

// PublicKey holds the public key
type PublicKey struct {
	ptr C.TfhePublicKey
	ctx *Context
}

// Ciphertext holds an encrypted bit
type Ciphertext struct {
	ptr C.TfheCiphertext
	ctx *Context
}

// Integer holds an encrypted integer (bit vector)
type Integer struct {
	ptr    C.TfheInteger
	ctx    *Context
	bitLen int
}

// NewContext creates a new FHE context with given security level and method
func NewContext(level SecurityLevel, method Method) (*Context, error) {
	ctx := &Context{}
	ctx.ptr = C.tfhe_context_new(C.TfheSecurityLevel(level), C.TfheMethod(method))
	if ctx.ptr == nil {
		return nil, errors.New("failed to create FHE context")
	}
	runtime.SetFinalizer(ctx, (*Context).Free)
	return ctx, nil
}

// Free releases the context resources
func (c *Context) Free() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ptr != nil {
		C.tfhe_context_free(c.ptr)
		c.ptr = nil
	}
}

// GenerateSecretKey generates a new secret key
func (c *Context) GenerateSecretKey() (*SecretKey, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil {
		return nil, errors.New("context is nil")
	}

	sk := &SecretKey{ctx: c}
	sk.ptr = C.tfhe_keygen(c.ptr)
	if sk.ptr == nil {
		return nil, errors.New("failed to generate secret key")
	}
	runtime.SetFinalizer(sk, (*SecretKey).Free)
	return sk, nil
}

// Free releases the secret key
func (sk *SecretKey) Free() {
	if sk.ptr != nil {
		C.tfhe_secret_key_free(sk.ptr)
		sk.ptr = nil
	}
}

// GenerateBootstrapKey generates the bootstrapping key (evaluation key)
func (c *Context) GenerateBootstrapKey(sk *SecretKey) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ptr == nil {
		return errors.New("context is nil")
	}
	if sk.ptr == nil {
		return errors.New("secret key is nil")
	}

	result := C.tfhe_bootstrap_keygen(c.ptr, sk.ptr)
	if result != 0 {
		return errors.New("failed to generate bootstrap key")
	}
	return nil
}

// GeneratePublicKey generates a public key from secret key
func (c *Context) GeneratePublicKey(sk *SecretKey) (*PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ptr == nil {
		return nil, errors.New("context is nil")
	}
	if sk.ptr == nil {
		return nil, errors.New("secret key is nil")
	}

	pk := &PublicKey{ctx: c}
	pk.ptr = C.tfhe_public_keygen(c.ptr, sk.ptr)
	if pk.ptr == nil {
		return nil, errors.New("failed to generate public key")
	}
	runtime.SetFinalizer(pk, (*PublicKey).Free)
	return pk, nil
}

// Free releases the public key
func (pk *PublicKey) Free() {
	if pk.ptr != nil {
		C.tfhe_public_key_free(pk.ptr)
		pk.ptr = nil
	}
}

// EncryptBit encrypts a single bit using secret key
func (c *Context) EncryptBit(sk *SecretKey, bit bool) (*Ciphertext, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || sk.ptr == nil {
		return nil, errors.New("nil context or key")
	}

	var b C.int
	if bit {
		b = 1
	}

	ct := &Ciphertext{ctx: c}
	ct.ptr = C.tfhe_encrypt_bit(c.ptr, sk.ptr, b)
	if ct.ptr == nil {
		return nil, errors.New("failed to encrypt bit")
	}
	runtime.SetFinalizer(ct, (*Ciphertext).Free)
	return ct, nil
}

// DecryptBit decrypts a single bit
func (c *Context) DecryptBit(sk *SecretKey, ct *Ciphertext) (bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || sk.ptr == nil || ct.ptr == nil {
		return false, errors.New("nil context, key, or ciphertext")
	}

	result := C.tfhe_decrypt_bit(c.ptr, sk.ptr, ct.ptr)
	return result != 0, nil
}

// EncryptBitPublic encrypts a single bit using public key
func (c *Context) EncryptBitPublic(pk *PublicKey, bit bool) (*Ciphertext, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || pk.ptr == nil {
		return nil, errors.New("nil context or public key")
	}

	var b C.int
	if bit {
		b = 1
	}

	ct := &Ciphertext{ctx: c}
	ct.ptr = C.tfhe_encrypt_bit_public(c.ptr, pk.ptr, b)
	if ct.ptr == nil {
		return nil, errors.New("failed to encrypt bit with public key")
	}
	runtime.SetFinalizer(ct, (*Ciphertext).Free)
	return ct, nil
}

// Free releases the ciphertext
func (ct *Ciphertext) Free() {
	if ct.ptr != nil {
		C.tfhe_ciphertext_free(ct.ptr)
		ct.ptr = nil
	}
}

// Clone creates a copy of the ciphertext
func (ct *Ciphertext) Clone() (*Ciphertext, error) {
	if ct.ptr == nil || ct.ctx == nil {
		return nil, errors.New("nil ciphertext")
	}

	ct.ctx.mu.RLock()
	defer ct.ctx.mu.RUnlock()

	newCt := &Ciphertext{ctx: ct.ctx}
	newCt.ptr = C.tfhe_ciphertext_clone(ct.ptr)
	if newCt.ptr == nil {
		return nil, errors.New("failed to clone ciphertext")
	}
	runtime.SetFinalizer(newCt, (*Ciphertext).Free)
	return newCt, nil
}

// Boolean Gate Operations

// And performs AND gate on two ciphertexts
func (c *Context) And(ct1, ct2 *Ciphertext) (*Ciphertext, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || ct1.ptr == nil || ct2.ptr == nil {
		return nil, errors.New("nil operand")
	}

	result := &Ciphertext{ctx: c}
	result.ptr = C.tfhe_and(c.ptr, ct1.ptr, ct2.ptr)
	if result.ptr == nil {
		return nil, errors.New("AND gate failed")
	}
	runtime.SetFinalizer(result, (*Ciphertext).Free)
	return result, nil
}

// Or performs OR gate on two ciphertexts
func (c *Context) Or(ct1, ct2 *Ciphertext) (*Ciphertext, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || ct1.ptr == nil || ct2.ptr == nil {
		return nil, errors.New("nil operand")
	}

	result := &Ciphertext{ctx: c}
	result.ptr = C.tfhe_or(c.ptr, ct1.ptr, ct2.ptr)
	if result.ptr == nil {
		return nil, errors.New("OR gate failed")
	}
	runtime.SetFinalizer(result, (*Ciphertext).Free)
	return result, nil
}

// Xor performs XOR gate on two ciphertexts
func (c *Context) Xor(ct1, ct2 *Ciphertext) (*Ciphertext, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || ct1.ptr == nil || ct2.ptr == nil {
		return nil, errors.New("nil operand")
	}

	result := &Ciphertext{ctx: c}
	result.ptr = C.tfhe_xor(c.ptr, ct1.ptr, ct2.ptr)
	if result.ptr == nil {
		return nil, errors.New("XOR gate failed")
	}
	runtime.SetFinalizer(result, (*Ciphertext).Free)
	return result, nil
}

// Not performs NOT gate on a ciphertext
func (c *Context) Not(ct *Ciphertext) (*Ciphertext, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || ct.ptr == nil {
		return nil, errors.New("nil operand")
	}

	result := &Ciphertext{ctx: c}
	result.ptr = C.tfhe_not(c.ptr, ct.ptr)
	if result.ptr == nil {
		return nil, errors.New("NOT gate failed")
	}
	runtime.SetFinalizer(result, (*Ciphertext).Free)
	return result, nil
}

// Nand performs NAND gate on two ciphertexts
func (c *Context) Nand(ct1, ct2 *Ciphertext) (*Ciphertext, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || ct1.ptr == nil || ct2.ptr == nil {
		return nil, errors.New("nil operand")
	}

	result := &Ciphertext{ctx: c}
	result.ptr = C.tfhe_nand(c.ptr, ct1.ptr, ct2.ptr)
	if result.ptr == nil {
		return nil, errors.New("NAND gate failed")
	}
	runtime.SetFinalizer(result, (*Ciphertext).Free)
	return result, nil
}

// Nor performs NOR gate on two ciphertexts
func (c *Context) Nor(ct1, ct2 *Ciphertext) (*Ciphertext, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || ct1.ptr == nil || ct2.ptr == nil {
		return nil, errors.New("nil operand")
	}

	result := &Ciphertext{ctx: c}
	result.ptr = C.tfhe_nor(c.ptr, ct1.ptr, ct2.ptr)
	if result.ptr == nil {
		return nil, errors.New("NOR gate failed")
	}
	runtime.SetFinalizer(result, (*Ciphertext).Free)
	return result, nil
}

// Xnor performs XNOR gate on two ciphertexts
func (c *Context) Xnor(ct1, ct2 *Ciphertext) (*Ciphertext, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || ct1.ptr == nil || ct2.ptr == nil {
		return nil, errors.New("nil operand")
	}

	result := &Ciphertext{ctx: c}
	result.ptr = C.tfhe_xnor(c.ptr, ct1.ptr, ct2.ptr)
	if result.ptr == nil {
		return nil, errors.New("XNOR gate failed")
	}
	runtime.SetFinalizer(result, (*Ciphertext).Free)
	return result, nil
}

// Mux performs multiplexer: if sel then ct1 else ct2
func (c *Context) Mux(sel, ct1, ct2 *Ciphertext) (*Ciphertext, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || sel.ptr == nil || ct1.ptr == nil || ct2.ptr == nil {
		return nil, errors.New("nil operand")
	}

	result := &Ciphertext{ctx: c}
	result.ptr = C.tfhe_mux(c.ptr, sel.ptr, ct1.ptr, ct2.ptr)
	if result.ptr == nil {
		return nil, errors.New("MUX gate failed")
	}
	runtime.SetFinalizer(result, (*Ciphertext).Free)
	return result, nil
}

// Integer Operations

// EncryptInteger encrypts an integer value
func (c *Context) EncryptInteger(sk *SecretKey, value int64, bitLen int) (*Integer, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || sk.ptr == nil {
		return nil, errors.New("nil context or key")
	}
	if bitLen <= 0 || bitLen > 64 {
		return nil, errors.New("invalid bit length")
	}

	result := &Integer{ctx: c, bitLen: bitLen}
	result.ptr = C.tfhe_encrypt_integer(c.ptr, sk.ptr, C.int64_t(value), C.int(bitLen))
	if result.ptr == nil {
		return nil, errors.New("failed to encrypt integer")
	}
	runtime.SetFinalizer(result, (*Integer).Free)
	return result, nil
}

// EncryptIntegerPublic encrypts an integer using public key
func (c *Context) EncryptIntegerPublic(pk *PublicKey, value int64, bitLen int) (*Integer, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || pk.ptr == nil {
		return nil, errors.New("nil context or public key")
	}
	if bitLen <= 0 || bitLen > 64 {
		return nil, errors.New("invalid bit length")
	}

	result := &Integer{ctx: c, bitLen: bitLen}
	result.ptr = C.tfhe_encrypt_integer_public(c.ptr, pk.ptr, C.int64_t(value), C.int(bitLen))
	if result.ptr == nil {
		return nil, errors.New("failed to encrypt integer with public key")
	}
	runtime.SetFinalizer(result, (*Integer).Free)
	return result, nil
}

// DecryptInteger decrypts an encrypted integer
func (c *Context) DecryptInteger(sk *SecretKey, ct *Integer) (int64, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || sk.ptr == nil || ct.ptr == nil {
		return 0, errors.New("nil context, key, or ciphertext")
	}

	return int64(C.tfhe_decrypt_integer(c.ptr, sk.ptr, ct.ptr)), nil
}

// Free releases the integer ciphertext
func (i *Integer) Free() {
	if i.ptr != nil {
		C.tfhe_integer_free(i.ptr)
		i.ptr = nil
	}
}

// Clone creates a copy of the integer
func (i *Integer) Clone() (*Integer, error) {
	if i.ptr == nil || i.ctx == nil {
		return nil, errors.New("nil integer")
	}

	i.ctx.mu.RLock()
	defer i.ctx.mu.RUnlock()

	newInt := &Integer{ctx: i.ctx, bitLen: i.bitLen}
	newInt.ptr = C.tfhe_integer_clone(i.ptr)
	if newInt.ptr == nil {
		return nil, errors.New("failed to clone integer")
	}
	runtime.SetFinalizer(newInt, (*Integer).Free)
	return newInt, nil
}

// BitLen returns the bit length of the integer
func (i *Integer) BitLen() int {
	return i.bitLen
}

// Add performs encrypted addition
func (c *Context) Add(a, b *Integer) (*Integer, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || a.ptr == nil || b.ptr == nil {
		return nil, errors.New("nil operand")
	}

	result := &Integer{ctx: c, bitLen: max(a.bitLen, b.bitLen)}
	result.ptr = C.tfhe_add(c.ptr, a.ptr, b.ptr)
	if result.ptr == nil {
		return nil, errors.New("addition failed")
	}
	runtime.SetFinalizer(result, (*Integer).Free)
	return result, nil
}

// Sub performs encrypted subtraction
func (c *Context) Sub(a, b *Integer) (*Integer, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || a.ptr == nil || b.ptr == nil {
		return nil, errors.New("nil operand")
	}

	result := &Integer{ctx: c, bitLen: max(a.bitLen, b.bitLen)}
	result.ptr = C.tfhe_sub(c.ptr, a.ptr, b.ptr)
	if result.ptr == nil {
		return nil, errors.New("subtraction failed")
	}
	runtime.SetFinalizer(result, (*Integer).Free)
	return result, nil
}

// Neg performs encrypted negation
func (c *Context) Neg(a *Integer) (*Integer, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || a.ptr == nil {
		return nil, errors.New("nil operand")
	}

	result := &Integer{ctx: c, bitLen: a.bitLen}
	result.ptr = C.tfhe_neg(c.ptr, a.ptr)
	if result.ptr == nil {
		return nil, errors.New("negation failed")
	}
	runtime.SetFinalizer(result, (*Integer).Free)
	return result, nil
}

// AddScalar adds a plaintext scalar to encrypted integer
func (c *Context) AddScalar(a *Integer, scalar int64) (*Integer, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || a.ptr == nil {
		return nil, errors.New("nil operand")
	}

	result := &Integer{ctx: c, bitLen: a.bitLen}
	result.ptr = C.tfhe_add_scalar(c.ptr, a.ptr, C.int64_t(scalar))
	if result.ptr == nil {
		return nil, errors.New("scalar addition failed")
	}
	runtime.SetFinalizer(result, (*Integer).Free)
	return result, nil
}

// SubScalar subtracts a plaintext scalar from encrypted integer
func (c *Context) SubScalar(a *Integer, scalar int64) (*Integer, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || a.ptr == nil {
		return nil, errors.New("nil operand")
	}

	result := &Integer{ctx: c, bitLen: a.bitLen}
	result.ptr = C.tfhe_sub_scalar(c.ptr, a.ptr, C.int64_t(scalar))
	if result.ptr == nil {
		return nil, errors.New("scalar subtraction failed")
	}
	runtime.SetFinalizer(result, (*Integer).Free)
	return result, nil
}

// MulScalar multiplies encrypted integer by plaintext scalar
func (c *Context) MulScalar(a *Integer, scalar int64) (*Integer, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || a.ptr == nil {
		return nil, errors.New("nil operand")
	}

	result := &Integer{ctx: c, bitLen: a.bitLen}
	result.ptr = C.tfhe_mul_scalar(c.ptr, a.ptr, C.int64_t(scalar))
	if result.ptr == nil {
		return nil, errors.New("scalar multiplication failed")
	}
	runtime.SetFinalizer(result, (*Integer).Free)
	return result, nil
}

// Comparison Operations

// Eq tests equality of two encrypted integers
func (c *Context) Eq(a, b *Integer) (*Ciphertext, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || a.ptr == nil || b.ptr == nil {
		return nil, errors.New("nil operand")
	}

	result := &Ciphertext{ctx: c}
	result.ptr = C.tfhe_eq(c.ptr, a.ptr, b.ptr)
	if result.ptr == nil {
		return nil, errors.New("equality comparison failed")
	}
	runtime.SetFinalizer(result, (*Ciphertext).Free)
	return result, nil
}

// Ne tests inequality of two encrypted integers
func (c *Context) Ne(a, b *Integer) (*Ciphertext, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || a.ptr == nil || b.ptr == nil {
		return nil, errors.New("nil operand")
	}

	result := &Ciphertext{ctx: c}
	result.ptr = C.tfhe_ne(c.ptr, a.ptr, b.ptr)
	if result.ptr == nil {
		return nil, errors.New("inequality comparison failed")
	}
	runtime.SetFinalizer(result, (*Ciphertext).Free)
	return result, nil
}

// Lt tests if a < b for encrypted integers
func (c *Context) Lt(a, b *Integer) (*Ciphertext, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || a.ptr == nil || b.ptr == nil {
		return nil, errors.New("nil operand")
	}

	result := &Ciphertext{ctx: c}
	result.ptr = C.tfhe_lt(c.ptr, a.ptr, b.ptr)
	if result.ptr == nil {
		return nil, errors.New("less-than comparison failed")
	}
	runtime.SetFinalizer(result, (*Ciphertext).Free)
	return result, nil
}

// Le tests if a <= b for encrypted integers
func (c *Context) Le(a, b *Integer) (*Ciphertext, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || a.ptr == nil || b.ptr == nil {
		return nil, errors.New("nil operand")
	}

	result := &Ciphertext{ctx: c}
	result.ptr = C.tfhe_le(c.ptr, a.ptr, b.ptr)
	if result.ptr == nil {
		return nil, errors.New("less-equal comparison failed")
	}
	runtime.SetFinalizer(result, (*Ciphertext).Free)
	return result, nil
}

// Gt tests if a > b for encrypted integers
func (c *Context) Gt(a, b *Integer) (*Ciphertext, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || a.ptr == nil || b.ptr == nil {
		return nil, errors.New("nil operand")
	}

	result := &Ciphertext{ctx: c}
	result.ptr = C.tfhe_gt(c.ptr, a.ptr, b.ptr)
	if result.ptr == nil {
		return nil, errors.New("greater-than comparison failed")
	}
	runtime.SetFinalizer(result, (*Ciphertext).Free)
	return result, nil
}

// Ge tests if a >= b for encrypted integers
func (c *Context) Ge(a, b *Integer) (*Ciphertext, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || a.ptr == nil || b.ptr == nil {
		return nil, errors.New("nil operand")
	}

	result := &Ciphertext{ctx: c}
	result.ptr = C.tfhe_ge(c.ptr, a.ptr, b.ptr)
	if result.ptr == nil {
		return nil, errors.New("greater-equal comparison failed")
	}
	runtime.SetFinalizer(result, (*Ciphertext).Free)
	return result, nil
}

// Min returns the minimum of two encrypted integers
func (c *Context) Min(a, b *Integer) (*Integer, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || a.ptr == nil || b.ptr == nil {
		return nil, errors.New("nil operand")
	}

	result := &Integer{ctx: c, bitLen: max(a.bitLen, b.bitLen)}
	result.ptr = C.tfhe_min(c.ptr, a.ptr, b.ptr)
	if result.ptr == nil {
		return nil, errors.New("min operation failed")
	}
	runtime.SetFinalizer(result, (*Integer).Free)
	return result, nil
}

// Max returns the maximum of two encrypted integers
func (c *Context) Max(a, b *Integer) (*Integer, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || a.ptr == nil || b.ptr == nil {
		return nil, errors.New("nil operand")
	}

	result := &Integer{ctx: c, bitLen: max(a.bitLen, b.bitLen)}
	result.ptr = C.tfhe_max(c.ptr, a.ptr, b.ptr)
	if result.ptr == nil {
		return nil, errors.New("max operation failed")
	}
	runtime.SetFinalizer(result, (*Integer).Free)
	return result, nil
}

// Bitwise Operations on Integers

// BitwiseAnd performs bitwise AND on encrypted integers
func (c *Context) BitwiseAnd(a, b *Integer) (*Integer, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || a.ptr == nil || b.ptr == nil {
		return nil, errors.New("nil operand")
	}

	result := &Integer{ctx: c, bitLen: max(a.bitLen, b.bitLen)}
	result.ptr = C.tfhe_bitwise_and(c.ptr, a.ptr, b.ptr)
	if result.ptr == nil {
		return nil, errors.New("bitwise AND failed")
	}
	runtime.SetFinalizer(result, (*Integer).Free)
	return result, nil
}

// BitwiseOr performs bitwise OR on encrypted integers
func (c *Context) BitwiseOr(a, b *Integer) (*Integer, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || a.ptr == nil || b.ptr == nil {
		return nil, errors.New("nil operand")
	}

	result := &Integer{ctx: c, bitLen: max(a.bitLen, b.bitLen)}
	result.ptr = C.tfhe_bitwise_or(c.ptr, a.ptr, b.ptr)
	if result.ptr == nil {
		return nil, errors.New("bitwise OR failed")
	}
	runtime.SetFinalizer(result, (*Integer).Free)
	return result, nil
}

// BitwiseXor performs bitwise XOR on encrypted integers
func (c *Context) BitwiseXor(a, b *Integer) (*Integer, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || a.ptr == nil || b.ptr == nil {
		return nil, errors.New("nil operand")
	}

	result := &Integer{ctx: c, bitLen: max(a.bitLen, b.bitLen)}
	result.ptr = C.tfhe_bitwise_xor(c.ptr, a.ptr, b.ptr)
	if result.ptr == nil {
		return nil, errors.New("bitwise XOR failed")
	}
	runtime.SetFinalizer(result, (*Integer).Free)
	return result, nil
}

// BitwiseNot performs bitwise NOT on encrypted integer
func (c *Context) BitwiseNot(a *Integer) (*Integer, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || a.ptr == nil {
		return nil, errors.New("nil operand")
	}

	result := &Integer{ctx: c, bitLen: a.bitLen}
	result.ptr = C.tfhe_bitwise_not(c.ptr, a.ptr)
	if result.ptr == nil {
		return nil, errors.New("bitwise NOT failed")
	}
	runtime.SetFinalizer(result, (*Integer).Free)
	return result, nil
}

// Shl shifts encrypted integer left by given amount
func (c *Context) Shl(a *Integer, shift uint) (*Integer, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || a.ptr == nil {
		return nil, errors.New("nil operand")
	}

	result := &Integer{ctx: c, bitLen: a.bitLen}
	result.ptr = C.tfhe_shl(c.ptr, a.ptr, C.int(shift))
	if result.ptr == nil {
		return nil, errors.New("left shift failed")
	}
	runtime.SetFinalizer(result, (*Integer).Free)
	return result, nil
}

// Shr shifts encrypted integer right by given amount
func (c *Context) Shr(a *Integer, shift uint) (*Integer, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || a.ptr == nil {
		return nil, errors.New("nil operand")
	}

	result := &Integer{ctx: c, bitLen: a.bitLen}
	result.ptr = C.tfhe_shr(c.ptr, a.ptr, C.int(shift))
	if result.ptr == nil {
		return nil, errors.New("right shift failed")
	}
	runtime.SetFinalizer(result, (*Integer).Free)
	return result, nil
}

// Control Flow

// Select chooses between two values based on encrypted condition
func (c *Context) Select(cond *Ciphertext, ifTrue, ifFalse *Integer) (*Integer, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || cond.ptr == nil || ifTrue.ptr == nil || ifFalse.ptr == nil {
		return nil, errors.New("nil operand")
	}

	result := &Integer{ctx: c, bitLen: max(ifTrue.bitLen, ifFalse.bitLen)}
	result.ptr = C.tfhe_select(c.ptr, cond.ptr, ifTrue.ptr, ifFalse.ptr)
	if result.ptr == nil {
		return nil, errors.New("select operation failed")
	}
	runtime.SetFinalizer(result, (*Integer).Free)
	return result, nil
}

// CastTo changes the bit width of an encrypted integer
func (c *Context) CastTo(a *Integer, newBitLen int) (*Integer, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || a.ptr == nil {
		return nil, errors.New("nil operand")
	}
	if newBitLen <= 0 || newBitLen > 64 {
		return nil, errors.New("invalid bit length")
	}

	result := &Integer{ctx: c, bitLen: newBitLen}
	result.ptr = C.tfhe_cast_to(c.ptr, a.ptr, C.int(newBitLen))
	if result.ptr == nil {
		return nil, errors.New("cast operation failed")
	}
	runtime.SetFinalizer(result, (*Integer).Free)
	return result, nil
}

// Serialization

// SerializeCiphertext serializes a ciphertext to bytes
func (c *Context) SerializeCiphertext(ct *Ciphertext) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || ct.ptr == nil {
		return nil, errors.New("nil ciphertext")
	}

	var size C.size_t
	data := C.tfhe_serialize_ciphertext(c.ptr, ct.ptr, &size)
	if data == nil {
		return nil, errors.New("serialization failed")
	}
	defer C.free(unsafe.Pointer(data))

	return C.GoBytes(unsafe.Pointer(data), C.int(size)), nil
}

// DeserializeCiphertext deserializes a ciphertext from bytes
func (c *Context) DeserializeCiphertext(data []byte) (*Ciphertext, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || len(data) == 0 {
		return nil, errors.New("nil context or empty data")
	}

	result := &Ciphertext{ctx: c}
	result.ptr = C.tfhe_deserialize_ciphertext(c.ptr, (*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
	if result.ptr == nil {
		return nil, errors.New("deserialization failed")
	}
	runtime.SetFinalizer(result, (*Ciphertext).Free)
	return result, nil
}

// SerializeInteger serializes an encrypted integer to bytes
func (c *Context) SerializeInteger(ct *Integer) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || ct.ptr == nil {
		return nil, errors.New("nil integer")
	}

	var size C.size_t
	data := C.tfhe_serialize_integer(c.ptr, ct.ptr, &size)
	if data == nil {
		return nil, errors.New("serialization failed")
	}
	defer C.free(unsafe.Pointer(data))

	return C.GoBytes(unsafe.Pointer(data), C.int(size)), nil
}

// DeserializeInteger deserializes an encrypted integer from bytes
func (c *Context) DeserializeInteger(data []byte, bitLen int) (*Integer, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || len(data) == 0 {
		return nil, errors.New("nil context or empty data")
	}

	result := &Integer{ctx: c, bitLen: bitLen}
	result.ptr = C.tfhe_deserialize_integer(c.ptr, (*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
	if result.ptr == nil {
		return nil, errors.New("deserialization failed")
	}
	runtime.SetFinalizer(result, (*Integer).Free)
	return result, nil
}

// SerializeSecretKey serializes the secret key to bytes
func (c *Context) SerializeSecretKey(sk *SecretKey) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || sk.ptr == nil {
		return nil, errors.New("nil secret key")
	}

	var size C.size_t
	data := C.tfhe_serialize_secret_key(c.ptr, sk.ptr, &size)
	if data == nil {
		return nil, errors.New("serialization failed")
	}
	defer C.free(unsafe.Pointer(data))

	return C.GoBytes(unsafe.Pointer(data), C.int(size)), nil
}

// DeserializeSecretKey deserializes a secret key from bytes
func (c *Context) DeserializeSecretKey(data []byte) (*SecretKey, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || len(data) == 0 {
		return nil, errors.New("nil context or empty data")
	}

	result := &SecretKey{ctx: c}
	result.ptr = C.tfhe_deserialize_secret_key(c.ptr, (*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
	if result.ptr == nil {
		return nil, errors.New("deserialization failed")
	}
	runtime.SetFinalizer(result, (*SecretKey).Free)
	return result, nil
}

// SerializePublicKey serializes the public key to bytes
func (c *Context) SerializePublicKey(pk *PublicKey) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || pk.ptr == nil {
		return nil, errors.New("nil public key")
	}

	var size C.size_t
	data := C.tfhe_serialize_public_key(c.ptr, pk.ptr, &size)
	if data == nil {
		return nil, errors.New("serialization failed")
	}
	defer C.free(unsafe.Pointer(data))

	return C.GoBytes(unsafe.Pointer(data), C.int(size)), nil
}

// DeserializePublicKey deserializes a public key from bytes
func (c *Context) DeserializePublicKey(data []byte) (*PublicKey, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ptr == nil || len(data) == 0 {
		return nil, errors.New("nil context or empty data")
	}

	result := &PublicKey{ctx: c}
	result.ptr = C.tfhe_deserialize_public_key(c.ptr, (*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
	if result.ptr == nil {
		return nil, errors.New("deserialization failed")
	}
	runtime.SetFinalizer(result, (*PublicKey).Free)
	return result, nil
}

// Helper function
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
