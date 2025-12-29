// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025, Lux Industries Inc
//
// CGO exports for the LuxFHE C API

package main

/*
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
*/
import "C"

import (
	"sync"
	"unsafe"

	"github.com/luxfi/tfhe"
)

// =============================================================================
// Handle Management
// =============================================================================

// handleStore maintains a thread-safe mapping of handles to Go objects
type handleStore struct {
	mu      sync.RWMutex
	handles map[uintptr]interface{}
	nextID  uintptr
}

var store = &handleStore{
	handles: make(map[uintptr]interface{}),
	nextID:  1,
}

func (s *handleStore) put(v interface{}) uintptr {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.nextID
	s.nextID++
	s.handles[id] = v
	return id
}

func (s *handleStore) get(id uintptr) (interface{}, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.handles[id]
	return v, ok
}

func (s *handleStore) delete(id uintptr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.handles, id)
}

// =============================================================================
// Internal Types
// =============================================================================

type contextWrapper struct {
	params tfhe.Parameters
	kgen   *tfhe.KeyGenerator
}

type encryptorWrapper struct {
	enc    *tfhe.Encryptor
	params tfhe.Parameters
}

type publicEncryptorWrapper struct {
	enc    *tfhe.BitwisePublicEncryptor
	params tfhe.Parameters
}

type decryptorWrapper struct {
	dec    *tfhe.Decryptor
	params tfhe.Parameters
}

type evaluatorWrapper struct {
	eval   *tfhe.Evaluator
	params tfhe.Parameters
}

// =============================================================================
// Error Codes
// =============================================================================

const (
	LUXFHE_OK                  = 0
	LUXFHE_ERR_NULL_POINTER    = -1
	LUXFHE_ERR_INVALID_PARAM   = -2
	LUXFHE_ERR_ALLOCATION      = -3
	LUXFHE_ERR_NOT_INITIALIZED = -4
	LUXFHE_ERR_KEY_NOT_SET     = -5
	LUXFHE_ERR_SERIALIZATION   = -6
	LUXFHE_ERR_DESERIALIZATION = -7
	LUXFHE_ERR_OPERATION       = -8
	LUXFHE_ERR_TYPE_MISMATCH   = -9
	LUXFHE_ERR_OUT_OF_RANGE    = -10
)

// =============================================================================
// Version Information
// =============================================================================

//export luxfhe_version
func luxfhe_version() *C.char {
	return C.CString("1.0.0")
}

//export luxfhe_version_info
func luxfhe_version_info(major *C.int, minor *C.int, patch *C.int) {
	if major != nil {
		*major = 1
	}
	if minor != nil {
		*minor = 0
	}
	if patch != nil {
		*patch = 0
	}
}

//export luxfhe_error_string
func luxfhe_error_string(err C.int) *C.char {
	messages := map[C.int]string{
		LUXFHE_OK:                  "success",
		LUXFHE_ERR_NULL_POINTER:    "null pointer",
		LUXFHE_ERR_INVALID_PARAM:   "invalid parameter",
		LUXFHE_ERR_ALLOCATION:      "allocation failed",
		LUXFHE_ERR_NOT_INITIALIZED: "not initialized",
		LUXFHE_ERR_KEY_NOT_SET:     "key not set",
		LUXFHE_ERR_SERIALIZATION:   "serialization failed",
		LUXFHE_ERR_DESERIALIZATION: "deserialization failed",
		LUXFHE_ERR_OPERATION:       "operation failed",
		LUXFHE_ERR_TYPE_MISMATCH:   "type mismatch",
		LUXFHE_ERR_OUT_OF_RANGE:    "out of range",
	}
	if msg, ok := messages[err]; ok {
		return C.CString(msg)
	}
	return C.CString("unknown error")
}

// =============================================================================
// Context Management
// =============================================================================

//export luxfhe_context_new
func luxfhe_context_new(paramSet C.int, out *uintptr) C.int {
	if out == nil {
		return LUXFHE_ERR_NULL_POINTER
	}

	var lit tfhe.ParametersLiteral
	switch paramSet {
	case 0: // LUXFHE_PARAMS_PN10QP27
		lit = tfhe.PN10QP27
	case 1: // LUXFHE_PARAMS_PN11QP54
		lit = tfhe.PN11QP54
	default:
		return LUXFHE_ERR_INVALID_PARAM
	}

	params, err := tfhe.NewParametersFromLiteral(lit)
	if err != nil {
		return LUXFHE_ERR_ALLOCATION
	}

	ctx := &contextWrapper{
		params: params,
		kgen:   tfhe.NewKeyGenerator(params),
	}

	*out = store.put(ctx)
	return LUXFHE_OK
}

//export luxfhe_context_free
func luxfhe_context_free(ctx uintptr) {
	store.delete(ctx)
}

//export luxfhe_context_params
func luxfhe_context_params(ctx uintptr, nLWE *C.int, nBR *C.int, qLWE *C.uint64_t, qBR *C.uint64_t) C.int {
	v, ok := store.get(ctx)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	ctxW := v.(*contextWrapper)

	if nLWE != nil {
		*nLWE = C.int(ctxW.params.N())
	}
	if nBR != nil {
		*nBR = C.int(ctxW.params.NBR())
	}
	if qLWE != nil {
		*qLWE = C.uint64_t(ctxW.params.QLWE())
	}
	if qBR != nil {
		*qBR = C.uint64_t(ctxW.params.QBR())
	}
	return LUXFHE_OK
}

// =============================================================================
// Key Generation
// =============================================================================

//export luxfhe_keygen_secret
func luxfhe_keygen_secret(ctx uintptr, out *uintptr) C.int {
	if out == nil {
		return LUXFHE_ERR_NULL_POINTER
	}

	v, ok := store.get(ctx)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	ctxW := v.(*contextWrapper)

	sk := ctxW.kgen.GenSecretKey()
	*out = store.put(sk)
	return LUXFHE_OK
}

//export luxfhe_keygen_public
func luxfhe_keygen_public(ctx uintptr, sk uintptr, out *uintptr) C.int {
	if out == nil {
		return LUXFHE_ERR_NULL_POINTER
	}

	ctxV, ok := store.get(ctx)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	ctxW := ctxV.(*contextWrapper)

	skV, ok := store.get(sk)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	skPtr := skV.(*tfhe.SecretKey)

	pk := ctxW.kgen.GenPublicKey(skPtr)
	*out = store.put(pk)
	return LUXFHE_OK
}

//export luxfhe_keygen_bootstrap
func luxfhe_keygen_bootstrap(ctx uintptr, sk uintptr, out *uintptr) C.int {
	if out == nil {
		return LUXFHE_ERR_NULL_POINTER
	}

	ctxV, ok := store.get(ctx)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	ctxW := ctxV.(*contextWrapper)

	skV, ok := store.get(sk)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	skPtr := skV.(*tfhe.SecretKey)

	bsk := ctxW.kgen.GenBootstrapKey(skPtr)
	*out = store.put(bsk)
	return LUXFHE_OK
}

//export luxfhe_keygen_all
func luxfhe_keygen_all(ctx uintptr, skOut *uintptr, pkOut *uintptr, bskOut *uintptr) C.int {
	if skOut == nil || pkOut == nil || bskOut == nil {
		return LUXFHE_ERR_NULL_POINTER
	}

	ctxV, ok := store.get(ctx)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	ctxW := ctxV.(*contextWrapper)

	sk, pk := ctxW.kgen.GenKeyPair()
	bsk := ctxW.kgen.GenBootstrapKey(sk)

	*skOut = store.put(sk)
	*pkOut = store.put(pk)
	*bskOut = store.put(bsk)
	return LUXFHE_OK
}

//export luxfhe_secretkey_free
func luxfhe_secretkey_free(sk uintptr) {
	store.delete(sk)
}

//export luxfhe_publickey_free
func luxfhe_publickey_free(pk uintptr) {
	store.delete(pk)
}

//export luxfhe_bootstrapkey_free
func luxfhe_bootstrapkey_free(bsk uintptr) {
	store.delete(bsk)
}

// =============================================================================
// Encryptor / Decryptor / Evaluator
// =============================================================================

//export luxfhe_encryptor_new_sk
func luxfhe_encryptor_new_sk(ctx uintptr, sk uintptr, out *uintptr) C.int {
	if out == nil {
		return LUXFHE_ERR_NULL_POINTER
	}

	ctxV, ok := store.get(ctx)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	ctxW := ctxV.(*contextWrapper)

	skV, ok := store.get(sk)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	skPtr := skV.(*tfhe.SecretKey)

	enc := tfhe.NewEncryptor(ctxW.params, skPtr)
	*out = store.put(&encryptorWrapper{enc: enc, params: ctxW.params})
	return LUXFHE_OK
}

//export luxfhe_encryptor_new_pk
func luxfhe_encryptor_new_pk(ctx uintptr, pk uintptr, out *uintptr) C.int {
	if out == nil {
		return LUXFHE_ERR_NULL_POINTER
	}

	ctxV, ok := store.get(ctx)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	ctxW := ctxV.(*contextWrapper)

	pkV, ok := store.get(pk)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	pkPtr := pkV.(*tfhe.PublicKey)

	enc := tfhe.NewBitwisePublicEncryptor(ctxW.params, pkPtr)
	*out = store.put(&publicEncryptorWrapper{enc: enc, params: ctxW.params})
	return LUXFHE_OK
}

//export luxfhe_decryptor_new
func luxfhe_decryptor_new(ctx uintptr, sk uintptr, out *uintptr) C.int {
	if out == nil {
		return LUXFHE_ERR_NULL_POINTER
	}

	ctxV, ok := store.get(ctx)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	ctxW := ctxV.(*contextWrapper)

	skV, ok := store.get(sk)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	skPtr := skV.(*tfhe.SecretKey)

	dec := tfhe.NewDecryptor(ctxW.params, skPtr)
	*out = store.put(&decryptorWrapper{dec: dec, params: ctxW.params})
	return LUXFHE_OK
}

//export luxfhe_evaluator_new
func luxfhe_evaluator_new(ctx uintptr, bsk uintptr, sk uintptr, out *uintptr) C.int {
	if out == nil {
		return LUXFHE_ERR_NULL_POINTER
	}

	ctxV, ok := store.get(ctx)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	ctxW := ctxV.(*contextWrapper)

	bskV, ok := store.get(bsk)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	bskPtr := bskV.(*tfhe.BootstrapKey)

	// NOTE: sk parameter is no longer needed - evaluator uses only public key switching
	// The sk parameter is kept in the C API for backward compatibility but ignored
	_, _ = store.get(sk) // Validate sk handle but don't use it

	eval := tfhe.NewEvaluator(ctxW.params, bskPtr)
	*out = store.put(&evaluatorWrapper{eval: eval, params: ctxW.params})
	return LUXFHE_OK
}

//export luxfhe_encryptor_free
func luxfhe_encryptor_free(enc uintptr) {
	store.delete(enc)
}

//export luxfhe_decryptor_free
func luxfhe_decryptor_free(dec uintptr) {
	store.delete(dec)
}

//export luxfhe_evaluator_free
func luxfhe_evaluator_free(eval uintptr) {
	store.delete(eval)
}

// =============================================================================
// Boolean Encryption / Decryption
// =============================================================================

//export luxfhe_encrypt_bool
func luxfhe_encrypt_bool(enc uintptr, value C.bool, out *uintptr) C.int {
	if out == nil {
		return LUXFHE_ERR_NULL_POINTER
	}

	encV, ok := store.get(enc)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}

	var ct *tfhe.Ciphertext
	switch e := encV.(type) {
	case *encryptorWrapper:
		ct = e.enc.Encrypt(bool(value))
	case *publicEncryptorWrapper:
		var err error
		ct, err = e.enc.Encrypt(bool(value))
		if err != nil {
			return LUXFHE_ERR_OPERATION
		}
	default:
		return LUXFHE_ERR_INVALID_PARAM
	}

	*out = store.put(ct)
	return LUXFHE_OK
}

//export luxfhe_decrypt_bool
func luxfhe_decrypt_bool(dec uintptr, ct uintptr, out *C.bool) C.int {
	if out == nil {
		return LUXFHE_ERR_NULL_POINTER
	}

	decV, ok := store.get(dec)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	decW := decV.(*decryptorWrapper)

	ctV, ok := store.get(ct)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	ctPtr := ctV.(*tfhe.Ciphertext)

	result := decW.dec.Decrypt(ctPtr)
	*out = C.bool(result)
	return LUXFHE_OK
}

//export luxfhe_ciphertext_free
func luxfhe_ciphertext_free(ct uintptr) {
	store.delete(ct)
}

//export luxfhe_ciphertext_clone
func luxfhe_ciphertext_clone(ct uintptr, out *uintptr) C.int {
	if out == nil {
		return LUXFHE_ERR_NULL_POINTER
	}

	ctV, ok := store.get(ct)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	ctPtr := ctV.(*tfhe.Ciphertext)

	clone := ctPtr.CopyNew()
	*out = store.put(&tfhe.Ciphertext{Ciphertext: clone})
	return LUXFHE_OK
}

// =============================================================================
// Byte Encryption / Decryption
// =============================================================================

//export luxfhe_encrypt_byte
func luxfhe_encrypt_byte(enc uintptr, value C.uint8_t, out *uintptr) C.int {
	if out == nil {
		return LUXFHE_ERR_NULL_POINTER
	}

	encV, ok := store.get(enc)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}

	var cts [8]*tfhe.Ciphertext
	switch e := encV.(type) {
	case *encryptorWrapper:
		cts = e.enc.EncryptByte(byte(value))
	case *publicEncryptorWrapper:
		// Public key encryption of byte: encrypt each bit separately
		b := byte(value)
		for i := 0; i < 8; i++ {
			bit := (b >> i) & 1
			ct, err := e.enc.Encrypt(bit == 1)
			if err != nil {
				return LUXFHE_ERR_OPERATION
			}
			cts[i] = ct
		}
	default:
		return LUXFHE_ERR_INVALID_PARAM
	}

	*out = store.put(cts)
	return LUXFHE_OK
}

//export luxfhe_decrypt_byte
func luxfhe_decrypt_byte(dec uintptr, ct uintptr, out *C.uint8_t) C.int {
	if out == nil {
		return LUXFHE_ERR_NULL_POINTER
	}

	decV, ok := store.get(dec)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	decW := decV.(*decryptorWrapper)

	ctV, ok := store.get(ct)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	cts := ctV.([8]*tfhe.Ciphertext)

	result := decW.dec.DecryptByte(cts)
	*out = C.uint8_t(result)
	return LUXFHE_OK
}

// =============================================================================
// Boolean Gates
// =============================================================================

//export luxfhe_not
func luxfhe_not(eval uintptr, ct uintptr, out *uintptr) C.int {
	if out == nil {
		return LUXFHE_ERR_NULL_POINTER
	}

	evalV, ok := store.get(eval)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	evalW := evalV.(*evaluatorWrapper)

	ctV, ok := store.get(ct)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	ctPtr := ctV.(*tfhe.Ciphertext)

	result := evalW.eval.NOT(ctPtr)
	*out = store.put(result)
	return LUXFHE_OK
}

//export luxfhe_and
func luxfhe_and(eval uintptr, ct1 uintptr, ct2 uintptr, out *uintptr) C.int {
	if out == nil {
		return LUXFHE_ERR_NULL_POINTER
	}

	evalV, ok := store.get(eval)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	evalW := evalV.(*evaluatorWrapper)

	ct1V, ok := store.get(ct1)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	ct1Ptr := ct1V.(*tfhe.Ciphertext)

	ct2V, ok := store.get(ct2)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	ct2Ptr := ct2V.(*tfhe.Ciphertext)

	result, err := evalW.eval.AND(ct1Ptr, ct2Ptr)
	if err != nil {
		return LUXFHE_ERR_OPERATION
	}
	*out = store.put(result)
	return LUXFHE_OK
}

//export luxfhe_or
func luxfhe_or(eval uintptr, ct1 uintptr, ct2 uintptr, out *uintptr) C.int {
	if out == nil {
		return LUXFHE_ERR_NULL_POINTER
	}

	evalV, ok := store.get(eval)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	evalW := evalV.(*evaluatorWrapper)

	ct1V, ok := store.get(ct1)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	ct1Ptr := ct1V.(*tfhe.Ciphertext)

	ct2V, ok := store.get(ct2)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	ct2Ptr := ct2V.(*tfhe.Ciphertext)

	result, err := evalW.eval.OR(ct1Ptr, ct2Ptr)
	if err != nil {
		return LUXFHE_ERR_OPERATION
	}
	*out = store.put(result)
	return LUXFHE_OK
}

//export luxfhe_xor
func luxfhe_xor(eval uintptr, ct1 uintptr, ct2 uintptr, out *uintptr) C.int {
	if out == nil {
		return LUXFHE_ERR_NULL_POINTER
	}

	evalV, ok := store.get(eval)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	evalW := evalV.(*evaluatorWrapper)

	ct1V, ok := store.get(ct1)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	ct1Ptr := ct1V.(*tfhe.Ciphertext)

	ct2V, ok := store.get(ct2)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	ct2Ptr := ct2V.(*tfhe.Ciphertext)

	result, err := evalW.eval.XOR(ct1Ptr, ct2Ptr)
	if err != nil {
		return LUXFHE_ERR_OPERATION
	}
	*out = store.put(result)
	return LUXFHE_OK
}

//export luxfhe_nand
func luxfhe_nand(eval uintptr, ct1 uintptr, ct2 uintptr, out *uintptr) C.int {
	if out == nil {
		return LUXFHE_ERR_NULL_POINTER
	}

	evalV, ok := store.get(eval)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	evalW := evalV.(*evaluatorWrapper)

	ct1V, ok := store.get(ct1)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	ct1Ptr := ct1V.(*tfhe.Ciphertext)

	ct2V, ok := store.get(ct2)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	ct2Ptr := ct2V.(*tfhe.Ciphertext)

	result, err := evalW.eval.NAND(ct1Ptr, ct2Ptr)
	if err != nil {
		return LUXFHE_ERR_OPERATION
	}
	*out = store.put(result)
	return LUXFHE_OK
}

//export luxfhe_nor
func luxfhe_nor(eval uintptr, ct1 uintptr, ct2 uintptr, out *uintptr) C.int {
	if out == nil {
		return LUXFHE_ERR_NULL_POINTER
	}

	evalV, ok := store.get(eval)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	evalW := evalV.(*evaluatorWrapper)

	ct1V, ok := store.get(ct1)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	ct1Ptr := ct1V.(*tfhe.Ciphertext)

	ct2V, ok := store.get(ct2)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	ct2Ptr := ct2V.(*tfhe.Ciphertext)

	result, err := evalW.eval.NOR(ct1Ptr, ct2Ptr)
	if err != nil {
		return LUXFHE_ERR_OPERATION
	}
	*out = store.put(result)
	return LUXFHE_OK
}

//export luxfhe_xnor
func luxfhe_xnor(eval uintptr, ct1 uintptr, ct2 uintptr, out *uintptr) C.int {
	if out == nil {
		return LUXFHE_ERR_NULL_POINTER
	}

	evalV, ok := store.get(eval)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	evalW := evalV.(*evaluatorWrapper)

	ct1V, ok := store.get(ct1)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	ct1Ptr := ct1V.(*tfhe.Ciphertext)

	ct2V, ok := store.get(ct2)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	ct2Ptr := ct2V.(*tfhe.Ciphertext)

	result, err := evalW.eval.XNOR(ct1Ptr, ct2Ptr)
	if err != nil {
		return LUXFHE_ERR_OPERATION
	}
	*out = store.put(result)
	return LUXFHE_OK
}

//export luxfhe_mux
func luxfhe_mux(eval uintptr, sel uintptr, ctTrue uintptr, ctFalse uintptr, out *uintptr) C.int {
	if out == nil {
		return LUXFHE_ERR_NULL_POINTER
	}

	evalV, ok := store.get(eval)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	evalW := evalV.(*evaluatorWrapper)

	selV, ok := store.get(sel)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	selPtr := selV.(*tfhe.Ciphertext)

	ctTrueV, ok := store.get(ctTrue)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	ctTruePtr := ctTrueV.(*tfhe.Ciphertext)

	ctFalseV, ok := store.get(ctFalse)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	ctFalsePtr := ctFalseV.(*tfhe.Ciphertext)

	result, err := evalW.eval.MUX(selPtr, ctTruePtr, ctFalsePtr)
	if err != nil {
		return LUXFHE_ERR_OPERATION
	}
	*out = store.put(result)
	return LUXFHE_OK
}

// =============================================================================
// Multi-Input Gates
// =============================================================================

//export luxfhe_and3
func luxfhe_and3(eval uintptr, ct1 uintptr, ct2 uintptr, ct3 uintptr, out *uintptr) C.int {
	if out == nil {
		return LUXFHE_ERR_NULL_POINTER
	}

	evalV, ok := store.get(eval)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	evalW := evalV.(*evaluatorWrapper)

	ct1V, ok := store.get(ct1)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	ct1Ptr := ct1V.(*tfhe.Ciphertext)

	ct2V, ok := store.get(ct2)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	ct2Ptr := ct2V.(*tfhe.Ciphertext)

	ct3V, ok := store.get(ct3)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	ct3Ptr := ct3V.(*tfhe.Ciphertext)

	result, err := evalW.eval.AND3(ct1Ptr, ct2Ptr, ct3Ptr)
	if err != nil {
		return LUXFHE_ERR_OPERATION
	}
	*out = store.put(result)
	return LUXFHE_OK
}

//export luxfhe_or3
func luxfhe_or3(eval uintptr, ct1 uintptr, ct2 uintptr, ct3 uintptr, out *uintptr) C.int {
	if out == nil {
		return LUXFHE_ERR_NULL_POINTER
	}

	evalV, ok := store.get(eval)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	evalW := evalV.(*evaluatorWrapper)

	ct1V, ok := store.get(ct1)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	ct1Ptr := ct1V.(*tfhe.Ciphertext)

	ct2V, ok := store.get(ct2)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	ct2Ptr := ct2V.(*tfhe.Ciphertext)

	ct3V, ok := store.get(ct3)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	ct3Ptr := ct3V.(*tfhe.Ciphertext)

	result, err := evalW.eval.OR3(ct1Ptr, ct2Ptr, ct3Ptr)
	if err != nil {
		return LUXFHE_ERR_OPERATION
	}
	*out = store.put(result)
	return LUXFHE_OK
}

//export luxfhe_majority
func luxfhe_majority(eval uintptr, ct1 uintptr, ct2 uintptr, ct3 uintptr, out *uintptr) C.int {
	if out == nil {
		return LUXFHE_ERR_NULL_POINTER
	}

	evalV, ok := store.get(eval)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	evalW := evalV.(*evaluatorWrapper)

	ct1V, ok := store.get(ct1)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	ct1Ptr := ct1V.(*tfhe.Ciphertext)

	ct2V, ok := store.get(ct2)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	ct2Ptr := ct2V.(*tfhe.Ciphertext)

	ct3V, ok := store.get(ct3)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	ct3Ptr := ct3V.(*tfhe.Ciphertext)

	result, err := evalW.eval.MAJORITY(ct1Ptr, ct2Ptr, ct3Ptr)
	if err != nil {
		return LUXFHE_ERR_OPERATION
	}
	*out = store.put(result)
	return LUXFHE_OK
}

// =============================================================================
// Serialization
// =============================================================================

//export luxfhe_bytes_free
func luxfhe_bytes_free(data *C.uint8_t) {
	if data != nil {
		C.free(unsafe.Pointer(data))
	}
}

//export luxfhe_secretkey_serialize
func luxfhe_secretkey_serialize(sk uintptr, data **C.uint8_t, length *C.size_t) C.int {
	if data == nil || length == nil {
		return LUXFHE_ERR_NULL_POINTER
	}

	skV, ok := store.get(sk)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	skPtr := skV.(*tfhe.SecretKey)

	bytes, err := skPtr.MarshalBinary()
	if err != nil {
		return LUXFHE_ERR_SERIALIZATION
	}

	*length = C.size_t(len(bytes))
	*data = (*C.uint8_t)(C.malloc(C.size_t(len(bytes))))
	if *data == nil {
		return LUXFHE_ERR_ALLOCATION
	}

	// Copy data
	for i, b := range bytes {
		*(*C.uint8_t)(unsafe.Pointer(uintptr(unsafe.Pointer(*data)) + uintptr(i))) = C.uint8_t(b)
	}

	return LUXFHE_OK
}

//export luxfhe_ciphertext_serialize
func luxfhe_ciphertext_serialize(ct uintptr, data **C.uint8_t, length *C.size_t) C.int {
	if data == nil || length == nil {
		return LUXFHE_ERR_NULL_POINTER
	}

	ctV, ok := store.get(ct)
	if !ok {
		return LUXFHE_ERR_NULL_POINTER
	}
	ctPtr := ctV.(*tfhe.Ciphertext)

	bytes, err := ctPtr.MarshalBinary()
	if err != nil {
		return LUXFHE_ERR_SERIALIZATION
	}

	*length = C.size_t(len(bytes))
	*data = (*C.uint8_t)(C.malloc(C.size_t(len(bytes))))
	if *data == nil {
		return LUXFHE_ERR_ALLOCATION
	}

	// Copy data
	for i, b := range bytes {
		*(*C.uint8_t)(unsafe.Pointer(uintptr(unsafe.Pointer(*data)) + uintptr(i))) = C.uint8_t(b)
	}

	return LUXFHE_OK
}

// Required for C shared library
func main() {}
