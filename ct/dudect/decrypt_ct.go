// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build tfhe_decrypt_ct

// decrypt_ct.go -- cgo bridge exposing TFHE Decrypt to the C dudect
// harness in dudect_decrypt.c.
//
// DECRYPT IS THE MOST CT-CRITICAL TFHE ROUTINE. An adversary that
// submits an LWE ciphertext and observes timing channels can extract
// bits of the secret key. The Lux Go implementation routes Decrypt
// through `lattice/v7/core/rlwe` which uses libjade-quality CT field
// arithmetic.
//
// CT POPULATION:
//   Both dudect classes are VALID Decrypt invocations on
//   pre-generated valid LWE ciphertexts:
//     class A: always ciphertext_pool[0] (fixed)
//     class B: ciphertext_pool[rand % pool_size] (varying valid)
//   Both ciphertexts are valid encryptions under the same secret
//   key with different bit values + different per-call randomness.
//
// Build:
//   GOWORK=off go build -buildmode=c-shared \
//       -o libtfhe_decrypt.{so,dylib} ./decrypt_ct.go

package main

/*
#cgo arm64 CFLAGS: -include ${SRCDIR}/dudect_compat.h
#include <stdint.h>
#include <stddef.h>
*/
import "C"

import (
	"crypto/rand"
	"unsafe"

	"github.com/luxfi/fhe"
)

// Pool size -- K independent valid ciphertexts. dudect class A uses
// pool[0] uniformly; class B uses pool[rand % K].
const kDecryptValidPool = 32

var (
	dFhParams  fhe.Parameters
	dFhSecret  *fhe.SecretKey
	dFhDecrypt *fhe.Decryptor
	dFhPool    [kDecryptValidPool]*fhe.Ciphertext
)

//export tfhe_decrypt_ct_setup
//
// Initialise the long-lived fixture. Returns 0 on success.
func tfhe_decrypt_ct_setup() C.int {
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		return 1
	}
	kg := fhe.NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	enc := fhe.NewEncryptor(params, sk)
	dec := fhe.NewDecryptor(params, sk)

	for i := 0; i < kDecryptValidPool; i++ {
		var b [1]byte
		if _, err := rand.Read(b[:]); err != nil {
			return 3
		}
		ct, err := enc.EncryptSafe(b[0]&1 == 1)
		if err != nil {
			return 4
		}
		dFhPool[i] = ct
	}

	dFhParams = params
	dFhSecret = sk
	dFhDecrypt = dec
	return 0
}

//export tfhe_decrypt_ct_pool_size
func tfhe_decrypt_ct_pool_size() C.size_t {
	return C.size_t(kDecryptValidPool)
}

//export tfhe_decrypt_ct_input_size
//
// Returns the per-sample input width: 4 bytes (a big-endian uint32
// pool index, mod kDecryptValidPool).
func tfhe_decrypt_ct_input_size() C.size_t {
	return C.size_t(4)
}

//export tfhe_decrypt_ct
//
// One dudect measurement sample. `data` points to a 4-byte
// big-endian uint32 pool index. We read the index, take its mod
// against the pool size, and Decrypt the indexed ciphertext.
//
// This is CT over `data` beyond the modular reduction.
func tfhe_decrypt_ct(data *C.uint8_t) {
	if dFhDecrypt == nil {
		return
	}
	src := unsafe.Slice((*byte)(unsafe.Pointer(data)), 4)
	idx := (uint32(src[0])<<24 | uint32(src[1])<<16 | uint32(src[2])<<8 | uint32(src[3])) %
		uint32(kDecryptValidPool)
	_ = dFhDecrypt.Decrypt(dFhPool[idx])
}

func main() {}
