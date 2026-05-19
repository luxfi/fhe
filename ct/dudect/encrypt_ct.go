// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build tfhe_encrypt_ct

// encrypt_ct.go -- cgo bridge exposing TFHE Encrypt to the C dudect
// harness in dudect_encrypt.c.
//
// CT POPULATION (operational framing):
//   Both dudect classes are VALID Encrypt invocations differing in
//   the secret bit being encrypted:
//     class A: always encrypt(false)
//     class B: encrypt(random bit)
//   Any timing difference between classes is a real bit-dependent
//   timing in the Encrypt pipeline.
//
// The fixture uses Lux's default parameter set PN10QP27 with a
// freshly-generated secret key. Each dudect sample re-invokes
// Encrypt; the leakage profile is the per-call wall-clock + cycle
// counter as collected by dudect's measurement loop.
//
// Build (Linux):
//   GOWORK=off go build -buildmode=c-shared \
//       -o libtfhe_encrypt.so ./encrypt_ct.go
// Build (macOS):
//   GOWORK=off go build -buildmode=c-shared \
//       -o libtfhe_encrypt.dylib ./encrypt_ct.go

package main

/*
#cgo arm64 CFLAGS: -include ${SRCDIR}/dudect_compat.h
#include <stdint.h>
#include <stddef.h>
*/
import "C"

import (
	"unsafe"

	"github.com/luxfi/fhe"
)

// Long-lived fixture.
var (
	fhParams  fhe.Parameters
	fhSecret  *fhe.SecretKey
	fhEncrypt *fhe.Encryptor
)

//export tfhe_encrypt_ct_setup
//
// Initialise the long-lived fixture. Returns 0 on success.
func tfhe_encrypt_ct_setup() C.int {
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		return 1
	}
	kg := fhe.NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	fhParams = params
	fhSecret = sk
	fhEncrypt = fhe.NewEncryptor(params, sk)
	return 0
}

//export tfhe_encrypt_ct_input_size
//
// Returns the per-sample input width: 1 byte (the bit to encrypt,
// where any non-zero value is `true`).
func tfhe_encrypt_ct_input_size() C.size_t {
	return C.size_t(1)
}

//export tfhe_encrypt_ct
//
// One dudect measurement sample. `data` points to a 1-byte input.
// data[0] = 0 => encrypt(false); data[0] != 0 => encrypt(true).
//
// This call must NOT branch on the input bit beyond the conversion
// from byte to bool.
func tfhe_encrypt_ct(data *C.uint8_t) {
	if fhEncrypt == nil {
		return
	}
	src := unsafe.Slice((*byte)(unsafe.Pointer(data)), 1)
	bit := src[0] != 0
	_, _ = fhEncrypt.EncryptSafe(bit)
}

func main() {}
