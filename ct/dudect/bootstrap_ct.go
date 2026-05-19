// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build tfhe_bootstrap_ct

// bootstrap_ct.go -- cgo bridge exposing TFHE PBS to the C dudect
// harness in dudect_bootstrap.c.
//
// CT POPULATION:
//   Both dudect classes are VALID Bootstrap invocations on
//   pre-generated valid LWE ciphertexts encoding different secret
//   bits:
//     class A: always ciphertext_pool[0] (fixed)
//     class B: ciphertext_pool[rand % pool_size] (varying valid)
//
// The bootstrap operation is the heaviest TFHE primitive (~50-80 ms
// per call on M2 Pro for the NTT-fused fast path). Each dudect
// sample re-runs the full PBS; the harness defaults are smaller
// than for verify/decrypt (5000 samples/batch x 100 batches).
//
// Build:
//   GOWORK=off go build -buildmode=c-shared \
//       -o libtfhe_bootstrap.{so,dylib} ./bootstrap_ct.go

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

const kBootstrapValidPool = 16

var (
	bFhParams fhe.Parameters
	bFhSecret *fhe.SecretKey
	bFhEval   *fhe.Evaluator
	bFhBSK    *fhe.BootstrapKey
	bFhPool   [kBootstrapValidPool]*fhe.Ciphertext
)

//export tfhe_bootstrap_ct_setup
//
// Initialise the long-lived fixture. Returns 0 on success.
func tfhe_bootstrap_ct_setup() C.int {
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		return 1
	}
	kg := fhe.NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)
	enc := fhe.NewEncryptor(params, sk)

	for i := 0; i < kBootstrapValidPool; i++ {
		var b [1]byte
		if _, err := rand.Read(b[:]); err != nil {
			return 4
		}
		ct, err := enc.EncryptSafe(b[0]&1 == 1)
		if err != nil {
			return 5
		}
		bFhPool[i] = ct
	}

	bFhParams = params
	bFhSecret = sk
	bFhBSK = bsk
	bFhEval = fhe.NewEvaluator(params, bsk)
	return 0
}

//export tfhe_bootstrap_ct_pool_size
func tfhe_bootstrap_ct_pool_size() C.size_t {
	return C.size_t(kBootstrapValidPool)
}

//export tfhe_bootstrap_ct_input_size
func tfhe_bootstrap_ct_input_size() C.size_t {
	return C.size_t(4)
}

//export tfhe_bootstrap_ct
//
// One dudect measurement sample. data points to a 4-byte big-endian
// uint32 pool index. We read the index, mod it against the pool
// size, and PBS the indexed ciphertext through the NAND LUT (most
// CT-uniform choice).
func tfhe_bootstrap_ct(data *C.uint8_t) {
	if bFhEval == nil {
		return
	}
	src := unsafe.Slice((*byte)(unsafe.Pointer(data)), 4)
	idx := (uint32(src[0])<<24 | uint32(src[1])<<16 | uint32(src[2])<<8 | uint32(src[3])) %
		uint32(kBootstrapValidPool)
	// NAND exercises the PBS pipeline with a deterministic LUT.
	_, _ = bFhEval.NAND(bFhPool[idx], bFhPool[idx])
}

func main() {}
