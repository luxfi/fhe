// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package tfhe

import (
	"github.com/luxfi/lattice/v6/core/rlwe"
	"github.com/luxfi/lattice/v6/ring"
)

// Decryptor decrypts TFHE ciphertexts to boolean values
type Decryptor struct {
	params    Parameters
	decryptor *rlwe.Decryptor
	ringQ     *ring.Ring
}

// NewDecryptor creates a new decryptor from secret key
func NewDecryptor(params Parameters, sk *SecretKey) *Decryptor {
	return &Decryptor{
		params:    params,
		decryptor: rlwe.NewDecryptor(params.paramsLWE, sk.SKLWE),
		ringQ:     params.paramsLWE.RingQ(),
	}
}

// Decrypt decrypts a ciphertext to a boolean
func (dec *Decryptor) Decrypt(ct *Ciphertext) bool {
	pt := rlwe.NewPlaintext(dec.params.paramsLWE, ct.Level())
	dec.decryptor.Decrypt(ct.Ciphertext, pt)

	if pt.IsNTT {
		dec.ringQ.INTT(pt.Value, pt.Value)
	}

	// Get the constant term
	c := pt.Value.Coeffs[0][0]
	q := dec.params.QLWE()
	qHalf := q >> 1

	// Decode:
	// - true was encoded as Q/8, so c ∈ [0, Q/2) means true
	// - false was encoded as 7Q/8, so c ∈ [Q/2, Q) means false
	return c < qHalf
}

// DecryptBit returns the decrypted bit as int (0 or 1)
func (dec *Decryptor) DecryptBit(ct *Ciphertext) int {
	if dec.Decrypt(ct) {
		return 1
	}
	return 0
}

// DecryptByte decrypts 8 ciphertexts to a byte
func (dec *Decryptor) DecryptByte(cts [8]*Ciphertext) byte {
	var b byte
	for i := 0; i < 8; i++ {
		if dec.Decrypt(cts[i]) {
			b |= 1 << i
		}
	}
	return b
}

// DecryptUint32 decrypts 32 ciphertexts to uint32
func (dec *Decryptor) DecryptUint32(cts [32]*Ciphertext) uint32 {
	var v uint32
	for i := 0; i < 32; i++ {
		if dec.Decrypt(cts[i]) {
			v |= 1 << i
		}
	}
	return v
}

// DecryptUint64 decrypts 64 ciphertexts to uint64
func (dec *Decryptor) DecryptUint64(cts [64]*Ciphertext) uint64 {
	var v uint64
	for i := 0; i < 64; i++ {
		if dec.Decrypt(cts[i]) {
			v |= 1 << i
		}
	}
	return v
}

// DecryptUint256 decrypts 256 ciphertexts to 4 uint64s
func (dec *Decryptor) DecryptUint256(cts [256]*Ciphertext) [4]uint64 {
	var v [4]uint64
	for w := 0; w < 4; w++ {
		for i := 0; i < 64; i++ {
			if dec.Decrypt(cts[w*64+i]) {
				v[w] |= 1 << i
			}
		}
	}
	return v
}
