// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package tfhe

import (
	"github.com/luxfi/lattice/v6/core/rlwe"
)

// Encryptor encrypts boolean values into TFHE ciphertexts
type Encryptor struct {
	params    Parameters
	encryptor *rlwe.Encryptor
	scale     float64
}

// NewEncryptor creates a new encryptor from secret key
func NewEncryptor(params Parameters, sk *SecretKey) *Encryptor {
	return &Encryptor{
		params:    params,
		encryptor: rlwe.NewEncryptor(params.paramsLWE, sk.SKLWE),
		scale:     float64(params.QLWE()) / 4.0, // Encode bit as Q/4 or -Q/4
	}
}

// Encrypt encrypts a boolean value
// Note: Panics on error (should not happen with valid parameters)
func (enc *Encryptor) Encrypt(value bool) *Ciphertext {
	pt := rlwe.NewPlaintext(enc.params.paramsLWE, enc.params.paramsLWE.MaxLevel())

	q := enc.params.QLWE()
	// Encode with Q/8 scale so sums of two bits stay in distinguishable range:
	// - true  -> +Q/8 (normalized +0.5 relative to Q/4 scale)
	// - false -> -Q/8 (normalized -0.5)
	// After sum:
	// - (0,0): -Q/4 normalized to -1
	// - (0,1): 0 normalized to 0
	// - (1,1): +Q/4 normalized to +1
	if value {
		pt.Value.Coeffs[0][0] = q / 8
	} else {
		pt.Value.Coeffs[0][0] = q - (q / 8) // = -Q/8 mod Q
	}

	enc.params.paramsLWE.RingQ().NTT(pt.Value, pt.Value)

	ct := rlwe.NewCiphertext(enc.params.paramsLWE, 1, enc.params.paramsLWE.MaxLevel())
	if err := enc.encryptor.Encrypt(pt, ct); err != nil {
		panic(err) // Should not happen with valid parameters
	}

	return &Ciphertext{ct}
}

// EncryptBit is an alias for Encrypt
func (enc *Encryptor) EncryptBit(bit int) *Ciphertext {
	return enc.Encrypt(bit != 0)
}

// EncryptByte encrypts a byte as 8 ciphertexts (LSB first)
func (enc *Encryptor) EncryptByte(b byte) [8]*Ciphertext {
	var cts [8]*Ciphertext
	for i := 0; i < 8; i++ {
		cts[i] = enc.Encrypt((b>>i)&1 == 1)
	}
	return cts
}

// EncryptUint32 encrypts a uint32 as 32 ciphertexts (LSB first)
func (enc *Encryptor) EncryptUint32(v uint32) [32]*Ciphertext {
	var cts [32]*Ciphertext
	for i := 0; i < 32; i++ {
		cts[i] = enc.Encrypt((v>>i)&1 == 1)
	}
	return cts
}

// EncryptUint64 encrypts a uint64 as 64 ciphertexts (LSB first)
func (enc *Encryptor) EncryptUint64(v uint64) [64]*Ciphertext {
	var cts [64]*Ciphertext
	for i := 0; i < 64; i++ {
		cts[i] = enc.Encrypt((v>>i)&1 == 1)
	}
	return cts
}

// EncryptUint256 encrypts a 256-bit value as 256 ciphertexts (LSB first)
func (enc *Encryptor) EncryptUint256(v [4]uint64) [256]*Ciphertext {
	var cts [256]*Ciphertext
	for w := 0; w < 4; w++ {
		for i := 0; i < 64; i++ {
			cts[w*64+i] = enc.Encrypt((v[w]>>i)&1 == 1)
		}
	}
	return cts
}
