// Package tfhe implements the TFHE (Threshold Fully Homomorphic Encryption) scheme
// for boolean circuit evaluation on encrypted data.
//
// TFHE enables computation on encrypted bits with bootstrapping after each gate,
// making it ideal for arbitrary boolean circuits including EVM execution.
//
// This implementation is built on luxfi/lattice primitives:
//   - LWE encryption for bits
//   - RGSW for bootstrap keys
//   - Blind rotations for programmable bootstrapping
//
// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause
package tfhe

import (
	"github.com/luxfi/lattice/v6/core/rgsw/blindrot"
	"github.com/luxfi/lattice/v6/core/rlwe"
	"github.com/luxfi/lattice/v6/ring"
	"github.com/luxfi/lattice/v6/utils"
)

// Parameters defines the TFHE parameter set
type Parameters struct {
	// paramsLWE defines parameters for LWE samples (encrypted bits)
	paramsLWE rlwe.Parameters
	// paramsBR defines parameters for blind rotation (bootstrapping)
	paramsBR rlwe.Parameters
	// evkParams defines evaluation key decomposition
	evkParams rlwe.EvaluationKeyParameters
}

// ParametersLiteral is a user-friendly parameter specification
type ParametersLiteral struct {
	// LogNLWE is log2 of the LWE dimension (typically 9-10)
	LogNLWE int
	// LogNBR is log2 of the blind rotation dimension (typically 10-11)
	LogNBR int
	// QLWE is the LWE modulus
	QLWE uint64
	// QBR is the blind rotation modulus
	QBR uint64
	// BaseTwoDecomposition for key switching (typically 7-10)
	BaseTwoDecomposition int
}

// Standard parameter sets
var (
	// PN10QP27 provides ~128-bit security with good performance
	// LWE: N=512, Q=12289
	// BR:  N=1024, Q=134217729
	PN10QP27 = ParametersLiteral{
		LogNLWE:              9,
		LogNBR:               10,
		QLWE:                 0x3001,    // 12289
		QBR:                  0x7fff801, // ~134M
		BaseTwoDecomposition: 7,
	}

	// PN11QP54 provides ~128-bit security with higher precision
	// LWE: N=1024, Q=65537
	// BR:  N=2048, Q=~2^54
	PN11QP54 = ParametersLiteral{
		LogNLWE:              10,
		LogNBR:               11,
		QLWE:                 0x10001,           // 65537
		QBR:                  0x3FFFFFFFFFC0001, // ~2^54
		BaseTwoDecomposition: 10,
	}
)

// NewParametersFromLiteral creates Parameters from a literal specification
func NewParametersFromLiteral(lit ParametersLiteral) (params Parameters, err error) {
	params.paramsLWE, err = rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
		LogN:    lit.LogNLWE,
		Q:       []uint64{lit.QLWE},
		NTTFlag: true,
	})
	if err != nil {
		return
	}

	params.paramsBR, err = rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
		LogN:    lit.LogNBR,
		Q:       []uint64{lit.QBR},
		NTTFlag: true,
	})
	if err != nil {
		return
	}

	params.evkParams = rlwe.EvaluationKeyParameters{
		BaseTwoDecomposition: utils.Pointy(lit.BaseTwoDecomposition),
	}

	return
}

// N returns the LWE dimension
func (p Parameters) N() int {
	return p.paramsLWE.N()
}

// NBR returns the blind rotation dimension
func (p Parameters) NBR() int {
	return p.paramsBR.N()
}

// QLWE returns the LWE modulus
func (p Parameters) QLWE() uint64 {
	return p.paramsLWE.Q()[0]
}

// QBR returns the blind rotation modulus
func (p Parameters) QBR() uint64 {
	return p.paramsBR.Q()[0]
}

// SecretKey contains the LWE and RLWE secret keys
type SecretKey struct {
	// LWE secret key for encrypting bits
	SKLWE *rlwe.SecretKey
	// RLWE secret key for blind rotation results
	SKBR *rlwe.SecretKey
}

// PublicKey contains the LWE public key for encryption
// This allows users to encrypt data without having the secret key
type PublicKey struct {
	// PKLWE is the LWE public key for encrypting bits
	PKLWE *rlwe.PublicKey
}

// BootstrapKey contains the keys needed for bootstrapping
type BootstrapKey struct {
	// BRK is the blind rotation key (RGSW encryptions of LWE secret key bits)
	BRK blindrot.BlindRotationEvaluationKeySet
	// KSK is the key switching key from SKBR to SKLWE
	// This enables sample extraction without decryption
	KSK *rlwe.EvaluationKey
	// TestPolyAND is the test polynomial for AND gate
	TestPolyAND *ring.Poly
	// TestPolyOR is the test polynomial for OR gate
	TestPolyOR *ring.Poly
	// TestPolyXOR is the test polynomial for XOR gate
	TestPolyXOR *ring.Poly
	// TestPolyNAND is the test polynomial for NAND gate
	TestPolyNAND *ring.Poly
	// TestPolyNOR is the test polynomial for NOR gate
	TestPolyNOR *ring.Poly
	// TestPolyXNOR is the test polynomial for XNOR gate
	TestPolyXNOR *ring.Poly
	// TestPolyID is the test polynomial for identity (refresh/NOT)
	TestPolyID *ring.Poly
	// TestPolyMAJORITY is the test polynomial for majority vote (2 of 3)
	TestPolyMAJORITY *ring.Poly
	// Parameters
	params Parameters
}

// Ciphertext represents an encrypted bit
type Ciphertext struct {
	*rlwe.Ciphertext
}

// KeyGenerator generates TFHE keys
type KeyGenerator struct {
	params  Parameters
	kgenLWE *rlwe.KeyGenerator
	kgenBR  *rlwe.KeyGenerator
	ringQBR *ring.Ring
	scaleBR float64
}

// NewKeyGenerator creates a new key generator
func NewKeyGenerator(params Parameters) *KeyGenerator {
	return &KeyGenerator{
		params:  params,
		kgenLWE: rlwe.NewKeyGenerator(params.paramsLWE),
		kgenBR:  rlwe.NewKeyGenerator(params.paramsBR),
		ringQBR: params.paramsBR.RingQ(),
		scaleBR: float64(params.QBR()) / 8.0, // Scale for [-1, 1] -> [-Q/8, Q/8]
	}
}

// GenSecretKey generates a new secret key pair
func (kg *KeyGenerator) GenSecretKey() *SecretKey {
	return &SecretKey{
		SKLWE: kg.kgenLWE.GenSecretKeyNew(),
		SKBR:  kg.kgenBR.GenSecretKeyNew(),
	}
}

// GenPublicKey generates a public key from a secret key
// The public key can be shared with users to allow them to encrypt data
// without having access to the secret key
func (kg *KeyGenerator) GenPublicKey(sk *SecretKey) *PublicKey {
	return &PublicKey{
		PKLWE: kg.kgenLWE.GenPublicKeyNew(sk.SKLWE),
	}
}

// GenKeyPair generates both a secret key and corresponding public key
func (kg *KeyGenerator) GenKeyPair() (*SecretKey, *PublicKey) {
	sk := kg.GenSecretKey()
	pk := kg.GenPublicKey(sk)
	return sk, pk
}

// GenBootstrapKey generates the bootstrap key from secret keys
func (kg *KeyGenerator) GenBootstrapKey(sk *SecretKey) *BootstrapKey {
	// Generate blind rotation key
	brk := blindrot.GenEvaluationKeyNew(kg.params.paramsBR, sk.SKBR, kg.params.paramsLWE, sk.SKLWE, kg.params.evkParams)

	// Generate key switching key from SKBR to SKLWE
	// This key switches from the extraction key (SKBR coefficients treated as LWE key)
	// to the LWE secret key (SKLWE).
	//
	// The extraction key for sample extraction from RLWE(N_BR) is the polynomial
	// secret key SKBR, where decryption becomes:
	//   m[0] = c0[0] + <extraction_vector, c1_coeffs>
	// where extraction_vector is derived from SKBR coefficients.
	//
	// For simplicity and to work with the lattice library, we generate a key switching
	// key that operates in the BR dimension and switches to an SKLWE-compatible key.
	ksk := kg.kgenBR.GenEvaluationKeyNew(sk.SKBR, kg.createExtendedSKLWE(sk.SKLWE), kg.params.evkParams)

	// Scale for test polynomials
	scale := rlwe.NewScale(kg.scaleBR)

	// Test polynomials for TFHE gates
	// With Q/8 encoding, after adding two bits the normalized positions are:
	// - true+true:   highest x (> 0.25)
	// - true+false:  middle x (∈ [-0.25, 0.25])
	// - false+false: lowest x (< -0.25)

	// AND: output 1 only when both inputs are 1 (x > 0.25)
	testPolyAND := blindrot.InitTestPolynomial(func(x float64) float64 {
		if x > 0.25 {
			return 1.0
		}
		return -1.0
	}, scale, kg.ringQBR, -1, 1)

	// OR: output 1 when at least one input is 1 (x > -0.25)
	testPolyOR := blindrot.InitTestPolynomial(func(x float64) float64 {
		if x > -0.25 {
			return 1.0
		}
		return -1.0
	}, scale, kg.ringQBR, -1, 1)

	// XOR: output 1 when exactly one input is 1
	// With 2*(ct1+ct2) pre-processing (matching OpenFHE):
	// - (F,F): 2*(-0.25) = -0.5
	// - (T,F) or (F,T): 2*(0) = 0
	// - (T,T): 2*(0.25) = 0.5 → wraps to -0.5
	// So XOR = TRUE only when x ≈ 0
	testPolyXOR := blindrot.InitTestPolynomial(func(x float64) float64 {
		if x > -0.25 && x < 0.25 {
			return 1.0
		}
		return -1.0
	}, scale, kg.ringQBR, -1, 1)

	// NAND: output 0 only when both inputs are 1
	testPolyNAND := blindrot.InitTestPolynomial(func(x float64) float64 {
		if x > 0.25 {
			return -1.0
		}
		return 1.0
	}, scale, kg.ringQBR, -1, 1)

	// NOR: output 1 only when both inputs are 0 (x < -0.25)
	testPolyNOR := blindrot.InitTestPolynomial(func(x float64) float64 {
		if x > -0.25 {
			return -1.0
		}
		return 1.0
	}, scale, kg.ringQBR, -1, 1)

	// XNOR: output 1 when both inputs same (NOT of XOR)
	// With 2*(ct1+ct2) pre-processing:
	// - (F,F): -0.5 → TRUE
	// - (T,F) or (F,T): 0 → FALSE
	// - (T,T): -0.5 (wrapped) → TRUE
	testPolyXNOR := blindrot.InitTestPolynomial(func(x float64) float64 {
		if x > -0.25 && x < 0.25 {
			return -1.0
		}
		return 1.0
	}, scale, kg.ringQBR, -1, 1)

	// Identity (for refresh): preserve input bit (TRUE for high values)
	testPolyID := blindrot.InitTestPolynomial(func(x float64) float64 {
		if x >= 0 {
			return 1.0
		}
		return -1.0
	}, scale, kg.ringQBR, -1, 1)

	// ========== Multi-Input Gates ==========
	// MAJORITY: output 1 when at least 2 of 3 inputs are 1
	// For 3 inputs with Q/8 encoding, sum ranges from -3Q/8 to +3Q/8:
	// - 0 true: -3/8 = -0.375 → FALSE
	// - 1 true: -1/8 = -0.125 → FALSE
	// - 2 true: +1/8 = +0.125 → TRUE
	// - 3 true: +3/8 = +0.375 → TRUE
	// Threshold at 0 correctly separates these cases
	testPolyMAJORITY := blindrot.InitTestPolynomial(func(x float64) float64 {
		if x > 0 {
			return 1.0
		}
		return -1.0
	}, scale, kg.ringQBR, -1, 1)

	// Note: AND3 and OR3 use composition (2 bootstraps) rather than
	// single-bootstrap with gate constants. Single-bootstrap versions
	// would require OpenFHE-style gate constant offsets.

	return &BootstrapKey{
		BRK:              brk,
		KSK:              ksk,
		TestPolyAND:      &testPolyAND,
		TestPolyOR:       &testPolyOR,
		TestPolyXOR:      &testPolyXOR,
		TestPolyNAND:     &testPolyNAND,
		TestPolyNOR:      &testPolyNOR,
		TestPolyXNOR:     &testPolyXNOR,
		TestPolyID:       &testPolyID,
		TestPolyMAJORITY: &testPolyMAJORITY,
		params:           kg.params,
	}
}

// createExtendedSKLWE creates a secret key in the BR dimension that is compatible
// with SKLWE for key switching purposes. The extended key has SKLWE coefficients
// in the first N_LWE positions and zeros elsewhere.
func (kg *KeyGenerator) createExtendedSKLWE(sklwe *rlwe.SecretKey) *rlwe.SecretKey {
	// Create a new secret key in BR parameters
	extendedSK := rlwe.NewSecretKey(kg.params.paramsBR)

	// Get the polynomial rings
	ringQLWE := kg.params.paramsLWE.RingQ()
	ringQBR := kg.params.paramsBR.RingQ()

	// Convert SKLWE from NTT to coefficient form to copy coefficients
	sklweCoeffs := ringQLWE.NewPoly()
	sklweCoeffs.CopyLvl(ringQLWE.Level(), sklwe.Value.Q)
	ringQLWE.INTT(sklweCoeffs, sklweCoeffs)

	// The extended secret key in BR dimension
	// For sample extraction compatibility, we embed the LWE key as:
	// s_ext[i] = s_lwe[i] for i < N_LWE, s_ext[i] = 0 for i >= N_LWE
	extCoeffs := ringQBR.NewPoly()
	nLWE := ringQLWE.N()
	for i := 0; i < nLWE; i++ {
		extCoeffs.Coeffs[0][i] = sklweCoeffs.Coeffs[0][i]
	}

	// Convert to NTT form (required by lattice library)
	ringQBR.NTT(extCoeffs, extendedSK.Value.Q)
	ringQBR.MForm(extendedSK.Value.Q, extendedSK.Value.Q)

	return extendedSK
}
