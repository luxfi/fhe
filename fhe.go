// Package fhe implements the FHE (Threshold Fully Homomorphic Encryption) scheme
// for boolean circuit evaluation on encrypted data.
//
// FHE enables computation on encrypted bits with bootstrapping after each gate,
// making it ideal for arbitrary boolean circuits including EVM execution.
//
// This implementation is built on luxfi/lattice primitives:
//   - LWE encryption for bits
//   - RGSW for bootstrap keys
//   - Blind rotations for programmable bootstrapping
//
// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause
package fhe

import (
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/luxfi/lattice/v7/core/rgsw/blindrot"
	"github.com/luxfi/lattice/v7/core/rlwe"
	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils"
	"github.com/luxfi/lattice/v7/utils/sampling"
	"golang.org/x/crypto/hkdf"
)

// Parameters defines the FHE parameter set
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
	// Uses same dimension for LWE and BR to avoid key switching complexity.
	// This simplifies bootstrapping while maintaining security.
	// N=1024, Q=134215681
	PN10QP27 = ParametersLiteral{
		LogNLWE:              10, // Same as BR for simplified key switching
		LogNBR:               10,
		QLWE:                 0x7fff801, // Same modulus for direct compatibility
		QBR:                  0x7fff801, // ~134M
		BaseTwoDecomposition: 7,
	}

	// PN11QP54 provides ~128-bit security with higher precision
	// Uses same dimension for LWE and BR.
	// N=2048, Q=0x3FFFFFFFFED001 (prime, 54-bit, Q ≡ 1 mod 4096)
	PN11QP54 = ParametersLiteral{
		LogNLWE:              11, // Same as BR
		LogNBR:               11,
		QLWE:                 0x3FFFFFFFFED001, // NTT-friendly prime ~2^54
		QBR:                  0x3FFFFFFFFED001, // Q ≡ 1 (mod 2*2048)
		BaseTwoDecomposition: 10,
	}

	// PN9QP28_STD128 matches OpenFHE's STD128_LMKCDEY as closely as possible
	// OpenFHE uses LWEDim=447, we use 512 (nearest power of 2)
	// This enables apples-to-apples comparison with C++ OpenFHE
	// Security: 128-bit classical
	// Note: Uses NTT-friendly prime Q ≡ 1 (mod 2048)
	PN9QP28_STD128 = ParametersLiteral{
		LogNLWE:              9,          // N=512 (OpenFHE uses 447)
		LogNBR:               10,         // N=1024 (matches OpenFHE)
		QLWE:                 0x10001801, // Prime ~2^28 ≡ 1 (mod 2048)
		QBR:                  0x10001801, // Prime ~2^28 ≡ 1 (mod 2048)
		BaseTwoDecomposition: 5,          // Base 32 = 2^5 (matches OpenFHE)
	}

	// PN9QP27_STD128Q matches OpenFHE's STD128Q_LMKCDEY (post-quantum)
	// OpenFHE uses LWEDim=483, we use 512 (nearest power of 2)
	// Security: 128-bit post-quantum
	// Note: Uses NTT-friendly prime Q ≡ 1 (mod 2048)
	PN9QP27_STD128Q = ParametersLiteral{
		LogNLWE:              9,         // N=512 (OpenFHE uses 483)
		LogNBR:               10,        // N=1024 (matches OpenFHE)
		QLWE:                 0x8007001, // Prime ~2^27 ≡ 1 (mod 2048)
		QBR:                  0x8007001, // Prime ~2^27 ≡ 1 (mod 2048)
		BaseTwoDecomposition: 5,         // Base 32 = 2^5 (matches OpenFHE)
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

// ParamsLWE returns the underlying rlwe.Parameters used for LWE bit ciphertexts.
// Exposed so out-of-tree consumers (notably pkg/threshold) can drive lattice
// primitives directly against the same parameter set used by Encryptor /
// Decryptor — no duplicate parameter construction, no ad-hoc Q recomputation.
func (p Parameters) ParamsLWE() rlwe.Parameters {
	return p.paramsLWE
}

// ParamsBR returns the underlying rlwe.Parameters used for blind-rotation /
// bootstrapping. Exposed for the same reason as ParamsLWE.
func (p Parameters) ParamsBR() rlwe.Parameters {
	return p.paramsBR
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
	// TestPolyCMPCOMBINE is the test polynomial for comparison combine:
	// output = isLess OR (isEqual AND bitLt)
	// Uses weighted sum: 2*isLess + isEqual + bitLt >= 0
	TestPolyCMPCOMBINE *ring.Poly
	// Parameters
	params Parameters
}

// Ciphertext represents an encrypted bit
type Ciphertext struct {
	*rlwe.Ciphertext
}

// KeyGenerator generates FHE keys
type KeyGenerator struct {
	params  Parameters
	kgenLWE *rlwe.KeyGenerator
	kgenBR  *rlwe.KeyGenerator
	ringQBR *ring.Ring
	scaleBR float64
	// prngLWE and prngBR are non-nil only when the generator was constructed
	// via NewKeyGeneratorFromSeed. They drive deterministic sampling of the
	// secret-key coefficients in GenSecretKey.
	prngLWE sampling.PRNG
	prngBR  sampling.PRNG
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

// keygenHKDFInfoLWE is the HKDF info string for the LWE secret-key stream.
// Domain-separated from BR to ensure the two PRNG streams never collide.
const keygenHKDFInfoLWE = "LUX_FHE_KEYGEN_v1:LWE"

// keygenHKDFInfoBR is the HKDF info string for the blind-rotation secret-key
// stream. Domain-separated from LWE.
const keygenHKDFInfoBR = "LUX_FHE_KEYGEN_v1:BR"

// keygenHKDFSalt is a fixed salt used for HKDF-SHA256 extract. Treated as a
// network constant — changing it invalidates all keys derived from prior seeds.
var keygenHKDFSalt = []byte("LUX_FHE_KEYGEN_v1")

// NewKeyGeneratorFromSeed creates a key generator that deterministically
// derives the secret-key material from `seed`. All validators using the same
// seed produce identical secret keys (and therefore identical public/bootstrap
// keys), which is required for consensus.
//
// Derivation pipeline:
//
//	prk     = HKDF-Extract(SHA-256, salt=keygenHKDFSalt, ikm=seed)
//	keyLWE  = HKDF-Expand(prk, info="LUX_FHE_KEYGEN_v1:LWE", L=32)
//	keyBR   = HKDF-Expand(prk, info="LUX_FHE_KEYGEN_v1:BR",  L=32)
//
// keyLWE and keyBR seed two independent blake2b-based KeyedPRNG streams which
// drive `ring.NewSampler` to fill the secret-key polynomial coefficients
// according to the parameter set's secret distribution `Xs`.
//
// WARNING: The seed is a network parameter. Changing it invalidates all
// existing ciphertexts. Use a domain-separated constant
// (e.g. "LUX_FHE_KEYGEN_v1").
func NewKeyGeneratorFromSeed(params Parameters, seed []byte) (*KeyGenerator, error) {
	if len(seed) == 0 {
		return nil, fmt.Errorf("fhe: NewKeyGeneratorFromSeed: empty seed")
	}

	// HKDF-SHA256 extract once, expand to two domain-separated 32-byte keys.
	prk := hkdf.Extract(sha256.New, seed, keygenHKDFSalt)
	keyLWE, err := hkdfExpand32(prk, keygenHKDFInfoLWE)
	if err != nil {
		return nil, fmt.Errorf("fhe: HKDF-Expand LWE: %w", err)
	}
	keyBR, err := hkdfExpand32(prk, keygenHKDFInfoBR)
	if err != nil {
		return nil, fmt.Errorf("fhe: HKDF-Expand BR: %w", err)
	}

	prngLWE, err := sampling.NewKeyedPRNG(keyLWE)
	if err != nil {
		return nil, fmt.Errorf("fhe: NewKeyedPRNG LWE: %w", err)
	}
	prngBR, err := sampling.NewKeyedPRNG(keyBR)
	if err != nil {
		return nil, fmt.Errorf("fhe: NewKeyedPRNG BR: %w", err)
	}

	return &KeyGenerator{
		params:  params,
		kgenLWE: rlwe.NewKeyGenerator(params.paramsLWE),
		kgenBR:  rlwe.NewKeyGenerator(params.paramsBR),
		ringQBR: params.paramsBR.RingQ(),
		scaleBR: float64(params.QBR()) / 8.0,
		// Stash the per-stream PRNGs; GenSecretKey consumes them when set so
		// the resulting secret key is fully deterministic for a given seed.
		prngLWE: prngLWE,
		prngBR:  prngBR,
	}, nil
}

// hkdfExpand32 expands `prk` to a 32-byte key using HKDF-SHA256 with the
// given info string.
func hkdfExpand32(prk []byte, info string) ([]byte, error) {
	r := hkdf.Expand(sha256.New, prk, []byte(info))
	out := make([]byte, 32)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

// sampleSecretKeyDeterministic fills `sk` in-place with secret-key
// coefficients drawn from the parameter set's `Xs` distribution using `prng`
// as the source of randomness. The polynomial is left in NTT + Montgomery
// form, matching the convention used by `rlwe.KeyGenerator.GenSecretKeyNew`.
func sampleSecretKeyDeterministic(params rlwe.Parameters, prng sampling.PRNG, sk *rlwe.SecretKey) error {
	ringQP := params.RingQP()

	// RingQ is always present; sample Xs into sk.Value.Q at level Q.
	samplerQ, err := ring.NewSampler(prng, ringQP.RingQ, params.Xs(), false)
	if err != nil {
		return fmt.Errorf("fhe: ring.NewSampler Q: %w", err)
	}
	samplerQ.AtLevel(sk.LevelQ()).Read(sk.Value.Q)
	ringQP.RingQ.AtLevel(sk.LevelQ()).NTT(sk.Value.Q, sk.Value.Q)
	ringQP.RingQ.AtLevel(sk.LevelQ()).MForm(sk.Value.Q, sk.Value.Q)

	// RingP is optional (only when special primes P are configured).
	if ringQP.RingP != nil && sk.LevelP() >= 0 {
		samplerP, err := ring.NewSampler(prng, ringQP.RingP, params.Xs(), false)
		if err != nil {
			return fmt.Errorf("fhe: ring.NewSampler P: %w", err)
		}
		samplerP.AtLevel(sk.LevelP()).Read(sk.Value.P)
		ringQP.RingP.AtLevel(sk.LevelP()).NTT(sk.Value.P, sk.Value.P)
		ringQP.RingP.AtLevel(sk.LevelP()).MForm(sk.Value.P, sk.Value.P)
	}
	return nil
}

// GenSecretKey generates a new secret key pair.
//
// When the generator was constructed via NewKeyGeneratorFromSeed the secret
// key coefficients are sampled from the seeded blake2b stream so the result
// is fully deterministic. Otherwise the standard cryptographically random
// sampler is used.
func (kg *KeyGenerator) GenSecretKey() *SecretKey {
	// When LWE and BR have the same dimension, use the same key for both
	// This simplifies bootstrapping by eliminating key switching.
	if kg.params.N() == kg.params.NBR() {
		sk := kg.kgenBR.GenSecretKeyNew()
		if kg.prngBR != nil {
			if err := sampleSecretKeyDeterministic(kg.params.paramsBR, kg.prngBR, sk); err != nil {
				panic(fmt.Sprintf("fhe: deterministic BR sample: %v", err))
			}
		}
		return &SecretKey{
			SKLWE: sk,
			SKBR:  sk,
		}
	}
	// Different dimensions require separate keys.
	skLWE := kg.kgenLWE.GenSecretKeyNew()
	skBR := kg.kgenBR.GenSecretKeyNew()
	if kg.prngLWE != nil {
		if err := sampleSecretKeyDeterministic(kg.params.paramsLWE, kg.prngLWE, skLWE); err != nil {
			panic(fmt.Sprintf("fhe: deterministic LWE sample: %v", err))
		}
	}
	if kg.prngBR != nil {
		if err := sampleSecretKeyDeterministic(kg.params.paramsBR, kg.prngBR, skBR); err != nil {
			panic(fmt.Sprintf("fhe: deterministic BR sample: %v", err))
		}
	}
	return &SecretKey{
		SKLWE: skLWE,
		SKBR:  skBR,
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

	// Test polynomials for FHE gates
	// With Q/8 encoding, after adding two bits the normalized positions are:
	// - true+true:   highest x (> 0.25)
	// - true+false:  middle x (∈ [-0.25, 0.25])
	// - false+false: lowest x (< -0.25)

	// AND: output 1 only when both inputs are 1 (x >= 0.25)
	// Use >= to handle exact boundary case when sum of two TRUE = 0.25
	testPolyAND := blindrot.InitTestPolynomial(func(x float64) float64 {
		if x >= 0.25 {
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
	// Use 0.30 boundaries for noise margin in carry chains (FALSE at ±0.5 has 0.20 margin)
	testPolyXOR := blindrot.InitTestPolynomial(func(x float64) float64 {
		if x > -0.30 && x < 0.30 {
			return 1.0
		}
		return -1.0
	}, scale, kg.ringQBR, -1, 1)

	// NAND: output 0 only when both inputs are 1
	// Use >= to handle exact boundary case when sum of two TRUE = 0.25
	testPolyNAND := blindrot.InitTestPolynomial(func(x float64) float64 {
		if x >= 0.25 {
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
	// Use 0.30 boundaries to match XOR noise margin
	testPolyXNOR := blindrot.InitTestPolynomial(func(x float64) float64 {
		if x > -0.30 && x < 0.30 {
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

	// CMPCOMBINE: computes isLess OR (isEqual AND bitLt) in one bootstrap
	// Uses weighted encoding: 2*isLess + isEqual + bitLt
	// With Q/8 encoding, weighted sum ranges:
	// - (F,F,F): 2*(-1/8) + (-1/8) + (-1/8) = -4/8 = -0.5 → FALSE
	// - (F,F,T): 2*(-1/8) + (-1/8) + (+1/8) = -2/8 = -0.25 → FALSE
	// - (F,T,F): 2*(-1/8) + (+1/8) + (-1/8) = -2/8 = -0.25 → FALSE
	// - (F,T,T): 2*(-1/8) + (+1/8) + (+1/8) = 0 → TRUE
	// - (T,F,F): 2*(+1/8) + (-1/8) + (-1/8) = 0 → TRUE
	// - (T,F,T): 2*(+1/8) + (-1/8) + (+1/8) = +2/8 = +0.25 → TRUE
	// - (T,T,F): 2*(+1/8) + (+1/8) + (-1/8) = +2/8 = +0.25 → TRUE
	// - (T,T,T): 2*(+1/8) + (+1/8) + (+1/8) = +4/8 = +0.5 → TRUE
	// Threshold at -0.125 (midpoint between -0.25 and 0) for maximum noise margin
	testPolyCMPCOMBINE := blindrot.InitTestPolynomial(func(x float64) float64 {
		if x > -0.125 {
			return 1.0
		}
		return -1.0
	}, scale, kg.ringQBR, -1, 1)

	// Note: AND3 and OR3 use composition (2 bootstraps) rather than
	// single-bootstrap with gate constants. Single-bootstrap versions
	// would require OpenFHE-style gate constant offsets.

	return &BootstrapKey{
		BRK:                brk,
		KSK:                ksk,
		TestPolyAND:        &testPolyAND,
		TestPolyOR:         &testPolyOR,
		TestPolyXOR:        &testPolyXOR,
		TestPolyNAND:       &testPolyNAND,
		TestPolyNOR:        &testPolyNOR,
		TestPolyXNOR:       &testPolyXNOR,
		TestPolyID:         &testPolyID,
		TestPolyMAJORITY:   &testPolyMAJORITY,
		TestPolyCMPCOMBINE: &testPolyCMPCOMBINE,
		params:             kg.params,
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
