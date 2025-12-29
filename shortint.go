// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package tfhe

import (
	"fmt"

	"github.com/luxfi/lattice/v6/core/rgsw/blindrot"
	"github.com/luxfi/lattice/v6/core/rlwe"
	"github.com/luxfi/lattice/v6/ring"
)

// ShortInt represents a small encrypted integer (1-4 bits) in a single ciphertext.
// Uses LUT-based programmable bootstrapping for operations.
// This is the building block for larger radix integers.
type ShortInt struct {
	ct       *rlwe.Ciphertext
	msgBits  int // Number of message bits (1-4)
	msgSpace int // Message space = 2^msgBits
}

// ShortIntParams holds parameters for shortint operations
type ShortIntParams struct {
	params   Parameters
	msgBits  int
	msgSpace int
	scale    float64 // Q / (2 * msgSpace) for encoding
}

// NewShortIntParams creates parameters for shortint with given message bits
func NewShortIntParams(params Parameters, msgBits int) (*ShortIntParams, error) {
	if msgBits < 1 || msgBits > 4 {
		return nil, fmt.Errorf("msgBits must be 1-4, got %d", msgBits)
	}
	msgSpace := 1 << msgBits
	return &ShortIntParams{
		params:   params,
		msgBits:  msgBits,
		msgSpace: msgSpace,
		scale:    float64(params.QLWE()) / float64(2*msgSpace),
	}, nil
}

// ShortIntEncryptor encrypts small integers
type ShortIntEncryptor struct {
	params    *ShortIntParams
	encryptor *rlwe.Encryptor
}

// NewShortIntEncryptor creates a new shortint encryptor
func NewShortIntEncryptor(params *ShortIntParams, sk *SecretKey) *ShortIntEncryptor {
	return &ShortIntEncryptor{
		params:    params,
		encryptor: rlwe.NewEncryptor(params.params.paramsLWE, sk.SKLWE),
	}
}

// Encrypt encrypts a small integer value
func (enc *ShortIntEncryptor) Encrypt(value int) (*ShortInt, error) {
	if value < 0 || value >= enc.params.msgSpace {
		return nil, fmt.Errorf("value %d out of range [0, %d)", value, enc.params.msgSpace)
	}

	pt := rlwe.NewPlaintext(enc.params.params.paramsLWE, enc.params.params.paramsLWE.MaxLevel())

	// Encode: value * (Q / (2*msgSpace)) centers message in [0, Q/2) range
	// This leaves room for carry in the upper half
	// Use pure integer arithmetic to avoid floating-point precision issues in crypto
	q := enc.params.params.QLWE()
	msgSpace := uint64(enc.params.msgSpace)
	// encoded = value * q / (2 * msgSpace)
	// To avoid overflow, compute as: (value * (q / msgSpace)) / 2
	// Since q is always divisible by powers of 2 and msgSpace is a power of 2,
	// this is exact integer arithmetic
	encoded := (uint64(value) * (q / (2 * msgSpace))) % q
	pt.Value.Coeffs[0][0] = encoded

	enc.params.params.paramsLWE.RingQ().NTT(pt.Value, pt.Value)

	ct := rlwe.NewCiphertext(enc.params.params.paramsLWE, 1, enc.params.params.paramsLWE.MaxLevel())
	if err := enc.encryptor.Encrypt(pt, ct); err != nil {
		return nil, err
	}

	return &ShortInt{
		ct:       ct,
		msgBits:  enc.params.msgBits,
		msgSpace: enc.params.msgSpace,
	}, nil
}

// ShortIntDecryptor decrypts small integers
type ShortIntDecryptor struct {
	params    *ShortIntParams
	decryptor *rlwe.Decryptor
	ringQ     *ring.Ring
}

// NewShortIntDecryptor creates a new shortint decryptor
func NewShortIntDecryptor(params *ShortIntParams, sk *SecretKey) *ShortIntDecryptor {
	return &ShortIntDecryptor{
		params:    params,
		decryptor: rlwe.NewDecryptor(params.params.paramsLWE, sk.SKLWE),
		ringQ:     params.params.paramsLWE.RingQ(),
	}
}

// Decrypt decrypts a shortint to its integer value
func (dec *ShortIntDecryptor) Decrypt(si *ShortInt) int {
	pt := rlwe.NewPlaintext(dec.params.params.paramsLWE, si.ct.Level())
	dec.decryptor.Decrypt(si.ct, pt)

	if pt.IsNTT {
		dec.ringQ.INTT(pt.Value, pt.Value)
	}

	// Decode: round(value * 2*msgSpace / Q)
	c := pt.Value.Coeffs[0][0]
	q := dec.params.params.QLWE()

	// Scale and round to nearest integer
	scaled := float64(c) * float64(2*si.msgSpace) / float64(q)
	value := int(scaled + 0.5)

	// Handle wrap-around for values near Q
	if value >= si.msgSpace {
		value = value % si.msgSpace
	}

	return value
}

// ShortIntEvaluator performs operations on shortints
// SECURITY: This evaluator does NOT require the secret key.
// It uses sample extraction and key switching for bootstrapping.
type ShortIntEvaluator struct {
	params   *ShortIntParams
	eval     *blindrot.Evaluator
	bsk      *BootstrapKey
	ringQLWE *ring.Ring
	ringQBR  *ring.Ring

	// Key switching evaluator (BR -> LWE)
	ksEval *rlwe.Evaluator

	// Precomputed LUT polynomials
	lutAdd   map[int]*ring.Poly // LUT for (a + b) mod msgSpace
	lutSub   map[int]*ring.Poly // LUT for (a - b) mod msgSpace
	lutMul   map[int]*ring.Poly // LUT for (a * b) mod msgSpace
	lutNeg   *ring.Poly         // LUT for -a mod msgSpace
	lutCarry *ring.Poly         // LUT for carry bit
}

// NewShortIntEvaluator creates a new shortint evaluator
// SECURITY: No secret key is required - bootstrapping uses public key switching.
func NewShortIntEvaluator(params *ShortIntParams, bsk *BootstrapKey) *ShortIntEvaluator {
	// Create key switching evaluator using the key switch key in bootstrap key
	var ksEval *rlwe.Evaluator
	if bsk.KSK != nil {
		ksEval = rlwe.NewEvaluator(params.params.paramsBR, nil)
	}

	eval := &ShortIntEvaluator{
		params:   params,
		eval:     blindrot.NewEvaluator(params.params.paramsBR, params.params.paramsLWE),
		bsk:      bsk,
		ringQLWE: params.params.paramsLWE.RingQ(),
		ringQBR:  params.params.paramsBR.RingQ(),
		ksEval:   ksEval,
		lutAdd:   make(map[int]*ring.Poly),
		lutSub:   make(map[int]*ring.Poly),
		lutMul:   make(map[int]*ring.Poly),
	}

	// Precompute LUTs for each possible second operand
	eval.precomputeLUTs()

	return eval
}

// precomputeLUTs generates lookup tables for arithmetic operations
func (eval *ShortIntEvaluator) precomputeLUTs() {
	msgSpace := eval.params.msgSpace
	scale := rlwe.NewScale(float64(eval.params.params.QBR()) / float64(2*msgSpace))
	ringQ := eval.ringQBR

	// For each possible value of the second operand, create an addition LUT
	for b := 0; b < msgSpace; b++ {
		// Addition LUT: f(a) = (a + b) mod msgSpace
		addPoly := blindrot.InitTestPolynomial(func(x float64) float64 {
			// x is normalized to [0, 1) representing a in [0, msgSpace)
			a := int((x + 1) * float64(msgSpace) / 2) // Map [-1,1] to [0, msgSpace)
			if a >= msgSpace {
				a = msgSpace - 1
			}
			if a < 0 {
				a = 0
			}
			result := (a + b) % msgSpace
			// Map back to [-1, 1] range
			return float64(result)*2/float64(msgSpace) - 1
		}, scale, ringQ, -1, 1)
		eval.lutAdd[b] = &addPoly

		// Subtraction LUT: f(a) = (a - b) mod msgSpace
		subPoly := blindrot.InitTestPolynomial(func(x float64) float64 {
			a := int((x + 1) * float64(msgSpace) / 2)
			if a >= msgSpace {
				a = msgSpace - 1
			}
			if a < 0 {
				a = 0
			}
			result := (a - b + msgSpace) % msgSpace
			return float64(result)*2/float64(msgSpace) - 1
		}, scale, ringQ, -1, 1)
		eval.lutSub[b] = &subPoly

		// Multiplication LUT: f(a) = (a * b) mod msgSpace
		mulPoly := blindrot.InitTestPolynomial(func(x float64) float64 {
			a := int((x + 1) * float64(msgSpace) / 2)
			if a >= msgSpace {
				a = msgSpace - 1
			}
			if a < 0 {
				a = 0
			}
			result := (a * b) % msgSpace
			return float64(result)*2/float64(msgSpace) - 1
		}, scale, ringQ, -1, 1)
		eval.lutMul[b] = &mulPoly
	}

	// Negation LUT: f(a) = -a mod msgSpace
	negPoly := blindrot.InitTestPolynomial(func(x float64) float64 {
		a := int((x + 1) * float64(msgSpace) / 2)
		if a >= msgSpace {
			a = msgSpace - 1
		}
		if a < 0 {
			a = 0
		}
		result := (msgSpace - a) % msgSpace
		return float64(result)*2/float64(msgSpace) - 1
	}, scale, ringQ, -1, 1)
	eval.lutNeg = &negPoly

	// Carry LUT: f(a+b) = 1 if a+b >= msgSpace, else 0
	// Used for radix addition
	carryPoly := blindrot.InitTestPolynomial(func(x float64) float64 {
		// x represents sum in [-1, 1] normalized from [0, 2*msgSpace)
		sum := int((x + 1) * float64(msgSpace)) // Map to [0, 2*msgSpace)
		if sum >= msgSpace {
			return 1.0 // Carry = 1
		}
		return -1.0 // Carry = 0
	}, scale, ringQ, -1, 1)
	eval.lutCarry = &carryPoly
}

// sampleExtractAndKeySwitch extracts the constant coefficient from an RLWE ciphertext
// and key-switches it to an LWE ciphertext.
//
// SECURITY: This does NOT decrypt - uses sample extraction and key switching.
func (eval *ShortIntEvaluator) sampleExtractAndKeySwitch(ctBR *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	if eval.bsk.KSK == nil {
		return nil, fmt.Errorf("bootstrap key does not contain key switching key")
	}

	levelBR := ctBR.Level()
	ringQBR := eval.ringQBR.AtLevel(levelBR)
	NBR := ringQBR.N()
	qBR := eval.params.params.QBR()

	// Ensure we're working in coefficient domain
	c0 := ctBR.Value[0].CopyNew()
	c1 := ctBR.Value[1].CopyNew()

	if ctBR.IsNTT {
		ringQBR.INTT(*c0, *c0)
		ringQBR.INTT(*c1, *c1)
	}

	// Create an LWE ciphertext in the BR dimension
	ctLWEBR := rlwe.NewCiphertext(eval.params.params.paramsBR, 1, levelBR)

	// Sample extraction: LWE (b, a) where
	// b = c0[0]
	// a = (c1[0], -c1[N-1], -c1[N-2], ..., -c1[1])
	ctLWEBR.Value[0].Coeffs[0][0] = c0.Coeffs[0][0]
	ctLWEBR.Value[1].Coeffs[0][0] = c1.Coeffs[0][0]
	for i := 1; i < NBR; i++ {
		ctLWEBR.Value[1].Coeffs[0][i] = qBR - c1.Coeffs[0][NBR-i]
	}

	// Zero out higher coefficients of c0
	for i := 1; i < NBR; i++ {
		ctLWEBR.Value[0].Coeffs[0][i] = 0
	}

	// Convert to NTT for key switching
	ringQBR.NTT(ctLWEBR.Value[0], ctLWEBR.Value[0])
	ringQBR.NTT(ctLWEBR.Value[1], ctLWEBR.Value[1])
	ctLWEBR.IsNTT = true

	// Key switch from SKBR to SKLWE
	ctLWE := rlwe.NewCiphertext(eval.params.params.paramsLWE, 1, eval.params.params.paramsLWE.MaxLevel())
	ctLWE.IsNTT = true

	if err := eval.ksEval.ApplyEvaluationKey(ctLWEBR, eval.bsk.KSK, ctLWE); err != nil {
		return nil, fmt.Errorf("key switching failed: %w", err)
	}

	// Scale from Q_BR to Q_LWE
	levelLWE := ctLWE.Level()
	ringQLWE := eval.ringQLWE.AtLevel(levelLWE)

	if ctLWE.IsNTT {
		ringQLWE.INTT(ctLWE.Value[0], ctLWE.Value[0])
		ringQLWE.INTT(ctLWE.Value[1], ctLWE.Value[1])
		ctLWE.IsNTT = false
	}

	qLWE := eval.params.params.QLWE()
	scaleFactor := float64(qLWE) / float64(qBR)

	for i := 0; i < ringQLWE.N(); i++ {
		scaled0 := uint64(float64(ctLWE.Value[0].Coeffs[0][i]) * scaleFactor)
		scaled1 := uint64(float64(ctLWE.Value[1].Coeffs[0][i]) * scaleFactor)
		ctLWE.Value[0].Coeffs[0][i] = scaled0 % qLWE
		ctLWE.Value[1].Coeffs[0][i] = scaled1 % qLWE
	}

	ringQLWE.NTT(ctLWE.Value[0], ctLWE.Value[0])
	ringQLWE.NTT(ctLWE.Value[1], ctLWE.Value[1])
	ctLWE.IsNTT = true

	return ctLWE, nil
}

// bootstrap performs LUT evaluation via programmable bootstrapping
// SECURITY: This does NOT decrypt - uses sample extraction and key switching.
func (eval *ShortIntEvaluator) bootstrap(ct *rlwe.Ciphertext, lut *ring.Poly) (*rlwe.Ciphertext, error) {
	testPolyMap := map[int]*ring.Poly{0: lut}

	results, err := eval.eval.Evaluate(ct, testPolyMap, eval.bsk.BRK)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}

	ctBR, ok := results[0]
	if !ok {
		return nil, fmt.Errorf("bootstrap: no result for slot 0")
	}

	// Sample extract and key switch (no decryption!)
	return eval.sampleExtractAndKeySwitch(ctBR)
}

// ScalarAdd adds a plaintext value to a shortint using LWE additive homomorphism
func (eval *ShortIntEvaluator) ScalarAdd(si *ShortInt, scalar int) (*ShortInt, error) {
	scalar = scalar % si.msgSpace
	if scalar < 0 {
		scalar += si.msgSpace
	}

	// LWE is additively homomorphic - we can add scalar * scale to the ciphertext directly
	result := rlwe.NewCiphertext(eval.params.params.paramsLWE, 1, si.ct.Level())

	// Copy ct to result
	result.Value[0] = *si.ct.Value[0].CopyNew()
	result.Value[1] = *si.ct.Value[1].CopyNew()
	result.IsNTT = si.ct.IsNTT

	// Add scalar * scale to the constant term (b = Value[0])
	// Use pure integer arithmetic: scale = Q / (2 * msgSpace)
	q := eval.params.params.QLWE()
	msgSpace := uint64(eval.params.msgSpace)
	scalarEncoded := (uint64(scalar) * (q / (2 * msgSpace))) % q

	if result.IsNTT {
		// Need to add in NTT domain - add to all coefficients
		for i := range result.Value[0].Coeffs[0] {
			result.Value[0].Coeffs[0][i] = (result.Value[0].Coeffs[0][i] + scalarEncoded) % q
		}
	} else {
		// Add to constant term only
		result.Value[0].Coeffs[0][0] = (result.Value[0].Coeffs[0][0] + scalarEncoded) % q
	}

	return &ShortInt{
		ct:       result,
		msgBits:  si.msgBits,
		msgSpace: si.msgSpace,
	}, nil
}

// ScalarSub subtracts a plaintext value from a shortint using LWE additive homomorphism
func (eval *ShortIntEvaluator) ScalarSub(si *ShortInt, scalar int) (*ShortInt, error) {
	// Subtraction is addition of negation
	negScalar := (si.msgSpace - (scalar % si.msgSpace)) % si.msgSpace
	return eval.ScalarAdd(si, negScalar)
}

// ScalarMul multiplies a shortint by a plaintext value
func (eval *ShortIntEvaluator) ScalarMul(si *ShortInt, scalar int) (*ShortInt, error) {
	scalar = scalar % si.msgSpace
	if scalar < 0 {
		scalar += si.msgSpace
	}

	lut := eval.lutMul[scalar]
	result, err := eval.bootstrap(si.ct, lut)
	if err != nil {
		return nil, err
	}

	return &ShortInt{
		ct:       result,
		msgBits:  si.msgBits,
		msgSpace: si.msgSpace,
	}, nil
}

// Neg negates a shortint
func (eval *ShortIntEvaluator) Neg(si *ShortInt) (*ShortInt, error) {
	result, err := eval.bootstrap(si.ct, eval.lutNeg)
	if err != nil {
		return nil, err
	}

	return &ShortInt{
		ct:       result,
		msgBits:  si.msgBits,
		msgSpace: si.msgSpace,
	}, nil
}

// EncryptTrivial creates a trivial encryption of a plaintext value
// A trivial ciphertext is a ciphertext where the message is encoded without noise,
// effectively embedding plaintext in ciphertext format for homomorphic operations.
func (eval *ShortIntEvaluator) EncryptTrivial(value int) (*ShortInt, error) {
	value = value % eval.params.msgSpace
	if value < 0 {
		value += eval.params.msgSpace
	}

	// Create a trivial ciphertext: (0, m * scale)
	// This is a "noiseless" encryption that can be used in homomorphic operations
	ct := rlwe.NewCiphertext(eval.params.params.paramsLWE, 1, eval.params.params.paramsLWE.MaxLevel())

	// Encode the message value using pure integer arithmetic
	// scale = Q / (2 * msgSpace), so encoded = value * Q / (2 * msgSpace)
	q := eval.params.params.QLWE()
	msgSpace := uint64(eval.params.msgSpace)
	encoded := (uint64(value) * (q / (2 * msgSpace))) % q

	// Set b = encoded (the message), a = 0
	// In NTT domain, this means setting all coefficients
	for i := range ct.Value[0].Coeffs[0] {
		ct.Value[0].Coeffs[0][i] = encoded % q
	}
	// a (Value[1]) is already zero from NewCiphertext

	ct.IsNTT = true

	return &ShortInt{
		ct:       ct,
		msgBits:  eval.params.msgBits,
		msgSpace: eval.params.msgSpace,
	}, nil
}

// addCiphertexts adds two LWE ciphertexts element-wise
func (eval *ShortIntEvaluator) addCiphertexts(ct1, ct2 *rlwe.Ciphertext) *rlwe.Ciphertext {
	result := rlwe.NewCiphertext(eval.params.params.paramsLWE, 1, ct1.Level())
	eval.ringQLWE.Add(ct1.Value[0], ct2.Value[0], result.Value[0])
	eval.ringQLWE.Add(ct1.Value[1], ct2.Value[1], result.Value[1])
	result.IsNTT = ct1.IsNTT
	return result
}

// Add adds two shortints (with modular wrap)
func (eval *ShortIntEvaluator) Add(a, b *ShortInt) (*ShortInt, error) {
	if a.msgSpace != b.msgSpace {
		return nil, fmt.Errorf("mismatched message spaces: %d vs %d", a.msgSpace, b.msgSpace)
	}

	// Add ciphertexts directly, then bootstrap to reduce and refresh
	sum := eval.addCiphertexts(a.ct, b.ct)

	// Create a modular reduction LUT
	msgSpace := a.msgSpace
	scale := rlwe.NewScale(float64(eval.params.params.QBR()) / float64(2*msgSpace))
	modLUT := blindrot.InitTestPolynomial(func(x float64) float64 {
		// x represents sum in range [0, 2*msgSpace) normalized to [-1, 1]
		rawSum := int((x + 1) * float64(msgSpace)) // [0, 2*msgSpace)
		result := rawSum % msgSpace
		return float64(result)*2/float64(msgSpace) - 1
	}, scale, eval.ringQBR, -1, 1)

	result, err := eval.bootstrap(sum, &modLUT)
	if err != nil {
		return nil, err
	}

	return &ShortInt{
		ct:       result,
		msgBits:  a.msgBits,
		msgSpace: a.msgSpace,
	}, nil
}

// AddWithCarry adds two shortints and returns result and carry bit
func (eval *ShortIntEvaluator) AddWithCarry(a, b *ShortInt) (*ShortInt, *Ciphertext, error) {
	if a.msgSpace != b.msgSpace {
		return nil, nil, fmt.Errorf("mismatched message spaces: %d vs %d", a.msgSpace, b.msgSpace)
	}

	// Add ciphertexts
	sum := eval.addCiphertexts(a.ct, b.ct)

	// Get modular result
	msgSpace := a.msgSpace
	scale := rlwe.NewScale(float64(eval.params.params.QBR()) / float64(2*msgSpace))

	modLUT := blindrot.InitTestPolynomial(func(x float64) float64 {
		rawSum := int((x + 1) * float64(msgSpace))
		result := rawSum % msgSpace
		return float64(result)*2/float64(msgSpace) - 1
	}, scale, eval.ringQBR, -1, 1)

	resultCt, err := eval.bootstrap(sum, &modLUT)
	if err != nil {
		return nil, nil, err
	}

	// Get carry bit using carry LUT
	carryCt, err := eval.bootstrap(sum, eval.lutCarry)
	if err != nil {
		return nil, nil, err
	}

	return &ShortInt{
			ct:       resultCt,
			msgBits:  a.msgBits,
			msgSpace: a.msgSpace,
		}, &Ciphertext{carryCt},
		nil
}

// Sub subtracts b from a
func (eval *ShortIntEvaluator) Sub(a, b *ShortInt) (*ShortInt, error) {
	// Negate b and add
	negB, err := eval.Neg(b)
	if err != nil {
		return nil, err
	}
	return eval.Add(a, negB)
}
