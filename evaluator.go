// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package tfhe

import (
	"fmt"

	"github.com/luxfi/lattice/v6/core/rgsw/blindrot"
	"github.com/luxfi/lattice/v6/core/rlwe"
	"github.com/luxfi/lattice/v6/ring"
)

// Evaluator evaluates boolean gates on encrypted data
// SECURITY: This evaluator does NOT require the secret key.
// It uses sample extraction and key switching for bootstrapping.
type Evaluator struct {
	params   Parameters
	eval     *blindrot.Evaluator
	bsk      *BootstrapKey
	ringQLWE *ring.Ring
	ringQBR  *ring.Ring

	// Key switching evaluator (BR -> LWE)
	ksEval *rlwe.Evaluator
}

// NewEvaluator creates a new evaluator with bootstrap key.
// SECURITY: No secret key is required - bootstrapping uses public key switching.
func NewEvaluator(params Parameters, bsk *BootstrapKey) *Evaluator {
	// Create key switching evaluator using the key switch key in bootstrap key
	var ksEval *rlwe.Evaluator
	if bsk.KSK != nil {
		ksEval = rlwe.NewEvaluator(params.paramsBR, nil)
	}

	return &Evaluator{
		params:   params,
		eval:     blindrot.NewEvaluator(params.paramsBR, params.paramsLWE),
		bsk:      bsk,
		ringQLWE: params.paramsLWE.RingQ(),
		ringQBR:  params.paramsBR.RingQ(),
		ksEval:   ksEval,
	}
}

// sampleExtractAndKeySwitch extracts the constant coefficient from an RLWE ciphertext
// and key-switches it to an LWE ciphertext.
//
// This is the core operation that replaces the insecure decrypt-then-reencrypt pattern.
//
// Mathematical background:
// - RLWE: (c0, c1) where c0 + c1 * s_BR = m(X) + e
// - The constant term m[0] is encoded as an LWE sample
// - Sample extraction: LWE_BR = (c0[0], a') where a' derived from c1 coefficients
// - Key switching: LWE_LWE = KeySwitch(LWE_BR, KSK)
func (eval *Evaluator) sampleExtractAndKeySwitch(ctBR *rlwe.Ciphertext) (*Ciphertext, error) {
	if eval.bsk.KSK == nil {
		return nil, fmt.Errorf("bootstrap key does not contain key switching key")
	}

	// Step 1: Extract constant coefficient from RLWE to get an LWE sample
	// For RLWE ciphertext (c0(X), c1(X)) under secret s(X):
	//   c0 + c1 * s = m + e
	// The constant term gives:
	//   c0[0] + sum(c1[i] * s[N-i] for i=1..N-1) + c1[0]*s[0] = m[0] + e[0]
	//
	// This is an LWE sample (b, a) where:
	//   b = c0[0]
	//   a = (c1[0], -c1[N-1], -c1[N-2], ..., -c1[1])
	// under key (s[0], s[1], s[2], ..., s[N-1])

	levelBR := ctBR.Level()
	ringQBR := eval.ringQBR.AtLevel(levelBR)
	NBR := ringQBR.N()
	qBR := eval.params.QBR()

	// Ensure we're working in coefficient domain
	c0 := ctBR.Value[0].CopyNew()
	c1 := ctBR.Value[1].CopyNew()

	if ctBR.IsNTT {
		ringQBR.INTT(*c0, *c0)
		ringQBR.INTT(*c1, *c1)
	}

	// Create an LWE ciphertext in the BR dimension
	// We represent this as an RLWE ciphertext for compatibility
	ctLWEBR := rlwe.NewCiphertext(eval.params.paramsBR, 1, levelBR)

	// Set the constant term (b component of LWE)
	// b = c0[0]
	ctLWEBR.Value[0].Coeffs[0][0] = c0.Coeffs[0][0]

	// Set the a vector: a = (c1[0], -c1[N-1], -c1[N-2], ..., -c1[1])
	// Stored as polynomial coefficients
	ctLWEBR.Value[1].Coeffs[0][0] = c1.Coeffs[0][0]
	for i := 1; i < NBR; i++ {
		// -c1[N-i] mod q
		ctLWEBR.Value[1].Coeffs[0][i] = qBR - c1.Coeffs[0][NBR-i]
	}

	// Zero out higher coefficients of c0 (only constant term matters)
	for i := 1; i < NBR; i++ {
		ctLWEBR.Value[0].Coeffs[0][i] = 0
	}

	// Convert to NTT for key switching
	ringQBR.NTT(ctLWEBR.Value[0], ctLWEBR.Value[0])
	ringQBR.NTT(ctLWEBR.Value[1], ctLWEBR.Value[1])
	ctLWEBR.IsNTT = true

	// Step 2: Key switch from SKBR to SKLWE
	// The KSK switches from dimension NBR under SKBR to dimension NLWE under SKLWE
	ctLWE := rlwe.NewCiphertext(eval.params.paramsLWE, 1, eval.params.paramsLWE.MaxLevel())
	ctLWE.IsNTT = true

	// Apply the key switching key
	if err := eval.ksEval.ApplyEvaluationKey(ctLWEBR, eval.bsk.KSK, ctLWE); err != nil {
		return nil, fmt.Errorf("key switching failed: %w", err)
	}

	// Step 3: Scale from Q_BR to Q_LWE
	// The message was encoded at scale Q_BR/8, we need Q_LWE/8
	// Modulus switching: round(x * Q_LWE / Q_BR)
	levelLWE := ctLWE.Level()
	ringQLWE := eval.ringQLWE.AtLevel(levelLWE)

	if ctLWE.IsNTT {
		ringQLWE.INTT(ctLWE.Value[0], ctLWE.Value[0])
		ringQLWE.INTT(ctLWE.Value[1], ctLWE.Value[1])
		ctLWE.IsNTT = false
	}

	// Scale the constant term
	qLWE := eval.params.QLWE()
	scaleFactor := float64(qLWE) / float64(qBR)

	for i := 0; i < ringQLWE.N(); i++ {
		scaled0 := uint64(float64(ctLWE.Value[0].Coeffs[0][i]) * scaleFactor)
		scaled1 := uint64(float64(ctLWE.Value[1].Coeffs[0][i]) * scaleFactor)
		ctLWE.Value[0].Coeffs[0][i] = scaled0 % qLWE
		ctLWE.Value[1].Coeffs[0][i] = scaled1 % qLWE
	}

	// Convert back to NTT
	ringQLWE.NTT(ctLWE.Value[0], ctLWE.Value[0])
	ringQLWE.NTT(ctLWE.Value[1], ctLWE.Value[1])
	ctLWE.IsNTT = true

	return &Ciphertext{ctLWE}, nil
}

// bootstrap performs programmable bootstrapping with the given test polynomial
// and returns a fresh LWE ciphertext with the result.
//
// SECURITY: This implementation does NOT decrypt - it uses sample extraction
// and key switching, which are public operations on ciphertexts.
func (eval *Evaluator) bootstrap(ct *Ciphertext, testPoly *ring.Poly) (*Ciphertext, error) {
	// Create map for single slot evaluation
	testPolyMap := map[int]*ring.Poly{0: testPoly}

	// Step 1: Evaluate blind rotation
	// This produces an RLWE ciphertext under SKBR with the test polynomial
	// evaluated at the encrypted value
	results, err := eval.eval.Evaluate(ct.Ciphertext, testPolyMap, eval.bsk.BRK)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}

	// Extract result for slot 0
	ctBR, ok := results[0]
	if !ok {
		return nil, fmt.Errorf("bootstrap: no result for slot 0")
	}

	// Step 2: Sample extract and key switch
	// This extracts the constant term and switches to SKLWE
	return eval.sampleExtractAndKeySwitch(ctBR)
}

// addCiphertexts adds two ciphertexts element-wise
func (eval *Evaluator) addCiphertexts(ct1, ct2 *Ciphertext) *Ciphertext {
	result := rlwe.NewCiphertext(eval.params.paramsLWE, 1, ct1.Level())

	eval.ringQLWE.Add(ct1.Value[0], ct2.Value[0], result.Value[0])
	eval.ringQLWE.Add(ct1.Value[1], ct2.Value[1], result.Value[1])

	result.IsNTT = ct1.IsNTT

	return &Ciphertext{result}
}

// doubleCiphertext multiplies a ciphertext by 2 (element-wise addition with itself)
// This is key to OpenFHE's optimized XOR: 2*(ct1+ct2) causes wrap-around for (T,T) case
func (eval *Evaluator) doubleCiphertext(ct *Ciphertext) *Ciphertext {
	result := rlwe.NewCiphertext(eval.params.paramsLWE, 1, ct.Level())

	eval.ringQLWE.Add(ct.Value[0], ct.Value[0], result.Value[0])
	eval.ringQLWE.Add(ct.Value[1], ct.Value[1], result.Value[1])

	result.IsNTT = ct.IsNTT

	return &Ciphertext{result}
}

// negateCiphertext negates a ciphertext
func (eval *Evaluator) negateCiphertext(ct *Ciphertext) *Ciphertext {
	result := rlwe.NewCiphertext(eval.params.paramsLWE, 1, ct.Level())

	eval.ringQLWE.Neg(ct.Value[0], result.Value[0])
	eval.ringQLWE.Neg(ct.Value[1], result.Value[1])

	result.IsNTT = ct.IsNTT

	return &Ciphertext{result}
}

// addConstant adds a scalar constant to the ciphertext's constant term (b)
// This is used for gate offsets like OpenFHE's gate constants
func (eval *Evaluator) addConstant(ct *Ciphertext, constant uint64) *Ciphertext {
	result := ct.CopyNew()

	// Add constant to the constant term (coefficient 0 of polynomial b)
	// Need to handle NTT form
	if result.IsNTT {
		eval.ringQLWE.INTT(result.Value[1], result.Value[1])
	}

	q := eval.params.QLWE()
	result.Value[1].Coeffs[0][0] = (result.Value[1].Coeffs[0][0] + constant) % q

	if ct.IsNTT {
		eval.ringQLWE.NTT(result.Value[1], result.Value[1])
	}

	return &Ciphertext{result}
}

// ========== Boolean Gates ==========

// NOT computes the logical NOT of the input
// NOT(a) = 1 - a (free operation - just negate)
func (eval *Evaluator) NOT(ct *Ciphertext) *Ciphertext {
	return eval.negateCiphertext(ct)
}

// AND computes the logical AND of two inputs
// AND(a, b) = 1 if a + b >= 1.5 (both are 1)
func (eval *Evaluator) AND(ct1, ct2 *Ciphertext) (*Ciphertext, error) {
	sum := eval.addCiphertexts(ct1, ct2)
	return eval.bootstrap(sum, eval.bsk.TestPolyAND)
}

// OR computes the logical OR of two inputs
// OR(a, b) = 1 if a + b >= 0.5 (at least one is 1)
func (eval *Evaluator) OR(ct1, ct2 *Ciphertext) (*Ciphertext, error) {
	sum := eval.addCiphertexts(ct1, ct2)
	return eval.bootstrap(sum, eval.bsk.TestPolyOR)
}

// XOR computes the logical XOR of two inputs
// Optimized algorithm matching OpenFHE: 2*(ct1 + ct2) with single bootstrap
// The doubling causes (T,T) → 2*0.25 = 0.5 to wrap around to -0.5,
// making the XOR test polynomial correctly return FALSE for both (T,T) and (F,F)
func (eval *Evaluator) XOR(ct1, ct2 *Ciphertext) (*Ciphertext, error) {
	sum := eval.addCiphertexts(ct1, ct2)
	doubled := eval.doubleCiphertext(sum) // Key: 2*(ct1+ct2)
	return eval.bootstrap(doubled, eval.bsk.TestPolyXOR)
}

// NAND computes the logical NAND of two inputs
func (eval *Evaluator) NAND(ct1, ct2 *Ciphertext) (*Ciphertext, error) {
	sum := eval.addCiphertexts(ct1, ct2)
	return eval.bootstrap(sum, eval.bsk.TestPolyNAND)
}

// NOR computes the logical NOR of two inputs
func (eval *Evaluator) NOR(ct1, ct2 *Ciphertext) (*Ciphertext, error) {
	sum := eval.addCiphertexts(ct1, ct2)
	return eval.bootstrap(sum, eval.bsk.TestPolyNOR)
}

// XNOR computes the logical XNOR of two inputs
// Optimized algorithm matching OpenFHE: 2*(ct1 + ct2) with single bootstrap
// Same as XOR but with inverted test polynomial
func (eval *Evaluator) XNOR(ct1, ct2 *Ciphertext) (*Ciphertext, error) {
	sum := eval.addCiphertexts(ct1, ct2)
	doubled := eval.doubleCiphertext(sum) // Key: 2*(ct1+ct2)
	return eval.bootstrap(doubled, eval.bsk.TestPolyXNOR)
}

// ANDNY computes AND with negated first input: AND(NOT(a), b)
func (eval *Evaluator) ANDNY(ct1, ct2 *Ciphertext) (*Ciphertext, error) {
	return eval.AND(eval.NOT(ct1), ct2)
}

// ANDYN computes AND with negated second input: AND(a, NOT(b))
func (eval *Evaluator) ANDYN(ct1, ct2 *Ciphertext) (*Ciphertext, error) {
	return eval.AND(ct1, eval.NOT(ct2))
}

// ORNY computes OR with negated first input: OR(NOT(a), b)
func (eval *Evaluator) ORNY(ct1, ct2 *Ciphertext) (*Ciphertext, error) {
	return eval.OR(eval.NOT(ct1), ct2)
}

// ORYN computes OR with negated second input: OR(a, NOT(b))
func (eval *Evaluator) ORYN(ct1, ct2 *Ciphertext) (*Ciphertext, error) {
	return eval.OR(ct1, eval.NOT(ct2))
}

// MUX computes the multiplexer: if sel then a else b
// MUX(sel, a, b) = (sel AND a) OR (NOT(sel) AND b)
func (eval *Evaluator) MUX(sel, ctTrue, ctFalse *Ciphertext) (*Ciphertext, error) {
	selAndTrue, err := eval.AND(sel, ctTrue)
	if err != nil {
		return nil, err
	}

	notSelAndFalse, err := eval.AND(eval.NOT(sel), ctFalse)
	if err != nil {
		return nil, err
	}

	return eval.OR(selAndTrue, notSelAndFalse)
}

// ========== Multi-Input Gates ==========
//
// Note: Single-bootstrap multi-input gates require careful offset tuning
// matching OpenFHE's gate constants. For correctness, we use 2-bootstrap
// composition here. Future optimization could add single-bootstrap versions.

// AND3 computes the logical AND of three inputs
// AND3(a, b, c) = AND(AND(a, b), c)
func (eval *Evaluator) AND3(ct1, ct2, ct3 *Ciphertext) (*Ciphertext, error) {
	ab, err := eval.AND(ct1, ct2)
	if err != nil {
		return nil, err
	}
	return eval.AND(ab, ct3)
}

// OR3 computes the logical OR of three inputs
// OR3(a, b, c) = OR(OR(a, b), c)
func (eval *Evaluator) OR3(ct1, ct2, ct3 *Ciphertext) (*Ciphertext, error) {
	ab, err := eval.OR(ct1, ct2)
	if err != nil {
		return nil, err
	}
	return eval.OR(ab, ct3)
}

// MAJORITY computes the majority vote of three inputs with single bootstrap
// MAJORITY(a, b, c) = 1 if at least two inputs are 1
// This uses a single bootstrap since the threshold at 0 correctly separates
// 0-1 true inputs (sum < 0) from 2-3 true inputs (sum > 0)
func (eval *Evaluator) MAJORITY(ct1, ct2, ct3 *Ciphertext) (*Ciphertext, error) {
	sum := eval.addCiphertexts(ct1, ct2)
	sum = eval.addCiphertexts(sum, ct3)
	return eval.bootstrap(sum, eval.bsk.TestPolyMAJORITY)
}

// NAND3 computes the logical NAND of three inputs
// NAND3(a, b, c) = NOT(AND3(a, b, c))
func (eval *Evaluator) NAND3(ct1, ct2, ct3 *Ciphertext) (*Ciphertext, error) {
	result, err := eval.AND3(ct1, ct2, ct3)
	if err != nil {
		return nil, err
	}
	return eval.NOT(result), nil
}

// NOR3 computes the logical NOR of three inputs
// NOR3(a, b, c) = NOT(OR3(a, b, c))
func (eval *Evaluator) NOR3(ct1, ct2, ct3 *Ciphertext) (*Ciphertext, error) {
	result, err := eval.OR3(ct1, ct2, ct3)
	if err != nil {
		return nil, err
	}
	return eval.NOT(result), nil
}

// Copy creates a copy of a ciphertext
func (eval *Evaluator) Copy(ct *Ciphertext) *Ciphertext {
	return &Ciphertext{ct.CopyNew()}
}

// Refresh bootstraps a ciphertext to reduce noise
func (eval *Evaluator) Refresh(ct *Ciphertext) (*Ciphertext, error) {
	return eval.bootstrap(ct, eval.bsk.TestPolyID)
}
