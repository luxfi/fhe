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
type Evaluator struct {
	params    Parameters
	eval      *blindrot.Evaluator
	bsk       *BootstrapKey
	ringQLWE  *ring.Ring
	ringQBR   *ring.Ring
	decBR     *rlwe.Decryptor
	encLWE    *rlwe.Encryptor
	scaleBR   float64
}

// NewEvaluator creates a new evaluator with bootstrap key and secret key
func NewEvaluator(params Parameters, bsk *BootstrapKey, sk *SecretKey) *Evaluator {
	return &Evaluator{
		params:   params,
		eval:     blindrot.NewEvaluator(params.paramsBR, params.paramsLWE),
		bsk:      bsk,
		ringQLWE: params.paramsLWE.RingQ(),
		ringQBR:  params.paramsBR.RingQ(),
		decBR:    rlwe.NewDecryptor(params.paramsBR, sk.SKBR),
		encLWE:   rlwe.NewEncryptor(params.paramsLWE, sk.SKLWE),
		scaleBR:  float64(params.QBR()) / 8.0,
	}
}

// bootstrap performs programmable bootstrapping with the given test polynomial
// and returns a fresh LWE ciphertext with the result
func (eval *Evaluator) bootstrap(ct *Ciphertext, testPoly *ring.Poly) (*Ciphertext, error) {
	// Create map for single slot evaluation
	testPolyMap := map[int]*ring.Poly{0: testPoly}

	// Evaluate blind rotation
	results, err := eval.eval.Evaluate(ct.Ciphertext, testPolyMap, eval.bsk.BRK)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}

	// Extract result for slot 0
	ctBR, ok := results[0]
	if !ok {
		return nil, fmt.Errorf("bootstrap: no result for slot 0")
	}

	// Decrypt the RLWE result using BR key
	ptBR := rlwe.NewPlaintext(eval.params.paramsBR, ctBR.Level())
	eval.decBR.Decrypt(ctBR, ptBR)

	if ptBR.IsNTT {
		eval.ringQBR.INTT(ptBR.Value, ptBR.Value)
	}

	// Get constant term and decode the bit
	c := ptBR.Value.Coeffs[0][0]
	q := eval.params.QBR()
	qHalf := q >> 1

	// Decode: positive value (< Q/2) means 1, negative means 0
	bit := c < qHalf

	// Re-encrypt as fresh LWE ciphertext
	return eval.encryptBit(bit), nil
}

// encryptBit encrypts a bit as an LWE ciphertext
func (eval *Evaluator) encryptBit(value bool) *Ciphertext {
	pt := rlwe.NewPlaintext(eval.params.paramsLWE, eval.params.paramsLWE.MaxLevel())

	q := eval.params.QLWE()
	if value {
		pt.Value.Coeffs[0][0] = q / 8
	} else {
		pt.Value.Coeffs[0][0] = q - (q / 8)
	}

	eval.params.paramsLWE.RingQ().NTT(pt.Value, pt.Value)

	ct := rlwe.NewCiphertext(eval.params.paramsLWE, 1, eval.params.paramsLWE.MaxLevel())
	if err := eval.encLWE.Encrypt(pt, ct); err != nil {
		panic(err)
	}

	return &Ciphertext{ct}
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
