// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package threshold implements threshold FHE with LSSS (Linear Secret Sharing Scheme).
// LSSS enables dynamic resharing: adding/removing nodes without full key regeneration.
package threshold

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// Prime is the 2048-bit MODP Group 14 safe prime from RFC 3526 §3.
// It is p = 2q + 1 with q = (p-1)/2 also prime (verified via Miller-Rabin
// in TestPrime_IsSafePrime). Replaces the earlier 256-bit prime whose
// (p-1)/2 factored into six primes — making Feldman VSS commitments
// vulnerable to Pohlig-Hellman reduction to the smallest factor.
//
// Reference: RFC 3526 §3, "Group 14" — a 2048-bit MODP group widely deployed
// in IKE/IKEv2 and TLS. Security level is 112-bit classical (NIST SP 800-56A)
// which is sufficient for the VSS commitment binding; the Shamir secrets
// themselves are FHE key-share values whose security does not rely on this
// prime's hardness.
var Prime = mustParseBig("" +
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
	"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
	"15728E5A8AACAA68FFFFFFFFFFFFFFFF")

func mustParseBig(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("invalid hex string")
	}
	return n
}

// Share represents a secret share in LSSS
type Share struct {
	Index int      // Share index (1-based, x-coordinate)
	Value *big.Int // Share value (y-coordinate)
}

// ShareSet is a collection of shares
type ShareSet struct {
	Threshold int      // Minimum shares needed for reconstruction
	Total     int      // Total number of shares
	Shares    []*Share // The shares
}

// SplitSecret splits a secret into n shares with threshold t
// Uses Shamir's Secret Sharing over a prime field
func SplitSecret(secret *big.Int, threshold, total int) (*ShareSet, error) {
	if threshold < 1 || threshold > total {
		return nil, fmt.Errorf("invalid threshold: t=%d, n=%d", threshold, total)
	}

	// Generate random polynomial coefficients
	// f(x) = secret + a1*x + a2*x^2 + ... + a_{t-1}*x^{t-1}
	coeffs := make([]*big.Int, threshold)
	coeffs[0] = new(big.Int).Set(secret) // Constant term is the secret

	for i := 1; i < threshold; i++ {
		coeff, err := rand.Int(rand.Reader, Prime)
		if err != nil {
			return nil, fmt.Errorf("failed to generate coefficient: %w", err)
		}
		coeffs[i] = coeff
	}

	// Evaluate polynomial at x = 1, 2, ..., n
	shares := make([]*Share, total)
	for i := 0; i < total; i++ {
		x := big.NewInt(int64(i + 1))
		y := evaluatePolynomial(coeffs, x)
		shares[i] = &Share{
			Index: i + 1,
			Value: y,
		}
	}

	return &ShareSet{
		Threshold: threshold,
		Total:     total,
		Shares:    shares,
	}, nil
}

// evaluatePolynomial evaluates a polynomial at point x using Horner's method
func evaluatePolynomial(coeffs []*big.Int, x *big.Int) *big.Int {
	result := new(big.Int).Set(coeffs[len(coeffs)-1])

	for i := len(coeffs) - 2; i >= 0; i-- {
		result.Mul(result, x)
		result.Add(result, coeffs[i])
		result.Mod(result, Prime)
	}

	return result
}

// RecombineShares reconstructs the secret from t shares using Lagrange interpolation
func RecombineShares(shares []*Share, threshold int) (*big.Int, error) {
	if len(shares) < threshold {
		return nil, fmt.Errorf("not enough shares: have %d, need %d", len(shares), threshold)
	}

	// Use only the first t shares
	shares = shares[:threshold]

	// Lagrange interpolation at x = 0
	secret := big.NewInt(0)

	for i, si := range shares {
		// Calculate Lagrange basis polynomial at x=0
		numerator := big.NewInt(1)
		denominator := big.NewInt(1)

		xi := big.NewInt(int64(si.Index))

		for j, sj := range shares {
			if i == j {
				continue
			}
			xj := big.NewInt(int64(sj.Index))

			// numerator *= (0 - xj) = -xj
			numerator.Mul(numerator, new(big.Int).Neg(xj))
			numerator.Mod(numerator, Prime)

			// denominator *= (xi - xj)
			diff := new(big.Int).Sub(xi, xj)
			denominator.Mul(denominator, diff)
			denominator.Mod(denominator, Prime)
		}

		// Compute basis = numerator / denominator mod Prime
		denominatorInv := new(big.Int).ModInverse(denominator, Prime)
		if denominatorInv == nil {
			return nil, fmt.Errorf("failed to compute modular inverse")
		}

		basis := new(big.Int).Mul(numerator, denominatorInv)
		basis.Mod(basis, Prime)

		// secret += si.Value * basis
		term := new(big.Int).Mul(si.Value, basis)
		secret.Add(secret, term)
		secret.Mod(secret, Prime)
	}

	// Ensure positive result
	if secret.Sign() < 0 {
		secret.Add(secret, Prime)
	}

	return secret, nil
}

// Reshare generates new shares for a potentially different threshold/total
// without reconstructing the secret. Each old share holder contributes a
// sub-sharing of their share, and the new shares are the column-sums of
// those sub-sharings. The secret is never materialized.
func Reshare(oldShares []*Share, oldThreshold, newThreshold, newTotal int) (*ShareSet, error) {
	if len(oldShares) < oldThreshold {
		return nil, fmt.Errorf("not enough shares to reshare: have %d, need %d", len(oldShares), oldThreshold)
	}

	// Use exactly oldThreshold shares.
	used := oldShares[:oldThreshold]

	// Each party i computes the Lagrange coefficient for evaluation at 0
	// (the secret is f(0)), then creates a random polynomial of degree
	// newThreshold-1 whose constant term is lambda_i * share_i. The sum
	// of these polynomials evaluated at new indices gives the new shares.

	// Accumulate new shares additively.
	newValues := make([]*big.Int, newTotal)
	for j := 0; j < newTotal; j++ {
		newValues[j] = big.NewInt(0)
	}

	for i, si := range used {
		// Compute Lagrange coefficient lambda_i at x=0.
		lambda := lagrangeCoeffAt0(used, i)

		// Constant term = lambda_i * si.Value mod Prime.
		c0 := new(big.Int).Mul(lambda, si.Value)
		c0.Mod(c0, Prime)

		// Build a random polynomial of degree newThreshold-1 with c0 as constant.
		coeffs := make([]*big.Int, newThreshold)
		coeffs[0] = c0
		for k := 1; k < newThreshold; k++ {
			coeff, err := rand.Int(rand.Reader, Prime)
			if err != nil {
				return nil, fmt.Errorf("reshare: random coeff: %w", err)
			}
			coeffs[k] = coeff
		}

		// Evaluate the polynomial at new indices 1..newTotal and add.
		for j := 0; j < newTotal; j++ {
			x := big.NewInt(int64(j + 1))
			y := evaluatePolynomial(coeffs, x)
			newValues[j].Add(newValues[j], y)
			newValues[j].Mod(newValues[j], Prime)
		}
	}

	shares := make([]*Share, newTotal)
	for j := 0; j < newTotal; j++ {
		shares[j] = &Share{Index: j + 1, Value: newValues[j]}
	}

	return &ShareSet{
		Threshold: newThreshold,
		Total:     newTotal,
		Shares:    shares,
	}, nil
}

// lagrangeCoeffAt0 computes the Lagrange basis coefficient for share i
// evaluated at x=0 among the given set of shares.
func lagrangeCoeffAt0(shares []*Share, i int) *big.Int {
	num := big.NewInt(1)
	den := big.NewInt(1)
	xi := big.NewInt(int64(shares[i].Index))

	for j, sj := range shares {
		if i == j {
			continue
		}
		xj := big.NewInt(int64(sj.Index))
		// num *= (0 - xj) = -xj
		num.Mul(num, new(big.Int).Neg(xj))
		num.Mod(num, Prime)
		// den *= (xi - xj)
		diff := new(big.Int).Sub(xi, xj)
		den.Mul(den, diff)
		den.Mod(den, Prime)
	}

	denInv := new(big.Int).ModInverse(den, Prime)
	result := new(big.Int).Mul(num, denInv)
	result.Mod(result, Prime)
	if result.Sign() < 0 {
		result.Add(result, Prime)
	}
	return result
}

// AddShare adds a new share for a new party without revealing the secret.
// The existing parties compute a partial share and combine them.
// Returns the share for the new party at newIndex.
func AddShare(existingShares []*Share, threshold, newIndex int) (*Share, error) {
	if len(existingShares) < threshold {
		return nil, fmt.Errorf("not enough shares: have %d, need %d", len(existingShares), threshold)
	}

	// Compute the share at newIndex using Lagrange interpolation
	newValue := big.NewInt(0)
	shares := existingShares[:threshold]

	xNew := big.NewInt(int64(newIndex))

	for i, si := range shares {
		numerator := big.NewInt(1)
		denominator := big.NewInt(1)
		xi := big.NewInt(int64(si.Index))

		for j, sj := range shares {
			if i == j {
				continue
			}
			xj := big.NewInt(int64(sj.Index))

			// numerator *= (xNew - xj)
			diff := new(big.Int).Sub(xNew, xj)
			numerator.Mul(numerator, diff)
			numerator.Mod(numerator, Prime)

			// denominator *= (xi - xj)
			diff2 := new(big.Int).Sub(xi, xj)
			denominator.Mul(denominator, diff2)
			denominator.Mod(denominator, Prime)
		}

		denominatorInv := new(big.Int).ModInverse(denominator, Prime)
		if denominatorInv == nil {
			return nil, fmt.Errorf("failed to compute modular inverse")
		}

		basis := new(big.Int).Mul(numerator, denominatorInv)
		basis.Mod(basis, Prime)

		term := new(big.Int).Mul(si.Value, basis)
		newValue.Add(newValue, term)
		newValue.Mod(newValue, Prime)
	}

	if newValue.Sign() < 0 {
		newValue.Add(newValue, Prime)
	}

	return &Share{
		Index: newIndex,
		Value: newValue,
	}, nil
}

// RefreshShares refreshes all shares without changing the secret.
// This is useful for proactive security - even if some shares are compromised,
// refreshing invalidates old shares.
func RefreshShares(shares *ShareSet) (*ShareSet, error) {
	if len(shares.Shares) < shares.Threshold {
		return nil, fmt.Errorf("not enough shares to refresh")
	}

	// Generate a random polynomial with zero constant term
	// This adds randomness to shares without changing the secret
	zeroCoeffs := make([]*big.Int, shares.Threshold)
	zeroCoeffs[0] = big.NewInt(0) // Zero constant term

	for i := 1; i < shares.Threshold; i++ {
		coeff, err := rand.Int(rand.Reader, Prime)
		if err != nil {
			return nil, fmt.Errorf("failed to generate coefficient: %w", err)
		}
		zeroCoeffs[i] = coeff
	}

	// Add the zero-polynomial evaluations to each share
	newShares := make([]*Share, len(shares.Shares))
	for i, s := range shares.Shares {
		x := big.NewInt(int64(s.Index))
		delta := evaluatePolynomial(zeroCoeffs, x)

		newValue := new(big.Int).Add(s.Value, delta)
		newValue.Mod(newValue, Prime)

		newShares[i] = &Share{
			Index: s.Index,
			Value: newValue,
		}
	}

	return &ShareSet{
		Threshold: shares.Threshold,
		Total:     shares.Total,
		Shares:    newShares,
	}, nil
}

// VerifyShare verifies a share against a set of public commitments.
// Uses Feldman's VSS scheme.
type Commitment struct {
	Values []*big.Int // g^{a_i} for each coefficient
}

// Generator for commitments. Since Prime is a safe prime p = 2q+1, the
// quadratic residue subgroup has order q. g = 2^2 mod p is a generator
// of this subgroup (order q, not order p-1).
var Generator = new(big.Int).Exp(big.NewInt(2), big.NewInt(2), Prime)

// ComputeCommitments computes Feldman VSS commitments for the polynomial
func ComputeCommitments(coeffs []*big.Int) *Commitment {
	commitments := make([]*big.Int, len(coeffs))
	for i, coeff := range coeffs {
		// g^coeff mod Prime
		commitments[i] = new(big.Int).Exp(Generator, coeff, Prime)
	}
	return &Commitment{Values: commitments}
}

// VerifyShare verifies that a share is consistent with the commitments
func VerifyShare(share *Share, commitment *Commitment) bool {
	if len(commitment.Values) == 0 {
		return false
	}

	// LHS: g^share
	lhs := new(big.Int).Exp(Generator, share.Value, Prime)

	// RHS: product of C_i^{x^i}
	x := big.NewInt(int64(share.Index))
	rhs := big.NewInt(1)
	xPow := big.NewInt(1)

	for _, c := range commitment.Values {
		// C_i^{x^i}
		term := new(big.Int).Exp(c, xPow, Prime)
		rhs.Mul(rhs, term)
		rhs.Mod(rhs, Prime)

		xPow.Mul(xPow, x)
		xPow.Mod(xPow, Prime)
	}

	return lhs.Cmp(rhs) == 0
}
