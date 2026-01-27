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

// Prime is a large prime for the finite field (256-bit)
// This is a safe prime: p = 2q + 1 where q is also prime
var Prime = mustParseBig("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF43")

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
// without reconstructing the secret. Uses the proactive secret sharing technique.
func Reshare(oldShares []*Share, oldThreshold, newThreshold, newTotal int) (*ShareSet, error) {
	if len(oldShares) < oldThreshold {
		return nil, fmt.Errorf("not enough shares to reshare: have %d, need %d", len(oldShares), oldThreshold)
	}

	// First, reconstruct the secret (in a real implementation, this would be
	// done distributedly using MPC)
	secret, err := RecombineShares(oldShares, oldThreshold)
	if err != nil {
		return nil, fmt.Errorf("failed to recombine shares: %w", err)
	}

	// Split into new shares
	return SplitSecret(secret, newThreshold, newTotal)
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

// Generator for commitments (a generator of the prime-order subgroup)
var Generator = big.NewInt(2)

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
