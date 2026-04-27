// Copyright (c) 2026, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

// Package policy implements an FHE-encoded transaction policy program.
//
// A PolicyProgram holds a set of encrypted policy clauses (amount limit,
// destination allowlist, velocity cap). The program is evaluated against an
// EncryptedIntent (encrypted amount, destination hash, running velocity
// total) homomorphically; the result is a single encrypted boolean that an
// authorized party must decrypt — either with the secret key (single-key
// dev mode) or via the F-Chain threshold-decrypt protocol (production).
//
// Ciphertexts are bit-sliced encryptions built from luxfi/fhe's
// BitwiseEvaluator. The same FHE network keys (F-Chain public bootstrap key)
// encrypt both the policy and the intent, so policy ciphertexts can be
// stored on chain and reused across many evaluations.
package policy

import (
	"errors"
	"fmt"

	"github.com/luxfi/fhe"
)

// ClauseSet groups the encrypted bounds and allowlist for a single wallet
// policy version. Every field is a ciphertext under the F-Chain network key.
//
// Allowlist is a slice of encrypted destination hashes. Membership is checked
// by computing OR over equality with each entry.
type ClauseSet struct {
	AmountLimit *fhe.BitCiphertext   // amount < AmountLimit
	VelocityCap *fhe.BitCiphertext   // velocityWindow < VelocityCap
	Allowlist   []*fhe.BitCiphertext // destination ∈ Allowlist
}

// Intent is the per-transaction encrypted input to a PolicyProgram. The
// caller (M-Chain MPC node, wallet client) encrypts these under the same
// network key the policy was encoded under and submits them for evaluation.
type Intent struct {
	Amount          *fhe.BitCiphertext
	DestinationHash *fhe.BitCiphertext
	VelocityWindow  *fhe.BitCiphertext
}

// PolicyProgram evaluates a ClauseSet over an Intent homomorphically.
//
// The evaluator never sees plaintexts. It only needs the public bootstrap
// key of the F-Chain FHE network — no secret key required.
type PolicyProgram struct {
	bitEval *fhe.BitwiseEvaluator
	gates   *fhe.Evaluator
	clauses ClauseSet
}

// New builds a PolicyProgram from F-Chain FHE parameters, the public
// bootstrap key, and the encrypted clause set.
//
// params and bsk MUST come from the same FHE key generation as the
// ciphertexts in clauses; mixing keys produces undefined plaintexts.
func New(params fhe.Parameters, bsk *fhe.BootstrapKey, clauses ClauseSet) (*PolicyProgram, error) {
	if bsk == nil {
		return nil, errors.New("policy: nil bootstrap key")
	}
	if clauses.AmountLimit == nil || clauses.VelocityCap == nil {
		return nil, errors.New("policy: clauses missing required bounds")
	}
	return &PolicyProgram{
		// sk is deprecated/unused in NewBitwiseEvaluator; passing nil is correct.
		bitEval: fhe.NewBitwiseEvaluator(params, bsk, nil),
		gates:   fhe.NewEvaluator(params, bsk),
		clauses: clauses,
	}, nil
}

// Evaluate returns an encrypted boolean: 1 iff the intent satisfies every
// clause. The result must be decrypted (single-key) or threshold-decrypted
// (F-Chain MPC committee) to learn the verdict.
//
// Logic:
//
//	allow = (amount < AmountLimit)
//	      ∧ (velocityWindow < VelocityCap)
//	      ∧ (destination ∈ Allowlist)
//
// An empty Allowlist returns an error: there is intentionally no "wildcard"
// mode. If there are no entries, nothing is allowed. This matches a
// deny-by-default posture and avoids the trap of shipping a policy that
// silently allows everything if its allowlist is blanked.
func (p *PolicyProgram) Evaluate(in Intent) (*fhe.Ciphertext, error) {
	if in.Amount == nil || in.DestinationHash == nil || in.VelocityWindow == nil {
		return nil, errors.New("policy: intent missing required ciphertexts")
	}
	if len(p.clauses.Allowlist) == 0 {
		return nil, errors.New("policy: empty allowlist denies all transactions")
	}

	amountOK, err := p.bitEval.Lt(in.Amount, p.clauses.AmountLimit)
	if err != nil {
		return nil, fmt.Errorf("policy: amount clause: %w", err)
	}

	velocityOK, err := p.bitEval.Lt(in.VelocityWindow, p.clauses.VelocityCap)
	if err != nil {
		return nil, fmt.Errorf("policy: velocity clause: %w", err)
	}

	destOK, err := p.allowlistContains(in.DestinationHash)
	if err != nil {
		return nil, fmt.Errorf("policy: allowlist clause: %w", err)
	}

	combined, err := p.gates.AND(amountOK, velocityOK)
	if err != nil {
		return nil, fmt.Errorf("policy: AND amount,velocity: %w", err)
	}
	combined, err = p.gates.AND(combined, destOK)
	if err != nil {
		return nil, fmt.Errorf("policy: AND combined,dest: %w", err)
	}
	return combined, nil
}

// allowlistContains returns an encrypted bool: 1 iff dest equals any entry.
//
// We OR the per-entry equalities. Cost is O(len(allowlist)) bootstraps; the
// allowlist is intentionally kept small (per-tier whitelist, typically <= 32
// entries) to keep evaluation latency tractable.
func (p *PolicyProgram) allowlistContains(dest *fhe.BitCiphertext) (*fhe.Ciphertext, error) {
	var acc *fhe.Ciphertext
	for i, entry := range p.clauses.Allowlist {
		if entry == nil {
			return nil, fmt.Errorf("policy: allowlist entry %d is nil", i)
		}
		eq, err := p.bitEval.Eq(dest, entry)
		if err != nil {
			return nil, fmt.Errorf("policy: allowlist[%d] eq: %w", i, err)
		}
		if acc == nil {
			acc = eq
			continue
		}
		acc, err = p.gates.OR(acc, eq)
		if err != nil {
			return nil, fmt.Errorf("policy: allowlist[%d] or: %w", i, err)
		}
	}
	return acc, nil
}
