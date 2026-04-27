// Copyright (c) 2026, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package policy

import (
	"context"
	"errors"
	"fmt"

	"github.com/luxfi/fhe"
)

// ErrMissingOperand is returned when an EvaluationStep references a field
// or constant key that is not present in the input/constant map. Callers
// must populate every key referenced by the plan; partial maps are not
// accepted.
var ErrMissingOperand = errors.New("rule_executor: missing operand")

// Operands bundles the per-call inputs and the per-policy constants used
// during evaluation. Both maps are read-only during a single Evaluate
// call; the executor never writes to either.
//
// Inputs (per intent): encryptedAmount, encryptedDestination, encryptedSum.
// Constants (per policy version): encryptedLimit, encryptedAddrN, encryptedVelocityCap.
//
// The keys used here MUST match the YAML clause names verbatim. Mismatch
// returns ErrMissingOperand.
type Operands struct {
	Inputs    map[string]*fhe.BitCiphertext
	Constants map[string]*fhe.BitCiphertext
}

// Engine bundles the FHE evaluators a RulePlan needs.
//
// IMPORTANT: an Engine is NOT goroutine-safe. luxfi/fhe.Evaluator and
// BitwiseEvaluator hold internal scratch buffers used during blind
// rotation; concurrent calls into the same Engine race on those
// buffers. For parallel batch evaluation use EngineFactory and one
// Engine per worker — see rule_batch.go.
type Engine struct {
	Bit   *fhe.BitwiseEvaluator
	Gates *fhe.Evaluator
}

// NewEngine wires a fresh BitwiseEvaluator + Evaluator pair from the
// FHE network public material. The evaluators do not need a secret key.
func NewEngine(params fhe.Parameters, bsk *fhe.BootstrapKey) *Engine {
	return &Engine{
		Bit:   fhe.NewBitwiseEvaluator(params, bsk, nil),
		Gates: fhe.NewEvaluator(params, bsk),
	}
}

// Evaluate runs every step in order, then reduces the per-step verdicts
// via the plan's Combinator. Returns a single encrypted boolean.
//
// A single RulePlan may be Evaluate'd from N goroutines concurrently
// (the plan is read-only after Compile) — but each goroutine MUST pass
// its own Engine. See rule_batch.go for the canonical batch executor.
func (p *RulePlan) Evaluate(ctx context.Context, eng *Engine, ops Operands) (*fhe.Ciphertext, error) {
	if eng == nil || eng.Bit == nil || eng.Gates == nil {
		return nil, errors.New("rule_executor: nil engine")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	verdicts := make([]*fhe.Ciphertext, len(p.Steps))
	for i := range p.Steps {
		v, err := runStep(eng, &p.Steps[i], ops)
		if err != nil {
			return nil, fmt.Errorf("rule_executor: step %d (%s): %w", i, p.Steps[i].Name, err)
		}
		verdicts[i] = v
	}

	return reduce(eng, verdicts, p.Combinator)
}

// runStep dispatches a single EvaluationStep to its FHE primitive and
// returns the encrypted boolean verdict.
func runStep(eng *Engine, s *EvaluationStep, ops Operands) (*fhe.Ciphertext, error) {
	field, ok := ops.Inputs[s.FieldKey]
	if !ok || field == nil {
		return nil, fmt.Errorf("%w: input %q", ErrMissingOperand, s.FieldKey)
	}

	switch s.Op {
	case OpLt:
		c, err := lookupConst(ops, s.ConstKey)
		if err != nil {
			return nil, err
		}
		return eng.Bit.Lt(field, c)

	case OpLte:
		c, err := lookupConst(ops, s.ConstKey)
		if err != nil {
			return nil, err
		}
		return eng.Bit.Le(field, c)

	case OpEq:
		c, err := lookupConst(ops, s.ConstKey)
		if err != nil {
			return nil, err
		}
		return eng.Bit.Eq(field, c)

	case OpIn:
		return setMembership(eng, field, ops, s.ConstKeys)

	default:
		return nil, fmt.Errorf("rule_executor: unknown op %q", s.Op)
	}
}

// setMembership computes (field == c1) OR (field == c2) OR ... OR (field == cN).
// Cost is O(N) bootstraps; callers keep N small (typically <= 32).
func setMembership(eng *Engine, field *fhe.BitCiphertext, ops Operands, keys []string) (*fhe.Ciphertext, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: empty constants list", ErrMissingOperand)
	}
	var acc *fhe.Ciphertext
	for i, k := range keys {
		c, err := lookupConst(ops, k)
		if err != nil {
			return nil, err
		}
		eq, err := eng.Bit.Eq(field, c)
		if err != nil {
			return nil, fmt.Errorf("in[%d] eq: %w", i, err)
		}
		if acc == nil {
			acc = eq
			continue
		}
		acc, err = eng.Gates.OR(acc, eq)
		if err != nil {
			return nil, fmt.Errorf("in[%d] or: %w", i, err)
		}
	}
	return acc, nil
}

// reduce folds N per-step verdicts into one via Combinator. AND for
// "all must pass", OR for "any may pass". A single-step plan returns
// that step's verdict unchanged.
func reduce(eng *Engine, verdicts []*fhe.Ciphertext, comb Combinator) (*fhe.Ciphertext, error) {
	if len(verdicts) == 0 {
		return nil, errors.New("rule_executor: empty verdict slice")
	}
	if len(verdicts) == 1 {
		return verdicts[0], nil
	}
	acc := verdicts[0]
	for i := 1; i < len(verdicts); i++ {
		var err error
		switch comb {
		case CombAnd:
			acc, err = eng.Gates.AND(acc, verdicts[i])
		case CombOr:
			acc, err = eng.Gates.OR(acc, verdicts[i])
		default:
			return nil, fmt.Errorf("rule_executor: unknown combinator %q", comb)
		}
		if err != nil {
			return nil, fmt.Errorf("reduce[%d]: %w", i, err)
		}
	}
	return acc, nil
}

// lookupConst returns the ciphertext registered under key, or
// ErrMissingOperand if absent.
func lookupConst(ops Operands, key string) (*fhe.BitCiphertext, error) {
	c, ok := ops.Constants[key]
	if !ok || c == nil {
		return nil, fmt.Errorf("%w: constant %q", ErrMissingOperand, key)
	}
	return c, nil
}
