// Copyright (c) 2026, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

// Batch executor: parallel evaluation of one compiled RulePlan against
// N intent-specific Operands.
//
// The natural parallel-signing pattern is N transactions arriving in a
// single round; each one needs the same policy evaluated against its
// own encrypted inputs. This file evaluates them concurrently across
// the available CPU cores using a worker pool. The same entry point is
// the natural place to wire GPU dispatch later — when the FHE stack
// exposes a path that batches N evaluations in one kernel launch, this
// function is what swaps to it.
//
// Concurrency note: luxfi/fhe.Evaluator (and BitwiseEvaluator) hold
// internal scratch buffers used by blind-rotation. Sharing one
// Evaluator across goroutines is NOT safe — concurrent evaluators
// will race on those buffers and panic. Each worker therefore owns
// its own Engine constructed via the supplied EngineFactory. The
// BootstrapKey + Parameters they share are read-only and may be
// reused freely.

package policy

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/luxfi/fhe"
)

// EngineFactory builds a fresh Engine for one worker. Implementations
// typically close over a (Parameters, *BootstrapKey) pair.
type EngineFactory func() *Engine

// NewEngineFactory returns the canonical EngineFactory for a given
// FHE parameter set + bootstrap key. The returned factory allocates
// a fresh BitwiseEvaluator + Evaluator on each call; the caller is
// responsible for not invoking it more times than needed.
func NewEngineFactory(params fhe.Parameters, bsk *fhe.BootstrapKey) EngineFactory {
	return func() *Engine { return NewEngine(params, bsk) }
}

// BatchRequest is N transactions sharing one policy. Operands[i] is the
// encrypted input set for transaction i. Constants live alongside the
// request; the batch executor does not duplicate them.
type BatchRequest struct {
	// Inputs holds N per-intent encrypted input maps. len(Inputs) == N.
	Inputs []map[string]*fhe.BitCiphertext

	// Constants are the per-policy ciphertexts shared across all N
	// evaluations. They are the same pointers passed to single-shot
	// Evaluate; no copy is made. Ciphertexts are read-only during
	// evaluation, so sharing across workers is safe.
	Constants map[string]*fhe.BitCiphertext

	// Concurrency caps the number of worker goroutines (each owning
	// one Engine). Zero or negative means runtime.NumCPU(). The cap
	// is honoured exactly; overflow is queued and dispatched as
	// workers free.
	Concurrency int
}

// BatchResult carries the encrypted verdicts and timing metadata.
type BatchResult struct {
	// Verdicts[i] is the encrypted boolean produced by Inputs[i]. On
	// any per-intent failure the entire batch returns an error; partial
	// results are not surfaced.
	Verdicts []*fhe.Ciphertext

	// Latency is wall-clock time spent inside EvaluateBatch.
	Latency time.Duration
}

// EvaluateBatch fans N intents across a worker pool and returns N
// encrypted verdicts. Each worker owns its own Engine constructed via
// factory — required because luxfi/fhe.Evaluator is not goroutine-safe.
//
// Failures fail the whole batch — a stuck or noisy intent is treated
// as a deny signal upstream, which is the safe posture for a signing
// gate.
func (p *RulePlan) EvaluateBatch(ctx context.Context, factory EngineFactory, batch BatchRequest) (BatchResult, error) {
	if factory == nil {
		return BatchResult{}, errors.New("rule_executor: nil engine factory")
	}
	n := len(batch.Inputs)
	if n == 0 {
		return BatchResult{}, errors.New("rule_executor: empty batch")
	}

	workers := batch.Concurrency
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	if workers > n {
		workers = n
	}

	verdicts := make([]*fhe.Ciphertext, n)
	jobs := make(chan int, n)
	for i := 0; i < n; i++ {
		jobs <- i
	}
	close(jobs)

	var wg sync.WaitGroup
	errCh := make(chan error, workers)

	cctx, cancel := context.WithCancel(ctx)
	defer cancel()

	start := time.Now()

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			eng := factory()
			for i := range jobs {
				if cctx.Err() != nil {
					return
				}
				v, err := p.Evaluate(cctx, eng, Operands{
					Inputs:    batch.Inputs[i],
					Constants: batch.Constants,
				})
				if err != nil {
					select {
					case errCh <- fmt.Errorf("intent[%d]: %w", i, err):
						cancel()
					default:
					}
					return
				}
				verdicts[i] = v
			}
		}()
	}

	wg.Wait()
	close(errCh)

	if err, ok := <-errCh; ok {
		return BatchResult{}, err
	}

	return BatchResult{
		Verdicts: verdicts,
		Latency:  time.Since(start),
	}, nil
}
