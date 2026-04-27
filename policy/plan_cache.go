// Copyright (c) 2026, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

// Plan cache: compile YAML once per policy version, reuse across every
// subsequent evaluation. The cache is keyed by (PolicyID, sha256(YAML))
// so any byte change in the policy document evicts the old entry —
// there is no "soft" policy invalidation, no TTL, no stale eviction
// after-the-fact. If the bytes match, the plan is reused; if not, the
// caller compiles a new one.
//
// The cache is a thin wrapper around sync.Map: lock-free reads on the
// hot path. Compile happens behind a singleflight-style lock so
// concurrent miss-by-key callers do not redundantly parse the same
// YAML.

package policy

import (
	"errors"
	"fmt"
	"sync"
)

// PlanLoader fetches the canonical YAML bytes for a given (policyID,
// policyHash) from F-Chain PolicyVault. Callers — typically the
// FHEVerifier in luxfi/mpc — supply this. The cache treats the loader
// as the source of truth: if the loader returns bytes whose sha256
// does not match the requested hash, GetOrCompile rejects the
// response.
type PlanLoader interface {
	LoadYAML(policyID string, policyHash [32]byte) ([]byte, error)
}

// PlanLoaderFunc adapts a function to PlanLoader.
type PlanLoaderFunc func(policyID string, policyHash [32]byte) ([]byte, error)

// LoadYAML calls f.
func (f PlanLoaderFunc) LoadYAML(policyID string, policyHash [32]byte) ([]byte, error) {
	return f(policyID, policyHash)
}

// PlanCache memoizes compiled RulePlans by (policyID, policyHash).
//
// The zero value is ready to use. Callers may share one PlanCache
// across all FHEVerifier instances in a process; entries never grow
// large (a RulePlan is ~hundreds of bytes plus retained YAML).
type PlanCache struct {
	plans sync.Map // map[planKey]*RulePlan
	mu    sync.Mutex
}

type planKey struct {
	id   string
	hash [32]byte
}

// ErrHashMismatch is returned by GetOrCompile when the loader returns
// bytes that do not hash to the requested PolicyHash. F-Chain MUST be
// authoritative on the bytes; serving a different policy than the
// caller asked for is a bug, not a backwards-compat case.
var ErrHashMismatch = errors.New("plan_cache: policy hash mismatch")

// GetOrCompile returns a cached RulePlan for (policyID, policyHash) or
// invokes loader to fetch the YAML bytes and compile a new one.
//
// Concurrent callers requesting the same key share the compile work:
// the first caller compiles, subsequent callers wait on the same
// mutex and see the cached result.
func (c *PlanCache) GetOrCompile(policyID string, policyHash [32]byte, loader PlanLoader) (*RulePlan, error) {
	if loader == nil {
		return nil, fmt.Errorf("plan_cache: nil loader")
	}
	if policyID == "" {
		return nil, fmt.Errorf("plan_cache: empty policy_id")
	}

	key := planKey{id: policyID, hash: policyHash}
	if v, ok := c.plans.Load(key); ok {
		return v.(*RulePlan), nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	// re-check inside the lock to avoid double-compile under contention
	if v, ok := c.plans.Load(key); ok {
		return v.(*RulePlan), nil
	}

	data, err := loader.LoadYAML(policyID, policyHash)
	if err != nil {
		return nil, fmt.Errorf("plan_cache: load %s: %w", policyID, err)
	}
	if got := HashYAML(data); got != policyHash {
		return nil, fmt.Errorf("%w: id=%s want=%x got=%x", ErrHashMismatch, policyID, policyHash[:8], got[:8])
	}

	plan, err := Compile(data)
	if err != nil {
		return nil, fmt.Errorf("plan_cache: compile %s: %w", policyID, err)
	}
	if plan.PolicyID != policyID {
		return nil, fmt.Errorf("plan_cache: policy_id mismatch in YAML: want=%s got=%s", policyID, plan.PolicyID)
	}
	c.plans.Store(key, plan)
	return plan, nil
}

// Forget evicts every cached entry for policyID, regardless of hash. A
// version bump on F-Chain that retires the prior bytes calls Forget so
// the next evaluation reloads.
func (c *PlanCache) Forget(policyID string) {
	c.plans.Range(func(k, _ any) bool {
		if k.(planKey).id == policyID {
			c.plans.Delete(k)
		}
		return true
	})
}

// Len returns the number of cached plans. Useful in tests to assert
// the cache hit/miss behaviour.
func (c *PlanCache) Len() int {
	n := 0
	c.plans.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}
