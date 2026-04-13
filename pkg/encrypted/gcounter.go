// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package encrypted

import (
	"fmt"
	"sort"
	"sync"

	"github.com/luxfi/fhe"
)

// ErrUnauthorizedNode is returned when a nodeID is not in the authorized set.
var ErrUnauthorizedNode = fmt.Errorf("encrypted/gcounter: unauthorized nodeID")

// GCounter is a grow-only counter where each node's count is an FHE-encrypted
// unsigned integer. Merge takes the homomorphic max per node.
//
// Cost warning: merge requires a full unsigned comparison circuit per node.
// For a uint32 field, that is ~32 XNOR + 32 AND + 32 OR + 32 MUX = ~128
// bootstraps per node (~13 seconds at PN10QP27). Use this only for
// sensitive counters where the relay must not learn individual counts.
type GCounter struct {
	mu         sync.RWMutex
	state      map[string]*encUint // nodeID -> encrypted count
	bits       int                 // bit-width per count
	authorized map[string]bool     // nil = open (all nodeIDs allowed)
}

type encUint struct {
	cts []*fhe.Ciphertext // LSB-first
}

// NewGCounter creates an encrypted grow-only counter with the given
// bit-width per node count. If authorizedNodes is non-empty, only those
// nodeIDs may be used with Set and MergeGCounter. Pass nil or empty to
// allow any nodeID (open mode).
func NewGCounter(bits int, authorizedNodes ...string) *GCounter {
	g := &GCounter{
		state: make(map[string]*encUint),
		bits:  bits,
	}
	if len(authorizedNodes) > 0 {
		g.authorized = make(map[string]bool, len(authorizedNodes))
		for _, n := range authorizedNodes {
			g.authorized[n] = true
		}
	}
	return g
}

// Set stores the encrypted count for a node. The caller is responsible
// for encrypting the value; the counter stores it opaquely.
func (g *GCounter) Set(nodeID string, cts []*fhe.Ciphertext) error {
	if len(cts) != g.bits {
		return fmt.Errorf("encrypted/gcounter: expected %d bits, got %d", g.bits, len(cts))
	}
	if g.authorized != nil && !g.authorized[nodeID] {
		return fmt.Errorf("%w: %q", ErrUnauthorizedNode, nodeID)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.state[nodeID] = &encUint{cts: cts}
	return nil
}

// Get returns the encrypted count for a node, or nil if absent.
func (g *GCounter) Get(nodeID string) []*fhe.Ciphertext {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if e, ok := g.state[nodeID]; ok {
		return e.cts
	}
	return nil
}

// Nodes returns all node IDs in sorted order.
func (g *GCounter) Nodes() []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	ids := make([]string, 0, len(g.state))
	for id := range g.state {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Bits returns the configured bit-width.
func (g *GCounter) Bits() int { return g.bits }

// authorizedList returns the authorized node IDs as a sorted slice, or nil
// if the counter is in open mode. Used by Document encoding so Decode can
// reconstruct the same authorization policy. Sorting is for deterministic
// serialization across replicas.
func (g *GCounter) authorizedList() []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.authorized == nil {
		return nil
	}
	out := make([]string, 0, len(g.authorized))
	for n := range g.authorized {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// MergeGCounter merges two GCounters by taking the homomorphic max per
// node. Nodes present in only one counter are copied directly (no FHE ops).
//
// Gate count per shared node: ~4*bits bootstraps (compare + MUX).
func MergeGCounter(eval *fhe.Evaluator, a, b *GCounter) (*GCounter, error) {
	if a.bits != b.bits {
		return nil, fmt.Errorf("encrypted/gcounter: bit-width mismatch: %d vs %d", a.bits, b.bits)
	}

	a.mu.RLock()
	b.mu.RLock()
	defer a.mu.RUnlock()
	defer b.mu.RUnlock()

	result := NewGCounter(a.bits)
	// Inherit authorization from a (both should agree; a is the target).
	result.authorized = a.authorized

	// Copy a's state.
	for id, eu := range a.state {
		result.state[id] = eu
	}

	// Merge b's state: take homomorphic max where both exist.
	for id, beu := range b.state {
		if a.authorized != nil && !a.authorized[id] {
			return nil, fmt.Errorf("%w: %q during merge", ErrUnauthorizedNode, id)
		}
		aeu, exists := a.state[id]
		if !exists {
			result.state[id] = beu
			continue
		}
		// Homomorphic max: compare, then MUX.
		maxCts, err := homomorphicMax(eval, aeu.cts, beu.cts, a.bits)
		if err != nil {
			return nil, fmt.Errorf("encrypted/gcounter: node %q max: %w", id, err)
		}
		result.state[id] = &encUint{cts: maxCts}
	}

	return result, nil
}

// homomorphicMax returns MUX(bGtA, b, a) where bGtA is the encrypted
// comparison bit B > A, computed MSB-to-LSB. Both slices must be the
// same length (bits), LSB-first.
func homomorphicMax(eval *fhe.Evaluator, a, b []*fhe.Ciphertext, bits int) ([]*fhe.Ciphertext, error) {
	var bGtA, eqSoFar *fhe.Ciphertext

	for i := bits - 1; i >= 0; i-- {
		bitGt, err := eval.ANDNY(a[i], b[i])
		if err != nil {
			return nil, fmt.Errorf("bit %d ANDNY: %w", i, err)
		}
		bitEq, err := eval.XNOR(a[i], b[i])
		if err != nil {
			return nil, fmt.Errorf("bit %d XNOR: %w", i, err)
		}

		if i == bits-1 {
			bGtA = bitGt
			eqSoFar = bitEq
		} else {
			contrib, err := eval.AND(eqSoFar, bitGt)
			if err != nil {
				return nil, fmt.Errorf("bit %d AND: %w", i, err)
			}
			bGtA, err = eval.OR(bGtA, contrib)
			if err != nil {
				return nil, fmt.Errorf("bit %d OR: %w", i, err)
			}
			eqSoFar, err = eval.AND(eqSoFar, bitEq)
			if err != nil {
				return nil, fmt.Errorf("bit %d eq-chain: %w", i, err)
			}
		}
	}

	result := make([]*fhe.Ciphertext, bits)
	for i := 0; i < bits; i++ {
		v, err := eval.MUX(bGtA, b[i], a[i])
		if err != nil {
			return nil, fmt.Errorf("MUX bit %d: %w", i, err)
		}
		result[i] = v
	}
	return result, nil
}
