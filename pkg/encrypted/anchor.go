// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package encrypted

import (
	"context"
	"crypto/sha256"
	"fmt"
)

// AnchorClient is the minimal surface required to checkpoint a Document's
// StateRoot onto a blockchain via CRDTAnchor.sol. This package intentionally
// does not depend on go-ethereum or any specific RPC library — callers pass
// in their own client that adapts viem / ethers / ethclient / etc.
//
// Implementations must:
//   - send a transaction calling CRDTAnchor.checkpoint(docID, root, opCount)
//   - return nil only on confirmed inclusion (or the RPC's equivalent)
//   - surface RPC errors without retrying (retry/backoff is caller's concern)
type AnchorClient interface {
	Checkpoint(ctx context.Context, docID [32]byte, root [32]byte, opCount uint64) error
}

// Anchor submits the document's current StateRoot to the configured
// AnchorClient. The docID is derived deterministically from the document's
// string ID via SHA-256 so every replica produces the same on-chain key.
//
// Typical caller: a cron job on the leader replica, or a client-side hook
// triggered after every N writes. Do NOT call this on every Set — on-chain
// gas dominates; batch via opCount delta thresholds instead.
//
// Returns the (docID, root, opCount) that was submitted so the caller can
// log / record the checkpoint for reconciliation.
func (d *Document) Anchor(ctx context.Context, client AnchorClient) ([32]byte, [32]byte, uint64, error) {
	if client == nil {
		return [32]byte{}, [32]byte{}, 0, fmt.Errorf("encrypted/anchor: nil client")
	}
	root, err := d.StateRoot()
	if err != nil {
		return [32]byte{}, [32]byte{}, 0, fmt.Errorf("encrypted/anchor: state root: %w", err)
	}
	docID := DocIDHash(d.ID())
	opCount := d.OpCount()
	if err := client.Checkpoint(ctx, docID, root, opCount); err != nil {
		return docID, root, opCount, fmt.Errorf("encrypted/anchor: checkpoint: %w", err)
	}
	return docID, root, opCount, nil
}

// DocIDHash returns the canonical on-chain identifier for a document ID
// string. Exposed so callers can look up existing checkpoints via
// CRDTAnchor.latest(owner, DocIDHash(id)).
func DocIDHash(id string) [32]byte {
	return sha256.Sum256([]byte(id))
}
