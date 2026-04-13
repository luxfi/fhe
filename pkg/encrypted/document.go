// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package encrypted

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"sort"
	"sync"

	"github.com/luxfi/fhe"
	"golang.org/x/crypto/sha3"
)

// Document is a named collection of encrypted CRDT fields, mirroring
// hanzo/base/crdt.Document but with FHE-encrypted values. Each field is
// one of: Register (LWW), ORSet, or GCounter.
//
// The Document itself never decrypts. It stores opaque ciphertexts and
// delegates merge to the type-specific functions. A relay holding only
// the evaluation key can merge two Documents without seeing plaintext.
//
// writeCount is incremented on every local Set* and every applied Merge;
// combined with the structural root (field names, kinds, bit widths) it
// yields a deterministic StateRoot that is stable across replicas
// regardless of ciphertext non-determinism.
type Document struct {
	mu         sync.RWMutex
	id         string
	registers  map[string]*Register
	orsets     map[string]*ORSet
	gcounters  map[string]*GCounter
	writeCount uint64
}

// NewDocument creates an empty encrypted Document.
func NewDocument(id string) *Document {
	return &Document{
		id:        id,
		registers: make(map[string]*Register),
		orsets:    make(map[string]*ORSet),
		gcounters: make(map[string]*GCounter),
	}
}

// OpCount returns the cumulative count of local Set* and applied Merge
// operations. Used together with StateRoot for on-chain anchoring.
func (d *Document) OpCount() uint64 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.writeCount
}

// ID returns the document identifier.
func (d *Document) ID() string { return d.id }

// SetRegister stores an encrypted LWW Register under the given field name.
func (d *Document) SetRegister(field string, r *Register) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.registers[field] = r
	d.writeCount++
}

// GetRegister returns the register for a field, or nil.
func (d *Document) GetRegister(field string) *Register {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.registers[field]
}

// SetORSet stores an encrypted OR-Set under the given field name.
func (d *Document) SetORSet(field string, s *ORSet) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.orsets[field] = s
	d.writeCount++
}

// GetORSet returns the OR-Set for a field, or nil.
func (d *Document) GetORSet(field string) *ORSet {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.orsets[field]
}

// SetGCounter stores an encrypted GCounter under the given field name.
func (d *Document) SetGCounter(field string, c *GCounter) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.gcounters[field] = c
	d.writeCount++
}

// GetGCounter returns the GCounter for a field, or nil.
func (d *Document) GetGCounter(field string) *GCounter {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.gcounters[field]
}

// Merge merges another Document into this one. Registers use LWW merge,
// OR-Sets use tag union, GCounters use homomorphic max. The evaluator is
// required for Register and GCounter merges (which perform FHE ops); it
// may be nil if the document contains only OR-Sets.
func (d *Document) Merge(eval *fhe.Evaluator, other *Document) error {
	other.mu.RLock()
	defer other.mu.RUnlock()
	d.mu.Lock()
	defer d.mu.Unlock()

	for name, otherReg := range other.registers {
		if existing, ok := d.registers[name]; ok {
			if eval == nil {
				return fmt.Errorf("encrypted/document: evaluator required for register merge on field %q", name)
			}
			merged, err := MergeLWW(eval, existing, otherReg)
			if err != nil {
				return fmt.Errorf("encrypted/document: merge register %q: %w", name, err)
			}
			d.registers[name] = merged
		} else {
			d.registers[name] = otherReg
		}
	}

	for name, otherSet := range other.orsets {
		if existing, ok := d.orsets[name]; ok {
			d.orsets[name] = MergeORSet(existing, otherSet)
		} else {
			d.orsets[name] = otherSet
		}
	}

	for name, otherCtr := range other.gcounters {
		if existing, ok := d.gcounters[name]; ok {
			if eval == nil {
				return fmt.Errorf("encrypted/document: evaluator required for gcounter merge on field %q", name)
			}
			merged, err := MergeGCounter(eval, existing, otherCtr)
			if err != nil {
				return fmt.Errorf("encrypted/document: merge gcounter %q: %w", name, err)
			}
			d.gcounters[name] = merged
		} else {
			d.gcounters[name] = otherCtr
		}
	}

	// Every merge counts as a single write event for StateRoot purposes.
	// Two replicas that have applied the same set of local Sets plus the
	// same set of incoming Merges end with identical writeCount, giving
	// the same StateRoot regardless of ordering.
	d.writeCount++
	return nil
}

// MarshalBinary serializes the entire Document for storage or transport.
func (d *Document) MarshalBinary() ([]byte, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)

	if err := enc.Encode(d.id); err != nil {
		return nil, err
	}
	// writeCount — needed so a replica restored from disk produces the
	// same StateRoot as it had before shutdown.
	if err := enc.Encode(d.writeCount); err != nil {
		return nil, err
	}

	// Registers
	if err := enc.Encode(len(d.registers)); err != nil {
		return nil, err
	}
	for _, name := range sortedKeys(d.registers) {
		if err := enc.Encode(name); err != nil {
			return nil, err
		}
		data, err := MarshalRegister(d.registers[name])
		if err != nil {
			return nil, fmt.Errorf("register %q: %w", name, err)
		}
		if err := enc.Encode(data); err != nil {
			return nil, err
		}
	}

	// ORSets
	if err := enc.Encode(len(d.orsets)); err != nil {
		return nil, err
	}
	for _, name := range sortedKeysORSet(d.orsets) {
		if err := enc.Encode(name); err != nil {
			return nil, err
		}
		data, err := MarshalORSet(d.orsets[name])
		if err != nil {
			return nil, fmt.Errorf("orset %q: %w", name, err)
		}
		if err := enc.Encode(data); err != nil {
			return nil, err
		}
	}

	// GCounters
	if err := enc.Encode(len(d.gcounters)); err != nil {
		return nil, err
	}
	for _, name := range sortedKeysGCounter(d.gcounters) {
		if err := enc.Encode(name); err != nil {
			return nil, err
		}
		ctr := d.gcounters[name]
		if err := enc.Encode(ctr.bits); err != nil {
			return nil, err
		}
		// Persist the authorized node list so Decode can rebuild a counter
		// that still rejects fabricated nodeIDs. Nil list = open mode.
		authorized := ctr.authorizedList()
		if err := enc.Encode(authorized); err != nil {
			return nil, err
		}
		nodes := ctr.Nodes()
		if err := enc.Encode(len(nodes)); err != nil {
			return nil, err
		}
		for _, nid := range nodes {
			if err := enc.Encode(nid); err != nil {
				return nil, err
			}
			if err := encodeCiphertexts(&buf, ctr.state[nid].cts); err != nil {
				return nil, fmt.Errorf("gcounter %q node %q: %w", name, nid, err)
			}
		}
	}

	return buf.Bytes(), nil
}

// UnmarshalBinary deserializes a Document.
func (d *Document) UnmarshalBinary(data []byte) error {
	r := bytes.NewReader(data)
	dec := gob.NewDecoder(r)

	if err := dec.Decode(&d.id); err != nil {
		return err
	}
	if err := dec.Decode(&d.writeCount); err != nil {
		return err
	}

	// Registers
	var nRegs int
	if err := dec.Decode(&nRegs); err != nil {
		return err
	}
	d.registers = make(map[string]*Register, nRegs)
	for i := 0; i < nRegs; i++ {
		var name string
		if err := dec.Decode(&name); err != nil {
			return err
		}
		var regData []byte
		if err := dec.Decode(&regData); err != nil {
			return err
		}
		reg, err := UnmarshalRegister(regData)
		if err != nil {
			return fmt.Errorf("register %q: %w", name, err)
		}
		d.registers[name] = reg
	}

	// ORSets
	var nSets int
	if err := dec.Decode(&nSets); err != nil {
		return err
	}
	d.orsets = make(map[string]*ORSet, nSets)
	for i := 0; i < nSets; i++ {
		var name string
		if err := dec.Decode(&name); err != nil {
			return err
		}
		var setData []byte
		if err := dec.Decode(&setData); err != nil {
			return err
		}
		s, err := UnmarshalORSet(setData)
		if err != nil {
			return fmt.Errorf("orset %q: %w", name, err)
		}
		d.orsets[name] = s
	}

	// GCounters
	var nCtrs int
	if err := dec.Decode(&nCtrs); err != nil {
		return err
	}
	d.gcounters = make(map[string]*GCounter, nCtrs)
	for i := 0; i < nCtrs; i++ {
		var name string
		if err := dec.Decode(&name); err != nil {
			return err
		}
		var bits int
		if err := dec.Decode(&bits); err != nil {
			return err
		}
		// Restore the authorized list — skipping this was S3 in the Scientist
		// audit: authorization was silently dropped on round-trip.
		var authorized []string
		if err := dec.Decode(&authorized); err != nil {
			return err
		}
		ctr := NewGCounter(bits, authorized...)
		var nNodes int
		if err := dec.Decode(&nNodes); err != nil {
			return err
		}
		for j := 0; j < nNodes; j++ {
			var nid string
			if err := dec.Decode(&nid); err != nil {
				return err
			}
			cts, err := decodeCiphertexts(r, bits)
			if err != nil {
				return fmt.Errorf("gcounter %q node %q: %w", name, nid, err)
			}
			ctr.state[nid] = &encUint{cts: cts}
		}
		d.gcounters[name] = ctr
	}

	return nil
}

// StateRoot computes a deterministic structural commitment suitable for
// on-chain anchoring via CRDTAnchor.checkpoint(). The root binds:
//
//   - the document ID
//   - the cumulative write count
//   - the sorted set of field names + kinds + bit widths
//
// It does NOT hash raw ciphertext bytes, because FHE ciphertexts are
// non-deterministic: two replicas applying the same logical ops produce
// different ciphertext objects. Hashing them directly would diverge.
// (Scientist audit finding S2.)
//
// Two replicas that have applied the same set of Set*/Merge operations
// produce the same StateRoot — regardless of order. This matches the
// convergence property of CRDTs at the structural level. For a commitment
// to the actual ciphertext bytes (useful for debugging / content
// addressing, not consistency), use CiphertextRoot.
func (d *Document) StateRoot() ([32]byte, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	h := sha3.NewLegacyKeccak256()
	// Domain separator so an attacker can't replay a StateRoot hash as
	// some other pre-image.
	h.Write([]byte("lux.fhe.encrypted.StateRoot.v1\x00"))
	writeLenString(h, d.id)
	writeUint64(h, d.writeCount)

	for _, name := range sortedKeys(d.registers) {
		r := d.registers[name]
		h.Write([]byte("reg\x00"))
		writeLenString(h, name)
		writeUint32(h, uint32(r.BitsVal))
		writeUint32(h, uint32(r.BitsTS))
	}
	for _, name := range sortedKeysORSet(d.orsets) {
		s := d.orsets[name]
		h.Write([]byte("orset\x00"))
		writeLenString(h, name)
		writeUint32(h, uint32(len(s.Tags())))
	}
	for _, name := range sortedKeysGCounter(d.gcounters) {
		c := d.gcounters[name]
		h.Write([]byte("gcounter\x00"))
		writeLenString(h, name)
		writeUint32(h, uint32(c.bits))
		writeUint32(h, uint32(len(c.state)))
	}

	var root [32]byte
	copy(root[:], h.Sum(nil))
	return root, nil
}

// CiphertextRoot computes keccak256 of the gob-encoded snapshot, including
// raw ciphertext bytes. Useful for content addressing of a specific
// serialized form; NOT useful for cross-replica consistency because FHE
// ciphertexts are non-deterministic. Do not use this for on-chain anchoring.
func (d *Document) CiphertextRoot() ([32]byte, error) {
	data, err := d.MarshalBinary()
	if err != nil {
		return [32]byte{}, fmt.Errorf("ciphertext root: %w", err)
	}
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte("lux.fhe.encrypted.CiphertextRoot.v1\x00"))
	h.Write(data)
	var root [32]byte
	copy(root[:], h.Sum(nil))
	return root, nil
}

// writeLenString writes a 32-bit big-endian length prefix followed by the
// string bytes — prevents canonicalization ambiguity when concatenating.
func writeLenString(h interface{ Write([]byte) (int, error) }, s string) {
	writeUint32(h, uint32(len(s)))
	h.Write([]byte(s))
}

func writeUint32(h interface{ Write([]byte) (int, error) }, v uint32) {
	var b [4]byte
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
	h.Write(b[:])
}

func writeUint64(h interface{ Write([]byte) (int, error) }, v uint64) {
	var b [8]byte
	for i := 0; i < 8; i++ {
		b[i] = byte(v >> (56 - 8*i))
	}
	h.Write(b[:])
}

func sortedKeys(m map[string]*Register) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedKeysORSet(m map[string]*ORSet) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedKeysGCounter(m map[string]*GCounter) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
