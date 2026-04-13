// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package encrypted

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"

	"github.com/luxfi/fhe"
)

// ORSet is an Observed-Remove Set where tags are plaintext (for identity)
// and values are FHE-encrypted. Merge is tag-union: no FHE operations are
// required during merge itself, only during read/decrypt. This makes ORSet
// the cheapest encrypted CRDT to merge (O(1) FHE ops per merge = zero).
//
// The plaintext tags reveal set membership to the relay. If membership
// itself is sensitive, wrap the entire ORSet state in an age envelope
// and sync as an opaque blob. The FHE encryption here protects values
// only — element identity leaks by design (same as Zcash shielded pool
// where transaction graph is visible but amounts are hidden).
type ORSet struct {
	mu    sync.RWMutex
	elems map[string]*ORSetEntry // tag -> encrypted value
	// TagKey, when non-nil, enables HMAC-wrapped tags. All tags passed
	// to Add/Remove/Contains are HMAC'd before use, hiding membership
	// from the relay. Leave nil for "public set" mode where membership
	// is already public.
	TagKey []byte
}

// ORSetEntry is a single element in the OR-Set.
type ORSetEntry struct {
	Tag   string            // plaintext unique tag (nodeID:seq)
	Value []*fhe.Ciphertext // encrypted value bits (LSB-first)
	Bits  int               // bit-width of encrypted value
}

// NewORSet creates an empty encrypted OR-Set with public tags (no HMAC).
func NewORSet() *ORSet {
	return &ORSet{elems: make(map[string]*ORSetEntry)}
}

// NewPrivateORSet creates an encrypted OR-Set with HMAC-wrapped tags.
// The tagKey seeds the HMAC; the relay only sees opaque hex digests.
func NewPrivateORSet(tagKey []byte) *ORSet {
	return &ORSet{elems: make(map[string]*ORSetEntry), TagKey: tagKey}
}

// wrapTag returns the HMAC-wrapped tag if TagKey is set, otherwise the raw tag.
func (s *ORSet) wrapTag(tag string) string {
	if len(s.TagKey) == 0 {
		return tag
	}
	mac := hmac.New(sha256.New, s.TagKey)
	mac.Write([]byte(tag))
	return hex.EncodeToString(mac.Sum(nil))
}

// Add inserts an encrypted value under a unique tag. If the tag already
// exists, the old value is overwritten (add-wins on tag collision).
// When TagKey is set, the stored key is HMAC(tag) so the relay cannot
// observe plaintext membership.
func (s *ORSet) Add(tag string, value []*fhe.Ciphertext, bits int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.wrapTag(tag)
	s.elems[k] = &ORSetEntry{Tag: k, Value: value, Bits: bits}
}

// Remove removes an element by tag.
func (s *ORSet) Remove(tag string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.elems, s.wrapTag(tag))
}

// Contains checks if a tag is present.
func (s *ORSet) Contains(tag string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.elems[s.wrapTag(tag)]
	return ok
}

// Tags returns all tags in sorted order (deterministic iteration).
func (s *ORSet) Tags() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tags := make([]string, 0, len(s.elems))
	for t := range s.elems {
		tags = append(tags, t)
	}
	sort.Strings(tags)
	return tags
}

// Get returns the encrypted entry for a tag, or nil.
func (s *ORSet) Get(tag string) *ORSetEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.elems[s.wrapTag(tag)]
}

// Len returns the number of elements.
func (s *ORSet) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.elems)
}

// MergeORSet merges two OR-Sets by taking the union of tags. When both
// sets contain the same tag, the entry from b wins (last-writer-wins on
// tag collision). No FHE operations are performed.
func MergeORSet(a, b *ORSet) *ORSet {
	a.mu.RLock()
	b.mu.RLock()
	defer a.mu.RUnlock()
	defer b.mu.RUnlock()

	result := NewORSet()
	for tag, entry := range a.elems {
		result.elems[tag] = entry
	}
	for tag, entry := range b.elems {
		result.elems[tag] = entry
	}
	return result
}

// MarshalORSet serializes an OR-Set.
func MarshalORSet(s *ORSet) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(len(s.elems)); err != nil {
		return nil, err
	}
	// Iterate in sorted order for deterministic encoding.
	tags := make([]string, 0, len(s.elems))
	for t := range s.elems {
		tags = append(tags, t)
	}
	sort.Strings(tags)

	for _, tag := range tags {
		entry := s.elems[tag]
		if err := enc.Encode(entry.Tag); err != nil {
			return nil, err
		}
		if err := enc.Encode(entry.Bits); err != nil {
			return nil, err
		}
		if err := encodeCiphertexts(&buf, entry.Value); err != nil {
			return nil, fmt.Errorf("orset tag %q: %w", tag, err)
		}
	}
	return buf.Bytes(), nil
}

// maxORSetElements caps the maximum number of elements in a deserialized
// OR-Set to prevent OOM from malformed payloads.
const maxORSetElements = 65536

// UnmarshalORSet deserializes an OR-Set.
func UnmarshalORSet(data []byte) (*ORSet, error) {
	r := bytes.NewReader(data)
	dec := gob.NewDecoder(r)

	var count int
	if err := dec.Decode(&count); err != nil {
		return nil, err
	}
	if count > maxORSetElements {
		return nil, fmt.Errorf("orset element count %d exceeds max %d", count, maxORSetElements)
	}
	s := NewORSet()
	for i := 0; i < count; i++ {
		var tag string
		var bits int
		if err := dec.Decode(&tag); err != nil {
			return nil, fmt.Errorf("entry %d tag: %w", i, err)
		}
		if err := dec.Decode(&bits); err != nil {
			return nil, fmt.Errorf("entry %d bits: %w", i, err)
		}
		cts, err := decodeCiphertexts(r, bits)
		if err != nil {
			return nil, fmt.Errorf("entry %d cts: %w", i, err)
		}
		s.elems[tag] = &ORSetEntry{Tag: tag, Value: cts, Bits: bits}
	}
	return s, nil
}
