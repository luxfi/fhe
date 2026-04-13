// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package encrypted

import (
	"bytes"
	"encoding/gob"
	"testing"

	"github.com/luxfi/fhe"
)

// testEnv holds shared FHE key material. Keygen is expensive (~2s), so
// we do it once per test binary. PN10QP27 gives ~128-bit security.
type testEnv struct {
	params fhe.Parameters
	sk     *fhe.SecretKey
	enc    *fhe.Encryptor
	dec    *fhe.Decryptor
	eval   *fhe.Evaluator
}

var env *testEnv

func setup(t *testing.T) *testEnv {
	t.Helper()
	if env != nil {
		return env
	}
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	keygen := fhe.NewKeyGenerator(params)
	sk, _ := keygen.GenKeyPair()
	bsk := keygen.GenBootstrapKey(sk)
	env = &testEnv{
		params: params,
		sk:     sk,
		enc:    fhe.NewEncryptor(params, sk),
		dec:    fhe.NewDecryptor(params, sk),
		eval:   fhe.NewEvaluator(params, bsk),
	}
	return env
}

// --- LWW Register ---

func TestMergeLWW_LaterTimestampWins(t *testing.T) {
	e := setup(t)
	// Node A: value=7, ts=3; Node B: value=12, ts=5.
	// B wins because ts=5 > ts=3.
	a := EncryptRegister(e.enc, 7, 3, 4, 4)
	b := EncryptRegister(e.enc, 12, 5, 4, 4)

	merged, err := MergeLWW(e.eval, a, b)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	val, ts := DecryptRegister(e.dec, merged)
	if val != 12 || ts != 5 {
		t.Fatalf("expected val=12 ts=5, got val=%d ts=%d", val, ts)
	}
}

func TestMergeLWW_Commutativity(t *testing.T) {
	e := setup(t)
	a := EncryptRegister(e.enc, 3, 1, 4, 4)
	b := EncryptRegister(e.enc, 9, 6, 4, 4)

	ab, err := MergeLWW(e.eval, a, b)
	if err != nil {
		t.Fatalf("merge a,b: %v", err)
	}
	ba, err := MergeLWW(e.eval, b, a)
	if err != nil {
		t.Fatalf("merge b,a: %v", err)
	}

	vAB, tAB := DecryptRegister(e.dec, ab)
	vBA, tBA := DecryptRegister(e.dec, ba)
	if vAB != vBA || tAB != tBA {
		t.Fatalf("not commutative: merge(a,b)=(%d,%d) merge(b,a)=(%d,%d)", vAB, tAB, vBA, tBA)
	}
}

func TestMergeLWWN_ThreeWay(t *testing.T) {
	e := setup(t)
	// Three concurrent writes; ts=7 should win.
	r1 := EncryptRegister(e.enc, 1, 2, 4, 4)
	r2 := EncryptRegister(e.enc, 5, 7, 4, 4)
	r3 := EncryptRegister(e.enc, 9, 4, 4, 4)

	merged, err := MergeLWWN(e.eval, r1, r2, r3)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	val, ts := DecryptRegister(e.dec, merged)
	if val != 5 || ts != 7 {
		t.Fatalf("expected val=5 ts=7, got val=%d ts=%d", val, ts)
	}
}

func TestMergeLWW_EqualTimestampPicksSmaller(t *testing.T) {
	e := setup(t)
	// Same timestamp => smaller value wins (deterministic tie-break).
	a := EncryptRegister(e.enc, 3, 5, 4, 4)
	b := EncryptRegister(e.enc, 9, 5, 4, 4)

	// merge(a, b) should pick val=3 (smaller).
	ab, err := MergeLWW(e.eval, a, b)
	if err != nil {
		t.Fatalf("merge(a,b): %v", err)
	}
	val, _ := DecryptRegister(e.dec, ab)
	if val != 3 {
		t.Fatalf("merge(a,b): expected val=3 (smaller), got %d", val)
	}

	// merge(b, a) should also pick val=3 (commutative tie-break).
	ba, err := MergeLWW(e.eval, b, a)
	if err != nil {
		t.Fatalf("merge(b,a): %v", err)
	}
	val2, _ := DecryptRegister(e.dec, ba)
	if val2 != 3 {
		t.Fatalf("merge(b,a): expected val=3 (commutative), got %d", val2)
	}
}

func TestMergeLWWN_EqualTimestamps_Deterministic(t *testing.T) {
	e := setup(t)
	// 5 registers with same timestamp, different values.
	vals := []uint64{7, 2, 11, 5, 2}
	regs := make([]*Register, len(vals))
	for i, v := range vals {
		regs[i] = EncryptRegister(e.enc, v, 10, 4, 4)
	}

	// Merge all permutations and verify the same value wins.
	baseline, err := MergeLWWN(e.eval, regs...)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	bVal, bTS := DecryptRegister(e.dec, baseline)
	if bVal != 2 {
		t.Fatalf("expected val=2 (smallest), got %d", bVal)
	}

	// Reverse order should produce same result.
	reversed := make([]*Register, len(regs))
	for i := range regs {
		reversed[i] = regs[len(regs)-1-i]
	}
	rev, err := MergeLWWN(e.eval, reversed...)
	if err != nil {
		t.Fatalf("merge reversed: %v", err)
	}
	rVal, rTS := DecryptRegister(e.dec, rev)
	if rVal != bVal || rTS != bTS {
		t.Fatalf("not permutation-invariant: forward=(%d,%d) reverse=(%d,%d)", bVal, bTS, rVal, rTS)
	}
}

func TestMergeLWW_BitWidthMismatchErrors(t *testing.T) {
	e := setup(t)
	a := EncryptRegister(e.enc, 1, 1, 4, 4)
	b := EncryptRegister(e.enc, 1, 1, 8, 4)
	_, err := MergeLWW(e.eval, a, b)
	if err == nil {
		t.Fatal("expected error on bit-width mismatch")
	}
}

// --- Register serialization ---

func TestRegisterMarshalRoundTrip(t *testing.T) {
	e := setup(t)
	orig := EncryptRegister(e.enc, 11, 6, 4, 4)

	data, err := MarshalRegister(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	restored, err := UnmarshalRegister(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	val, ts := DecryptRegister(e.dec, restored)
	if val != 11 || ts != 6 {
		t.Fatalf("round-trip failed: val=%d ts=%d", val, ts)
	}
}

// --- Deserialization bounds ---

func TestDecodeCiphertexts_RejectsOversized(t *testing.T) {
	// Attempting to unmarshal a Register with BitsVal=257 should fail.
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	enc.Encode(257) // BitsVal
	enc.Encode(4)   // BitsTS

	_, err := UnmarshalRegister(buf.Bytes())
	if err == nil {
		t.Fatal("expected error for BitsVal > maxBits")
	}

	// BitsTS too large.
	buf.Reset()
	enc = gob.NewEncoder(&buf)
	enc.Encode(4)   // BitsVal OK
	enc.Encode(300) // BitsTS too large

	_, err = UnmarshalRegister(buf.Bytes())
	if err == nil {
		t.Fatal("expected error for BitsTS > maxBits")
	}
}

func TestUnmarshalORSet_RejectsOversized(t *testing.T) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	enc.Encode(65537) // count > maxORSetElements

	_, err := UnmarshalORSet(buf.Bytes())
	if err == nil {
		t.Fatal("expected error for ORSet count > maxORSetElements")
	}
}

// --- OR-Set ---

func TestORSet_MergeIsTagUnion(t *testing.T) {
	e := setup(t)

	a := NewORSet()
	a.Add("nodeA:1", encryptUint(e.enc, 42, 8), 8)
	a.Add("nodeA:2", encryptUint(e.enc, 99, 8), 8)

	b := NewORSet()
	b.Add("nodeB:1", encryptUint(e.enc, 7, 8), 8)
	b.Add("nodeA:1", encryptUint(e.enc, 55, 8), 8) // overlapping tag

	merged := MergeORSet(a, b)
	if merged.Len() != 3 {
		t.Fatalf("expected 3 entries, got %d", merged.Len())
	}

	// nodeA:1 should have b's value (last-writer on tag collision).
	entry := merged.Get("nodeA:1")
	val := decryptUint(e.dec, entry.Value)
	if val != 55 {
		t.Fatalf("expected tag collision to pick b's value (55), got %d", val)
	}
}

func TestORSet_PrivateTagsHidesMembership(t *testing.T) {
	e := setup(t)
	key := []byte("secret-document-key")
	s := NewPrivateORSet(key)
	s.Add("alice:1", encryptUint(e.enc, 42, 8), 8)

	// Raw tag "alice:1" should not appear in the internal map.
	for k := range s.elems {
		if k == "alice:1" {
			t.Fatal("plaintext tag leaked in private ORSet")
		}
	}

	// But Contains/Get with the original tag should work.
	if !s.Contains("alice:1") {
		t.Fatal("private ORSet: Contains failed for wrapped tag")
	}
	entry := s.Get("alice:1")
	if entry == nil {
		t.Fatal("private ORSet: Get returned nil")
	}
	val := decryptUint(e.dec, entry.Value)
	if val != 42 {
		t.Fatalf("expected 42, got %d", val)
	}

	s.Remove("alice:1")
	if s.Contains("alice:1") {
		t.Fatal("private ORSet: Remove failed")
	}
}

func TestORSet_RemoveAndContains(t *testing.T) {
	e := setup(t)
	s := NewORSet()
	s.Add("x:1", encryptUint(e.enc, 1, 4), 4)
	if !s.Contains("x:1") {
		t.Fatal("should contain x:1")
	}
	s.Remove("x:1")
	if s.Contains("x:1") {
		t.Fatal("should not contain x:1 after remove")
	}
}

// --- GCounter ---

func TestGCounter_RejectsUnauthorizedNode(t *testing.T) {
	e := setup(t)
	bits := 4
	g := NewGCounter(bits, "nodeA", "nodeB")

	err := g.Set("nodeA", encryptUint(e.enc, 1, bits))
	if err != nil {
		t.Fatalf("authorized nodeA should succeed: %v", err)
	}

	err = g.Set("evil", encryptUint(e.enc, 1, bits))
	if err == nil {
		t.Fatal("expected error for unauthorized nodeID")
	}
}

func TestGCounter_MergeRejectsUnauthorizedNode(t *testing.T) {
	e := setup(t)
	bits := 4
	a := NewGCounter(bits, "nodeA", "nodeB")
	a.Set("nodeA", encryptUint(e.enc, 5, bits))

	// b has an unauthorized nodeID.
	b := NewGCounter(bits)
	b.Set("evil", encryptUint(e.enc, 1, bits))

	_, err := MergeGCounter(e.eval, a, b)
	if err == nil {
		t.Fatal("expected error for unauthorized nodeID during merge")
	}
}

func TestGCounter_OpenMode(t *testing.T) {
	e := setup(t)
	bits := 4
	g := NewGCounter(bits) // no authorized nodes = open mode
	err := g.Set("anyone", encryptUint(e.enc, 1, bits))
	if err != nil {
		t.Fatalf("open mode should accept any nodeID: %v", err)
	}
}

func TestGCounter_MergeHomomorphicMax(t *testing.T) {
	e := setup(t)
	bits := 4

	a := NewGCounter(bits, "nodeA", "nodeB", "nodeC")
	a.Set("nodeA", encryptUint(e.enc, 5, bits))
	a.Set("nodeB", encryptUint(e.enc, 3, bits))

	b := NewGCounter(bits, "nodeA", "nodeB", "nodeC")
	b.Set("nodeA", encryptUint(e.enc, 2, bits))
	b.Set("nodeB", encryptUint(e.enc, 7, bits))
	b.Set("nodeC", encryptUint(e.enc, 4, bits))

	merged, err := MergeGCounter(e.eval, a, b)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}

	// nodeA: max(5,2)=5, nodeB: max(3,7)=7, nodeC: 4 (only in b)
	checkNode := func(nid string, expected uint64) {
		t.Helper()
		cts := merged.Get(nid)
		if cts == nil {
			t.Fatalf("missing node %s", nid)
		}
		got := decryptUint(e.dec, cts)
		if got != expected {
			t.Fatalf("node %s: expected %d, got %d", nid, expected, got)
		}
	}
	checkNode("nodeA", 5)
	checkNode("nodeB", 7)
	checkNode("nodeC", 4)
}

// --- Document ---

func TestDocument_MergeAndStateRoot(t *testing.T) {
	e := setup(t)

	doc1 := NewDocument("doc-1")
	doc1.SetRegister("owner", EncryptRegister(e.enc, 1, 10, 4, 4))

	set1 := NewORSet()
	set1.Add("tag:a", encryptUint(e.enc, 42, 8), 8)
	doc1.SetORSet("members", set1)

	doc2 := NewDocument("doc-1")
	doc2.SetRegister("owner", EncryptRegister(e.enc, 2, 15, 4, 4))

	set2 := NewORSet()
	set2.Add("tag:b", encryptUint(e.enc, 99, 8), 8)
	doc2.SetORSet("members", set2)

	if err := doc1.Merge(e.eval, doc2); err != nil {
		t.Fatalf("merge: %v", err)
	}

	// owner should be doc2's value (ts=15 > ts=10).
	val, ts := DecryptRegister(e.dec, doc1.GetRegister("owner"))
	if val != 2 || ts != 15 {
		t.Fatalf("expected owner=2 ts=15, got %d %d", val, ts)
	}

	// members should have both tags.
	members := doc1.GetORSet("members")
	if members.Len() != 2 {
		t.Fatalf("expected 2 members, got %d", members.Len())
	}

	// StateRoot should be deterministic.
	r1, err := doc1.StateRoot()
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	r2, err := doc1.StateRoot()
	if err != nil {
		t.Fatalf("root2: %v", err)
	}
	if r1 != r2 {
		t.Fatal("state root not deterministic")
	}
}

func TestDocument_MarshalRoundTrip(t *testing.T) {
	e := setup(t)

	doc := NewDocument("roundtrip")
	doc.SetRegister("field1", EncryptRegister(e.enc, 15, 3, 4, 4))
	s := NewORSet()
	s.Add("t:1", encryptUint(e.enc, 7, 4), 4)
	doc.SetORSet("set1", s)

	data, err := doc.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	doc2 := &Document{}
	if err := doc2.UnmarshalBinary(data); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if doc2.ID() != "roundtrip" {
		t.Fatalf("id mismatch: %s", doc2.ID())
	}
	val, ts := DecryptRegister(e.dec, doc2.GetRegister("field1"))
	if val != 15 || ts != 3 {
		t.Fatalf("register round-trip: val=%d ts=%d", val, ts)
	}
	if doc2.GetORSet("set1").Len() != 1 {
		t.Fatal("orset lost entries")
	}
}
