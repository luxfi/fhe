// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

// bench_crdt_test.go -- fheCRDT benchmark harness and lattice property checks.
//
// Measures merge throughput for encrypted LWW-Register, G-Counter (simulated),
// and G-Set operations, plus ciphertext sizes and simulated geo-distributed
// convergence time.
//
// Run:
//   GOWORK=off go test -bench=. -benchtime=3s -timeout=600s ./...

package fhe

import (
	"fmt"
	"testing"
	"time"
	"unsafe"
)

// testCRDTContext holds shared FHE setup for CRDT benchmarks.
type testCRDTContext struct {
	params Parameters
	sk     *SecretKey
	bsk    *BootstrapKey
	enc    *Encryptor
	dec    *Decryptor
	eval   *Evaluator
}

func newCRDTTestContext(t testing.TB) *testCRDTContext {
	t.Helper()
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	keygen := NewKeyGenerator(params)
	sk, _ := keygen.GenKeyPair()
	bsk := keygen.GenBootstrapKey(sk)
	enc := NewEncryptor(params, sk)
	dec := NewDecryptor(params, sk)
	eval := NewEvaluator(params, bsk)
	return &testCRDTContext{params, sk, bsk, enc, dec, eval}
}

// encReg is an encrypted LWW-Register entry (value + timestamp as bit vectors).
type encReg struct {
	value []*Ciphertext
	ts    []*Ciphertext
}

func encryptUint(enc *Encryptor, v uint8, nbits int) []*Ciphertext {
	cts := make([]*Ciphertext, nbits)
	for i := 0; i < nbits; i++ {
		cts[i] = enc.Encrypt((v>>i)&1 == 1)
	}
	return cts
}

func decryptUint(dec *Decryptor, cts []*Ciphertext) uint8 {
	var v uint8
	for i, ct := range cts {
		if dec.Decrypt(ct) {
			v |= 1 << i
		}
	}
	return v
}

// lwwMerge performs encrypted LWW-Register merge: compare timestamps, MUX-select winner.
func lwwMerge(eval *Evaluator, a, b *encReg, bitsVal, bitsTS int) (*encReg, error) {
	// Compare timestamps MSB-to-LSB: compute bGtA = (B's timestamp > A's timestamp).
	bGtA := eval.NOT(a.ts[0])
	var eqSoFar *Ciphertext

	for i := bitsTS - 1; i >= 0; i-- {
		bitGt, err := eval.ANDNY(a.ts[i], b.ts[i])
		if err != nil {
			return nil, fmt.Errorf("ts bit %d ANDNY: %w", i, err)
		}
		bitEq, err := eval.XNOR(a.ts[i], b.ts[i])
		if err != nil {
			return nil, fmt.Errorf("ts bit %d XNOR: %w", i, err)
		}
		if i == bitsTS-1 {
			bGtA = bitGt
			eqSoFar = bitEq
		} else {
			contrib, err := eval.AND(eqSoFar, bitGt)
			if err != nil {
				return nil, fmt.Errorf("ts bit %d AND: %w", i, err)
			}
			bGtA, err = eval.OR(bGtA, contrib)
			if err != nil {
				return nil, fmt.Errorf("ts bit %d OR: %w", i, err)
			}
			eqSoFar, err = eval.AND(eqSoFar, bitEq)
			if err != nil {
				return nil, fmt.Errorf("ts bit %d eq-chain: %w", i, err)
			}
		}
	}

	mergedVal := make([]*Ciphertext, bitsVal)
	for i := 0; i < bitsVal; i++ {
		v, err := eval.MUX(bGtA, b.value[i], a.value[i])
		if err != nil {
			return nil, fmt.Errorf("val MUX bit %d: %w", i, err)
		}
		mergedVal[i] = v
	}
	mergedTS := make([]*Ciphertext, bitsTS)
	for i := 0; i < bitsTS; i++ {
		t, err := eval.MUX(bGtA, b.ts[i], a.ts[i])
		if err != nil {
			return nil, fmt.Errorf("ts MUX bit %d: %w", i, err)
		}
		mergedTS[i] = t
	}

	return &encReg{value: mergedVal, ts: mergedTS}, nil
}

// gcounterMerge simulates encrypted G-Counter merge for one replica slot:
// max(a, b) = select(a > b, a, b)
// Uses the same comparator + MUX pattern as LWW timestamp comparison.
func gcounterMerge(eval *Evaluator, a, b []*Ciphertext, nbits int) ([]*Ciphertext, error) {
	// Compare A > B (MSB-first).
	aGtB := eval.NOT(b[0])
	var eqSoFar *Ciphertext
	for i := nbits - 1; i >= 0; i-- {
		bitGt, err := eval.ANDNY(b[i], a[i])
		if err != nil {
			return nil, err
		}
		bitEq, err := eval.XNOR(a[i], b[i])
		if err != nil {
			return nil, err
		}
		if i == nbits-1 {
			aGtB = bitGt
			eqSoFar = bitEq
		} else {
			contrib, err := eval.AND(eqSoFar, bitGt)
			if err != nil {
				return nil, err
			}
			aGtB, err = eval.OR(aGtB, contrib)
			if err != nil {
				return nil, err
			}
			eqSoFar, err = eval.AND(eqSoFar, bitEq)
			if err != nil {
				return nil, err
			}
		}
	}

	result := make([]*Ciphertext, nbits)
	for i := 0; i < nbits; i++ {
		v, err := eval.MUX(aGtB, a[i], b[i])
		if err != nil {
			return nil, err
		}
		result[i] = v
	}
	return result, nil
}

// gsetMerge simulates encrypted G-Set merge for one element slot:
// OR of membership flags.
func gsetMerge(eval *Evaluator, a, b *Ciphertext) (*Ciphertext, error) {
	return eval.OR(a, b)
}

// -----------------------------------------------------------------------
// Lattice Property Tests
// -----------------------------------------------------------------------

// TestLWWMerge_Commutativity verifies merge(a,b) == merge(b,a) for LWW-Register.
func TestLWWMerge_Commutativity(t *testing.T) {
	tc := newCRDTTestContext(t)
	bits := 4

	regA := &encReg{
		value: encryptUint(tc.enc, 7, bits),
		ts:    encryptUint(tc.enc, 3, bits),
	}
	regB := &encReg{
		value: encryptUint(tc.enc, 12, bits),
		ts:    encryptUint(tc.enc, 5, bits),
	}

	ab, err := lwwMerge(tc.eval, regA, regB, bits, bits)
	if err != nil {
		t.Fatalf("merge(A,B): %v", err)
	}
	ba, err := lwwMerge(tc.eval, regB, regA, bits, bits)
	if err != nil {
		t.Fatalf("merge(B,A): %v", err)
	}

	abVal := decryptUint(tc.dec, ab.value)
	baVal := decryptUint(tc.dec, ba.value)
	abTS := decryptUint(tc.dec, ab.ts)
	baTS := decryptUint(tc.dec, ba.ts)

	if abVal != baVal || abTS != baTS {
		t.Fatalf("commutativity violated: merge(A,B)=(%d,%d) merge(B,A)=(%d,%d)",
			abVal, abTS, baVal, baTS)
	}
	t.Logf("PASS commutativity: merge(A,B) == merge(B,A) == (val=%d, ts=%d)", abVal, abTS)
}

// TestLWWMerge_Idempotence verifies merge(a,a) == a for LWW-Register.
func TestLWWMerge_Idempotence(t *testing.T) {
	tc := newCRDTTestContext(t)
	bits := 4

	regA := &encReg{
		value: encryptUint(tc.enc, 9, bits),
		ts:    encryptUint(tc.enc, 4, bits),
	}

	aa, err := lwwMerge(tc.eval, regA, regA, bits, bits)
	if err != nil {
		t.Fatalf("merge(A,A): %v", err)
	}

	origVal := decryptUint(tc.dec, regA.value)
	aaVal := decryptUint(tc.dec, aa.value)
	origTS := decryptUint(tc.dec, regA.ts)
	aaTS := decryptUint(tc.dec, aa.ts)

	if origVal != aaVal || origTS != aaTS {
		t.Fatalf("idempotence violated: A=(%d,%d) merge(A,A)=(%d,%d)",
			origVal, origTS, aaVal, aaTS)
	}
	t.Logf("PASS idempotence: merge(A,A) == A == (val=%d, ts=%d)", aaVal, aaTS)
}

// TestLWWMerge_Associativity verifies merge(merge(a,b),c) == merge(a,merge(b,c)).
func TestLWWMerge_Associativity(t *testing.T) {
	tc := newCRDTTestContext(t)
	bits := 4

	regA := &encReg{
		value: encryptUint(tc.enc, 2, bits),
		ts:    encryptUint(tc.enc, 1, bits),
	}
	regB := &encReg{
		value: encryptUint(tc.enc, 7, bits),
		ts:    encryptUint(tc.enc, 3, bits),
	}
	regC := &encReg{
		value: encryptUint(tc.enc, 5, bits),
		ts:    encryptUint(tc.enc, 6, bits),
	}

	// (A merge B) merge C
	ab, err := lwwMerge(tc.eval, regA, regB, bits, bits)
	if err != nil {
		t.Fatalf("merge(A,B): %v", err)
	}
	abc, err := lwwMerge(tc.eval, ab, regC, bits, bits)
	if err != nil {
		t.Fatalf("merge(AB,C): %v", err)
	}

	// A merge (B merge C)
	bc, err := lwwMerge(tc.eval, regB, regC, bits, bits)
	if err != nil {
		t.Fatalf("merge(B,C): %v", err)
	}
	a_bc, err := lwwMerge(tc.eval, regA, bc, bits, bits)
	if err != nil {
		t.Fatalf("merge(A,BC): %v", err)
	}

	abcVal := decryptUint(tc.dec, abc.value)
	abcTS := decryptUint(tc.dec, abc.ts)
	a_bcVal := decryptUint(tc.dec, a_bc.value)
	a_bcTS := decryptUint(tc.dec, a_bc.ts)

	if abcVal != a_bcVal || abcTS != a_bcTS {
		t.Fatalf("associativity violated: (A*B)*C=(%d,%d) A*(B*C)=(%d,%d)",
			abcVal, abcTS, a_bcVal, a_bcTS)
	}
	t.Logf("PASS associativity: (A*B)*C == A*(B*C) == (val=%d, ts=%d)", abcVal, abcTS)
}

// TestGCounterMerge_Correctness verifies encrypted max(a,b) matches plaintext.
func TestGCounterMerge_Correctness(t *testing.T) {
	tc := newCRDTTestContext(t)
	bits := 4

	cases := [][2]uint8{{3, 7}, {7, 3}, {5, 5}, {0, 15}, {15, 0}}
	for _, c := range cases {
		a := encryptUint(tc.enc, c[0], bits)
		b := encryptUint(tc.enc, c[1], bits)

		result, err := gcounterMerge(tc.eval, a, b, bits)
		if err != nil {
			t.Fatalf("gcounterMerge(%d,%d): %v", c[0], c[1], err)
		}
		got := decryptUint(tc.dec, result)
		want := c[0]
		if c[1] > c[0] {
			want = c[1]
		}
		if got != want {
			t.Fatalf("gcounterMerge(%d,%d) = %d, want %d", c[0], c[1], got, want)
		}
		t.Logf("PASS gcounter max(%d,%d) = %d", c[0], c[1], got)
	}
}

// TestGSetMerge_Correctness verifies encrypted OR matches plaintext.
func TestGSetMerge_Correctness(t *testing.T) {
	tc := newCRDTTestContext(t)

	cases := [][2]bool{{false, false}, {false, true}, {true, false}, {true, true}}
	for _, c := range cases {
		a := tc.enc.Encrypt(c[0])
		b := tc.enc.Encrypt(c[1])
		result, err := gsetMerge(tc.eval, a, b)
		if err != nil {
			t.Fatalf("gsetMerge(%v,%v): %v", c[0], c[1], err)
		}
		got := tc.dec.Decrypt(result)
		want := c[0] || c[1]
		if got != want {
			t.Fatalf("gsetMerge(%v,%v) = %v, want %v", c[0], c[1], got, want)
		}
	}
	t.Log("PASS gset OR all 4 truth table entries")
}

// TestGSetMerge_Idempotence verifies OR(a,a) == a (idempotence for G-Set).
func TestGSetMerge_Idempotence(t *testing.T) {
	tc := newCRDTTestContext(t)

	for _, val := range []bool{false, true} {
		a := tc.enc.Encrypt(val)
		result, err := gsetMerge(tc.eval, a, a)
		if err != nil {
			t.Fatalf("gsetMerge(%v,%v): %v", val, val, err)
		}
		got := tc.dec.Decrypt(result)
		if got != val {
			t.Fatalf("gset idempotence violated: OR(%v,%v) = %v", val, val, got)
		}
	}
	t.Log("PASS gset idempotence")
}

// -----------------------------------------------------------------------
// Benchmarks
// -----------------------------------------------------------------------

// BenchmarkLWWMerge measures LWW-Register merge throughput (4-bit val, 4-bit ts).
func BenchmarkLWWMerge(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	keygen := NewKeyGenerator(params)
	sk, _ := keygen.GenKeyPair()
	bsk := keygen.GenBootstrapKey(sk)
	enc := NewEncryptor(params, sk)
	eval := NewEvaluator(params, bsk)
	bits := 4

	regA := &encReg{
		value: encryptUint(enc, 7, bits),
		ts:    encryptUint(enc, 3, bits),
	}
	regB := &encReg{
		value: encryptUint(enc, 12, bits),
		ts:    encryptUint(enc, 5, bits),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := lwwMerge(eval, regA, regB, bits, bits)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGCounterMerge measures G-Counter single-slot merge throughput (4-bit).
func BenchmarkGCounterMerge(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	keygen := NewKeyGenerator(params)
	sk, _ := keygen.GenKeyPair()
	bsk := keygen.GenBootstrapKey(sk)
	enc := NewEncryptor(params, sk)
	eval := NewEvaluator(params, bsk)
	bits := 4

	a := encryptUint(enc, 3, bits)
	bCt := encryptUint(enc, 7, bits)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := gcounterMerge(eval, a, bCt, bits)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGSetMerge measures G-Set single-element merge throughput (1 OR gate).
func BenchmarkGSetMerge(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	keygen := NewKeyGenerator(params)
	sk, _ := keygen.GenKeyPair()
	bsk := keygen.GenBootstrapKey(sk)
	enc := NewEncryptor(params, sk)
	eval := NewEvaluator(params, bsk)

	a := enc.Encrypt(true)
	bCt := enc.Encrypt(false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := gsetMerge(eval, a, bCt)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkBootstrapSingle measures single bootstrap (the fundamental bottleneck).
func BenchmarkBootstrapSingle(b *testing.B) {
	params, _ := NewParametersFromLiteral(PN10QP27)
	keygen := NewKeyGenerator(params)
	sk, _ := keygen.GenKeyPair()
	bsk := keygen.GenBootstrapKey(sk)
	enc := NewEncryptor(params, sk)
	eval := NewEvaluator(params, bsk)

	ct := enc.Encrypt(true)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var err error
		ct, err = eval.Refresh(ct)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// TestCiphertextSize measures memory per encrypted element.
func TestCiphertextSize(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatal(err)
	}
	keygen := NewKeyGenerator(params)
	sk, _ := keygen.GenKeyPair()
	enc := NewEncryptor(params, sk)

	ct := enc.Encrypt(true)
	data, err := ct.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// In-memory size estimate: 2 polynomials of N uint64 coefficients each.
	n := params.N()
	inMemory := 2 * n * int(unsafe.Sizeof(uint64(0)))

	t.Logf("Single bit ciphertext: serialized=%d bytes, in-memory~=%d bytes", len(data), inMemory)
	t.Logf("4-bit value: serialized~=%d bytes, in-memory~=%d bytes", 4*len(data), 4*inMemory)
	t.Logf("LWW-Register (4-bit val + 4-bit ts): serialized~=%d bytes", 8*len(data))
	t.Logf("N=%d, Q=%d", n, params.QLWE())
}

// TestGeoConvergence simulates 2-node convergence with 50ms RTT.
func TestGeoConvergence(t *testing.T) {
	tc := newCRDTTestContext(t)
	bits := 4

	// Node A writes (val=7, ts=3)
	regA := &encReg{
		value: encryptUint(tc.enc, 7, bits),
		ts:    encryptUint(tc.enc, 3, bits),
	}
	// Node B writes (val=12, ts=5)
	regB := &encReg{
		value: encryptUint(tc.enc, 12, bits),
		ts:    encryptUint(tc.enc, 5, bits),
	}

	// Simulate: Node A sends state to Node B over 50ms RTT.
	rtt := 50 * time.Millisecond

	t0 := time.Now()

	// Network delay (one-way = RTT/2).
	time.Sleep(rtt / 2)

	// Node B merges.
	merged, err := lwwMerge(tc.eval, regA, regB, bits, bits)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}

	// ACK back.
	time.Sleep(rtt / 2)

	convergence := time.Since(t0)

	mergedVal := decryptUint(tc.dec, merged.value)
	mergedTS := decryptUint(tc.dec, merged.ts)

	t.Logf("Geo-convergence: %v (RTT=%v, merge compute=%v)",
		convergence, rtt, convergence-rtt)
	t.Logf("Merged state: val=%d ts=%d (expected: val=12 ts=5)", mergedVal, mergedTS)

	if mergedVal != 12 || mergedTS != 5 {
		t.Fatalf("incorrect merge result: val=%d ts=%d", mergedVal, mergedTS)
	}
}
