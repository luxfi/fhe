// Copyright (c) 2026, Lux Industries Inc / kcolbchain contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package fhe — repro test for IntegerEvaluator.Lt / Ge / Gt / Le returning
// wrong decrypts on PN10QP27. Originally reported (in luxfi/fhe#6,
// encrypted-loan demo) as nondeterminism on blockBits=2; closer reading
// shows the bug is deterministic and present on BOTH blockBits=2 and
// blockBits=4. The failing primitive is `blockLt` / `blockEq` in
// integer_ops.go.
//
// Witnesses reported from luxfi/fhe#6:
//
//	IntegerEvaluator.Lt(enc(12),  enc(12))  → decrypts to true  (expected false)
//	IntegerEvaluator.Ge(enc(120), enc(150)) → decrypts to true  (expected false; Ge = !Lt, so this implies Lt(120,150) = false, also wrong)
//
// Likely root cause (see // TODO comment below for the line citations):
// integer_ops.go:530 (`blockLt`) and integer_ops.go:555 (`blockEq`) build a
// LUT that *claims* to decode a bivariate encoding
//
//	combined = aVal * msgSpace + bVal
//
// (see lines 537-539 and 562-564). The input fed into the bootstrap, though,
// is the homomorphic SUM of the two block ciphertexts (line 534, 559):
//
//	sum := eval.shortEval.addCiphertexts(a.ct, b.ct)
//
// `a + b` is symmetric and only carries the sum (msgSpace+msgSpace-1 distinct
// values at most), not the ordered pair (a, b) needed for a non-symmetric
// comparison. Two different pairs (e.g. (0,3) and (3,0)) collapse to the same
// LUT input and decrypt to the same blockLt cell. That breaks every
// asymmetric comparator that walks through blockLt / blockEq:
// `IntegerEvaluator.Lt/Gt/Ge/Le`, and by extension `Min/Max/Div/Rem`
// (integers.go:769, integers.go:854) which call `eval.Ge` internally.
//
// xorBlocks (integer_ops.go:395) carries an explicit
// `// This is a simplified approach - proper implementation would use tensor product`
// comment — confirming the bivariate-from-sum encoding is known WIP and
// hasn't been carried through to the comparison primitives.
//
// The boolean primitives (XNOR, ANDYN, AND, OR, NOT in evaluator.go) operate
// on single ciphertexts and work correctly — that matches the reported
// observation that single-gate booleans pass.
//
// TODO(root-cause): replace `addCiphertexts` + univariate LUT in blockLt /
// blockEq / andBlocks / orBlocks / xorBlocks with a true bivariate
// evaluation. Options:
//
//	1. Tensor-product / packed RLWE bivariate LUT.
//	2. Scale `a.ct` by `msgSpace` before adding to `b.ct` so the sum
//	   genuinely encodes `aVal * msgSpace + bVal` (requires headroom check
//	   on the modulus and noise budget — PN10QP27 has ~27-bit Q, so for
//	   blockBits=4 → msgSpace=16, combined range = 256, scale Q/512, this
//	   should fit but needs cryptographer sign-off).
//	3. Use the BitwiseEvaluator path (`bitwise_integers.go`) which uses
//	   genuine fused gates (CMPCOMBINE) and is known to work in isolation.

package fhe

import (
	"testing"
)

// reproRounds — keep small for CI cost (each round ~1.5-13s depending on
// blockBits). Witnesses are deterministic enough to fail at rounds=1, but
// 4 rounds prove it is not a one-shot noise event.
const reproRounds = 4

// newIntegerStack wires the standard FHE keygen + IntegerEvaluator stack on
// PN10QP27 with the supplied blockBits.
func newIntegerStack(t *testing.T, blockBits int) (*IntegerEncryptor, *IntegerDecryptor, *IntegerEvaluator) {
	t.Helper()
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("NewParametersFromLiteral(PN10QP27): %v", err)
	}
	intParams, err := NewIntegerParams(params, blockBits)
	if err != nil {
		t.Fatalf("NewIntegerParams(blockBits=%d): %v", blockBits, err)
	}
	kg := NewKeyGenerator(params)
	sk, _ := kg.GenKeyPair()
	bsk := kg.GenBootstrapKey(sk)

	enc := NewIntegerEncryptor(intParams, sk)
	dec := NewIntegerDecryptor(intParams, sk)
	eval := NewIntegerEvaluator(intParams, bsk)
	return enc, dec, eval
}

// TestIntegerEvaluator_Witness_LtEqual_BlockBits2 — luxfi/fhe#6 witness #1.
// Lt(12, 12) on FheUint8 / blockBits=2 decrypts to true; expected false.
func TestIntegerEvaluator_Witness_LtEqual_BlockBits2(t *testing.T) {
	enc, dec, eval := newIntegerStack(t, 2)
	const a, b uint64 = 12, 12

	failures := 0
	for round := 0; round < reproRounds; round++ {
		ea, err := enc.EncryptUint64(a, FheUint8)
		if err != nil {
			t.Fatalf("round %d: encrypt a: %v", round, err)
		}
		eb, err := enc.EncryptUint64(b, FheUint8)
		if err != nil {
			t.Fatalf("round %d: encrypt b: %v", round, err)
		}
		ltCt, err := eval.Lt(ea, eb)
		if err != nil {
			t.Fatalf("round %d: Lt: %v", round, err)
		}
		got := dec.DecryptBool(ltCt)
		t.Logf("blockBits=2 round %d: Lt(%d, %d) = %v (want false)", round, a, b, got)
		if got {
			failures++
		}
	}
	if failures > 0 {
		t.Fatalf("blockBits=2: Lt(%d,%d) returned true in %d/%d rounds — Lt should be false when a == b (luxfi/fhe#6 witness)",
			a, b, failures, reproRounds)
	}
}

// TestIntegerEvaluator_Witness_GeStrictLess_BlockBits2 — luxfi/fhe#6 witness #2.
// Ge(120, 150) on FheUint8 / blockBits=2 decrypts to true; expected false.
// This implies Lt(120, 150) decrypts to false, also wrong.
func TestIntegerEvaluator_Witness_GeStrictLess_BlockBits2(t *testing.T) {
	enc, dec, eval := newIntegerStack(t, 2)
	const a, b uint64 = 120, 150

	failures := 0
	for round := 0; round < reproRounds; round++ {
		ea, err := enc.EncryptUint64(a, FheUint8)
		if err != nil {
			t.Fatalf("round %d: encrypt a: %v", round, err)
		}
		eb, err := enc.EncryptUint64(b, FheUint8)
		if err != nil {
			t.Fatalf("round %d: encrypt b: %v", round, err)
		}
		geCt, err := eval.Ge(ea, eb)
		if err != nil {
			t.Fatalf("round %d: Ge: %v", round, err)
		}
		got := dec.DecryptBool(geCt)
		t.Logf("blockBits=2 round %d: Ge(%d, %d) = %v (want false)", round, a, b, got)
		if got {
			failures++
		}
	}
	if failures > 0 {
		t.Fatalf("blockBits=2: Ge(%d,%d) returned true in %d/%d rounds — Ge should be false when a < b (luxfi/fhe#6 witness)",
			a, b, failures, reproRounds)
	}
}

// TestIntegerEvaluator_Witness_BlockBits4 — same witnesses on blockBits=4.
// Demonstrates the bug is NOT scoped to blockBits=2: it surfaces on
// blockBits=4 as well, contrary to the original triage assumption. This
// localises the bug to the blockLt / blockEq encoding (integer_ops.go:530,
// :555), which is independent of blockBits within the supported range.
//
// Faster than the blockBits=2 case (~0.7s/round vs ~1.5s/round on a
// reference machine) because fewer radix blocks per FheUint8.
func TestIntegerEvaluator_Witness_BlockBits4(t *testing.T) {
	enc, dec, eval := newIntegerStack(t, 4)

	cases := []struct {
		name    string
		op      string
		a, b    uint64
		want    bool
		witness bool // true if this case is one of the #6 witnesses
	}{
		{"Lt-equal-12-12", "lt", 12, 12, false, true},
		{"Ge-strict-less-120-150", "ge", 120, 150, false, true},
		// Control cases — should pass:
		{"Lt-strict-less-7-9", "lt", 7, 9, true, false},
		{"Ge-equal-64-64", "ge", 64, 64, true, false},
	}

	var witnessFailures, controlFailures []string
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ea, err := enc.EncryptUint64(tc.a, FheUint8)
			if err != nil {
				t.Fatalf("encrypt a: %v", err)
			}
			eb, err := enc.EncryptUint64(tc.b, FheUint8)
			if err != nil {
				t.Fatalf("encrypt b: %v", err)
			}
			var ct *RadixCiphertext
			switch tc.op {
			case "lt":
				ct, err = eval.Lt(ea, eb)
			case "ge":
				ct, err = eval.Ge(ea, eb)
			}
			if err != nil {
				t.Fatalf("%s: %v", tc.op, err)
			}
			got := dec.DecryptBool(ct)
			t.Logf("blockBits=4 %s(%d,%d) = %v, want %v (witness=%v)",
				tc.op, tc.a, tc.b, got, tc.want, tc.witness)
			if got != tc.want {
				msg := tc.name
				if tc.witness {
					witnessFailures = append(witnessFailures, msg)
				} else {
					controlFailures = append(controlFailures, msg)
				}
			}
		})
	}

	if len(witnessFailures) > 0 || len(controlFailures) > 0 {
		t.Fatalf("blockBits=4 comparison correctness violated: witness fails=%v control fails=%v",
			witnessFailures, controlFailures)
	}
}
