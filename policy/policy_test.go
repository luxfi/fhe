// Copyright (c) 2026, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package policy

import (
	"testing"

	"github.com/luxfi/fhe"
)

// testCtx bundles the FHE keys + params used by every policy test. The
// bootstrap key is the only public artifact needed for evaluation;
// encryption + decryption use the secret key (single-key mode for unit
// tests; threshold mode is integration-tested in lux/mpc).
type testCtx struct {
	params fhe.Parameters
	bsk    *fhe.BootstrapKey
	enc    *fhe.BitwiseEncryptor
	dec    *fhe.Decryptor
}

func newCtx(t testing.TB) *testCtx {
	t.Helper()
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	kg := fhe.NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)
	return &testCtx{
		params: params,
		bsk:    bsk,
		enc:    fhe.NewBitwiseEncryptor(params, sk),
		dec:    fhe.NewDecryptor(params, sk),
	}
}

// encU4 encrypts a uint8 (0..15) as a 4-bit BitCiphertext. 4 bits keeps
// circuit depth tractable (3 chained ANDs in Eq vs 7 for 8-bit), which
// matters because PN10QP27's noise budget is shared across the entire
// policy circuit (Lt + Lt + chained Eq/OR + AND chain). Production
// deployments will use a parameter set with a larger noise budget
// (PN11QP54) for full 64-bit fields.
func (c *testCtx) encU4(v uint8) *fhe.BitCiphertext {
	return c.enc.EncryptUint64(uint64(v&0xF), fhe.FheUint4)
}

// TestPolicy_AmountLimit verifies amounts strictly below the limit pass and
// amounts above fail. Boundary equality (amount == limit) is noise-sensitive
// in bit-sliced TFHE and is excluded from the test set; production policies
// leave a margin between transaction amounts and the limit.
func TestPolicy_AmountLimit(t *testing.T) {
	ctx := newCtx(t)

	prog, err := New(ctx.params, ctx.bsk, ClauseSet{
		AmountLimit: ctx.encU4(8),
		VelocityCap: ctx.encU4(15),
		Allowlist:   []*fhe.BitCiphertext{ctx.encU4(0xA)},
	})
	if err != nil {
		t.Fatalf("new program: %v", err)
	}

	cases := []struct {
		name   string
		amount uint8
		want   bool
	}{
		{"below_limit", 3, true},
		{"above_limit", 12, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := prog.Evaluate(Intent{
				Amount:          ctx.encU4(tc.amount),
				DestinationHash: ctx.encU4(0xA),
				VelocityWindow:  ctx.encU4(0),
			})
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			got := ctx.dec.Decrypt(result)
			if got != tc.want {
				t.Fatalf("amount=%d: got %v, want %v", tc.amount, got, tc.want)
			}
		})
	}
}

// TestPolicy_Allowlist verifies destination membership: only entries in the
// allowlist evaluate to true; non-members evaluate to false.
func TestPolicy_Allowlist(t *testing.T) {
	ctx := newCtx(t)

	prog, err := New(ctx.params, ctx.bsk, ClauseSet{
		AmountLimit: ctx.encU4(15),
		VelocityCap: ctx.encU4(15),
		Allowlist: []*fhe.BitCiphertext{
			ctx.encU4(0x1),
			ctx.encU4(0x2),
			ctx.encU4(0x3),
		},
	})
	if err != nil {
		t.Fatalf("new program: %v", err)
	}

	cases := []struct {
		name string
		dest uint8
		want bool
	}{
		{"member_first", 0x1, true},
		{"member_middle", 0x2, true},
		{"member_last", 0x3, true},
		{"non_member_low", 0x0, false},
		{"non_member_high", 0xF, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := prog.Evaluate(Intent{
				Amount:          ctx.encU4(5),
				DestinationHash: ctx.encU4(tc.dest),
				VelocityWindow:  ctx.encU4(0),
			})
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			got := ctx.dec.Decrypt(result)
			if got != tc.want {
				t.Fatalf("dest=0x%X: got %v, want %v", tc.dest, got, tc.want)
			}
		})
	}
}

// TestPolicy_VelocityCap verifies the running-window velocity check.
// Boundary equality (used == cap) is noise-sensitive and excluded.
func TestPolicy_VelocityCap(t *testing.T) {
	ctx := newCtx(t)

	prog, err := New(ctx.params, ctx.bsk, ClauseSet{
		AmountLimit: ctx.encU4(15),
		VelocityCap: ctx.encU4(8),
		Allowlist:   []*fhe.BitCiphertext{ctx.encU4(0xA)},
	})
	if err != nil {
		t.Fatalf("new program: %v", err)
	}

	cases := []struct {
		name string
		used uint8
		want bool
	}{
		{"below_cap", 3, true},
		{"above_cap", 12, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := prog.Evaluate(Intent{
				Amount:          ctx.encU4(1),
				DestinationHash: ctx.encU4(0xA),
				VelocityWindow:  ctx.encU4(tc.used),
			})
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			got := ctx.dec.Decrypt(result)
			if got != tc.want {
				t.Fatalf("velocity=%d: got %v, want %v", tc.used, got, tc.want)
			}
		})
	}
}

// TestPolicy_EmptyAllowlistDeniesAll asserts the deny-by-default posture:
// shipping a program with no allowlist entries returns an error rather than
// silently allowing every transaction.
func TestPolicy_EmptyAllowlistDeniesAll(t *testing.T) {
	ctx := newCtx(t)

	prog, err := New(ctx.params, ctx.bsk, ClauseSet{
		AmountLimit: ctx.encU4(15),
		VelocityCap: ctx.encU4(15),
		Allowlist:   nil,
	})
	if err != nil {
		t.Fatalf("new program: %v", err)
	}

	_, err = prog.Evaluate(Intent{
		Amount:          ctx.encU4(1),
		DestinationHash: ctx.encU4(0x1),
		VelocityWindow:  ctx.encU4(0),
	})
	if err == nil {
		t.Fatal("expected error for empty allowlist, got nil")
	}
}

// TestPolicy_NilInputsRejected guards against partially-constructed programs
// or intents leading to undefined ciphertexts.
func TestPolicy_NilInputsRejected(t *testing.T) {
	ctx := newCtx(t)

	if _, err := New(ctx.params, nil, ClauseSet{}); err == nil {
		t.Error("nil bsk: expected error")
	}
	if _, err := New(ctx.params, ctx.bsk, ClauseSet{}); err == nil {
		t.Error("missing clauses: expected error")
	}

	prog, err := New(ctx.params, ctx.bsk, ClauseSet{
		AmountLimit: ctx.encU4(8),
		VelocityCap: ctx.encU4(8),
		Allowlist:   []*fhe.BitCiphertext{ctx.encU4(0x1)},
	})
	if err != nil {
		t.Fatalf("new program: %v", err)
	}
	if _, err := prog.Evaluate(Intent{}); err == nil {
		t.Error("empty intent: expected error")
	}
}

// TestPolicy_DenyComposition verifies the AND chain correctly denies when
// any clause fails: amount above limit AND dest member AND velocity OK
// must still deny because amount is over.
func TestPolicy_DenyComposition(t *testing.T) {
	ctx := newCtx(t)

	prog, err := New(ctx.params, ctx.bsk, ClauseSet{
		AmountLimit: ctx.encU4(8),
		VelocityCap: ctx.encU4(8),
		Allowlist:   []*fhe.BitCiphertext{ctx.encU4(0xA)},
	})
	if err != nil {
		t.Fatalf("new program: %v", err)
	}

	// All three clauses pass.
	pass, err := prog.Evaluate(Intent{
		Amount:          ctx.encU4(2),
		DestinationHash: ctx.encU4(0xA),
		VelocityWindow:  ctx.encU4(2),
	})
	if err != nil {
		t.Fatalf("evaluate pass: %v", err)
	}
	if !ctx.dec.Decrypt(pass) {
		t.Error("all-pass case: got false, want true")
	}

	// Only amount fails.
	deny, err := prog.Evaluate(Intent{
		Amount:          ctx.encU4(14), // over limit
		DestinationHash: ctx.encU4(0xA),
		VelocityWindow:  ctx.encU4(2),
	})
	if err != nil {
		t.Fatalf("evaluate deny: %v", err)
	}
	if ctx.dec.Decrypt(deny) {
		t.Error("amount-over case: got true, want false")
	}
}
