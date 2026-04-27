// Copyright (c) 2026, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package policy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luxfi/fhe"
)

// --- DSL parsing -----------------------------------------------------

func TestRuleEngine_ParseValid(t *testing.T) {
	yamlBytes := []byte(`
rule_engine_version: "1"
policy_id: "treasury-cold-v4"
combinator: and
clauses:
  - name: amount_under_limit
    op: lt
    field: encryptedAmount
    constant: encryptedLimit
    field_width: u4
  - name: dest_in_allowlist
    op: in
    field: encryptedDestination
    constants:
      - encryptedAddr1
      - encryptedAddr2
      - encryptedAddr3
    field_width: u4
  - name: velocity_under_cap
    op: lt
    field: encryptedSum
    constant: encryptedVelocityCap
    field_width: u4
`)
	plan, err := Compile(yamlBytes)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if plan.Version != "1" {
		t.Errorf("version: got %q want 1", plan.Version)
	}
	if plan.PolicyID != "treasury-cold-v4" {
		t.Errorf("policy_id: got %q", plan.PolicyID)
	}
	if plan.Combinator != CombAnd {
		t.Errorf("combinator: got %q want and", plan.Combinator)
	}
	if len(plan.Steps) != 3 {
		t.Fatalf("steps: got %d want 3", len(plan.Steps))
	}
	if plan.Steps[1].Op != OpIn {
		t.Errorf("step 1 op: got %q want in", plan.Steps[1].Op)
	}
	if len(plan.Steps[1].ConstKeys) != 3 {
		t.Errorf("step 1 const keys: got %d want 3", len(plan.Steps[1].ConstKeys))
	}
}

func TestRuleEngine_ParseRejectsMalformed(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			"empty",
			``,
			"empty policy document",
		},
		{
			"wrong_version",
			`rule_engine_version: "2"
policy_id: x
combinator: and
clauses:
  - {name: a, op: lt, field: f, constant: c, field_width: u4}`,
			"unsupported schema version",
		},
		{
			"missing_policy_id",
			`rule_engine_version: "1"
combinator: and
clauses:
  - {name: a, op: lt, field: f, constant: c, field_width: u4}`,
			"policy_id required",
		},
		{
			"no_clauses",
			`rule_engine_version: "1"
policy_id: x
combinator: and
clauses: []`,
			"at least one clause required",
		},
		{
			"unknown_combinator",
			`rule_engine_version: "1"
policy_id: x
combinator: maybe
clauses:
  - {name: a, op: lt, field: f, constant: c, field_width: u4}`,
			"unknown combinator",
		},
		{
			"unknown_op",
			`rule_engine_version: "1"
policy_id: x
combinator: and
clauses:
  - {name: a, op: gt, field: f, constant: c, field_width: u4}`,
			"unknown op",
		},
		{
			"in_with_constant",
			`rule_engine_version: "1"
policy_id: x
combinator: and
clauses:
  - {name: a, op: in, field: f, constant: c, constants: [c1], field_width: u4}`,
			"constant forbidden for op in",
		},
		{
			"lt_without_constant",
			`rule_engine_version: "1"
policy_id: x
combinator: and
clauses:
  - {name: a, op: lt, field: f, field_width: u4}`,
			"constant required for op",
		},
		{
			"in_without_constants",
			`rule_engine_version: "1"
policy_id: x
combinator: and
clauses:
  - {name: a, op: in, field: f, field_width: u4}`,
			"at least one constants entry required",
		},
		{
			"bad_field_width",
			`rule_engine_version: "1"
policy_id: x
combinator: and
clauses:
  - {name: a, op: lt, field: f, constant: c, field_width: u3}`,
			"unknown field_width",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Compile([]byte(tc.body))
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want contains %q", err, tc.want)
			}
		})
	}
}

// --- Example YAML files compile -------------------------------------

func TestRuleEngine_ExamplesCompile(t *testing.T) {
	cases := []struct {
		name      string
		path      string
		stepCount int
	}{
		{"treasury_cold", "examples/treasury_cold.yaml", 3},
		{"hot_wallet_allowlist", "examples/hot_wallet_allowlist.yaml", 2},
		{"bridge_routing", "examples/bridge_routing.yaml", 4},
		{"validator_staking", "examples/validator_staking.yaml", 3},
		{"gas_topup", "examples/gas_topup.yaml", 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			abs, err := filepath.Abs(tc.path)
			if err != nil {
				t.Fatalf("abs: %v", err)
			}
			data, err := os.ReadFile(abs)
			if err != nil {
				t.Fatalf("read %s: %v", abs, err)
			}
			plan, err := Compile(data)
			if err != nil {
				t.Fatalf("compile %s: %v", tc.name, err)
			}
			if len(plan.Steps) != tc.stepCount {
				t.Fatalf("%s: steps got=%d want=%d", tc.name, len(plan.Steps), tc.stepCount)
			}
			// Hash is deterministic.
			if plan.PolicyHash == [32]byte{} {
				t.Fatal("policy hash is zero")
			}
		})
	}
}

// --- Evaluation against luxfi/fhe primitives ------------------------

// ruleCtx bundles FHE keys + 4-bit encrypt helpers — shared across the
// evaluation tests so each test case stays terse.
type ruleCtx struct {
	params fhe.Parameters
	bsk    *fhe.BootstrapKey
	enc    *fhe.BitwiseEncryptor
	dec    *fhe.Decryptor
	eng    *Engine
}

func newRuleCtx(t testing.TB) *ruleCtx {
	t.Helper()
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	kg := fhe.NewKeyGenerator(params)
	sk := kg.GenSecretKey()
	bsk := kg.GenBootstrapKey(sk)
	return &ruleCtx{
		params: params,
		bsk:    bsk,
		enc:    fhe.NewBitwiseEncryptor(params, sk),
		dec:    fhe.NewDecryptor(params, sk),
		eng:    NewEngine(params, bsk),
	}
}

func (c *ruleCtx) encU4(v uint8) *fhe.BitCiphertext {
	return c.enc.EncryptUint64(uint64(v&0xF), fhe.FheUint4)
}

// inlineYAML mirrors the treasury-cold example but at u4 width so the
// FHE evaluation completes inside the noise budget of PN10QP27.
const inlineYAMLU4 = `
rule_engine_version: "1"
policy_id: "treasury-cold-test"
combinator: and
clauses:
  - name: amount_under_limit
    op: lt
    field: encryptedAmount
    constant: encryptedLimit
    field_width: u4
  - name: dest_in_allowlist
    op: in
    field: encryptedDestination
    constants:
      - encryptedAddr1
      - encryptedAddr2
      - encryptedAddr3
    field_width: u4
  - name: velocity_under_cap
    op: lt
    field: encryptedSum
    constant: encryptedVelocityCap
    field_width: u4
`

func TestRuleEngine_EvaluateMatchesPlaintext(t *testing.T) {
	if testing.Short() {
		t.Skip("FHE evaluation is slow; -short skips")
	}
	ctx := newRuleCtx(t)
	plan, err := Compile([]byte(inlineYAMLU4))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	constants := map[string]*fhe.BitCiphertext{
		"encryptedLimit":       ctx.encU4(8),
		"encryptedAddr1":       ctx.encU4(0x1),
		"encryptedAddr2":       ctx.encU4(0x2),
		"encryptedAddr3":       ctx.encU4(0x3),
		"encryptedVelocityCap": ctx.encU4(8),
	}

	cases := []struct {
		name   string
		amount uint8
		dest   uint8
		used   uint8
		want   bool
	}{
		{"all_pass", 2, 0x2, 2, true},
		{"amount_over", 12, 0x2, 2, false},
		{"velocity_over", 2, 0x2, 12, false},
		{"dest_not_in_set", 2, 0xF, 2, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inputs := map[string]*fhe.BitCiphertext{
				"encryptedAmount":      ctx.encU4(tc.amount),
				"encryptedDestination": ctx.encU4(tc.dest),
				"encryptedSum":         ctx.encU4(tc.used),
			}
			result, err := plan.Evaluate(context.Background(), ctx.eng, Operands{
				Inputs:    inputs,
				Constants: constants,
			})
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			got := ctx.dec.Decrypt(result)
			if got != tc.want {
				t.Fatalf("amount=%d dest=0x%X used=%d: got %v, want %v",
					tc.amount, tc.dest, tc.used, got, tc.want)
			}
		})
	}
}

func TestRuleEngine_EvaluateOrCombinator(t *testing.T) {
	if testing.Short() {
		t.Skip("FHE evaluation is slow; -short skips")
	}
	ctx := newRuleCtx(t)
	plan, err := Compile([]byte(`
rule_engine_version: "1"
policy_id: "any-pass-v1"
combinator: or
clauses:
  - name: a_below
    op: lt
    field: encryptedA
    constant: encryptedThresh
    field_width: u4
  - name: b_eq_target
    op: eq
    field: encryptedB
    constant: encryptedTarget
    field_width: u4
`))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	constants := map[string]*fhe.BitCiphertext{
		"encryptedThresh": ctx.encU4(8),
		"encryptedTarget": ctx.encU4(0x5),
	}

	cases := []struct {
		name string
		a, b uint8
		want bool
	}{
		{"only_a_passes", 2, 0xA, true}, // a < 8 ✓, b != 5
		{"only_b_passes", 12, 0x5, true}, // a >= 8, b == 5 ✓
		{"both_pass", 2, 0x5, true},
		{"neither", 12, 0xA, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inputs := map[string]*fhe.BitCiphertext{
				"encryptedA": ctx.encU4(tc.a),
				"encryptedB": ctx.encU4(tc.b),
			}
			r, err := plan.Evaluate(context.Background(), ctx.eng, Operands{Inputs: inputs, Constants: constants})
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if got := ctx.dec.Decrypt(r); got != tc.want {
				t.Fatalf("a=%d b=0x%X: got %v want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestRuleEngine_MissingOperandRejected(t *testing.T) {
	ctx := newRuleCtx(t)
	plan, err := Compile([]byte(inlineYAMLU4))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// Missing encryptedDestination.
	inputs := map[string]*fhe.BitCiphertext{
		"encryptedAmount": ctx.encU4(1),
		"encryptedSum":    ctx.encU4(1),
	}
	constants := map[string]*fhe.BitCiphertext{
		"encryptedLimit":       ctx.encU4(8),
		"encryptedAddr1":       ctx.encU4(0x1),
		"encryptedAddr2":       ctx.encU4(0x2),
		"encryptedAddr3":       ctx.encU4(0x3),
		"encryptedVelocityCap": ctx.encU4(8),
	}
	_, err = plan.Evaluate(context.Background(), ctx.eng, Operands{Inputs: inputs, Constants: constants})
	if err == nil {
		t.Fatal("expected ErrMissingOperand, got nil")
	}
}

// --- Batch executor --------------------------------------------------

func TestRuleEngine_EvaluateBatch(t *testing.T) {
	if testing.Short() {
		t.Skip("FHE evaluation is slow; -short skips")
	}
	ctx := newRuleCtx(t)
	// Batch test uses a smaller 2-clause plan to keep gate depth well
	// inside PN10QP27's noise budget over N=16 intents. Single-shot
	// 3-clause evaluation is covered by TestRuleEngine_EvaluateMatchesPlaintext.
	plan, err := Compile([]byte(`
rule_engine_version: "1"
policy_id: "batch-smoke-v1"
combinator: and
clauses:
  - name: amount_under_limit
    op: lt
    field: encryptedAmount
    constant: encryptedLimit
    field_width: u4
  - name: dest_eq_target
    op: eq
    field: encryptedDestination
    constant: encryptedTarget
    field_width: u4
`))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	constants := map[string]*fhe.BitCiphertext{
		"encryptedLimit":  ctx.encU4(8),
		"encryptedTarget": ctx.encU4(0x2),
	}

	// Batch of N alternating pass/deny intents. Each intent has its
	// own freshly-encrypted ciphertexts so per-intent noise is
	// independent. Values are chosen well clear of the limit (pass
	// amount=1, deny amount=15) for clean noise margin.
	const N = 16
	inputs := make([]map[string]*fhe.BitCiphertext, N)
	want := make([]bool, N)
	for i := 0; i < N; i++ {
		amt := uint8(1)
		dest := uint8(0x2)
		expected := true
		if i%2 == 1 {
			amt = 15
			expected = false
		}
		inputs[i] = map[string]*fhe.BitCiphertext{
			"encryptedAmount":      ctx.encU4(amt),
			"encryptedDestination": ctx.encU4(dest),
		}
		want[i] = expected
	}

	factory := NewEngineFactory(ctx.params, ctx.bsk)
	for _, conc := range []int{1, 4} {
		conc := conc
		t.Run(fmt.Sprintf("conc=%d", conc), func(t *testing.T) {
			res, err := plan.EvaluateBatch(context.Background(), factory, BatchRequest{
				Inputs:      inputs,
				Constants:   constants,
				Concurrency: conc,
			})
			if err != nil {
				t.Fatalf("batch evaluate: %v", err)
			}
			if len(res.Verdicts) != N {
				t.Fatalf("verdicts: got %d want %d", len(res.Verdicts), N)
			}
			for i, v := range res.Verdicts {
				got := ctx.dec.Decrypt(v)
				if got != want[i] {
					t.Errorf("conc=%d verdict[%d]: got %v want %v", conc, i, got, want[i])
				}
			}
		})
	}
}

// --- Plan cache ------------------------------------------------------

func TestPlanCache_HitsAvoidRecompile(t *testing.T) {
	yamlBytes := []byte(inlineYAMLU4)
	hash := HashYAML(yamlBytes)

	var loadCalls int32
	loader := PlanLoaderFunc(func(id string, h [32]byte) ([]byte, error) {
		atomic.AddInt32(&loadCalls, 1)
		return yamlBytes, nil
	})

	cache := &PlanCache{}
	_, err := cache.GetOrCompile("treasury-cold-test", hash, loader)
	if err != nil {
		t.Fatalf("first GetOrCompile: %v", err)
	}
	for i := 0; i < 5; i++ {
		_, err := cache.GetOrCompile("treasury-cold-test", hash, loader)
		if err != nil {
			t.Fatalf("repeated GetOrCompile[%d]: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&loadCalls); got != 1 {
		t.Errorf("loader called %d times; want 1", got)
	}
	if cache.Len() != 1 {
		t.Errorf("cache len = %d; want 1", cache.Len())
	}
}

func TestPlanCache_RejectsHashMismatch(t *testing.T) {
	yamlBytes := []byte(inlineYAMLU4)
	wrongHash := [32]byte{0xDE, 0xAD, 0xBE, 0xEF}

	loader := PlanLoaderFunc(func(id string, h [32]byte) ([]byte, error) {
		return yamlBytes, nil
	})
	cache := &PlanCache{}
	_, err := cache.GetOrCompile("treasury-cold-test", wrongHash, loader)
	if err == nil {
		t.Fatal("expected ErrHashMismatch, got nil")
	}
	if !strings.Contains(err.Error(), "policy hash mismatch") {
		t.Fatalf("err = %v; want hash mismatch", err)
	}
}

func TestPlanCache_ForgetEvicts(t *testing.T) {
	yamlBytes := []byte(inlineYAMLU4)
	hash := HashYAML(yamlBytes)

	var loadCalls int32
	loader := PlanLoaderFunc(func(id string, h [32]byte) ([]byte, error) {
		atomic.AddInt32(&loadCalls, 1)
		return yamlBytes, nil
	})
	cache := &PlanCache{}
	_, _ = cache.GetOrCompile("treasury-cold-test", hash, loader)
	cache.Forget("treasury-cold-test")
	if cache.Len() != 0 {
		t.Errorf("after forget: len=%d want 0", cache.Len())
	}
	_, _ = cache.GetOrCompile("treasury-cold-test", hash, loader)
	if got := atomic.LoadInt32(&loadCalls); got != 2 {
		t.Errorf("loader called %d times; want 2 (one before, one after forget)", got)
	}
}

func TestPlanCache_DistinctHashesCacheSeparately(t *testing.T) {
	a := []byte(inlineYAMLU4)
	b := []byte(strings.Replace(inlineYAMLU4, "treasury-cold-test", "treasury-cold-test", 1) + "\n# trailing change\n")
	hashA := HashYAML(a)
	hashB := HashYAML(b)
	if hashA == hashB {
		t.Fatal("test setup: a and b must hash differently")
	}
	loader := PlanLoaderFunc(func(_ string, h [32]byte) ([]byte, error) {
		if h == hashA {
			return a, nil
		}
		return b, nil
	})
	cache := &PlanCache{}
	if _, err := cache.GetOrCompile("treasury-cold-test", hashA, loader); err != nil {
		t.Fatalf("a: %v", err)
	}
	if _, err := cache.GetOrCompile("treasury-cold-test", hashB, loader); err != nil {
		t.Fatalf("b: %v", err)
	}
	if cache.Len() != 2 {
		t.Errorf("len=%d want 2", cache.Len())
	}
}
