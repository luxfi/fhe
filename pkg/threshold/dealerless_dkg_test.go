// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package threshold

import (
	"go/ast"
	"go/parser"
	"go/token"
	"math/big"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/luxfi/fhe"
	"github.com/luxfi/lattice/v7/utils/sampling"
)

// crsSeed is a fixed CRS seed for the tests. In production this is supplied by
// consensus (e.g. a beacon/epoch nonce) and is identical on every validator.
var crsSeed = []byte("lux-fchain-tfhe-dealerless-dkg-test-crs-seed-v1")

// ============================================================================
// E2E: the trustless confidential-decrypt lane end to end.
//   dealerless DKG  →  encrypt under collective pk  →  t-of-n partial decrypt
//   →  combine  →  correct plaintext, with NO trusted dealer.
// ============================================================================

// TestDealerless_E2E_RoundTrip_2of3 runs the full trustless flow at PN10QP27.
func TestDealerless_E2E_RoundTrip_2of3(t *testing.T) {
	for _, value := range []bool{false, true} {
		runDealerlessRoundTrip(t, fhe.PN10QP27, 2, 3, value)
	}
}

// TestDealerless_E2E_RoundTrip_3of5 covers a larger committee at PN11QP54
// (wider modulus for the larger collective secret + public-key noise).
func TestDealerless_E2E_RoundTrip_3of5(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 3-of-5 dealerless round-trip under -short")
	}
	for _, value := range []bool{false, true} {
		runDealerlessRoundTrip(t, fhe.PN11QP54, 3, 5, value)
	}
}

func runDealerlessRoundTrip(t *testing.T, lit fhe.ParametersLiteral, threshold, total int, value bool) {
	t.Helper()
	params, err := fhe.NewParametersFromLiteral(lit)
	if err != nil {
		t.Fatalf("params: %v", err)
	}

	// DEALERLESS key generation: no trusted dealer ever holds the FHE secret.
	pub, shares, err := DealerlessKeyGen(params, threshold, total, crsSeed)
	if err != nil {
		t.Fatalf("dealerless keygen: %v", err)
	}
	if len(shares) != total {
		t.Fatalf("share count: got %d want %d", len(shares), total)
	}
	if pub == nil || pub.PKLWE == nil {
		t.Fatalf("nil collective public key")
	}

	// Encrypt under the COLLECTIVE PUBLIC KEY (public-key encryption — the
	// production path; no secret key anywhere).
	enc := fhe.NewBitwisePublicEncryptor(params, pub)
	ct, err := enc.Encrypt(value)
	if err != nil {
		t.Fatalf("public-key encrypt: %v", err)
	}

	// Threshold decrypt with the LAST t parties (avoids lucky small-Lagrange
	// alignment with the first shares).
	subset := shares[total-threshold:]
	partials := make([]*LWEPartialDecryption, threshold)
	for i := range subset {
		share := subset[i]
		prng, err := sampling.NewPRNG()
		if err != nil {
			t.Fatalf("prng: %v", err)
		}
		p, err := PartialDecryptFHE(&share, ct, params, threshold, prng)
		if err != nil {
			t.Fatalf("partial[%d]: %v", i, err)
		}
		partials[i] = p
	}

	got, err := CombineFHE(ct, partials, params)
	if err != nil {
		t.Fatalf("combine: %v", err)
	}
	if got != value {
		t.Fatalf("dealerless round trip: got %v want %v (%d-of-%d)", got, value, threshold, total)
	}
}

// TestDealerless_BelowThresholdFails confirms t-1 parties cannot recover the
// plaintext: a single partial leaves c_1·s_j unmasked, so the decoded bit is
// wrong with non-negligible probability.
func TestDealerless_BelowThresholdFails(t *testing.T) {
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	pub, shares, err := DealerlessKeyGen(params, 2, 3, crsSeed)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	enc := fhe.NewBitwisePublicEncryptor(params, pub)

	disagreements := 0
	trials := 32
	share := shares[0]
	for i := 0; i < trials; i++ {
		value := i&1 == 0
		ct, err := enc.Encrypt(value)
		if err != nil {
			t.Fatalf("encrypt[%d]: %v", i, err)
		}
		prng, _ := sampling.NewPRNG()
		p, err := PartialDecryptFHE(&share, ct, params, 1, prng)
		if err != nil {
			t.Fatalf("partial[%d]: %v", i, err)
		}
		got, err := CombineFHE(ct, []*LWEPartialDecryption{p}, params)
		if err != nil {
			t.Fatalf("combine[%d]: %v", i, err)
		}
		if got != value {
			disagreements++
		}
	}
	if disagreements == 0 {
		t.Fatalf("below-threshold (1 of 3) must not reliably decrypt; got 0/%d disagreements", trials)
	}
}

// ============================================================================
// DEALERLESS / NO-PARTY-HOLDS-SECRET (behavioural).
// ============================================================================

// TestDealerless_NoPartyHoldsSecret proves the shares form a genuine t-of-n
// Shamir sharing of a well-defined secret that NO single party holds:
//   - two disjoint-enough t-subsets reconstruct the SAME secret (a consistent
//     sharing of one secret exists), and
//   - no individual party's share equals that secret.
// The reconstruction oracle lives ONLY in this test file; production never
// reconstructs s (see TestDealerless_NoReconstruct_Structural).
func TestDealerless_NoPartyHoldsSecret(t *testing.T) {
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	_, shares, err := DealerlessKeyGen(params, 2, 3, crsSeed)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	q := params.QLWE()

	// Reconstruct from {party1,party2} and from {party2,party3}; both must agree
	// — the shares are a consistent Shamir sharing of one secret.
	sA := reconstructSecretForTest(t, []LWEShare{shares[0], shares[1]}, q)
	sB := reconstructSecretForTest(t, []LWEShare{shares[1], shares[2]}, q)
	if !equalU64(sA, sB) {
		t.Fatalf("two t-subsets reconstruct different secrets: shares are not a consistent sharing")
	}

	// No single share equals the secret — no party holds s.
	for _, share := range shares {
		if equalU64(share.Coeffs, sA) {
			t.Fatalf("party %d's share equals the reconstructed secret — a party holds s", share.Index)
		}
	}

	// And the reconstructed secret is non-trivial (not all-zero), i.e. a real
	// secret was shared.
	allZero := true
	for _, c := range sA {
		if c != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatalf("reconstructed secret is all-zero — degenerate sharing")
	}
}

// TestDealerless_CRP_Deterministic proves the public CRP a is identical for the
// same consensus seed (so every validator derives the same collective-key
// algebra), while differing seeds give different a. The SECRET is freshly
// sampled per run (trustless) — only the public reference is seed-derived.
func TestDealerless_CRP_Deterministic(t *testing.T) {
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	crp1, _, err := SampleDealerlessCRP(params, crsSeed)
	if err != nil {
		t.Fatalf("crp1: %v", err)
	}
	crp2, _, err := SampleDealerlessCRP(params, crsSeed)
	if err != nil {
		t.Fatalf("crp2: %v", err)
	}
	if !crp1.Value.Q.Equal(&crp2.Value.Q) {
		t.Fatalf("CRP not deterministic for identical seed — validators would diverge")
	}
	crp3, _, err := SampleDealerlessCRP(params, []byte("a-different-consensus-seed"))
	if err != nil {
		t.Fatalf("crp3: %v", err)
	}
	if crp1.Value.Q.Equal(&crp3.Value.Q) {
		t.Fatalf("CRP identical for different seeds — CRS is not seed-bound")
	}
}

// ============================================================================
// TRANSPORT CARRIES NO SECRET (reflect gate).
// The dealerless protocol messages must carry only public/share data — never a
// full secret key. A *rlwe.SecretKey or *fhe.SecretKey field on a wire type
// would let a single party's secret leave its node.
// ============================================================================

func TestDealerless_TransportCarriesNoSecret(t *testing.T) {
	forbidden := []string{"SecretKey", "SKLWE", "SKBR"}
	for _, msg := range []interface{}{PublicKeyShareMsg{}, SubShareMsg{}, LWEShare{}, LWEPartialDecryption{}} {
		ty := reflect.TypeOf(msg)
		for i := 0; i < ty.NumField(); i++ {
			f := ty.Field(i)
			fieldStr := f.Name + ":" + f.Type.String()
			for _, bad := range forbidden {
				if strings.Contains(fieldStr, bad) {
					t.Fatalf("wire type %s field %q references forbidden secret material (%q)", ty.Name(), fieldStr, bad)
				}
			}
		}
	}
}

// ============================================================================
// NO-RECONSTRUCT (structural, go/ast).
// The dealerless-keygen + threshold-decrypt path must never invoke a
// trusted-dealer keygen (forms/holds a full secret) nor a secret-reconstruction
// primitive. Modelled on corona's no_reconstruct_sign_test.go GATE A.
// ============================================================================

// noReconstructForbidden lists call targets that would mean the trustless path
// formed or reconstructed the full FHE secret key:
//   - GenKeyPair: generates the full master (sk, pk) in one process.
//   - ShareLWESecretKey / ShareLWESecretKeyFHE: deal a *whole* secret key (the
//     trusted-dealer split; the dealerless path never deals a full key).
//   - GenerateSharedKey: the trusted-dealer keygen wrapper.
// Plus any identifier whose name denotes secret reconstruction.
var noReconstructForbiddenCalls = map[string]struct{}{
	"GenKeyPair":            {},
	"ShareLWESecretKey":     {},
	"ShareLWESecretKeyFHE":  {},
	"GenerateSharedKey":     {},
}

var noReconstructForbiddenNameRe = regexp.MustCompile(`(?i)reconstruct|recoversecret|combinesecret|recovermaster`)

// noReconstructScannedFuncs is the trustless key-generation + threshold-decrypt
// surface that must be free of trusted-dealer / reconstruction calls.
var noReconstructScannedFuncs = map[string]struct{}{
	"DealRound1":                  {},
	"Aggregate":                   {},
	"AssembleCollectivePublicKey": {},
	"DealerlessKeyGen":            {},
	"NewDealerlessParty":          {},
	"PartialDecryptLWE":           {},
	"CombineLWE":                  {},
	"PartialDecryptFHE":           {},
	"CombineFHE":                  {},
}

func TestDealerless_NoReconstruct_Structural(t *testing.T) {
	// Scan PRODUCTION source only (exclude _test.go): the gate is about the
	// shipped trustless path, not test scaffolding.
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	fset := token.NewFileSet()
	scanned := map[string]bool{}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if _, want := noReconstructScannedFuncs[fn.Name.Name]; !want {
				continue
			}
			scanned[fn.Name.Name] = true
			if bad := findForbiddenCall(fn.Body); bad != "" {
				t.Errorf("function %s calls forbidden primitive %q — trustless path may form/reconstruct the full FHE secret",
					fn.Name.Name, bad)
			}
		}
	}

	// Every function we expect to scan must have been found — a rename that
	// silently drops a function from the gate is itself a failure.
	for name := range noReconstructScannedFuncs {
		if !scanned[name] {
			t.Errorf("expected to scan function %q but it was not found (renamed/removed?)", name)
		}
	}
}

// TestDealerless_NoReconstruct_Structural_NegativeControl proves the gate has
// teeth: a synthetic function body containing a forbidden call is flagged.
func TestDealerless_NoReconstruct_Structural_NegativeControl(t *testing.T) {
	src := `package x
func victim() {
	sk := genFull()
	ShareLWESecretKey(sk, params, 2, 3) // trusted-dealer deal — must be caught
}`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, 0)
	if err != nil {
		t.Fatalf("parse synthetic: %v", err)
	}
	var body *ast.BlockStmt
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "victim" {
			body = fn.Body
		}
	}
	if body == nil {
		t.Fatal("synthetic victim not parsed")
	}
	if bad := findForbiddenCall(body); bad == "" {
		t.Fatal("negative control: gate failed to flag an injected forbidden call (gate has no teeth)")
	}
}

// findForbiddenCall returns the name of the first forbidden call target found in
// body, or "" if clean. Matches both bare calls f(...) and selector calls x.f(...).
func findForbiddenCall(body *ast.BlockStmt) string {
	found := ""
	ast.Inspect(body, func(n ast.Node) bool {
		if found != "" {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		var name string
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			name = fn.Name
		case *ast.SelectorExpr:
			name = fn.Sel.Name
		}
		if name == "" {
			return true
		}
		if _, bad := noReconstructForbiddenCalls[name]; bad {
			found = name
			return false
		}
		if noReconstructForbiddenNameRe.MatchString(name) {
			found = name
			return false
		}
		return true
	})
	return found
}

// ============================================================================
// test-only reconstruction oracle (NOT in the production binary).
// ============================================================================

// reconstructSecretForTest Lagrange-interpolates the LWEShares at x=0 over Z_q
// to recover the shared secret in standard coefficient form. It exists solely to
// PROVE properties of the sharing (consistency, no-party-holds); production code
// never does this — the structural gate forbids it.
func reconstructSecretForTest(t *testing.T, shares []LWEShare, q uint64) []uint64 {
	t.Helper()
	qBig := new(big.Int).SetUint64(q)
	N := len(shares[0].Coeffs)
	out := make([]uint64, N)
	for i := 0; i < N; i++ {
		acc := new(big.Int)
		for j := range shares {
			xj := big.NewInt(int64(shares[j].Index))
			num := big.NewInt(1)
			den := big.NewInt(1)
			for k := range shares {
				if k == j {
					continue
				}
				xk := big.NewInt(int64(shares[k].Index))
				num.Mul(num, xk)
				num.Mod(num, qBig)
				d := new(big.Int).Sub(xk, xj)
				den.Mul(den, d)
				den.Mod(den, qBig)
			}
			denInv := new(big.Int).ModInverse(den, qBig)
			if denInv == nil {
				t.Fatalf("non-invertible Lagrange denominator (duplicate indices?)")
			}
			lambda := new(big.Int).Mul(num, denInv)
			lambda.Mod(lambda, qBig)
			term := new(big.Int).Mul(lambda, new(big.Int).SetUint64(shares[j].Coeffs[i]))
			acc.Add(acc, term)
			acc.Mod(acc, qBig)
		}
		out[i] = acc.Uint64()
	}
	return out
}

func equalU64(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
