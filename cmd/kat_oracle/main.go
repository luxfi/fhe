// Copyright (c) 2026, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause
//
// kat_oracle emits the canonical Lux FHE-KAT corpus consumed by the
// C++ production runtime (luxcpp/crypto/fhe/test/cpp/fhe_kat_replay_test).
//
// Each invocation writes one JSON record per (param_set, seed) tuple to
// stdout. The regen script (lux/fhe/scripts/regen-kats.sh) drives a
// fixed parameter-set / seed matrix into a deterministic corpus
// directory and writes a SHA-256 manifest to confirm byte-equality
// across runs.
//
// LP-167 §"Cross-runtime KAT contract" specifies the JSON shape:
//
//   {
//     "id":            "<test-name>",
//     "param_set":     "PN10QP27" | "PN11QP54" | "PN9QP28_STD128",
//     "seed":          "<32 hex bytes>",
//     "operation":     "secret_key" | "encrypt_decrypt",
//     "inputs":        [...plaintext bits...],
//     "expected_ct":   "<base64 ciphertext>",
//     "expected_decode": [...plaintext bits...]
//   }
//
// The scaffold milestone (v0.1.0-rc1-fhe-scaffold) emits the
// "secret_key" entries — they pin the (param_set, seed) → SecretKey
// bytes mapping. The "encrypt_decrypt" entries land at v0.1.0-rc2-fhe-gpu
// in lockstep with the C++ programmable-bootstrap path.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"hash/crc32"
	"os"
	"sort"

	"github.com/luxfi/fhe"
)

type katEntry struct {
	ID            string   `json:"id"`
	ParamSet      string   `json:"param_set"`
	Seed          string   `json:"seed"` // 32 hex bytes
	Operation     string   `json:"operation"`
	Inputs        []int    `json:"inputs,omitempty"`
	ExpectedCT    string   `json:"expected_ct,omitempty"`     // base64
	ExpectedDecode []int   `json:"expected_decode,omitempty"`
	// Manifest fingerprint (CRC32 of canonical encoding) — independent
	// proof of byte-stability across runs without requiring a full
	// C++-side parse.
	Fingerprint   string   `json:"fingerprint"`
}

// paramSetByName resolves a Lux FHE parameter-set ID string to the
// canonical lattice Parameters. The names match exactly across runtimes
// per LP-167 §"Parameter sets".
func paramSetByName(name string) (fhe.Parameters, error) {
	switch name {
	case "PN10QP27":
		return fhe.NewParametersFromLiteral(fhe.PN10QP27)
	case "PN11QP54":
		return fhe.NewParametersFromLiteral(fhe.PN11QP54)
	default:
		return fhe.Parameters{}, fmt.Errorf("kat_oracle: unsupported param_set %q (allowed: PN10QP27, PN11QP54)", name)
	}
}

// seedFromHex parses a 64-char hex string into 32 bytes. Required so
// the C++ side can reuse the same byte sequence verbatim.
func seedFromHex(seedHex string) ([]byte, error) {
	if len(seedHex) != 64 {
		return nil, fmt.Errorf("kat_oracle: seed must be 32 bytes hex (64 chars), got %d", len(seedHex))
	}
	return hex.DecodeString(seedHex)
}

// emitSecretKeyEntry generates a SecretKey from (param_set, seed) and
// returns the canonical KAT JSON entry. The Fingerprint is the CRC32 of
// the marshaled SKBR + SKLWE bytes — a small, fixed-size byte-stability
// witness suitable for cross-runtime equality assertion.
func emitSecretKeyEntry(id, paramSetName, seedHex string) (katEntry, error) {
	params, err := paramSetByName(paramSetName)
	if err != nil {
		return katEntry{}, err
	}
	seed, err := seedFromHex(seedHex)
	if err != nil {
		return katEntry{}, err
	}
	kg, err := fhe.NewKeyGeneratorFromSeed(params, seed)
	if err != nil {
		return katEntry{}, fmt.Errorf("kat_oracle: keygen: %w", err)
	}
	sk := kg.GenSecretKey()

	skBytes, err := sk.MarshalBinary()
	if err != nil {
		return katEntry{}, fmt.Errorf("kat_oracle: marshal sk: %w", err)
	}

	digest := sha256.Sum256(skBytes)
	fingerprint := fmt.Sprintf("%08x", crc32.ChecksumIEEE(digest[:]))

	return katEntry{
		ID:          id,
		ParamSet:    paramSetName,
		Seed:        seedHex,
		Operation:   "secret_key",
		Fingerprint: fingerprint,
	}, nil
}

// emitMatrix writes the full default matrix to outDir, one JSON entry per
// (param_set, seed) tuple. Returns the slice of relative paths emitted
// in sorted order so the manifest builder can hash them deterministically.
func emitMatrix(outDir string) ([]string, error) {
	matrix := []struct {
		ID, ParamSet, Seed string
	}{
		{"sk_pn10qp27_seed_zero", "PN10QP27",
			"0000000000000000000000000000000000000000000000000000000000000000"},
		{"sk_pn10qp27_seed_lp167", "PN10QP27",
			"4c503136372d6b61742d76312d7365656420666f72204c75782046484520202020"[:64]},
		{"sk_pn11qp54_seed_zero", "PN11QP54",
			"0000000000000000000000000000000000000000000000000000000000000000"},
		{"sk_pn11qp54_seed_lp167", "PN11QP54",
			"4c503136372d6b61742d76312d7365656420666f72204c75782046484520202020"[:64]},
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, err
	}

	emitted := make([]string, 0, len(matrix))
	for _, e := range matrix {
		entry, err := emitSecretKeyEntry(e.ID, e.ParamSet, e.Seed)
		if err != nil {
			return nil, err
		}
		body, err := json.MarshalIndent(entry, "", "  ")
		if err != nil {
			return nil, err
		}
		fname := e.ID + ".json"
		path := outDir + "/" + fname
		if err := os.WriteFile(path, append(body, '\n'), 0o644); err != nil {
			return nil, err
		}
		emitted = append(emitted, fname)
	}

	sort.Strings(emitted)
	return emitted, nil
}

func main() {
	out := flag.String("out", "", "output directory for KAT entries")
	emit := flag.Bool("emit", false, "emit the canonical KAT matrix to --out")
	flag.Parse()

	if *emit {
		if *out == "" {
			fmt.Fprintln(os.Stderr, "kat_oracle: --emit requires --out")
			os.Exit(2)
		}
		entries, err := emitMatrix(*out)
		if err != nil {
			fmt.Fprintf(os.Stderr, "kat_oracle: emit: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("emitted %d KAT entries to %s\n", len(entries), *out)
		for _, e := range entries {
			fmt.Println("  " + e)
		}
		return
	}

	fmt.Fprintln(os.Stderr, "usage: kat_oracle --emit --out <dir>")
	os.Exit(2)
}
