// Copyright (c) 2026, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

// Package bench is the canonical FHE benchmark ladder.
//
// Per FHE-GPU architecture spec section 19, this directory consolidates
// fragmented FHE benchmarks (#88 Metal NTT crossover, #118 FHE policy CPU,
// #121 FHE-GPU diagnostic) into one harness so that future agents have
// exactly one place to look for "how fast is this on my host".
//
// Layout:
//
//	bench_ntt_test.go            -- NTT ladder (N x B x domain x mode)
//	bench_tfhe_primitives_test.go -- LWE/TRLWE/external-product/etc.
//	bench_threshold_test.go       -- threshold ops
//	bench_circuits_test.go        -- production circuits
//	bench_reconcile_test.go       -- reconciliation #88 vs #121
//	results/                      -- JSON per run (gitignored content,
//	                                directory tracked via .gitkeep)
//	RESULTS.md                    -- aggregate Markdown table at top.
//
// All benchmarks here are pure-Go observers: they neither modify FHE
// primitives nor link new GPU code. The Metal-side benches reach
// libluxlattice via the existing luxfi/lattice/v7/gpu cgo wrapper. If
// the wrapper is unavailable (no -tags gpu, library not installed,
// dispatcher returns an error) the corresponding cells skip with
// b.Skip("NotApplicable: ...") rather than fabricating numbers.
//
// Reproduction:
//
//	cd /Users/z/work/lux/fhe/bench && \
//	  GOWORK=off go test -run=^$ -bench=. -benchtime=10x -timeout=1800s \
//	    -count=1 -benchmem ./
//
// Each benchmark logs its exact invocation, build tags, and the host's
// FHE commit hash to results/<benchmark>_<timestamp>.json so that two
// runs on different days are byte-comparable.
//
// Honest residual: the FHE-GPU FIX agent (#119 successor) is in flight.
// Several primitives in the TFHE ladder are CPU-only today; their GPU
// cells are NotApplicable and will be filled in as siblings ship. The
// reconciliation between #88's 14.02x and #121's 0.08x is the current
// load-bearing finding -- see bench_reconcile_test.go.
package bench
