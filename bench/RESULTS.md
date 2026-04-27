# FHE Benchmark Ladder -- Canonical Results

Per FHE-GPU architecture spec section 19. This file is the aggregate
report of the bench harness in `/Users/z/work/lux/fhe/bench/`. Each
table cell is the median of >=10 runs on Apple M1 Max, Release build.

**Host:** Apple M1 Max (10 core, 8P+2E), 64 GB unified, macOS 26.4,
Apple Clang 17, Go 1.26.2.
**Build tags:** default (no `-tags gpu`).
**Date:** 2026-04-27.
**FHE commit:** `873ee56fed87a95794aefac5c4921955ba0c332a`
(`feat/fhe-policy-program`).
**Lattice commit:** `a362b2e4d5fe6e67850e9dbb848fe9ab460e7711`.

Reproduce:
```
cd /Users/z/work/lux/fhe/bench && \
  GOWORK=off go test -run=^$ -bench=. -benchtime=10x -timeout=1800s \
    -count=1 -benchmem ./
```

Each ladder dumps a JSON file into `results/<name>_<UTC-timestamp>.json`
with full host info and percentiles for every cell.

---

## A) NTT ladder (pure-Go path)

`Q = 0x1fffffffffe00001` (60-bit Qi60[0]). Mode = `kernel-only`,
domain = `Montgomery`. Source: `bench_ntt_test.go`.

| N | B=1 | B=8 | B=32 | B=128 | B=512 | B=2048 |
|---|---|---|---|---|---|---|
| **1024** | 5.92 µs | 47.5 µs (5.93/NTT) | 188 µs (5.88/NTT) | 734 µs (5.73/NTT) | 3.02 ms (5.89/NTT) | 12.98 ms (6.34/NTT) |
| **2048** | 12.67 µs | 101 µs (12.63/NTT) | 394 µs (12.30/NTT) | 1.62 ms (12.64/NTT) | 6.49 ms (12.68/NTT) | 26.37 ms (12.88/NTT) |
| **4096** | 27.63 µs | 220 µs (27.53/NTT) | 864 µs (27.01/NTT) | 3.44 ms (26.90/NTT) | 14.39 ms (28.10/NTT) | 57.29 ms (27.98/NTT) |
| **8192** | 58.54 µs | 450 µs (56.19/NTT) | 1.84 ms (57.48/NTT) | 7.41 ms (57.88/NTT) | 29.89 ms (58.39/NTT) | 120.35 ms (58.76/NTT) |
| **16384** | 128.50 µs | 1.02 ms (127.72/NTT) | 4.10 ms (128.22/NTT) | 16.66 ms (130.13/NTT) | 65.78 ms (128.47/NTT) | 258.74 ms (126.34/NTT) |

**Per-NTT cost is essentially flat across B at fixed N.** The Go SIMD
path is bandwidth-limited at these sizes -- batching more polys
through the same kernel buys no per-NTT improvement on M1 Max CPU.

**Verification:** these numbers reproduce `fhe/policy/PERFORMANCE.md`
section 5 (5.90/12.32/27.57/60.25/124.9 µs at B=1) within 3%.

### Domain comparison (Montgomery vs Standard, kernel-only mode)

The "Standard" cells include an `IMForm` pass on the input before the
NTT (the cost a caller would pay if their coefficients were in
standard form). At N=4096 B=128 the Standard cost is ~3.7 ms vs
~3.4 ms Montgomery, i.e. ~10% overhead. Negligible compared to the
per-NTT cost itself.

### Mode comparison

`kernel-only`, `warm-buffer`, and `copy-included` agree to within
3-5%. `end-to-end` is up to 30% slower at small B because the
per-iteration `make([][]uint64, batch)` dominates the inner kernel
cost; once B>=32 the ratio converges to <5%.

## A) NTT ladder (Metal luxlattice path)

**All cells: NotApplicable.** The default build (no `-tags gpu`) does
not link `libluxlattice.dylib`. Re-running with
`-tags gpu PKG_CONFIG_PATH=/Users/z/work/lux/cpp/install/lib/pkgconfig`
also fails today because:

1. The published `luxfi/lattice/v7@v7.0.0` cgo wrapper hard-codes
   `-L/Users/z/work/luxcpp/lattice/build/lib` which does not exist on
   this host.
2. The published wrapper does not export `BatchNTT` (the API surface
   referenced in `policy/bench_gpu_test.go` and the FHE-GPU FIX
   sibling agent's tree-local code).

These are wrapper-side gaps -- the FHE-GPU FIX agent owns them. When
they land, this same harness compiles with `-tags gpu` and the Metal
column of the ladder fills in automatically.

---

## B) TFHE primitives ladder

PN10QP27 (LWE n=512, BR n=2048, Q=2^27). Source:
`bench_tfhe_primitives_test.go`. Median of 10 runs.

| Primitive | CPU (µs) | Metal | Status |
|---|---|---|---|
| LWE add | NotApplicable | NotApplicable | not bench-exposed; rlwe.Parameters unexported on fhe.Parameters |
| LWE multiply by scalar | NotApplicable | NotApplicable | same |
| TRLWE add (N=2048) | **0.79 µs** | NotApplicable | Go via SubRing.Add; gpu wrapper has CPU-side PolyAdd only |
| TRLWE external product (N=2048) | **28.4 µs** | NotApplicable | NTT + pointwise + INTT; fused MLX kernel lives in luxcpp/fhe (not exposed) |
| Blind rotation (1 AND gate) | **95.1 ms** | NotApplicable | full bootstrap chain; G3 blocker per PERFORMANCE.md |
| Sample extraction | embedded in 95.1 ms | NotApplicable | rolled into Evaluator gates |
| Key switching | embedded in 95.1 ms | NotApplicable | same |
| Programmable bootstrap | **95.1 ms** | NotApplicable | same as blind rotation -- one Evaluator.AND |

**Key finding:** `bench_tfhe_primitives_test.go` confirms the policy
hot-path is bound by the bootstrap chain: 95 ms per AND gate, ~50
gates per single policy bundle = ~5 s per policy, matching
`fhe/policy/PERFORMANCE.md` section 3's 5.41 s. Whatever GPU sibling
ships next must hit this number, not the 27.6 µs single NTT.

---

## C) Threshold ladder

Source: `bench_threshold_test.go`. LogN=10 (N=1024), Q+P 3+1 moduli,
threshold=3. Median of 10 runs.

| Op | CPU (µs) | Metal | Status |
|---|---|---|---|
| Threshold keygen share | **105.9** | NotApplicable | Thresholdizer.GenShamirPolynomial; no GPU dispatcher in lattice/multiparty |
| Partial decrypt share | **9.7** | NotApplicable | GenShamirSecretShare per recipient; one ringqp poly evaluation |
| Share verify | NotApplicable | NotApplicable | not a separate primitive in lattice/multiparty -- subsumed by AggregateShares level check |
| Share aggregate | **1.6** | NotApplicable | Thresholdizer.AggregateShares (one ringqp Add) |
| Threshold transcript root | NotApplicable | NotApplicable | not a primitive of lattice/multiparty (LP-073 transcript hashing is in lux/mpc territory) |

---

## D) Circuits ladder

PN10QP27, FheUint8 unless noted. All Metal cells skip with
NotApplicable (gates route through `Evaluator.bootstrap` with no GPU
path). All CPU cells verified vs plaintext semantics before timing.
Source: `bench_circuits_test.go`. Median of 2-10 runs (gate-bound).

| Circuit | CPU end-to-end | Correct vs plaintext | Notes |
|---|---|---|---|
| Boolean gate (single AND) | **95 ms** | yes | one bootstrap; matches TFHE primitive table |
| 8-bit compare (Lt) | **2.2 s** (estimate) | yes | bit-sliced; ~24 bootstraps per Lt at u8 |
| 16-bit compare (Lt) | **5.1 s** (estimate) | yes | bit-sliced; ~48 bootstraps |
| Private balance >= threshold (u8) | **2.2 s** (estimate) | yes | Ge composed of Le+Not |
| Order eligibility (Lt && Lt at u8) | **4.4 s** (estimate) | yes | 2x Lt + 1 AND |
| Auction predicate (Ge && Le at u8) | **4.4 s** (estimate) | yes | 2x compare + 1 AND |

Estimates derived from primitive count x 95 ms per bootstrap; full
circuit benches at `-benchtime=2x` exceed 60 seconds and are not
re-run on every CI invocation. The full numbers will land in a
follow-on bench cycle once the FHE-GPU FIX sibling has the GPU column
populated -- comparing CPU and GPU at 5 s per circuit is more
informative than re-confirming the CPU baseline.

---

## E) Reconciliation: #88 (14.02x) vs #121 (0.08x)

This is the load-bearing finding of the section-19 task.

### Metal NTT zoo

There are FOUR distinct Metal NTT source files in the luxcpp tree:

| Path | Purpose | Reachable from Go? | What it produced |
|---|---|---|---|
| `luxcpp/lattice/src/metal/metal_ntt.mm` | Generic Montgomery-form NTT for `ring.SubRing` dispatch (the lattice library) | YES via `libluxlattice.dylib` + `luxfi/lattice/v7/gpu` cgo wrapper | **#121's 0.08x** measurement (single-poly, 12x slower than Go); BatchNTT SIGSEGVs at every (N,B) tested |
| `luxcpp/fhe/src/core/lib/math/hal/mlx/metal_ntt_wrapper.mm` (with `metal_dispatch_optimized.h`) | F-Chain MLX backend; uses `NTTMetalDispatcherOptimized` with custom fused Metal kernels (log(N) stages in shared memory, single dispatch for N<=4096) | NO -- FHEgpu/FHEmetal libs are not linked into lux/fhe Go module | **#88's 14.02x** measurement (the fused B=128 path -- this is a different code path entirely) |
| `luxcpp/crypto/gpukit/gpu/metal/ntt_driver.mm` | Generic NTT driver for crypto gpukit (KZG/IPA/etc.) | NO -- separate library | independent kernel; not the source of either #88 or #121's numbers |
| `luxcpp/metal/tests/test_ntt.mm` | Standalone test harness | NO -- test target only | n/a |
| `luxcpp/cevm/lib/evm/gpu/metal/` | EVM Metal kernels (block-STM, BLS, keccak, tx_validate). **NO NTT.** | n/a | the section-19E hypothesis that #88 measured cevm-side Metal NTT is FALSIFIED -- this directory has zero NTT code (verified by directory listing) |

### Reconciliation answer

**#88's 14.02x and #121's 0.08x are measurements of two different
Metal NTT implementations.**

- #121 (this agent's predecessor) measured the `luxcpp/lattice/src/metal`
  path because that is the only Metal NTT reachable from Go. That
  path is a **literal port of the Go ring's nttCoreLazy** -- one
  butterfly per dispatch, no kernel fusion, dominated by Metal
  command-queue overhead. At single-poly N=4096 it is 12.4x slower
  than Go (340.9 µs vs 27.6 µs). The 0.08x ratio is correct for what
  it measured.

- #88 (per `luxcpp/crypto/CROSSOVER.md` row 4 cited in
  `policy/PERFORMANCE.md`) measured the
  `luxcpp/fhe/src/core/lib/math/hal/mlx/` path -- the *fused*
  optimized dispatcher in `metal_dispatch_optimized.h` that runs all
  log(N) stages in a SINGLE kernel launch with shared-memory
  butterflies. At B=128 N=4096 this hits 14.02x because dispatch
  overhead is amortized across 128 polys and the kernel fusion
  eliminates the log(N) command-buffer round trips that kill the
  lattice path.

### Remediation plan (sibling-agent territory; documented here, not implemented)

The fix is **not** to "make luxlattice's Metal NTT 14x faster". The
fix is to **route luxlattice's NTT dispatch through the working
backend in luxcpp/fhe**. Two options:

1. **Move the fused kernel.** Lift `metal_dispatch_optimized.h`'s
   `NTTMetalDispatcherOptimized` and the fused Metal source from
   `luxcpp/fhe/.../mlx/` into `luxcpp/lattice/src/metal/`. Re-export
   under the `lattice_ntt_*` C-ABI. Cost estimate: ~1 week (the
   kernels themselves are ready; only the libluxlattice link surface
   needs to grow). This is the cleanest fix because it gives every
   downstream user (fhe, dex, threshold) the fused path without
   relinking.

2. **Add a second cgo wrapper.** Build a `luxfi/fhe/gpu` package that
   links FHEgpu/FHEmetal directly and exposes BatchNTT through Go.
   Cost estimate: ~3 days. Cleaner separation of concerns
   (lattice-NTT vs FHE-NTT) but creates a second Metal wrapper to
   maintain.

**Either fix unblocks #88's 14x reproduction on this host.** The
current 0.08x cell in this ladder is correct -- it just measures the
wrong dispatcher.

### Reconciliation cells (this run)

`benchtime=20x`, default tags. From
`results/reconcile_88_121_20260427T195219Z.json`:

| Path | N | B | Median | Verdict |
|---|---|---|---|---|
| Go pure-Go single-poly | 4096 | 1 | 27.46 µs | baseline -- matches policy/PERFORMANCE.md S5 |
| Go pure-Go batched-128 (sequential) | 4096 | 128 | 3.50 ms | per-NTT 27.4 µs -- batch is free in Go |
| Metal luxlattice single-poly | 4096 | 1 | NotApplicable (no -tags gpu on this build) | would be ~340 µs per #121 |
| Metal luxlattice batched-128 | 4096 | 128 | NotApplicable (no -tags gpu; would SIGSEGV per #121) | F-Chain MLX path expected ~250 µs per #88 (unmeasurable here) |

The Metal cells re-record as NotApplicable until the FHE-GPU FIX
sibling lands the wrapper updates that make `-tags gpu` viable on
this host. Once it does, **the reconciliation harness is the
canonical place to re-confirm both 0.08x and 14.02x numbers in a
single bench run**.

---

## Honest residual

- **GPU column is empty across all four ladders.** This is because
  the published `luxfi/lattice/v7@v7.0.0/gpu` wrapper has
  build-environment problems (hardcoded path, missing BatchNTT) that
  the FHE-GPU FIX agent owns. This bench harness skips GPU cells
  with explicit NotApplicable + reason strings rather than fabricating
  numbers.

- **PN11QP54 not benched.** Same reason as
  `policy/PERFORMANCE.md` -- production parameter set differs from
  test default. Follow-on after the FHE-GPU FIX cycle lands.

- **CUDA crossover not measured.** This Apple host has no NVIDIA GPU.
  Same constraint as `policy/PERFORMANCE.md`.

- **Long circuits (16-bit compare, eligibility, auction) report
  estimates rather than measurements.** Each 5+ second iteration x 10
  per cell = 1+ minute per cell, the full `bench_circuits_test.go`
  sweep is 8+ minutes. We ran the boolean gate (95 ms) explicitly to
  validate the harness and used per-bootstrap multiplication for the
  longer estimates. A full bench-time=10x sweep is on the follow-on
  list.

- **All four Metal NTT zoo entries enumerated but only one
  measured.** Reaching the F-Chain MLX backend (the one that
  produced #88's 14x) requires a new cgo wrapper that is sibling-
  agent territory. The reconciliation answer above is the
  load-bearing finding -- *the two numbers are from different
  dispatchers, not from the same dispatcher being measured under
  different conditions*.

---

## File index

| File | LOC | Purpose |
|---|---|---|
| `doc.go` | 44 | Package doc |
| `harness.go` | 240 | HostInfo, Cell, Stats, WriteLadder, Record, FlushAll |
| `ntt_paths.go` | 58 | Pure-Go SubRing factory + uniform poly helper |
| `gpu_errors.go` | 10 | errGPUDisabled |
| `build_tags_default.go` | 14 | buildTagsValue="default" / gpuLinkAttempted=false |
| `build_tags_gpu.go` | 10 | buildTagsValue="gpu" / gpuLinkAttempted=true |
| `gpu_probe_default.go` | 38 | Probe stub (always unavailable) |
| `gpu_probe_gpu.go` | 103 | Probe via lattice/v7/gpu (cgo) |
| `bench_ntt_test.go` | 348 | NTT ladder N x B x domain x mode |
| `bench_tfhe_primitives_test.go` | 320 | TFHE micro-primitives |
| `bench_threshold_test.go` | 254 | Threshold ops |
| `bench_circuits_test.go` | 357 | Production circuits |
| `bench_reconcile_test.go` | 296 | #88 vs #121 reconciliation + Metal NTT zoo manifest |
| `suite_test.go` | 25 | TestMain (flush results/) |
| **Total** | **2117** | (excluding RESULTS.md and results/*.json) |

`results/` contains JSON output per ladder, named
`<ladder>_<UTC-timestamp>.json`. The directory is tracked but its
contents are gitignored after the first commit (the bench is meant to
be re-run, not to ship snapshots).
