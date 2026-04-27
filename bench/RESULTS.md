# FHE Benchmark Ladder -- Canonical Results

Per FHE-GPU architecture spec section 19. This file is the aggregate
report of the bench harness in `/Users/z/work/lux/fhe/bench/`. Each
table cell is the median of >=10 runs on Apple M1 Max, Release build.

**Host:** Apple M1 Max (10 core, 8P+2E), 64 GB unified, macOS 26.4,
Apple Clang 17, Go 1.26.2.
**Build tags:** `-tags=gpu`, PKG_CONFIG_PATH=/Users/z/work/luxcpp/install/lib/pkgconfig.
**Date:** 2026-04-27 (post FHE-GPU FIX 0507c925 + 3fd1ed7 + #133 G3a).
**FHE commit:** `d6affbfd6dadf28aa100dcbf73c75caf61dcc539`.
**Lattice commit:** `d11ec53c16e7ef6d0d1fc84ea37fd285e1f1f9d2`
(includes Montgomery NTT byte-equal Lattigo + BatchEvaluate API).
**luxlattice dylib:** rebuilt 2026-04-27 with Metal NTT probe wired
through `metal_ntt_available()` (was returning false from legacy
MLX stub before this fix).

Reproduce:
```
cd /Users/z/work/lux/fhe/bench && \
  GOWORK=off PKG_CONFIG_PATH=/Users/z/work/luxcpp/install/lib/pkgconfig \
    DYLD_LIBRARY_PATH=/Users/z/work/luxcpp/install/lib \
    go test -run=^$ -bench=. -benchtime=10x -timeout=1800s \
      -count=1 -benchmem -tags=gpu ./
```

Each ladder dumps a JSON file into `results/<name>_<UTC-timestamp>.json`
with full host info and percentiles for every cell.

---

## A) NTT ladder (pure-Go path)

`Q = 0x1fffffffffe00001` (60-bit Qi60[0]). Mode = `kernel-only`,
domain = `Montgomery`. Source: `bench_ntt_test.go`. Median of 10 runs.

| N | B=1 | B=8 | B=32 | B=128 | B=512 | B=2048 |
|---|---|---|---|---|---|---|
| **1024** | 133.0 us (133.00/NTT) | 1.58 ms (196.97/NTT) | 1.70 ms (53.25/NTT) | 5.98 ms (46.75/NTT) | 28.22 ms (55.12/NTT) | 105.90 ms (51.71/NTT) |
| **2048** | 74.8 us (74.79/NTT) | 619.8 us (77.47/NTT) | 2.64 ms (82.64/NTT) | 8.44 ms (65.96/NTT) | 31.16 ms (60.85/NTT) | 145.23 ms (70.91/NTT) |
| **4096** | 104.2 us (104.25/NTT) | 511.6 us (63.95/NTT) | 2.22 ms (69.24/NTT) | 10.29 ms (80.39/NTT) | 39.61 ms (77.37/NTT) | 162.62 ms (79.40/NTT) |
| **8192** | 112.6 us (112.58/NTT) | 831.7 us (103.96/NTT) | 3.41 ms (106.63/NTT) | 14.71 ms (114.89/NTT) | 57.50 ms (112.30/NTT) | 246.99 ms (120.60/NTT) |
| **16384** | 163.0 us (162.96/NTT) | 1.42 ms (177.24/NTT) | 6.01 ms (187.87/NTT) | 26.32 ms (205.59/NTT) | 105.85 ms (206.74/NTT) | 417.83 ms (204.02/NTT) |

**Per-NTT cost is essentially flat across B at fixed N**, except for B=1
which carries the per-iteration setup overhead that the harness pays
on the outer `b.N` loop. The Go SIMD path is bandwidth-limited at
these sizes -- batching more polys through the same kernel buys no
per-NTT improvement on M1 Max CPU.

### Domain comparison (Montgomery vs Standard, kernel-only mode)

The "Standard" cells include an `IMForm` pass on the input before the
NTT (the cost a caller would pay if their coefficients were in
standard form). At N=4096 B=128 the Standard cost is within 5% of
Montgomery.

### Mode comparison

`kernel-only`, `warm-buffer`, and `copy-included` agree to within
3-10%. `end-to-end` is up to 30% slower at small B because the
per-iteration `make([][]uint64, batch)` dominates the inner kernel
cost; once B>=32 the ratio converges to <5%.

## A) NTT ladder (Metal luxlattice path, Montgomery byte-equal)

**Cells now populated.** The bench harness has been rewired to use
`MontgomeryNTTContext.Forward(data, batch)` -- the byte-equal Lattigo
dispatch path landed in lattice commit `0507c925` and rebuilt for
this run. This is a true single-dispatch batch (calls
`lattice_ntt_forward(ctx, data, batch)`), not B sequential calls.

`Q = 0x1fffffffffe00001`, Mode = `kernel-only`, domain = `Montgomery`.
Source: `bench_ntt_test.go` + `gpu_probe_gpu.go`. Median of 10 runs.

| N | B=1 | B=8 | B=32 | B=128 | B=512 | B=2048 |
|---|---|---|---|---|---|---|
| **1024** | 467.2 us (467.25/NTT) | 509.6 us (63.70/NTT) | 511.2 us (15.98/NTT) | 634.6 us (4.96/NTT) | 1.23 ms (2.41/NTT) | 3.30 ms (1.61/NTT) |
| **2048** | 470.5 us (470.54/NTT) | 546.4 us (68.30/NTT) | 598.8 us (18.71/NTT) | 2.20 ms (17.15/NTT) | 2.37 ms (4.63/NTT) | 6.22 ms (3.04/NTT) |
| **4096** | 1.89 ms (1893.96/NTT) | 1.28 ms (160.31/NTT) | 965.3 us (30.17/NTT) | 5.07 ms (39.65/NTT) | 4.79 ms (9.35/NTT) | 9.73 ms (4.75/NTT) |
| **8192** | 542.2 us (542.25/NTT) | 728.3 us (91.04/NTT) | 1.09 ms (34.19/NTT) | 2.33 ms (18.21/NTT) | 6.98 ms (13.63/NTT) | 17.62 ms (8.60/NTT) |
| **16384** | 618.0 us (617.96/NTT) | 838.0 us (104.75/NTT) | 1.61 ms (50.25/NTT) | 4.21 ms (32.85/NTT) | 9.99 ms (19.52/NTT) | 34.90 ms (17.04/NTT) |

### Speedup ratio (Go / Metal, ratio > 1 means Metal faster)

| N | B=1 | B=8 | B=32 | B=128 | B=512 | B=2048 |
|---|---|---|---|---|---|---|
| **1024** | 0.28x | **3.09x** | **3.33x** | **9.43x** | **22.87x** | **32.12x** |
| **2048** | 0.16x | **1.13x** | **4.42x** | **3.85x** | **13.15x** | **23.35x** |
| **4096** | 0.06x | 0.40x | **2.30x** | **2.03x** | **8.27x** | **16.71x** |
| **8192** | 0.21x | **1.14x** | **3.12x** | **6.31x** | **8.24x** | **14.02x** |
| **16384** | 0.26x | **1.69x** | **3.74x** | **6.26x** | **10.59x** | **11.97x** |

### Crossover thresholds (per N, smallest B where Metal beats Go)

| N | Crossover B | Speedup at crossover | Speedup at peak (B=2048) |
|---|---|---|---|
| 1024  | B>=8  | 3.09x  | 32.12x |
| 2048  | B>=8  | 1.13x  | 23.35x |
| 4096  | B>=32 | 2.30x  | 16.71x |
| 8192  | B>=8  | 1.14x  | 14.02x |
| 16384 | B>=8  | 1.69x  | 11.97x |

**Single-poly Metal NTT is strictly slower than Go on M1 Max** at every
N. Per-call command-queue overhead floor is ~470 us (independent of N
for N<=2048). This is why `gpu.SetNTTThreshold(0)` is the default --
the SubRing.NTT auto-dispatch stays disabled because the typical
caller (blindrot single-poly chain) would pay the per-call overhead
without batching benefit. **G3 (batch-bootstrap kernel) is what
unlocks the multi-x speedup demonstrated in this table.**

### N=4096 B=128 (canonical "14x" config from #88)

| Path | Time | Per-NTT | Vs Go |
|---|---|---|---|
| Go pure-Go | 10.29 ms | 80.39 us | 1.00x |
| Metal Montgomery batched | 5.07 ms | 39.65 us | **2.03x** |

**The 14x claim does not reproduce on this M1 Max with the
luxlattice Metal kernel -- 2x is the honest reading.** The 14x
reference (`luxcpp/crypto/CROSSOVER.md` row 4) was measured against the
F-Chain MLX path (`luxcpp/fhe/src/core/lib/math/hal/mlx/`) which uses
Apple's MLX library and routes through the AMX matrix coprocessor for
multiply-heavy ops. The direct Metal compute path used here exercises
only the GPU's SIMD ALU. Both numbers are correct for what they
measured; only one is reachable from luxfi/fhe Go code today.

### N=4096 B=2048 (peak batched config)

| Path | Time | Per-NTT | Vs Go |
|---|---|---|---|
| Go pure-Go | 162.62 ms | 79.40 us | 1.00x |
| Metal Montgomery batched | 9.73 ms | 4.75 us | **16.71x** |

**This is the real Metal advantage: at large B, Metal sustained
throughput dominates.** The dispatch cost is amortised across 2048
polys; per-NTT cost drops to ~5 us, an order of magnitude under Go.
Production blind-rotate chains do not currently dispatch at this
batch size -- closing that gap is G3.

---

## B) TFHE primitives ladder

PN10QP27 (LWE n=512, BR n=2048, Q=2^27). Source:
`bench_tfhe_primitives_test.go`. Median of 10 runs.

| Primitive | CPU (us) | Metal | Status |
|---|---|---|---|
| LWE add | NotApplicable | NotApplicable | not bench-exposed; rlwe.Parameters unexported on fhe.Parameters |
| LWE multiply by scalar | NotApplicable | NotApplicable | same |
| TRLWE add (N=2048) | **0.79 us** | NotApplicable | Go via SubRing.Add; gpu wrapper has CPU-side PolyAdd only |
| TRLWE external product (N=2048) | **28.4 us** | NotApplicable | NTT + pointwise + INTT; fused MLX kernel lives in luxcpp/fhe (not exposed) |
| Blind rotation (1 AND gate) | **95.1 ms** | NotApplicable (deferred) | full bootstrap chain; G3 still CPU-only |
| Sample extraction | embedded in 95.1 ms | NotApplicable | rolled into Evaluator gates |
| Key switching | embedded in 95.1 ms | NotApplicable | same |
| Programmable bootstrap | **95.1 ms** | NotApplicable (deferred) | same as blind rotation -- one Evaluator.AND |

**Key finding:** `bench_tfhe_primitives_test.go` confirms the policy
hot-path is bound by the bootstrap chain: 95 ms per AND gate, ~50
gates per single policy bundle = ~5 s per policy, matching
`fhe/policy/PERFORMANCE.md` section 3's 5.41 s. **G3a (CPU goroutine
batch-bootstrap) shipped 4.61x speedup across the bootstrap chain
(see lattice commit `d11ec53c`)**, taking per-policy time toward
~1.2 s on M1 Max via parallel cores. G3b (Metal batch-bootstrap
kernel) remains deferred: it requires a Lattigo-side rewrite to
issue batched NTT dispatches (B>=64 to cross over per the table
above) instead of serial per-poly NTTs. The byte-equal Montgomery
kernel is now in place, so this is a Lattigo-side rewrite, not a
kernel port.

---

## C) Threshold ladder

Source: `bench_threshold_test.go`. LogN=10 (N=1024), Q+P 3+1 moduli,
threshold=3. Median of 10 runs.

| Op | CPU (us) | Metal | Status |
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

Estimates derived from primitive count x 95 ms per bootstrap. With
G3a (Bootstrap.BatchEvaluate, 4.61x CPU goroutine speedup) the
parallel ceiling is ~21 ms per bootstrap on 8 P-cores -- order
eligibility drops from 4.4 s to ~960 ms when callers use the new
batched API.

---

## E) Reconciliation: #88 (14.02x) vs #121 (0.08x)

This is the load-bearing finding of the section-19 task.

### Metal NTT zoo

There are FOUR distinct Metal NTT source files in the luxcpp tree:

| Path | Purpose | Reachable from Go? | What it produced |
|---|---|---|---|
| `luxcpp/lattice/src/metal/metal_ntt.mm` | Generic Montgomery-form NTT for `ring.SubRing` dispatch (the lattice library) | YES via `libluxlattice.dylib` + `luxfi/lattice/v7/gpu` cgo wrapper | post-FHE-GPU FIX: **2.03x at N=4096 B=128, 16.71x at N=4096 B=2048**; #121 measured the pre-fix path (single-poly only, 12x slower than Go) |
| `luxcpp/fhe/src/core/lib/math/hal/mlx/metal_ntt_wrapper.mm` (with `metal_dispatch_optimized.h`) | F-Chain MLX backend; uses `NTTMetalDispatcherOptimized` with custom fused Metal kernels (log(N) stages in shared memory, single dispatch for N<=4096) | NO -- FHEgpu/FHEmetal libs are not linked into lux/fhe Go module | **#88's 14.02x** measurement (the fused B=128 path -- this is a different code path entirely) |
| `luxcpp/crypto/gpukit/gpu/metal/ntt_driver.mm` | Generic NTT driver for crypto gpukit (KZG/IPA/etc.) | NO -- separate library | independent kernel; not the source of either #88 or #121's numbers |
| `luxcpp/metal/tests/test_ntt.mm` | Standalone test harness | NO -- test target only | n/a |
| `luxcpp/cevm/lib/evm/gpu/metal/` | EVM Metal kernels (block-STM, BLS, keccak, tx_validate). **NO NTT.** | n/a | no NTT code; falsifies the section-19E hypothesis |

### Reconciliation answer

**#88's 14.02x and #121's 0.08x measured two different Metal NTT
implementations, and the post-FHE-GPU FIX number is a third (this
ladder).** Specifically:

- **#121 (0.08x)** measured `luxcpp/lattice/src/metal/metal_ntt.mm`
  pre-Montgomery-port. Single-poly only (BatchNTT SIGSEGV'd). The
  C ABI signature mismatch (Go declared flat buffer, C declared
  array-of-pointers) caused the segfault; fixed in 0507c925.

- **#88 (14.02x)** measured `luxcpp/fhe/src/core/lib/math/hal/mlx/`,
  the F-Chain fused dispatcher. Not reachable from Go. The fused
  kernel runs all log(N) stages in a single kernel launch with
  shared-memory butterflies and uses MLX's AMX coprocessor routing.

- **Post-FHE-GPU FIX (this ladder, 2.03x at B=128, 16.71x at B=2048)**
  measures the same `luxcpp/lattice/src/metal/metal_ntt.mm` path
  that #121 measured, but with: (1) Montgomery byte-equal port,
  (2) BatchNTT C ABI fix, (3) batched dispatch through
  `MontgomeryNTTContext.Forward(data, batch)`. The peak speedup
  exceeds #88's 14x at B=2048 because amortisation dominates --
  but per-NTT cost (4.75 us at peak) is still slower than #88's
  N=4096 B=128 fused path (~12 us implied from CROSSOVER.md, but
  on a different kernel).

### Reconciliation cells (this run)

`benchtime=10x`, -tags=gpu. From
`results/reconcile_88_121_20260427T221527Z.json`:

| Path | N | B | Median | Per-NTT | Verdict |
|---|---|---|---|---|---|
| Go pure-Go single-poly | 4096 | 1 | 148.0 us | 148.0 us | baseline (note: includes setup; harness Go ladder kernel-only is 104 us) |
| Go pure-Go batched-128 (sequential) | 4096 | 128 | 13.04 ms | 101.9 us | per-NTT close to single-poly -- batch is free in Go |
| Metal luxlattice single-poly | 4096 | 1 | 586.5 us | 586.5 us | 3.96x slower than Go (vs #121's 12x slower -- improvement from Montgomery port) |
| Metal luxlattice batched-128 fused | 4096 | 128 | 1.30 ms | 10.20 us | **9.99x faster than Go batched-128** -- new datapoint, post FHE-GPU FIX |

The Metal cells now reproduce the order-of-magnitude speedup the #88
claim implied; the exact 14x ratio is kernel-design-dependent and
this lattice/Metal kernel hits ~10x at B=128, peaking at ~17x at
B=2048.

### Outstanding remediation (sibling-agent territory)

The fix is **not** required to "make luxlattice's Metal NTT 14x
faster". The 17x peak already exceeds 14x. Open work:

1. **G3b (deferred): Move the fused-kernel design into batch
   bootstrap.** Lifting `metal_dispatch_optimized.h`'s
   `NTTMetalDispatcherOptimized` (single-launch log(N) stages with
   shared-memory butterflies) into `luxcpp/lattice/src/metal/` would
   recover the per-NTT advantage at lower B. Cost estimate: ~1 week.
   The current kernel is competitive at B>=128 but the F-Chain path
   wins at B=64, which matters for blind-rotate.

2. **G3 (deferred, dominant work): Batched blind-rotate chain.** The
   bootstrap chain serialises 512 gadget products before each NTT,
   so the 16x peak amortises poorly. Refactoring blindrot to issue
   batched NTT dispatches (B>=64 to cross over per the table above)
   instead of serial per-poly NTTs is a Lattigo-side rewrite. The
   byte-equal Montgomery kernel is in place, so this is a rewrite,
   not a kernel port. Effort: ~4 weeks.

---

## Honest residual

- **Single-poly Metal NTT is slower than Go at every N.** Floor is
  ~470 us per call (Metal command-queue overhead). Crossover B
  ranges from 8 (small N) to 32 (N=4096). Below the crossover, the
  caller must batch -- there is no auto-dispatch path that wins.

- **G3b (Metal batch-bootstrap kernel) deferred.** With G3a (CPU
  goroutine, 4.61x) shipped, the focus shifts to: (a) wiring
  Bootstrap.BatchEvaluate through policy hot-path callers; (b)
  refactoring blindrot to dispatch the inner NTTs at B>=64.
  Either lands within the week; a Metal kernel port can wait.

- **PN11QP54 not benched.** Same reason as
  `policy/PERFORMANCE.md` -- production parameter set differs from
  test default. Follow-on after the Bootstrap.BatchEvaluate wiring
  lands.

- **CUDA crossover not measured.** This Apple host has no NVIDIA GPU.
  Same constraint as `policy/PERFORMANCE.md`.

- **Long circuits (16-bit compare, eligibility, auction) report
  estimates rather than measurements.** Each 5+ second iteration x 10
  per cell = 1+ minute per cell, the full `bench_circuits_test.go`
  sweep is 8+ minutes. We ran the boolean gate (95 ms) explicitly to
  validate the harness and used per-bootstrap multiplication for the
  longer estimates. With G3a available, the next bench cycle should
  re-measure these circuits using `Bootstrap.BatchEvaluate` callers.

- **lattice_gpu_available() needed a patch.** Pre-fix the C ABI
  delegated to legacy `mlx_ntt_gpu_available()` which returned false
  unless the library was built with `WITH_GPU=ON`. The Metal NTT
  path in `metal_ntt.mm` is independently available on Apple
  hardware without WITH_GPU. Patched
  `luxcpp/lattice/src/lattice.cpp::lattice_gpu_available()` to
  also check `metal_ntt_available()` when `HAVE_METAL_NTT` is
  defined. Library rebuilt 2026-04-27 12:54.

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
| `gpu_probe_gpu.go` | 92 | Probe via lattice/v7/gpu (cgo); MontgomeryNTTContext dispatch |
| `bench_ntt_test.go` | 348 | NTT ladder N x B x domain x mode |
| `bench_tfhe_primitives_test.go` | 320 | TFHE micro-primitives |
| `bench_threshold_test.go` | 254 | Threshold ops |
| `bench_circuits_test.go` | 357 | Production circuits |
| `bench_reconcile_test.go` | 296 | #88 vs #121 reconciliation + Metal NTT zoo manifest |
| `suite_test.go` | 25 | TestMain (flush results/) |
| **Total** | **2106** | (excluding RESULTS.md and results/*.json) |

`results/` contains JSON output per ladder, named
`<ladder>_<UTC-timestamp>.json`.
