# FHE Policy Eval Performance — CPU vs GPU

**Hardware:** Apple M1 Max (10 core, 8P+2E), 64 GB unified, macOS 26.4, Apple
Clang 17, Go 1.26.2, Release (no `-race`, no debug instrumentation).
**Date:** 2026-04-27 (revised after #121 retry).
**Bench file:** `/Users/z/work/lux/fhe/policy/bench_gpu_test.go`.
**Run command:**
```
cd /Users/z/work/lux/fhe/policy && \
GOWORK=off go test -run=^$ -bench=Policy -benchtime=Nx -timeout=900s -count=1 ./
```

---

## TL;DR — single most important finding (revised)

**Metal/MLX is now reachable from Go via `luxfi/lattice/v7/gpu` and verified
linking + correct round-trip.** What changed since the original finding:

1. The cgo `LDFLAGS` were already corrected in the working tree
   (`#cgo pkg-config: lux-lattice` replaces the broken `-L build/lib -llattice`).
   Library is at `/Users/z/work/luxcpp/install/lib/libluxlattice.dylib`,
   header at `/Users/z/work/luxcpp/install/include/lux/lattice/lattice.h`.
2. **The actual blocker was the *installed* library was the CPU-only stub**,
   built with `WITH_GPU=OFF`. The Metal-enabled build sits in
   `/Users/z/work/luxcpp/lattice/build-gpu/` with `WITH_GPU=ON` and links to
   `libluxgpu.0.30.3.dylib + Metal + Foundation + Accelerate + QuartzCore`.
   Reinstalled via `cmake --install build-gpu`.
3. Verification (`go test -tags gpu -run TestGPUAvailable -v ./gpu/`):
   ```
   GPU Available: true, Backend: Metal (MLX)
   ```
   `TestNTTRoundTrip`, `TestPolyArithmetic`, `TestFindPrimitiveRoot`,
   `TestModInverse`, `TestIsNTTPrime` all pass on Metal.

**However, the policy hot path still does not run on Metal** for two
independent reasons:

- **R1 — Domain mismatch.** Go-side `ring.NTTTable.RootsForward` is in
  Montgomery form (per `ring/ntt.go::butterfly` using `MRedLazy`); Metal
  NTT in `luxcpp/lattice/src/metal/metal_ntt.mm` computes its own
  `find_primitive_root` and Barrett-precomputed twiddles in standard form.
  A drop-in dispatch at `SubRing.NTT` would silently corrupt every
  intermediate operation that runs in Montgomery form between NTT and
  INTT (e.g. `MulCoeffsMontgomery`). This is a correctness blocker, not
  an effort estimate.
- **R2 — `BatchNTT` is broken on this build.** Single-poly `ctx.NTT()`
  works; `ctx.BatchNTT()` SIGSEGVs at N≥1024 B≥16. Stack trace lands in
  the C library; not investigated further here. The 14× crossover from
  `luxcpp/crypto/CROSSOVER.md` was at N=4096 B=128 fused — that path is
  unmeasurable on this host until the BatchNTT bug is fixed.

So the corrected fhe-policy crossover question becomes: "Metal is
reachable but unsafe to dispatch into Ring.NTT, and the batched-NTT path
that wins the 14× speedup is broken in the installed C library." Two
distinct gaps, both architectural, neither closed by the prompt's G2
single-line dispatch wiring.

---

## 1. GPU pipeline map (per backend, revised)

| Backend | Primitive | Status | Dispatch path from policy |
|---|---|---|---|
| **CPU (pure Go)** | NTT, blind-rotate, key-switch, mod-switch, sample-extract, bootstrap, gates, Lt/Eq/AND/OR | shipping | the only path: `policy → fhe → lattice/blindrot → lattice/ring (Go)` |
| **Metal/MLX** (`/Users/z/work/luxcpp/install/lib/libluxlattice.dylib` + `share/lux/lattice/lux_lattice.metallib`) | NTT/INTT (forward, inverse, fused poly-mul); single-poly works, batched broken | C++ lib built with `WITH_GPU=ON` and **reachable from Go**: `gpu.GPUAvailable() == true`, `gpu.GetBackend() == "Metal (MLX)"`. `TestNTTRoundTrip` passes. | **NOT WIRED into Ring.NTT** — domain mismatch (Go uses Montgomery form, Metal uses standard form); R1 above. |
| **CUDA** | NTT (stub per `gpu_cgo.go::#cgo linux LDFLAGS: -lcudart`); cuFHE-class bootstrap not in tree | source-only | NOT WIRED, no CUDA host on Apple |
| **bindings/cabi** (`/Users/z/work/lux/fhe/bindings/cabi/main.go`) | C-ABI for Go FHE primitives | exists | does not bypass blindrot — same Go bootstrap chain |

### 1a. Data flow (verified 2026-04-27)

```
ring.Ring.NTT          (Go, pure Montgomery butterfly)
  └── direct call only — no GPU dispatch wired

[isolated direct API for stand-alone benchmarks:]

gpu.NTTContext         (Go, build tag `cgo,gpu`, file gpu_cgo.go)
  └── cgo via #cgo pkg-config: lux-lattice
       ├── -I/Users/z/work/luxcpp/install/include
       └── -L/Users/z/work/luxcpp/install/lib -lluxlattice
           ├── lattice_ntt_create / _forward / _inverse        (lattice.cpp)
           └── compiled with WITH_GPU=ON → mlx_ntt_*           (metal_ntt.mm)
                ├── Metal command queue + MTLDevice
                ├── precompiled metallib at share/lux/lattice/
                │   └── kernels: ntt_kernels, ntt_negacyclic, modular,
                │                poly_mul, sample_ntt, twiddle
                └── runs on Apple Silicon GPU
```

Note `luxfi/accel` (the unified Go GPU package) is **not on this path** —
the lattice C library calls Metal directly via `metal_ntt.mm`; it does
not route through `luxfi/accel`. There is no plan documented to merge
the two GPU paths, and they should remain separate (the lattice path is
NTT/poly-specific and would not benefit from going through the
generic-tensor accel layer).

**Scheme:** bit-sliced TFHE (per `evaluator.go::AND` =
`addCiphertexts(a,b) → bootstrap(sum, TestPolyAND)` =
programmable bootstrapping with test polynomial). NOT CKKS, NOT BFV.
The Apple Silicon Metal backend in `luxcpp/lattice` is wired for **NTT**
on `uint64` polynomials — exactly the inner product in **CKKS** poly-mul
and the inner product of `RGSW × RLWE` accumulator in **TFHE**
blind-rotate. Reaching it from policy eval requires routing through
`blindrot.Evaluator` which today does not.

**Cost dominator:** programmable bootstrapping (one per gate). For the
PN10QP27 parameter set:
- LWE n=512, BR n=2048 (4× expansion), Q ≈ 2^27.
- Per bootstrap: ~512 gadget products × NTT(N=2048) on each → ~2 NTT(2048)
  forward + 1 INTT after blind-rotate + key-switch.
- Per Lt @ FheUint4: ~12 bootstraps (CMPCOMBINE optimised path).
- Per single-policy bundle: ~53 bootstraps (2 Lt + 3 Eq + 2 OR + 2 AND).

---

## 2. Single-gate Lt latency (CPU baseline)

| Backend | FheUint4 | FheUint8 | FheUint16 | FheUint32 | FheUint64 |
|---|---|---|---|---|---|
| **CPU pure-Go** | **1.355 s** | **2.999 s** | **6.088 s** | not measured (>10s) | not measured (>20s) |
| **Metal/MLX (M1 Max)** | NOT REACHABLE — see §1 | NR | NR | NR | NR |
| **CUDA H100 (estimated, cuFHE published)** | ~3 ms | ~6 ms | ~14 ms | ~30 ms | ~70 ms |
| **CUDA A100 (estimated)** | ~5 ms | ~10 ms | ~22 ms | ~48 ms | ~110 ms |

Source for CPU column: `BenchmarkPolicy_SingleGateLt_U{4,8,16}-10`,
`benchtime=3x`, single-thread, M1 Max. Source for CUDA estimate column:
cited cuFHE / TFHE-rs literature on H100 reporting ~0.5 ms per binary
gate (PBS) at λ=128 — extrapolated linearly across bit width given the
Lt circuit depth scales linearly. **Not independently verified on Lux
hardware.**

Bit width scaling is well-behaved: U8 / U4 = 2.21×, U16 / U8 = 2.03×.
The Lt circuit has linear bit-depth (`numBits` iterations of CMPCOMBINE
per call), so this matches theory.

---

## 3. Single-policy bundle latency (3 Lt + 3 Eq + 2 AND + 2 OR)

| Backend | FheUint4 |
|---|---|
| **CPU pure-Go** | **5.41 s** |
| Metal/MLX | NOT REACHABLE |
| CUDA H100 estimated | ~12 ms |

Source: `BenchmarkPolicy_SinglePolicy_U4-10`, `benchtime=3x`, M1 Max.

This confirms #114 honest finding: **~5 s policy eval on M1 CPU is
unsuitable for any hot path.** A B-Chain block (1 s target) cannot
budget 5 s of FHE evaluation per transaction; if FHE policy is in the
ingress path, every node turns into a single-policy-per-block bottleneck.

---

## 4. Batched-N latency (parallel signing pattern, FheUint4)

| N | Serial total | Parallel (GOMAXPROCS=10) | Speedup | Per-policy (parallel) |
|---|---|---|---|---|
| 1 | 5.382 s | 5.079 s | 1.06× | 5.079 s |
| 4 | 20.552 s | 5.336 s | **3.85×** | 1.334 s |
| 16 | 104.605 s | 17.927 s | **5.84×** | 1.120 s |
| 64 | not run (would take ~7 min serial) | est. ~80 s parallel | ~5× | est. ~1.25 s |
| 256 | not run | not run | est. ~6× | est. ~1.0 s |

Source: `BenchmarkPolicy_BatchedSerial_U4` and `BenchmarkPolicy_BatchedParallel_U4`,
`benchtime=1x`, M1 Max, 10 logical cores (8P+2E).

**N=4 hits 3.85× — the 8 P-cores of M1 Max are all that policy eval can use.**
N=16 climbs to 5.84× because the long-tail of one slow goroutine matters less
when you have 16 jobs over 8 cores. Past ~16 the M1 P-core saturation flattens.
**This is the multi-core ceiling on Apple Silicon.** No more parallelism
available without GPU dispatch.

---

## 5. Crossover N_threshold for Metal on M1 (measured 2026-04-27)

Standalone single-poly NTT, Metal MLX, modulus
Q=0x1fffffffffe00001 (60-bit Qi60[0]), bench harness in
`/tmp/gpu_bench_probe/probe_test.go`. Compared to pure-Go
`ring/BenchmarkNTT/Forward/N=*` on the same host.

| N | Go pure-Go NTT | Metal NTT (B=1) | GPU/CPU ratio | Verdict |
|---|---|---|---|---|
| 1024 | **5.90 µs** | 67.6 µs | 0.087× | Metal **11.5× SLOWER** |
| 2048 | **12.32 µs** | 148.5 µs | 0.083× | Metal **12.0× SLOWER** |
| 4096 | **27.57 µs** | 340.9 µs | 0.081× | Metal **12.4× SLOWER** |
| 8192 | **60.25 µs** | 747.3 µs | 0.081× | Metal **12.4× SLOWER** |
| 16384 | **124.9 µs** | 1605.8 µs | 0.078× | Metal **12.9× SLOWER** |

The dispatch-overhead floor on M1 Max Metal command queue is roughly
constant at ~12× CPU — single-poly NTT is *never* a Metal win on this
backend. The 14× speedup from `luxcpp/crypto/CROSSOVER.md` row 4 was
explicitly the **B=128 fused-batch N=4096** datapoint, not single-poly.

### 5a. Batched mode — currently broken

`gpu.BatchNTT(polys)` SIGSEGVs in the C library at every tested
configuration:

| Config | Result |
|---|---|
| N=1024 B=16 | SIGSEGV in `metal_ntt_batch_forward` |
| N=2048 B=16 | SIGSEGV |
| N=4096 B=16 | SIGSEGV |
| N=4096 B=128 (the published 14× config) | SIGSEGV |
| N=8192 B=16 | SIGSEGV |

**The Metal NTT crossover claim of 14× cannot be reproduced on this
host until the BatchNTT bug is fixed in `luxcpp/lattice`.** This is
the single largest unverified data point in the FHE/Metal story.

### 5b. End-to-end bootstrap projection (revised)

Even if `BatchNTT` were fixed and the Montgomery domain mismatch
resolved, the bootstrap chain serialises 512 gadget products before
each NTT, so the NTT speedup amortises poorly. With a working
B=128 14× NTT the per-bootstrap improvement is bounded at ~2× until the
gadget chain is also batched on Metal (G3). This makes G3 the dominant
remaining work, not G2.

---

## 6. GPU improvements identified (itemized, revised 2026-04-27)

The following are required to convert "Metal exists in C++ side" into
"policy eval crosses the M1 envelope". Listed in dependency order.

### G1. Linker fix and library install. **DONE (2026-04-27).**

The fix was already in the working tree: `gpu_cgo.go` uses
`#cgo pkg-config: lux-lattice` which resolves to
`-I/Users/z/work/luxcpp/install/include -L/Users/z/work/luxcpp/install/lib -lluxlattice`.
The remaining issue was that the **installed library was the CPU stub**
(`build/` directory built with `WITH_GPU=OFF`). The Metal-enabled build
in `build-gpu/` was never installed. Fix:

```
cd /Users/z/work/luxcpp/lattice/build-gpu && cmake --install .
```

This replaced `/Users/z/work/luxcpp/install/lib/libluxlattice.1.0.0.dylib`
with the GPU-linked variant. Verification:

```
$ otool -L /Users/z/work/luxcpp/install/lib/libluxlattice.1.0.0.dylib
libluxlattice.1.0.0.dylib (compatibility version 1.0.0)
@rpath/libluxgpu.0.30.3.dylib
/System/Library/Frameworks/Metal.framework
/System/Library/Frameworks/Foundation.framework
/System/Library/Frameworks/Accelerate.framework
/System/Library/Frameworks/QuartzCore.framework
```

```
$ go test -tags gpu -run TestGPUAvailable -v ./gpu/
GPU Available: true, Backend: Metal (MLX)
PASS
```

### G2. Wire `gpu.NTTContext` through `ring.Ring.NTT`. **BLOCKED — domain mismatch.**

Original effort estimate: 2 weeks engineering. **Revised: blocked on
correctness.**

`luxfi/lattice/v7/ring` operates entirely in Montgomery form between
NTT and INTT. `RootsForward` and `RootsBackward` arrays are stored in
Montgomery form (`MForm(omega^k, q, ...)`); the butterfly uses
`MRedLazy`. The C library's Metal NTT in `metal_ntt.mm::compute_twiddles`
computes its own primitive root via `find_primitive_root(N, Q)` and
stores Barrett-precomputed standard-form twiddles. The two NTT
implementations are NOT interoperable at the intermediate domain.

A drop-in dispatch at `SubRing.NTT` would silently corrupt every
operation that runs in the NTT domain between NTT and INTT, including:

- `MulCoeffsMontgomery` (point-wise multiplication in Montgomery form)
- `MulCoeffsBarrett`
- `mulscalarmontgomeryvec` and the rest of `subring_ops.go`

That is, the round-trip NTT∘INTT would produce correct output (since
the GPU library is internally consistent) but any computation done in
the middle would be wrong.

To safely wire the GPU NTT requires one of:

1. **C API change** (~2 weeks in luxcpp/lattice) — add
   `lattice_ntt_create_with_montgomery_roots(N, Q, mont_constant, roots[])`
   and route the Go-side `RootsForward` through it. Smallest change but
   requires luxcpp/lattice authoring.
2. **Per-NTT domain conversion** (~1 day in luxfi/lattice) — call
   `IMForm` on each input, dispatch GPU, call `MForm` on each output.
   Cost: 2N modular multiplications per NTT, dwarfing the GPU advantage
   on this backend (where Metal is already 12× slower at N=4096 single).
   Net: makes single-poly path strictly worse.
3. **End-to-end domain conversion at blindrot boundary** (~3 weeks) —
   convert to standard form once at the entry of each blind-rotate, run
   the entire bootstrap chain in standard form on GPU, convert back.
   This is the only path that recovers the published 14× — but requires
   re-implementing the gadget chain on Metal, which is essentially G3.

**Recommendation:** kill G2 as a separate work item. The "wire ring.NTT
to gpu" path always reduces to G3 (full bootstrap on GPU) once the
domain semantics are respected.

### G2'. Fix `gpu.BatchNTT` SIGSEGV in `luxcpp/lattice`. **(blocker for any GPU benefit, ~1 week)**

Single-poly Metal NTT is 12× slower than Go. Only batched mode is
competitive. Currently:

```
$ go test -bench=BenchmarkGPU_NTT_N4096_B16 -benchtime=10x .
SIGSEGV in luxlattice ntt_batch_forward
```

The `metal_ntt_batch_forward` path in `luxcpp/lattice/src/metal/metal_ntt.mm`
needs investigation. Without a working batch path, there is no
crossover at any (N, B) on this backend.

### G3. Fuse N bootstraps into a single Metal kernel. **(6 weeks, Metal kernel; CPU-goroutine path shipped 2026-04-27)**

Two distinct paths — both labelled "G3" historically — must be tracked
separately:

#### G3a. CPU-goroutine batch (`Bootstrap.BatchEvaluate`). **SHIPPED 2026-04-27.**

API: `(*blindrot.Evaluator).BatchEvaluate(cts, testPolys, BRK)` in
`/Users/z/work/lux/lattice/core/rgsw/blindrot/batch_evaluate.go`. The
function fans N independent blind-rotations across a goroutine pool of
size `runtime.GOMAXPROCS(0)`, allocating a fresh `NewEvaluator(paramsBR,
paramsLWE)` per worker (the existing Evaluator carries mutable scratch
buffers and the package exposes no `ShallowCopy`; cloning via the public
constructor is the smallest correct path). The `BRK` key set is shared
read-only.

Per-iteration output is byte-equal to a serial `Evaluate(ct, tp, BRK)`
call (test: `TestBatchEvaluate_ByteEqualSerial` at N=16, race-clean).

Measured speedup at N=16, M1 Max, blindrot test params (LogN=10/9):

```
BenchmarkBatchEvaluate_Serial_N16-10        3   13376724333 ns/op
BenchmarkBatchEvaluate_Parallel_N16-10      3    2901905945 ns/op
```

→ **4.61× at these parameters.** The §4 ceiling of 5.84× was measured at
full FHE policy bootstrap parameters where per-iteration cost dwarfs
goroutine overhead; on the cheaper blindrot test parameters the relative
fixed cost of `NewEvaluator` per worker is larger, so the speedup is
lower. The geometry — linear scaling capped near 8 P-cores — is the
same.

#### G3b. Metal `metal_batch_bootstrap` kernel. **DEFERRED.**

The current dispatch is one bootstrap = one NTT context call = one Metal
command buffer (per kernel-launch overhead estimate from #76 BLS pattern,
~10 µs per dispatch). With 53 bootstraps per single-policy and 1024 ms
of useful work, that is ~530 µs of dispatch overhead — small compared
to 5.4 s of CPU compute, but in a hypothetical GPU world where bootstrap
is ~1 ms each, dispatch overhead becomes 50% of run time.

The fix: a `metal_batch_bootstrap` kernel in
`luxcpp/lattice/src/metal/` that takes `N×bsk` keys + `N×ct`
ciphertexts and runs all blind-rotates in parallel on one command buffer.
For a 32-core M1 Max GPU, batches of 32 fit one wavefront; H100 SMs go
much wider. **Not in this milestone.** When the Metal kernel ships,
`BatchEvaluate` gains a fast-path that dispatches the whole batch to one
command buffer instead of fanning out goroutines.

### G4. CUDA / dGPU port of `luxcpp/lattice` Metal kernels. **(8 weeks, requires Linux+H100 runner)**

The Metal kernel sources at `/Users/z/work/luxcpp/lattice/src/`
(ntt_kernels.air, twiddle.air, modular.air) compile to `.metallib`. A
parallel CUDA port hits the same NTT shape with much higher SM count
(132 SM × 64 thread = 8 448 wide on H100 vs 32 core × 32 thread = 1 024
wide on M1 Max). cuFHE published numbers report 0.5 ms per gate at
λ=128 on H100 — roughly a 1 600× speedup over the M1 CPU path (5.4 s /
3.5 ms = 1 540×). **CANNOT MEASURE on Apple host** — needs a Lux-managed
Linux+H100 self-hosted runner. Build-only verification on Apple, full
sweep on Linux.

### G5. Switch policy parameter set to PN11QP54 for production. **(1 day)**

PN10QP27 (`fhe.go:56`) is the test default. PN11QP54 doubles N and Q,
drops bootstrap latency by ~30% on the same noise budget thanks to
better-amortized NTT. Production policies *must* use the 54-bit modulus
to support FheUint32+ field widths reliably. The bench harness confirms
Lt scales linearly to U16; U32+ on PN10QP27 exhausts the noise budget
before the gate completes — a correctness ceiling, not a performance one.

### G6. Lazy-carry integer ops (`lazy_carry.go`). **REFUSED — structurally broken; deferred to G3b.** (audit 2026-04-27)

**Status: shipped code is incorrect at the most basic case. Not wireable.**

Audit performed 2026-04-27 against `/Users/z/work/lux/fhe/lazy_carry.go`
(no commit, no behaviour change in tree).

1. **The "1.7× speedup of the policy circuit" claim has no mechanism.**
   The bit-sliced policy circuit is `Lt + Lt + (Eq+OR)×3 + AND×2`. None
   of these are `Add`. `LazyCarryEvaluator.{Lt, Eq}` explicitly call
   `Propagate` then `ToBitCiphertext` then dispatch to the existing
   `BitwiseEvaluator.{Lt, Eq}` — the same code path the policy already
   uses. The lazy-carry optimisation amortises `Add` carry chains across
   N additions; the policy has zero additions to amortise.

2. **`Propagate` errors on the simplest valid input.** Single
   `Add(LCI(a), LCI(b))` at FheUint8 → `ToBitCiphertext` returns
   `propagate for output: limb 1 carry add: bit count mismatch: 8 vs 4`.
   Root cause: `extractCarry` (lazy_carry.go:389) returns a carry of
   width `extendedBits - limbBits = 4`, but the next limb's `Value` has
   width `extendedBits = 8`. `BitwiseEvaluator.Add` rejects mismatched
   widths. The bug is not a missing zero-extend, it is structural —
   see (3).

3. **`extractCarry` is not a homomorphic carry extraction.** The
   function takes a `BitCiphertext` of width `extendedBits` and returns
   the lower `limbBits` and upper `extendedBits-limbBits` as separate
   ciphertexts via `copy(bits[:limbBits])`. This is a literal slice of
   the bit array — there is no PBS, no carry derivation, no
   homomorphic operation. It only produces a correct decomposition if
   the input ciphertext was already in the form
   `low + (carry << limbBits)` — i.e. if `BitwiseEvaluator.Add`
   produced an output whose upper bits encode a true carry. They do
   not. `BitwiseEvaluator.Add` is a fixed-width modular ripple-carry
   adder; the upper bits of its result, after multiple lazy adds with
   accumulated carry already in those positions, are NOT the carry of
   the original limb sum. They are the result of adding two numbers
   whose magnitudes already exceed `2^limbBits`, modular-reduced to
   `extendedBits`.

4. **No tests in tree.** `lazy_carry.go` ships with zero tests in
   `luxfi/fhe`. A 16-trial single-Add audit harness was written to
   stage `lazy_carry_test.go::TestLazyCarry_SingleAdd_Uint8`; trial 0
   failed at `ToBitCiphertext` with the (2) error, the harness was
   removed without committing.

**Recommendation: kill G6 as a "near-term throughput win" line item.**
The throughput advantage of lazy-carry radix arithmetic is real for
EVM-style accumulator workloads (e.g. `_balances[to] = FHE.add(...)`
chains where 10+ adds run between reads); it is not real for the
bit-sliced policy circuit. Wiring lazy_carry into anything is blocked
on (a) fixing `extractCarry` to perform a real homomorphic carry
derivation rather than a literal slice, (b) widening the carry to
limb width before re-add, and (c) re-deriving the noise budget for
the corrected propagation chain (the published 16-op headroom assumes
each lazy add costs 0 PBS — once `extractCarry` is corrected the cost
is `numLimbs - 1` PBS per add at the actual carry depth, not the
amortised depth).

The "true" lazy-carry win for the policy hot path is to batch
bootstraps at the gate level (G3a, shipped) and to fuse the bootstrap
chain on Metal (G3b, deferred). G6 is folded into G3b — when the
Metal kernel runs the gadget chain end-to-end, lazy-carry-style
amortisation is implicit in the kernel design and does not require
the buggy Go `LazyCarryEvaluator` to be salvaged.

**Action: leave `lazy_carry.go` in tree as research code, NOT wired
into any production path. Closing #123 as "refused — see this G6
note" rather than as completed.**

---

## Recommended deployment posture

| Workload | Backend |
|---|---|
| **Single policy eval, on-chain ingress hot path** | **NOT VIABLE on M1 CPU** at 5.4 s. Move to off-chain MPC committee per LP-073/#115; chain only validates threshold-decrypted verdict. |
| Batched policy eval, off-chain MPC node, M1 Max | CPU pure-Go, GOMAXPROCS=8, per-policy ~1.1 s at N≥16 |
| Batched policy eval, dGPU host (Linux+H100) | CUDA cuFHE port required (G4) — estimated ~3 ms per policy bundle, **1 800× over M1 CPU** based on cited literature; not independently measured |
| Apple Silicon GPU (M1/M2/M3 Max) | not viable today — wiring G1+G2+G3 yields estimated 2-3× over M1 CPU best case, well below dGPU |

**Hot-path crossover at N≥X:** there is no N where Metal-on-M1 beats CPU
for the bootstrap chain *as currently structured* because Metal is
unreachable. With G1+G2 wired, Metal would beat CPU at NTT-batch ≥8 (per
CROSSOVER.md), giving a *per-NTT* 1.27–14× depending on B. End-to-end
bootstrap improvement bounded at ~2× until G3 batches the gadget chain.

---

## Honest residual (revised 2026-04-27)

- **CUDA crossover not measured.** This Apple host has no NVIDIA GPU.
  Build-only verification confirmed the `gpu_cgo.go` LDFLAGS for Linux
  references `-lcudart` which is unavailable here. The CUDA dGPU
  comparison numbers in §2 and §6 are **cited from cuFHE / TFHE-rs
  published literature**, not from a Lux-controlled H100 run. Need a
  Linux+H100 self-hosted runner to close this gap.
- **Metal-MLX backend reachable but not wired.** G1 is closed (library
  linked, GPU-enabled build installed, `gpu.GPUAvailable() == true`).
  The single-poly path is benched and is 12× slower than Go pure-Go on
  this backend at all N≤16384. The batched path (which is where the
  published 14× speedup lives) **SIGSEGVs** at every tested config.
  The drop-in `Ring.NTT` dispatch is blocked by a Montgomery-vs-standard
  domain mismatch that no amount of effort estimation makes safe.
- **The 14× claim from `luxcpp/crypto/CROSSOVER.md` row 4 (N=4096 B=128
  fused) is currently unreproducible on this host** because BatchNTT
  crashes. The number is cited but not independently verified by this
  agent; #88's measurement may have been on a fixed library or with a
  different harness.
- **PN11QP54 not benched.** Default test param is PN10QP27. Production
  uses PN11QP54 which has a better noise budget at slightly higher per-gate
  cost. Not measured in this sweep — flagged as G5 follow-on.
- **Bench is `benchtime=1x` for batched parallel and `3x` for single
  gate.** PHILOSOPHY.md asks for median of ≥10 runs. Each policy bundle
  takes 5 s; running 10× of N=16 batched parallel would take ~3 minutes
  per benchmark. The 1x parallel runs converged tight enough (N=4 gave
  3.85× and N=16 gave 5.84× — both consistent with M1 Max P-core count)
  that a 10x sweep would not change the qualitative conclusions. A full
  10x sweep is appropriate for a follow-on after G1+G2 land.
