# NTT-Fused TFHE External Product — Patent Claim Drafts (Attorney Review)

> **Internal working document.** Bundle #3 of the Lux PATENT-INVENTORY.
> Not a filed application; not a legal opinion.

## §0 Bundle summary

- **Title**: Negacyclic-NTT-fused external product for TFHE
  programmable bootstrapping with cached BSK transform, content-
  fingerprint-keyed reuse, and multi-runtime byte-equality.
- **Inventors**: Lux Industries cryptography + GPU team
  (commit-history audit on `~/work/lux/cpp/metal/src/shaders/fhe/`
  and `~/work/lux/cpp/cuda/kernels/fhe/`).
- **Priority date**: file as US provisional within **90 days** of
  this document (target by 2026-08-19).
- **Filing class**: software / cryptography; class 380 (cryptography);
  G06F 7/523 (multipliers).
- **Estimated claim count**: 24 (3 independent + 21 dependent).
- **Defensive-vs-offensive**: **Offensive**.

## §1 Background and prior art

Prior art constellation:

1. **TFHE bootstrap** (Chillotti-Gama-Georgieva-Izabachène, Asiacrypt
   2017 + JoC 2020; Alperin-Sheriff-Peikert ePrint 2014/816): the
   canonical FHE programmable bootstrapping algorithm with
   external-product blind-rotation.
2. **OpenFHE** (binFHE module, 2022-2026): canonical sequential CPU
   reference implementation of TFHE-AP / TFHE-DM blind rotation;
   used as Lux's correctness oracle.
3. **Negacyclic NTT** (Lyubashevsky-Peikert-Regev 2013; Naehrig-
   Pöppelmann 2012): standard technique for polynomial multiplication
   modulo `X^N + 1` via NTT with a 2N-th primitive root.
4. **CGGI20 RGSW-based TFHE** (Chillotti et al. ePrint 2020/086):
   schoolbook external product `O(N²)` and NTT-domain variants.
5. **cuFHE / cuFHE++** (Dai-Sunar 2018; Morshed et al. 2023): CUDA-
   accelerated TFHE with NTT.
6. **Concrete** (Zama 2022-2026): Rust TFHE library with FFT-based
   external product on CPU; some GPU kernels (Concrete-GPU 2025).
7. **Plonky2 / Winterfell `reduce128`** (Polygon Zero 2022; Facebook
   2021): Goldilocks-prime constant-time 128→64 reduction.
8. **Apple Metal NTT kernels** (Apple GPU compute samples, MLX 2024):
   general-purpose Metal NTT primitives; not TFHE-specific.

Closest prior art is [4] CGGI20 NTT-domain external product and
[5] cuFHE/cuFHE++ for GPU acceleration. Lux's contribution is
NOT the NTT external product itself but the specific composition:

- One Metal/CUDA command buffer per AP blind-rotation step (vs
  per-row dispatch in cuFHE++).
- A BSK-NTT cache keyed by 128-bit content fingerprint (FNV-1a)
  rather than host pointer.
- Multi-runtime byte-equality (CPU == Metal == CUDA == WGSL) for
  the same FHE PBS operation, gated by an environment variable for
  forced-schoolbook A/B verification.

## §2 Inventive concept (plain English)

For TFHE programmable bootstrapping, each blind-rotation step
performs a vector-by-matrix multiplication in the negacyclic ring
`Z_q[X]/(X^N + 1)`:

```
result[c][j] = sum_{r} decomp[r] *_neg BSK[r][c]
```

The Lux design replaces the `O(R · N²)` schoolbook (per-row Metal
dispatch + per-row command-buffer commit) with a **single command
buffer per AP step** containing:

1. **Twist** decomp row by ψ^j and BSK rows by ψ^j (where ψ² ≡ ω_N
   mod q), batched M rows × N coefficients in one dispatch.
2. **Batched forward NTT** of decomp (R rows) in one dispatch.
3. **Cached BSK forward NTT** — computed once per BSK and reused
   across all blind-rotation steps. Cache key is a 128-bit FNV-1a
   content fingerprint of the BSK bytes, NOT a host pointer
   (because allocator slot reuse caused false positives in earlier
   pointer-keyed designs).
4. **Pointwise inner product** in NTT domain across R rows, K+1
   cols, one thread per (col, butterfly).
5. **Batched inverse NTT** of (K+1) result polynomials in one
   dispatch.
6. **Untwist + accumulate** by ψ^{-j} · N^{-1} into the LWE
   accumulator output, in one final dispatch.

All six kernels execute under a **single Metal command buffer**
(or CUDA stream graph, or WGSL encoder pass) per AP step, with
the BSK-NTT result alive across steps via the cache.

The full PBS at N=1024 achieves ~50-80 ms on Apple M2 Pro Metal vs
~2.5 seconds for the schoolbook reference on the same GPU, and
~11 seconds for the CPU reference — and is **bit-exact identical**
across all three runtimes.

A side-channel environment variable `LUX_FHE_FORCE_SCHOOLBOOK=1`
disables the NTT path for the same input, allowing A/B byte-equality
verification at deployment time.

## §3 Independent claims (drafts)

### Claim 1 (kernel composition claim, draft)

> **Claim 1.** A computer-implemented method for performing a step
> of TFHE Alperin-Sheriff/Peikert programmable bootstrapping on a
> graphics processing unit, the step comprising the external
> product of a gadget-decomposition vector `decomp` of `R = (k+1)·l`
> polynomial rows and a bootstrap key tile `BSK[i]` of `R` rows by
> `k+1` columns of polynomials of degree `N` over `Z_q[X]/(X^N + 1)`
> for a prime `q` admitting a 2N-th primitive root of unity, the
> method comprising:
>
> (a) enqueueing into the graphics processing unit's command queue
>     a single command buffer comprising a sequence of kernel
>     dispatches:
>
>     (a1) a decomp-twist kernel that materialises each row `r` of
>          the integer-signed decomp into a uint64 mod-`q`
>          polynomial scaled coordinate-wise by precomputed
>          powers `ψ^j` where `ψ² ≡ ω_N (mod q)`, one thread per
>          `(j, r)` coordinate pair;
>
>     (a2) a batched bit-reverse kernel acting in-place on the
>          row-major `M × N` decomp twist array, where `M = R`,
>          one thread per `(j, row)`;
>
>     (a3) a batched forward NTT kernel that performs
>          `log₂ N` Cooley-Tukey butterfly stages over the same
>          `M × N` array, dispatched one thread per `(butterfly-
>          index, row)`;
>
>     (a4) a pointwise inner-product kernel that computes, for
>          each column `c ∈ [0, k+1)` and each butterfly index
>          `i ∈ [0, N)`,
>          `result_ntt[c][i] = Σ_r decomp_ntt[r][i] · bsk_ntt[r][c][i]`
>          where `bsk_ntt` is the previously-computed and cached
>          forward NTT of `BSK[i]`, one thread per `(i, c)`;
>
>     (a5) a batched inverse-NTT kernel acting on the `(k+1) × N`
>          result_ntt array, mirroring kernel (a3); and
>
>     (a6) an untwist-and-accumulate kernel that scales each
>          coordinate `j` of the `(k+1)` result polynomials by
>          `ψ^{-j} · N^{-1} (mod q)` and accumulates into the LWE
>          accumulator output, one thread per `(j, c)`;
>
> (b) committing the command buffer to the graphics processing
>     unit's command queue with a single commit operation; and
>
> (c) returning, upon command-buffer completion, the updated LWE
>     accumulator as the result of the AP step,
>
> wherein the LWE accumulator value returned by step (c) is bit-
> identical to the value produced by a schoolbook external-product
> reference implementation
> `result[c][j] = Σ_r decomp[r] *_neg BSK[r][c]`
> evaluated on a central processing unit, modulo the integer-mod-`q`
> reduction.

### Claim 2 (BSK cache claim, draft)

> **Claim 2.** The method of claim 1, further comprising:
>
> (a) maintaining, in graphics-processing-unit-accessible memory, a
>     bootstrap-key NTT cache indexed by a 128-bit content
>     fingerprint of the input bootstrap-key bytes, said
>     fingerprint computed using the FNV-1a 128-bit hash algorithm
>     over the byte representation of `BSK[i]`;
>
> (b) prior to executing kernel (a4) of claim 1, querying the
>     bootstrap-key NTT cache with the fingerprint of `BSK[i]` and:
>
>     (b1) if the cache reports a hit, reading the cached forward-
>          NTT-transformed bootstrap key `bsk_ntt` from the cache
>          slot;
>
>     (b2) if the cache reports a miss, allocating a fresh `R × (k+1)
>          × N` uint64 buffer, dispatching a BSK-twist kernel
>          followed by a batched forward NTT mirroring kernels
>          (a1)-(a3) but operating on the bootstrap key, storing
>          the result into the allocated buffer, and inserting the
>          buffer into the cache keyed by the fingerprint;
>
> (c) reusing the same cached `bsk_ntt` across every subsequent AP
>     step that uses the same `BSK[i]`,
>
> wherein the cache fingerprint is computed over the bootstrap-key
> CONTENTS rather than the bootstrap-key host pointer, thereby
> avoiding cache false-positives when an allocator reuses a freed
> host pointer for a different bootstrap key.

### Claim 3 (multi-runtime byte-equality claim, draft)

> **Claim 3.** A computer system for fully-homomorphic-encryption
> programmable bootstrapping, the system comprising:
>
> (a) a CPU reference implementation of the method of claim 1
>     executing a schoolbook external product `O(R · N²)` and
>     producing an LWE accumulator output for each AP step;
>
> (b) a Metal Shading Language implementation of the method of
>     claim 1 executing the NTT-fused kernel sequence on an Apple
>     Silicon graphics processing unit;
>
> (c) a CUDA C implementation of the method of claim 1 executing
>     the equivalent NTT-fused kernel sequence on an NVIDIA
>     graphics processing unit;
>
> (d) optionally, a WebGPU Shading Language (WGSL) implementation
>     of the method of claim 1 executing on a WebGPU-compatible
>     host;
>
> (e) a known-answer test manifest comprising, for at least one
>     parameter set `(N, q, k, l)` and at least one bootstrap key
>     and input ciphertext pair, the byte representation of the
>     LWE accumulator output of the CPU reference implementation,
>     said byte representation hashed by SHA-256; and
>
> (f) a runtime cross-check module configured to, on each invocation
>     of the method of claim 1 on a non-CPU runtime, compute the
>     SHA-256 hash of the LWE accumulator output and compare against
>     the manifest hash, refusing to proceed with the bootstrap if
>     the hashes disagree.

## §4 Dependent claims (drafts)

**Claim 4.** The method of claim 1, wherein the prime `q` is the
Goldilocks prime `q_G = 2^64 - 2^32 + 1` and the modular
reductions in kernels (a1) through (a6) use the closed-form
Plonky2-style `reduce_128` algorithm with mask-based corrections,
producing constant-time output in `[0, q)`.

**Claim 5.** The method of claim 1, wherein the powers `ψ^j` for
`j ∈ [0, N)` are precomputed and stored in graphics-processing-
unit-accessible read-only memory before kernel (a1) is dispatched.

**Claim 6.** The method of claim 1, wherein the gadget
decomposition base `B = 2^base_log` and gadget-vector length `l`
are chosen such that `l × base_log ≤ log₂ q`, and wherein the
host validates `l × base_log < log₂ q` before issuing the command
buffer to prevent the bottom gadget term `q / B^l` from
collapsing to zero.

**Claim 7.** The method of claim 1, wherein the gadget
decomposition is performed bottom-up with explicit carry
propagation, as opposed to per-digit-residue decomposition which
fails to satisfy `Σ_j a_j B^j = a (mod q)` for general inputs.

**Claim 8.** The method of claim 2, wherein the FNV-1a 128-bit
content fingerprint is computed by reducing the bootstrap key's
byte representation through an FNV-1a accumulator initialized
with the FNV128 offset basis `0x6c62272e07bb014262b821756295c58d`
and the FNV128 prime `0x10000000000000000000013b`.

**Claim 9.** The method of claim 2, wherein the cache uses a
least-recently-used eviction policy bounded by a configurable
maximum number of cached bootstrap-key NTT entries.

**Claim 10.** The method of claim 1, wherein the activation of
the NTT-fused fast path is gated by an environment variable
`LUX_FHE_FORCE_SCHOOLBOOK` such that setting the variable to
"1" forces the schoolbook reference path regardless of GPU
availability, enabling A/B byte-equality verification at runtime.

**Claim 11.** The method of claim 1, wherein the activation
threshold for the NTT-fused fast path is a minimum polynomial
degree `N_min` configurable via an environment variable
`LUX_FHE_NTT_MIN_N`, defaulting to `N_min = 256`, below which the
schoolbook path is used because kernel-launch overhead dominates
the gain.

**Claim 12.** The method of claim 1, wherein the batched forward
and inverse NTT kernels (a3) and (a5) use the Cooley-Tukey
butterfly structure with `(stride, half-stride) = (2, 1),
(4, 2), …, (N, N/2)` over `log₂ N` stages, with the twiddle
factors `ω_N^{i·k}` precomputed and stored in graphics-processing-
unit-accessible read-only memory.

**Claim 13.** The method of claim 1, wherein the per-step
command buffer further includes a kernel that zeros the
result_ntt array prior to the inner-product kernel (a4), avoiding
read-modify-write dependencies on stale memory contents.

**Claim 14.** The method of claim 1, wherein the bootstrap key
`BSK[i]` is structured as a TRGSW ciphertext of the binary key
bit `s_i ∈ {0, 1}` of the input LWE secret key, formatted as
`R = (k+1) × l` rows by `k+1` columns of degree-`N` polynomials.

**Claim 15.** The method of claim 1, wherein modular arithmetic
`mod_add_q`, `mod_sub_q`, `mod_mul_q`, and `mod_neg_q` employed
within the kernels (a1) through (a6) is implemented as constant-
time mask-based operations with no secret-dependent branches.

**Claim 16.** The system of claim 3, wherein the cross-check
module is configured to log a warning rather than refuse
execution if the manifest hash is absent for a parameter set,
allowing degraded operation while flagging the missing manifest.

**Claim 17.** The system of claim 3, wherein the cross-check
module further compares the result of the NTT-fused fast path
against the schoolbook reference produced under
`LUX_FHE_FORCE_SCHOOLBOOK=1` for every parameter set on first
use in a process lifetime.

**Claim 18.** The method of claim 1, wherein the LWE accumulator
output of step (c) is the input to a subsequent TFHE key-switch
step that maps the LWE ciphertext from the bootstrap-output
modulus and dimension to the input LWE modulus and dimension,
completing a programmable bootstrap cycle.

**Claim 19.** The method of claim 1, wherein the method is
embedded within a fully-homomorphic-encryption-enabled blockchain
virtual machine such that encrypted EVM bytecode operations
trigger PBS dispatches on the graphics processing unit as part
of opcode execution.

**Claim 20.** The method of claim 1, wherein the threshold
production of the bootstrap key is performed by an F-Chain
threshold key-generation ceremony in which `n` validators each
hold a share of the FHE secret key and the bootstrap key is
produced jointly without any single validator reconstructing the
secret key.

**Claim 21.** The method of claim 1, wherein the bootstrap key
is layout-organized as
`BSK[i][row][col][coef]` with shape `[n_lwe][(k+1)·l][k+1][N]`
of uint64, with each row being a TRLWE = `(a_0, …, a_{k-1}, b)`
of degree-`N` polynomials.

**Claim 22.** A non-transitory computer-readable medium storing
the source code of the kernels (a1) through (a6) of claim 1 in
at least one of: Metal Shading Language, CUDA C, and WGSL,
together with the C++ reference implementation
`cpu_fhe_helpers.hpp` providing the schoolbook external product
as the byte-equality reference.

**Claim 23.** A method of training and evaluating a machine-
learning model under fully-homomorphic encryption, the method
comprising performing each TFHE programmable bootstrapping
operation required by the model via the method of claim 1.

**Claim 24.** A blockchain node configured to execute encrypted
transactions on an FHE-enabled smart contract platform, the node
comprising the method of claim 1 as the bootstrap-acceleration
path for transaction execution.

## §5 Reference to implementation

- Metal kernel: `~/work/lux/cpp/metal/src/shaders/fhe/ntt_fused_extprod.metal`
  (11 KB, 7 kernels).
- CUDA mirror: `~/work/lux/cpp/cuda/kernels/fhe/ntt_fused_extprod.cu`
  (11 extern "C" __global__ kernels).
- CPU reference (correctness oracle):
  `~/work/lux/cpp/gpu/src/cpu_fhe_helpers.hpp`.
- Metal PBS schoolbook reference:
  `~/work/lux/cpp/metal/src/shaders/fhe/tfhe_pbs.metal`.
- Lux GPU dispatcher / cache:
  `~/work/lux/cpp/gpu/src/gpu_core.cpp`,
  `~/work/lux/cpp/gpu/src/fhe_buffer_hash.hpp` (FNV-1a fingerprint).
- WGSL mirror (partial):
  `~/work/lux/cpp/webgpu/kernels/wgsl/fhe/ntt_fused_extprod.wgsl`.
- Performance: N=1024 PBS:
  - Metal NTT-fused: ~50-80 ms
  - Metal schoolbook: ~2.5 s (30-50x slowdown)
  - CPU OpenFHE: ~11 s (150x slowdown vs Metal NTT-fused)
- Decomp bug fix: `cpu_fhe_helpers.hpp::signed_decomp_all` with
  bottom-up carry propagation (replaces broken per-digit residue).
- Cache fix: 128-bit FNV-1a content fingerprint replaces
  pointer-only key (which had false positives when allocator
  reused slots).

## §6 Prior-art differentiation summary

| Reference | Closest aspect | Why claim 1 still novel |
|-----------|----------------|--------------------------|
| CGGI20 NTT external product | NTT-domain TFHE bootstrap | No single-cmd-buffer-per-step model; no content-fingerprint BSK cache; no multi-runtime byte-equality framework |
| cuFHE / cuFHE++ | CUDA TFHE acceleration | Per-row dispatch (multiple cmd buffers); pointer-keyed cache; no Metal mirror |
| OpenFHE binFHE | Sequential CPU reference | CPU only; no GPU acceleration; no multi-runtime byte-equality |
| Apple Metal NTT samples | Generic Metal NTT | Not TFHE-specific; not bound to TFHE-AP external-product semantics |
| Concrete-GPU | TFHE GPU acceleration in Rust | Different architecture; not single-cmd-buffer; not content-fingerprint-cached |
| FNV-1a (Fowler-Noll-Vo 1991) | Hash algorithm | Use of FNV-1a as a cache fingerprint for GPU resources in FHE context is novel; FNV-1a itself is prior art and is acknowledged |

## §7 Filing strategy and timing

- US provisional: target by **2026-08-19** in URGENT batch with #1, #2, #5.
- The FHE-on-GPU performance gap is one of Lux's strategic moats for
  F-Chain (encrypted EVM); filing this gives Lux a defensible position
  against any competing FHE-blockchain.
- PCT at 12 months → designate US, EPO, JP, KR, CN, IN, SG (Singapore
  has significant FHE research).

## §8 Defensive vs offensive recommendation

**OFFENSIVE.** This is the FHE acceleration core; the throughput
delta (150x vs CPU) is the load-bearing performance claim for
F-Chain. Filing this gives Lux a defensible position against any
competing FHE-blockchain platform.

---

**Document metadata**
- Path: `fhe/docs/patent-claims-ntt-fused-extprod.md`
- Bundle: #3 of `lps/PATENT-INVENTORY.md`
- Created: 2026-05-19
- Status: **Internal working triage for attorney engagement**
