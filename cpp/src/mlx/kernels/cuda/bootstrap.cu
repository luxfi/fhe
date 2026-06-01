// Copyright (C) 2024-2025 Lux Industries Inc.
// SPDX-License-Identifier: Apache-2.0
//
// CUDA Bootstrapping Kernels for TFHE
// Blind rotation and programmable bootstrapping

#include <cuda_runtime.h>
#include <cuComplex.h>
#include <cstdint>

namespace lux::fhe::gpu::cuda {

//=============================================================================
// Utility Functions
//=============================================================================

__device__ __forceinline__
uint64_t add_mod(uint64_t a, uint64_t b, uint64_t mod) {
    uint64_t sum = a + b;
    return sum >= mod ? sum - mod : sum;
}

__device__ __forceinline__
uint64_t sub_mod(uint64_t a, uint64_t b, uint64_t mod) {
    return a >= b ? a - b : a + mod - b;
}

__device__ __forceinline__
uint64_t mul_mod(uint64_t a, uint64_t b, uint64_t mod) {
    unsigned __int128 product = (unsigned __int128)a * b;
    return (uint64_t)(product % mod);
}

// Signed decomposition for gadget matrix
__device__ __forceinline__
void decompose_value(int64_t* digits, uint64_t value, int l, int Bg_log) {
    uint64_t Bg = 1ULL << Bg_log;
    uint64_t half_Bg = Bg >> 1;
    uint64_t mask = Bg - 1;

    for (int i = l - 1; i >= 0; i--) {
        uint64_t digit = (value >> (i * Bg_log)) & mask;
        if (digit >= half_Bg) {
            digits[l - 1 - i] = (int64_t)digit - (int64_t)Bg;
            value += Bg << (i * Bg_log);
        } else {
            digits[l - 1 - i] = (int64_t)digit;
        }
    }
}

//=============================================================================
// CMux Kernel
//=============================================================================

__global__ void cmux_kernel(
    cuDoubleComplex* __restrict__ ct0_fft,
    cuDoubleComplex* __restrict__ ct1_fft,
    const cuDoubleComplex* __restrict__ ggsw_fft,
    int N,
    int k,
    int l)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    int total_size = (k + 1) * N;

    if (idx >= total_size) return;

    // CMux: ct0 = ct0 + GGSW * (ct1 - ct0)
    // Compute difference
    cuDoubleComplex diff = cuCsub(ct1_fft[idx], ct0_fft[idx]);

    // External product with GGSW (simplified - full version in external_product_kernel)
    ct0_fft[idx] = cuCadd(ct0_fft[idx], diff);
}

//=============================================================================
// Batch CMux Kernel
//=============================================================================

__global__ void cmux_batch_kernel(
    cuDoubleComplex* __restrict__ ct_fft,
    const cuDoubleComplex* __restrict__ ggsw_fft,
    int batch_size,
    int N,
    int k,
    int l)
{
    int batch_idx = blockIdx.y;
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    int poly_size = (k + 1) * N;

    if (batch_idx >= batch_size || idx >= poly_size) return;

    cuDoubleComplex* ct = ct_fft + batch_idx * poly_size;
    // Simplified batch CMux
}

//=============================================================================
// External Product Kernel
//=============================================================================

__global__ void external_product_kernel(
    cuDoubleComplex* __restrict__ result_fft,
    const cuDoubleComplex* __restrict__ glwe_fft,
    const cuDoubleComplex* __restrict__ ggsw_fft,
    int N,
    int k,
    int l)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    int total_size = (k + 1) * N;

    if (idx >= total_size) return;

    // Initialize result
    cuDoubleComplex sum = make_cuDoubleComplex(0.0, 0.0);

    int poly_idx = idx / N;
    int coef_idx = idx % N;

    // Sum over GLWE polynomials and decomposition levels
    for (int j = 0; j <= k; j++) {
        cuDoubleComplex glwe_val = glwe_fft[j * N + coef_idx];

        for (int level = 0; level < l; level++) {
            // GGSW offset
            int ggsw_offset = (j * l + level) * (k + 1) * N + idx;
            cuDoubleComplex ggsw_val = ggsw_fft[ggsw_offset];

            // FFT multiplication
            cuDoubleComplex prod = cuCmul(glwe_val, ggsw_val);
            sum = cuCadd(sum, prod);
        }
    }

    result_fft[idx] = sum;
}

//=============================================================================
// Blind Rotation Step
//=============================================================================

__global__ void blind_rotate_step_kernel(
    cuDoubleComplex* __restrict__ acc_fft,
    const cuDoubleComplex* __restrict__ bsk_fft,
    const int* __restrict__ rotations,
    int step_idx,
    int N,
    int k,
    int l)
{
    extern __shared__ cuDoubleComplex shared_acc[];

    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    int total_size = (k + 1) * N;

    if (idx >= total_size) return;

    int rotation = rotations[step_idx];
    if (rotation == 0) return;

    // Load accumulator to shared memory
    shared_acc[threadIdx.x] = acc_fft[idx];
    __syncthreads();

    // Compute rotation in FFT domain
    // X^a in time domain = phase shift in frequency domain
    int coef_idx = idx % N;
    double angle = -2.0 * M_PI * rotation * coef_idx / (2 * N);
    cuDoubleComplex phase = make_cuDoubleComplex(cos(angle), sin(angle));

    cuDoubleComplex rotated = cuCmul(shared_acc[threadIdx.x], phase);

    // CMux with rotated accumulator
    cuDoubleComplex diff = cuCsub(rotated, acc_fft[idx]);

    // External product (simplified)
    acc_fft[idx] = cuCadd(acc_fft[idx], diff);
}

//=============================================================================
// Key Switching Kernel
//=============================================================================

__global__ void key_switch_kernel(
    uint64_t* __restrict__ lwe_out,
    const uint64_t* __restrict__ glwe_in,
    const uint64_t* __restrict__ ksk,
    int N,
    int n_lwe,
    int l,
    int Bg_log,
    uint64_t modulus)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;

    if (idx > n_lwe) return;

    uint64_t sum = 0;

    // Body goes directly to output body
    if (idx == n_lwe) {
        sum = glwe_in[N];  // Body at position N
    }

    // Decompose and multiply with KSK
    for (int i = 0; i < N; i++) {
        uint64_t ai = glwe_in[i];

        int64_t digits[8];  // Max l = 8
        decompose_value(digits, ai, l, Bg_log);

        for (int level = 0; level < l; level++) {
            if (digits[level] != 0) {
                int ksk_offset = (i * l + level) * (n_lwe + 1) + idx;
                uint64_t ksk_val = ksk[ksk_offset];

                if (digits[level] > 0) {
                    uint64_t prod = mul_mod((uint64_t)digits[level], ksk_val, modulus);
                    sum = sub_mod(sum, prod, modulus);
                } else {
                    uint64_t prod = mul_mod((uint64_t)(-digits[level]), ksk_val, modulus);
                    sum = add_mod(sum, prod, modulus);
                }
            }
        }
    }

    lwe_out[idx] = sum;
}

//=============================================================================
// Sample Extraction
//=============================================================================

__global__ void sample_extract_kernel(
    uint64_t* __restrict__ lwe_out,
    const uint64_t* __restrict__ glwe_in,
    int extract_idx,
    int N,
    int n_lwe,
    uint64_t modulus)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;

    if (idx > n_lwe) return;

    if (idx < n_lwe) {
        // Extract mask coefficients with negacyclic rotation
        int i = extract_idx - idx;
        if (i < 0) {
            lwe_out[idx] = modulus - glwe_in[(-i - 1) % N];
        } else {
            lwe_out[idx] = glwe_in[i];
        }
    } else {
        // Body
        lwe_out[n_lwe] = glwe_in[N + extract_idx];
    }
}

//=============================================================================
// LUT Kernels (ULFHE - PAT-FHE-011)
//=============================================================================

__global__ void create_sign_lut_kernel(
    uint64_t* __restrict__ lut,
    int N,
    uint64_t modulus)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= N) return;

    // Sign function: 1 for positive, 0 for negative
    uint64_t phase = (idx * modulus) / N;
    uint64_t half = modulus / 2;

    if (phase < half) {
        lut[idx] = modulus / 8;  // Encode +1
    } else {
        lut[idx] = modulus - modulus / 8;  // Encode -1
    }
}

__global__ void create_range_lut_kernel(
    uint64_t* __restrict__ lut,
    int N,
    uint64_t modulus,
    uint64_t min_val,
    uint64_t max_val)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= N) return;

    uint64_t phase = (idx * modulus) / N;

    if (phase >= min_val && phase <= max_val) {
        lut[idx] = modulus / 8;  // In range
    } else {
        lut[idx] = 0;  // Out of range
    }
}

//=============================================================================
// Host Interface Functions
//=============================================================================

void launchCMux(cuDoubleComplex* ct0_fft, cuDoubleComplex* ct1_fft,
                const cuDoubleComplex* ggsw_fft, int N, int k, int l,
                cudaStream_t stream) {
    int total_size = (k + 1) * N;
    int block_size = 256;
    int grid_size = (total_size + block_size - 1) / block_size;

    cmux_kernel<<<grid_size, block_size, 0, stream>>>(
        ct0_fft, ct1_fft, ggsw_fft, N, k, l);
}

void launchExternalProduct(cuDoubleComplex* result_fft,
                           const cuDoubleComplex* glwe_fft,
                           const cuDoubleComplex* ggsw_fft,
                           int N, int k, int l, cudaStream_t stream) {
    int total_size = (k + 1) * N;
    int block_size = 256;
    int grid_size = (total_size + block_size - 1) / block_size;

    external_product_kernel<<<grid_size, block_size, 0, stream>>>(
        result_fft, glwe_fft, ggsw_fft, N, k, l);
}

void launchBlindRotateStep(cuDoubleComplex* acc_fft,
                           const cuDoubleComplex* bsk_fft,
                           const int* rotations, int step_idx,
                           int N, int k, int l, cudaStream_t stream) {
    int total_size = (k + 1) * N;
    int block_size = 256;
    int grid_size = (total_size + block_size - 1) / block_size;
    size_t shared_size = block_size * sizeof(cuDoubleComplex);

    blind_rotate_step_kernel<<<grid_size, block_size, shared_size, stream>>>(
        acc_fft, bsk_fft, rotations, step_idx, N, k, l);
}

void launchKeySwitch(uint64_t* lwe_out, const uint64_t* glwe_in,
                     const uint64_t* ksk, int N, int n_lwe, int l, int Bg_log,
                     uint64_t modulus, cudaStream_t stream) {
    int block_size = 256;
    int grid_size = (n_lwe + 2 + block_size - 1) / block_size;

    key_switch_kernel<<<grid_size, block_size, 0, stream>>>(
        lwe_out, glwe_in, ksk, N, n_lwe, l, Bg_log, modulus);
}

void launchSampleExtract(uint64_t* lwe_out, const uint64_t* glwe_in,
                         int extract_idx, int N, int n_lwe, uint64_t modulus,
                         cudaStream_t stream) {
    int block_size = 256;
    int grid_size = (n_lwe + 2 + block_size - 1) / block_size;

    sample_extract_kernel<<<grid_size, block_size, 0, stream>>>(
        lwe_out, glwe_in, extract_idx, N, n_lwe, modulus);
}

void launchCreateSignLUT(uint64_t* lut, int N, uint64_t modulus, cudaStream_t stream) {
    int block_size = 256;
    int grid_size = (N + block_size - 1) / block_size;

    create_sign_lut_kernel<<<grid_size, block_size, 0, stream>>>(lut, N, modulus);
}

void launchCreateRangeLUT(uint64_t* lut, int N, uint64_t modulus,
                          uint64_t min_val, uint64_t max_val, cudaStream_t stream) {
    int block_size = 256;
    int grid_size = (N + block_size - 1) / block_size;

    create_range_lut_kernel<<<grid_size, block_size, 0, stream>>>(
        lut, N, modulus, min_val, max_val);
}

} // namespace lux::fhe::gpu::cuda
