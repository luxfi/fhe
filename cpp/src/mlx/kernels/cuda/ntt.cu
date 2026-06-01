// Copyright (C) 2024-2025 Lux Industries Inc.
// SPDX-License-Identifier: Apache-2.0
//
// CUDA NTT (Number Theoretic Transform) Kernels
// High-performance polynomial operations for FHE

#include <cuda_runtime.h>
#include <cstdint>

namespace lux::fhe::gpu::cuda {

//=============================================================================
// Modular Arithmetic Device Functions
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

// Montgomery reduction
struct MontgomeryParams {
    uint64_t modulus;
    uint64_t modulus_inv;  // -modulus^(-1) mod 2^64
    uint64_t r_squared;    // R^2 mod modulus
};

__device__ __forceinline__
uint64_t montgomery_reduce(unsigned __int128 x, const MontgomeryParams& params) {
    uint64_t lo = (uint64_t)x;
    uint64_t m = lo * params.modulus_inv;
    unsigned __int128 t = x + (unsigned __int128)m * params.modulus;
    uint64_t result = (uint64_t)(t >> 64);
    return result >= params.modulus ? result - params.modulus : result;
}

__device__ __forceinline__
uint64_t mul_mod_montgomery(uint64_t a, uint64_t b, const MontgomeryParams& params) {
    unsigned __int128 product = (unsigned __int128)a * b;
    return montgomery_reduce(product, params);
}

//=============================================================================
// Bit Reversal
//=============================================================================

__device__ __forceinline__
int bit_reverse(int x, int log_n) {
    int result = 0;
    for (int i = 0; i < log_n; i++) {
        result = (result << 1) | (x & 1);
        x >>= 1;
    }
    return result;
}

//=============================================================================
// NTT Forward Kernel (Cooley-Tukey)
//=============================================================================

__global__ void ntt_forward_kernel(
    uint64_t* __restrict__ data,
    const uint64_t* __restrict__ twiddles,
    int n,
    int log_n,
    uint64_t modulus)
{
    extern __shared__ uint64_t shared_data[];

    int tid = threadIdx.x;
    int bid = blockIdx.x;
    int global_id = bid * blockDim.x + tid;

    // Load data to shared memory with bit-reversal
    if (global_id < n) {
        int rev_idx = bit_reverse(global_id, log_n);
        shared_data[tid] = data[rev_idx];
    }
    __syncthreads();

    // Cooley-Tukey butterfly iterations
    for (int s = 1; s <= log_n; s++) {
        int m = 1 << s;
        int m2 = m >> 1;
        int step = n / m;

        int k = (tid / m2) * m;
        int j = tid % m2;

        if (k + j + m2 < n && tid < n / 2) {
            int idx0 = k + j;
            int idx1 = k + j + m2;

            uint64_t w = twiddles[j * step];
            uint64_t u = shared_data[idx0];
            uint64_t t = mul_mod(w, shared_data[idx1], modulus);

            shared_data[idx0] = add_mod(u, t, modulus);
            shared_data[idx1] = sub_mod(u, t, modulus);
        }
        __syncthreads();
    }

    // Write back to global memory
    if (global_id < n) {
        data[global_id] = shared_data[tid];
    }
}

//=============================================================================
// NTT Inverse Kernel (Gentleman-Sande)
//=============================================================================

__global__ void ntt_inverse_kernel(
    uint64_t* __restrict__ data,
    const uint64_t* __restrict__ twiddles_inv,
    int n,
    int log_n,
    uint64_t modulus,
    uint64_t n_inv)
{
    extern __shared__ uint64_t shared_data[];

    int tid = threadIdx.x;
    int bid = blockIdx.x;
    int global_id = bid * blockDim.x + tid;

    // Load data to shared memory
    if (global_id < n) {
        shared_data[tid] = data[global_id];
    }
    __syncthreads();

    // Gentleman-Sande butterfly iterations (reversed order)
    for (int s = log_n; s >= 1; s--) {
        int m = 1 << s;
        int m2 = m >> 1;
        int step = n / m;

        int k = (tid / m2) * m;
        int j = tid % m2;

        if (k + j + m2 < n && tid < n / 2) {
            int idx0 = k + j;
            int idx1 = k + j + m2;

            uint64_t w = twiddles_inv[j * step];
            uint64_t u = shared_data[idx0];
            uint64_t t = shared_data[idx1];

            shared_data[idx0] = add_mod(u, t, modulus);
            shared_data[idx1] = mul_mod(sub_mod(u, t, modulus), w, modulus);
        }
        __syncthreads();
    }

    // Bit-reversal and scale by n^{-1}
    if (global_id < n) {
        int rev_idx = bit_reverse(tid, log_n);
        data[global_id] = mul_mod(shared_data[rev_idx], n_inv, modulus);
    }
}

//=============================================================================
// Batch NTT Forward
//=============================================================================

__global__ void ntt_forward_batch_kernel(
    uint64_t* __restrict__ data,
    const uint64_t* __restrict__ twiddles,
    int n,
    int log_n,
    int batch_size,
    uint64_t modulus)
{
    int poly_idx = blockIdx.y;
    int tid = threadIdx.x;
    int elem_idx = blockIdx.x * blockDim.x + tid;

    if (poly_idx >= batch_size || elem_idx >= n) return;

    uint64_t* poly = data + poly_idx * n;

    // Simplified batch NTT - each block handles part of one polynomial
    // Full implementation would use shared memory per polynomial

    for (int s = 1; s <= log_n; s++) {
        int m = 1 << s;
        int m2 = m >> 1;
        int step = n / m;

        int k = (elem_idx / m2) * m;
        int j = elem_idx % m2;

        if (k + j + m2 < n && elem_idx < n / 2) {
            int idx0 = k + j;
            int idx1 = k + j + m2;

            uint64_t w = twiddles[j * step];
            uint64_t u = poly[idx0];
            uint64_t t = mul_mod(w, poly[idx1], modulus);

            poly[idx0] = add_mod(u, t, modulus);
            poly[idx1] = sub_mod(u, t, modulus);
        }
        __syncthreads();
    }
}

//=============================================================================
// Polynomial Operations
//=============================================================================

__global__ void poly_add_kernel(
    uint64_t* __restrict__ result,
    const uint64_t* __restrict__ a,
    const uint64_t* __restrict__ b,
    int n,
    uint64_t modulus)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx < n) {
        result[idx] = add_mod(a[idx], b[idx], modulus);
    }
}

__global__ void poly_sub_kernel(
    uint64_t* __restrict__ result,
    const uint64_t* __restrict__ a,
    const uint64_t* __restrict__ b,
    int n,
    uint64_t modulus)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx < n) {
        result[idx] = sub_mod(a[idx], b[idx], modulus);
    }
}

__global__ void poly_mul_kernel(
    uint64_t* __restrict__ result,
    const uint64_t* __restrict__ a,
    const uint64_t* __restrict__ b,
    int n,
    uint64_t modulus)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx < n) {
        result[idx] = mul_mod(a[idx], b[idx], modulus);
    }
}

//=============================================================================
// Polynomial Rotation (Negacyclic)
//=============================================================================

__global__ void poly_rotate_kernel(
    uint64_t* __restrict__ data,
    uint64_t* __restrict__ temp,
    int rotation,
    int n,
    uint64_t modulus)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= n) return;

    int rot = ((rotation % n) + n) % n;
    int src_idx = (idx + rot) % n;

    if (idx + rot >= n) {
        // Negacyclic: negate when wrapping
        temp[idx] = modulus - data[src_idx];
    } else {
        temp[idx] = data[src_idx];
    }
}

__global__ void copy_kernel(
    uint64_t* __restrict__ dst,
    const uint64_t* __restrict__ src,
    int n)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx < n) {
        dst[idx] = src[idx];
    }
}

//=============================================================================
// Host Interface Functions
//=============================================================================

void launchNTTForward(uint64_t* data, int n, int log_n, uint64_t modulus,
                      const uint64_t* twiddles, cudaStream_t stream) {
    int block_size = min(n, 1024);
    int grid_size = (n + block_size - 1) / block_size;
    size_t shared_mem = n * sizeof(uint64_t);

    ntt_forward_kernel<<<grid_size, block_size, shared_mem, stream>>>(
        data, twiddles, n, log_n, modulus);
}

void launchNTTInverse(uint64_t* data, int n, int log_n, uint64_t modulus,
                      uint64_t n_inv, const uint64_t* twiddles_inv, cudaStream_t stream) {
    int block_size = min(n, 1024);
    int grid_size = (n + block_size - 1) / block_size;
    size_t shared_mem = n * sizeof(uint64_t);

    ntt_inverse_kernel<<<grid_size, block_size, shared_mem, stream>>>(
        data, twiddles_inv, n, log_n, modulus, n_inv);
}

void launchNTTForwardBatch(uint64_t* data, int batch_size, int n, int log_n,
                           uint64_t modulus, const uint64_t* twiddles, cudaStream_t stream) {
    int block_size = min(n / 2, 1024);
    dim3 grid_size((n / 2 + block_size - 1) / block_size, batch_size);

    ntt_forward_batch_kernel<<<grid_size, block_size, 0, stream>>>(
        data, twiddles, n, log_n, batch_size, modulus);
}

void launchPolyAdd(uint64_t* result, const uint64_t* a, const uint64_t* b,
                   int n, uint64_t modulus, cudaStream_t stream) {
    int block_size = 256;
    int grid_size = (n + block_size - 1) / block_size;
    poly_add_kernel<<<grid_size, block_size, 0, stream>>>(result, a, b, n, modulus);
}

void launchPolySub(uint64_t* result, const uint64_t* a, const uint64_t* b,
                   int n, uint64_t modulus, cudaStream_t stream) {
    int block_size = 256;
    int grid_size = (n + block_size - 1) / block_size;
    poly_sub_kernel<<<grid_size, block_size, 0, stream>>>(result, a, b, n, modulus);
}

void launchPolyMul(uint64_t* result, const uint64_t* a, const uint64_t* b,
                   int n, uint64_t modulus, cudaStream_t stream) {
    int block_size = 256;
    int grid_size = (n + block_size - 1) / block_size;
    poly_mul_kernel<<<grid_size, block_size, 0, stream>>>(result, a, b, n, modulus);
}

void launchPolyRotate(uint64_t* data, uint64_t* temp, int rotation, int n,
                      uint64_t modulus, cudaStream_t stream) {
    int block_size = 256;
    int grid_size = (n + block_size - 1) / block_size;
    poly_rotate_kernel<<<grid_size, block_size, 0, stream>>>(data, temp, rotation, n, modulus);
    copy_kernel<<<grid_size, block_size, 0, stream>>>(data, temp, n);
}

} // namespace lux::fhe::gpu::cuda
