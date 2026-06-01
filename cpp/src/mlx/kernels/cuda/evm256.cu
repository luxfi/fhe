// Copyright (C) 2024-2025 Lux Industries Inc.
// SPDX-License-Identifier: Apache-2.0
//
// CUDA EVM256PP Kernels - PAT-FHE-012
// Parallel uint256 operations for EVM compatibility

#include <cuda_runtime.h>
#include <cstdint>

namespace lux::fhe::gpu::cuda {

//=============================================================================
// uint256 Representation (4 × 64-bit limbs)
//=============================================================================

struct uint256 {
    uint64_t limbs[4];  // L0 (low) to L3 (high)
};

//=============================================================================
// uint256 Addition
//=============================================================================

__global__ void add256_batch_kernel(
    uint256* __restrict__ result,
    const uint256* __restrict__ a,
    const uint256* __restrict__ b,
    int count)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;

    uint256 va = a[idx];
    uint256 vb = b[idx];
    uint256 res;

    // Limb-wise addition with carry propagation
    uint64_t carry = 0;

    // L0
    res.limbs[0] = va.limbs[0] + vb.limbs[0];
    carry = (res.limbs[0] < va.limbs[0]) ? 1 : 0;

    // L1
    uint64_t sum1 = va.limbs[1] + carry;
    carry = (sum1 < va.limbs[1]) ? 1 : 0;
    res.limbs[1] = sum1 + vb.limbs[1];
    carry |= (res.limbs[1] < sum1) ? 1 : 0;

    // L2
    uint64_t sum2 = va.limbs[2] + carry;
    carry = (sum2 < va.limbs[2]) ? 1 : 0;
    res.limbs[2] = sum2 + vb.limbs[2];
    carry |= (res.limbs[2] < sum2) ? 1 : 0;

    // L3
    res.limbs[3] = va.limbs[3] + vb.limbs[3] + carry;

    result[idx] = res;
}

//=============================================================================
// uint256 Subtraction
//=============================================================================

__global__ void sub256_batch_kernel(
    uint256* __restrict__ result,
    const uint256* __restrict__ a,
    const uint256* __restrict__ b,
    int count)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;

    uint256 va = a[idx];
    uint256 vb = b[idx];
    uint256 res;

    uint64_t borrow = 0;

    // L0
    res.limbs[0] = va.limbs[0] - vb.limbs[0];
    borrow = (va.limbs[0] < vb.limbs[0]) ? 1 : 0;

    // L1
    uint64_t temp1 = va.limbs[1] - borrow;
    borrow = (va.limbs[1] < borrow) ? 1 : 0;
    res.limbs[1] = temp1 - vb.limbs[1];
    borrow |= (temp1 < vb.limbs[1]) ? 1 : 0;

    // L2
    uint64_t temp2 = va.limbs[2] - borrow;
    borrow = (va.limbs[2] < borrow) ? 1 : 0;
    res.limbs[2] = temp2 - vb.limbs[2];
    borrow |= (temp2 < vb.limbs[2]) ? 1 : 0;

    // L3
    res.limbs[3] = va.limbs[3] - vb.limbs[3] - borrow;

    result[idx] = res;
}

//=============================================================================
// uint256 Multiplication (Schoolbook, lower 256 bits)
//=============================================================================

__device__ __forceinline__
void mul128(uint64_t a, uint64_t b, uint64_t& lo, uint64_t& hi) {
    unsigned __int128 prod = (unsigned __int128)a * b;
    lo = (uint64_t)prod;
    hi = (uint64_t)(prod >> 64);
}

__global__ void mul256_batch_kernel(
    uint256* __restrict__ result,
    const uint256* __restrict__ a,
    const uint256* __restrict__ b,
    int count)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;

    uint256 va = a[idx];
    uint256 vb = b[idx];

    // Schoolbook multiplication, keeping only lower 256 bits
    uint64_t r[4] = {0, 0, 0, 0};
    uint64_t lo, hi;
    uint64_t carry;

    // a[0] * b[0]
    mul128(va.limbs[0], vb.limbs[0], r[0], carry);

    // a[0] * b[1] + a[1] * b[0]
    mul128(va.limbs[0], vb.limbs[1], lo, hi);
    r[1] = carry + lo;
    carry = hi + ((r[1] < lo) ? 1 : 0);

    mul128(va.limbs[1], vb.limbs[0], lo, hi);
    uint64_t old = r[1];
    r[1] += lo;
    carry += hi + ((r[1] < old) ? 1 : 0);

    // a[0] * b[2] + a[1] * b[1] + a[2] * b[0]
    r[2] = carry;
    carry = 0;

    mul128(va.limbs[0], vb.limbs[2], lo, hi);
    old = r[2]; r[2] += lo; carry += hi + ((r[2] < old) ? 1 : 0);

    mul128(va.limbs[1], vb.limbs[1], lo, hi);
    old = r[2]; r[2] += lo; carry += hi + ((r[2] < old) ? 1 : 0);

    mul128(va.limbs[2], vb.limbs[0], lo, hi);
    old = r[2]; r[2] += lo; carry += hi + ((r[2] < old) ? 1 : 0);

    // a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0]
    r[3] = carry;

    mul128(va.limbs[0], vb.limbs[3], lo, hi);
    r[3] += lo;

    mul128(va.limbs[1], vb.limbs[2], lo, hi);
    r[3] += lo;

    mul128(va.limbs[2], vb.limbs[1], lo, hi);
    r[3] += lo;

    mul128(va.limbs[3], vb.limbs[0], lo, hi);
    r[3] += lo;

    result[idx].limbs[0] = r[0];
    result[idx].limbs[1] = r[1];
    result[idx].limbs[2] = r[2];
    result[idx].limbs[3] = r[3];
}

//=============================================================================
// uint256 Comparison
//=============================================================================

__global__ void cmp256_batch_kernel(
    int* __restrict__ result,
    const uint256* __restrict__ a,
    const uint256* __restrict__ b,
    int count)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;

    uint256 va = a[idx];
    uint256 vb = b[idx];

    // Compare from most significant limb
    for (int i = 3; i >= 0; i--) {
        if (va.limbs[i] > vb.limbs[i]) {
            result[idx] = 1;
            return;
        }
        if (va.limbs[i] < vb.limbs[i]) {
            result[idx] = -1;
            return;
        }
    }
    result[idx] = 0;
}

//=============================================================================
// uint256 Bitwise Operations
//=============================================================================

__global__ void and256_batch_kernel(
    uint256* __restrict__ result,
    const uint256* __restrict__ a,
    const uint256* __restrict__ b,
    int count)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;

    result[idx].limbs[0] = a[idx].limbs[0] & b[idx].limbs[0];
    result[idx].limbs[1] = a[idx].limbs[1] & b[idx].limbs[1];
    result[idx].limbs[2] = a[idx].limbs[2] & b[idx].limbs[2];
    result[idx].limbs[3] = a[idx].limbs[3] & b[idx].limbs[3];
}

__global__ void or256_batch_kernel(
    uint256* __restrict__ result,
    const uint256* __restrict__ a,
    const uint256* __restrict__ b,
    int count)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;

    result[idx].limbs[0] = a[idx].limbs[0] | b[idx].limbs[0];
    result[idx].limbs[1] = a[idx].limbs[1] | b[idx].limbs[1];
    result[idx].limbs[2] = a[idx].limbs[2] | b[idx].limbs[2];
    result[idx].limbs[3] = a[idx].limbs[3] | b[idx].limbs[3];
}

__global__ void xor256_batch_kernel(
    uint256* __restrict__ result,
    const uint256* __restrict__ a,
    const uint256* __restrict__ b,
    int count)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;

    result[idx].limbs[0] = a[idx].limbs[0] ^ b[idx].limbs[0];
    result[idx].limbs[1] = a[idx].limbs[1] ^ b[idx].limbs[1];
    result[idx].limbs[2] = a[idx].limbs[2] ^ b[idx].limbs[2];
    result[idx].limbs[3] = a[idx].limbs[3] ^ b[idx].limbs[3];
}

__global__ void not256_batch_kernel(
    uint256* __restrict__ result,
    const uint256* __restrict__ a,
    int count)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;

    result[idx].limbs[0] = ~a[idx].limbs[0];
    result[idx].limbs[1] = ~a[idx].limbs[1];
    result[idx].limbs[2] = ~a[idx].limbs[2];
    result[idx].limbs[3] = ~a[idx].limbs[3];
}

//=============================================================================
// uint256 Shift Operations
//=============================================================================

__global__ void shl256_batch_kernel(
    uint256* __restrict__ result,
    const uint256* __restrict__ a,
    const int* __restrict__ shift,
    int count)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;

    int s = shift[idx] & 0xFF;

    if (s >= 256) {
        result[idx].limbs[0] = 0;
        result[idx].limbs[1] = 0;
        result[idx].limbs[2] = 0;
        result[idx].limbs[3] = 0;
        return;
    }

    uint256 va = a[idx];
    int limb_shift = s / 64;
    int bit_shift = s % 64;

    uint64_t r[4] = {0, 0, 0, 0};

    for (int i = limb_shift; i < 4; i++) {
        int src = i - limb_shift;
        r[i] = va.limbs[src] << bit_shift;
        if (bit_shift > 0 && src > 0) {
            r[i] |= va.limbs[src - 1] >> (64 - bit_shift);
        }
    }

    result[idx].limbs[0] = r[0];
    result[idx].limbs[1] = r[1];
    result[idx].limbs[2] = r[2];
    result[idx].limbs[3] = r[3];
}

__global__ void shr256_batch_kernel(
    uint256* __restrict__ result,
    const uint256* __restrict__ a,
    const int* __restrict__ shift,
    int count)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;

    int s = shift[idx] & 0xFF;

    if (s >= 256) {
        result[idx].limbs[0] = 0;
        result[idx].limbs[1] = 0;
        result[idx].limbs[2] = 0;
        result[idx].limbs[3] = 0;
        return;
    }

    uint256 va = a[idx];
    int limb_shift = s / 64;
    int bit_shift = s % 64;

    uint64_t r[4] = {0, 0, 0, 0};

    for (int i = 3 - limb_shift; i >= 0; i--) {
        int src = i + limb_shift;
        r[i] = va.limbs[src] >> bit_shift;
        if (bit_shift > 0 && src < 3) {
            r[i] |= va.limbs[src + 1] << (64 - bit_shift);
        }
    }

    result[idx].limbs[0] = r[0];
    result[idx].limbs[1] = r[1];
    result[idx].limbs[2] = r[2];
    result[idx].limbs[3] = r[3];
}

//=============================================================================
// Host Interface Functions
//=============================================================================

void launchAdd256Batch(uint256* result, const uint256* a, const uint256* b,
                       int count, cudaStream_t stream) {
    int block_size = 256;
    int grid_size = (count + block_size - 1) / block_size;
    add256_batch_kernel<<<grid_size, block_size, 0, stream>>>(result, a, b, count);
}

void launchSub256Batch(uint256* result, const uint256* a, const uint256* b,
                       int count, cudaStream_t stream) {
    int block_size = 256;
    int grid_size = (count + block_size - 1) / block_size;
    sub256_batch_kernel<<<grid_size, block_size, 0, stream>>>(result, a, b, count);
}

void launchMul256Batch(uint256* result, const uint256* a, const uint256* b,
                       int count, cudaStream_t stream) {
    int block_size = 256;
    int grid_size = (count + block_size - 1) / block_size;
    mul256_batch_kernel<<<grid_size, block_size, 0, stream>>>(result, a, b, count);
}

void launchCmp256Batch(int* result, const uint256* a, const uint256* b,
                       int count, cudaStream_t stream) {
    int block_size = 256;
    int grid_size = (count + block_size - 1) / block_size;
    cmp256_batch_kernel<<<grid_size, block_size, 0, stream>>>(result, a, b, count);
}

void launchAnd256Batch(uint256* result, const uint256* a, const uint256* b,
                       int count, cudaStream_t stream) {
    int block_size = 256;
    int grid_size = (count + block_size - 1) / block_size;
    and256_batch_kernel<<<grid_size, block_size, 0, stream>>>(result, a, b, count);
}

void launchOr256Batch(uint256* result, const uint256* a, const uint256* b,
                      int count, cudaStream_t stream) {
    int block_size = 256;
    int grid_size = (count + block_size - 1) / block_size;
    or256_batch_kernel<<<grid_size, block_size, 0, stream>>>(result, a, b, count);
}

void launchXor256Batch(uint256* result, const uint256* a, const uint256* b,
                       int count, cudaStream_t stream) {
    int block_size = 256;
    int grid_size = (count + block_size - 1) / block_size;
    xor256_batch_kernel<<<grid_size, block_size, 0, stream>>>(result, a, b, count);
}

void launchNot256Batch(uint256* result, const uint256* a,
                       int count, cudaStream_t stream) {
    int block_size = 256;
    int grid_size = (count + block_size - 1) / block_size;
    not256_batch_kernel<<<grid_size, block_size, 0, stream>>>(result, a, count);
}

void launchShl256Batch(uint256* result, const uint256* a, const int* shift,
                       int count, cudaStream_t stream) {
    int block_size = 256;
    int grid_size = (count + block_size - 1) / block_size;
    shl256_batch_kernel<<<grid_size, block_size, 0, stream>>>(result, a, shift, count);
}

void launchShr256Batch(uint256* result, const uint256* a, const int* shift,
                       int count, cudaStream_t stream) {
    int block_size = 256;
    int grid_size = (count + block_size - 1) / block_size;
    shr256_batch_kernel<<<grid_size, block_size, 0, stream>>>(result, a, shift, count);
}

} // namespace lux::fhe::gpu::cuda
