//go:build cgo

// Package gpu provides GPU-accelerated tensor operations for FHE workloads.
// This file defines the core types for CGO builds using the unified lux_gpu_* API.
//
// With CGO enabled, this package links to libLuxGPU for GPU acceleration:
//   - Metal (macOS/Apple Silicon)
//   - CUDA (Linux/NVIDIA)
//   - Optimized CPU fallback
//
// Copyright (c) 2024-2025 Lux Industries Inc.
// SPDX-License-Identifier: Apache-2.0
package gpu

/*
#cgo pkg-config: lux-gpu
#include <lux/gpu/gpu.h>
#include <stdlib.h>

// Short aliases for Go code readability (hides lux_gpu_ prefix)

// Types
#define GPU             LuxGPU
#define Tensor          LuxTensor
#define DType           LuxDType

// DType constants
#define DTYPE_F32       LUX_DTYPE_F32
#define DTYPE_F16       LUX_DTYPE_F16
#define DTYPE_BF16      LUX_DTYPE_BF16
#define DTYPE_I32       LUX_DTYPE_I32
#define DTYPE_U32       LUX_DTYPE_U32
#define DTYPE_I64       LUX_DTYPE_I64
#define DTYPE_U64       LUX_DTYPE_U64

// Context management
#define gpu_global           lux_gpu_global
#define gpu_create           lux_gpu_create
#define gpu_destroy          lux_gpu_destroy
#define gpu_sync             lux_gpu_sync
#define gpu_backend_name     lux_gpu_backend_name

// Tensor creation/destruction
#define tensor_create        lux_gpu_tensor_create
#define tensor_destroy       lux_gpu_tensor_destroy
#define tensor_zeros         lux_gpu_tensor_zeros
#define tensor_ones          lux_gpu_tensor_ones
#define tensor_full          lux_gpu_tensor_full
#define tensor_data          lux_gpu_tensor_data

// Tensor operations (arithmetic)
#define gpu_add              lux_gpu_add
#define gpu_subtract         lux_gpu_subtract
#define gpu_multiply         lux_gpu_multiply
#define gpu_divide           lux_gpu_divide
#define gpu_remainder        lux_gpu_remainder
#define gpu_floor            lux_gpu_floor
#define gpu_round            lux_gpu_round
#define gpu_right_shift      lux_gpu_right_shift
#define gpu_astype           lux_gpu_astype

// Tensor operations (shape manipulation)
#define gpu_reshape          lux_gpu_reshape
#define gpu_squeeze          lux_gpu_squeeze
#define gpu_broadcast        lux_gpu_broadcast
#define gpu_slice            lux_gpu_slice
#define gpu_take             lux_gpu_take
#define gpu_take_along_axis  lux_gpu_take_along_axis
#define gpu_concatenate      lux_gpu_concatenate

// Tensor operations (comparison)
#define gpu_less             lux_gpu_less
#define gpu_greater          lux_gpu_greater
#define gpu_less_equal       lux_gpu_less_equal
#define gpu_greater_equal    lux_gpu_greater_equal
#define gpu_where            lux_gpu_where

// Tensor operations (linear algebra & reduction)
#define gpu_matmul           lux_gpu_matmul
#define gpu_sum              lux_gpu_sum
#define gpu_mean             lux_gpu_mean
#define gpu_max              lux_gpu_max
#define gpu_min              lux_gpu_min
*/
import "C"
import (
	"sync"
	"unsafe"
)

// Dtype represents the data type of tensor elements
type Dtype int

const (
	Float32 Dtype = iota
	Float16
	BFloat16
	Int32
	Uint32
	Int64
	Uint64
	Bool
)

// dtypeToC converts Go Dtype to C DType
func dtypeToC(d Dtype) C.DType {
	switch d {
	case Float32:
		return C.DTYPE_F32
	case Float16:
		return C.DTYPE_F16
	case BFloat16:
		return C.DTYPE_BF16
	case Int32:
		return C.DTYPE_I32
	case Uint32:
		return C.DTYPE_U32
	case Int64:
		return C.DTYPE_I64
	case Uint64:
		return C.DTYPE_U64
	default:
		return C.DTYPE_F32
	}
}

// Array represents a GPU tensor
type Array struct {
	tensor *C.Tensor
	shape  []int
	dtype  Dtype
}

// Shape returns the array dimensions
func (a *Array) Shape() []int {
	return a.shape
}

// Dtype returns the array data type
func (a *Array) Dtype() Dtype {
	return a.dtype
}

// Free releases the GPU tensor memory
func (a *Array) Free() {
	if a.tensor != nil {
		C.tensor_destroy(a.tensor)
		a.tensor = nil
	}
}

// GPUContext manages GPU resources and array tracking
type GPUContext struct {
	gpu    *C.GPU
	mu     sync.Mutex
	arrays map[*C.Tensor]*Array
}

// DefaultContext is the global GPU context
var DefaultContext *GPUContext

func init() {
	// Initialize the global GPU context
	gpu := C.gpu_global()
	if gpu == nil {
		// Fall back to creating a new context
		gpu = C.gpu_create()
	}
	DefaultContext = &GPUContext{
		gpu:    gpu,
		arrays: make(map[*C.Tensor]*Array),
	}
}

// GPU returns the underlying C GPU handle
func (ctx *GPUContext) GPU() *C.GPU {
	return ctx.gpu
}

// Track adds an array to the context's tracking map
func (ctx *GPUContext) Track(arr *Array) {
	if arr.tensor != nil {
		ctx.arrays[arr.tensor] = arr
	}
}

// Untrack removes an array from the context's tracking map
func (ctx *GPUContext) Untrack(arr *Array) {
	if arr.tensor != nil {
		delete(ctx.arrays, arr.tensor)
	}
}

// Close releases all tracked arrays and the GPU context
func (ctx *GPUContext) Close() {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	for _, arr := range ctx.arrays {
		arr.Free()
	}
	ctx.arrays = make(map[*C.Tensor]*Array)

	if ctx.gpu != nil {
		C.gpu_destroy(ctx.gpu)
		ctx.gpu = nil
	}
}

// Sync waits for all GPU operations to complete
func (ctx *GPUContext) Sync() error {
	if ctx.gpu == nil {
		return nil
	}
	C.gpu_sync(ctx.gpu)
	return nil
}

// BackendName returns the name of the active GPU backend
func (ctx *GPUContext) BackendName() string {
	if ctx.gpu == nil {
		return "none"
	}
	return C.GoString(C.gpu_backend_name(ctx.gpu))
}

// NewArray creates a new GPU array from data
func NewArray(data []float32, shape []int) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	cShape := intsToCInts(shape)
	tensor := C.tensor_create(
		DefaultContext.gpu,
		unsafe.Pointer(&data[0]),
		&cShape[0],
		C.int(len(shape)),
		C.DTYPE_F32,
	)

	arr := &Array{
		tensor: tensor,
		shape:  shape,
		dtype:  Float32,
	}
	DefaultContext.Track(arr)
	return arr
}

// NewArrayInt64 creates a new GPU array from int64 data
func NewArrayInt64(data []int64, shape []int) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	cShape := intsToCInts(shape)
	tensor := C.tensor_create(
		DefaultContext.gpu,
		unsafe.Pointer(&data[0]),
		&cShape[0],
		C.int(len(shape)),
		C.DTYPE_I64,
	)

	arr := &Array{
		tensor: tensor,
		shape:  shape,
		dtype:  Int64,
	}
	DefaultContext.Track(arr)
	return arr
}

// Zeros creates a zero-filled array
func Zeros(shape []int, dtype Dtype) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	cShape := intsToCInts(shape)
	tensor := C.tensor_zeros(
		DefaultContext.gpu,
		&cShape[0],
		C.int(len(shape)),
		dtypeToC(dtype),
	)

	arr := &Array{
		tensor: tensor,
		shape:  shape,
		dtype:  dtype,
	}
	DefaultContext.Track(arr)
	return arr
}

// Ones creates a one-filled array
func Ones(shape []int, dtype Dtype) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	cShape := intsToCInts(shape)
	tensor := C.tensor_ones(
		DefaultContext.gpu,
		&cShape[0],
		C.int(len(shape)),
		dtypeToC(dtype),
	)

	arr := &Array{
		tensor: tensor,
		shape:  shape,
		dtype:  dtype,
	}
	DefaultContext.Track(arr)
	return arr
}

// GPUAvailable returns true when CGO is enabled and GPU is available
func GPUAvailable() bool {
	return DefaultContext != nil && DefaultContext.gpu != nil
}

// GetBackend returns the name of the GPU backend
func GetBackend() string {
	if DefaultContext == nil {
		return "none"
	}
	return DefaultContext.BackendName()
}
