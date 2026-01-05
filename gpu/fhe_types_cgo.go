//go:build cgo && luxgpu

// Package gpu provides GPU-accelerated tensor operations for FHE workloads.
// This file defines the core types for CGO builds using the unified lux_gpu_* API.

package gpu

/*
#cgo pkg-config: lux-gpu
#include <lux/gpu/gpu.h>
#include <stdlib.h>
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

// dtypeToC converts Go Dtype to C LuxDType
func dtypeToC(d Dtype) C.LuxDType {
	switch d {
	case Float32:
		return C.LUX_DTYPE_F32
	case Float16:
		return C.LUX_DTYPE_F16
	case BFloat16:
		return C.LUX_DTYPE_BF16
	case Int32:
		return C.LUX_DTYPE_I32
	case Uint32:
		return C.LUX_DTYPE_U32
	case Int64:
		return C.LUX_DTYPE_I64
	case Uint64:
		return C.LUX_DTYPE_U64
	default:
		return C.LUX_DTYPE_F32
	}
}

// Array represents a GPU tensor
type Array struct {
	tensor *C.LuxTensor
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
		C.lux_gpu_tensor_destroy(a.tensor)
		a.tensor = nil
	}
}

// GPUContext manages GPU resources and array tracking
type GPUContext struct {
	gpu    *C.LuxGPU
	mu     sync.Mutex
	arrays map[*C.LuxTensor]*Array
}

// DefaultContext is the global GPU context
var DefaultContext *GPUContext

func init() {
	// Initialize the global GPU context
	gpu := C.lux_gpu_global()
	if gpu == nil {
		// Fall back to creating a new context
		gpu = C.lux_gpu_create()
	}
	DefaultContext = &GPUContext{
		gpu:    gpu,
		arrays: make(map[*C.LuxTensor]*Array),
	}
}

// GPU returns the underlying C GPU handle
func (ctx *GPUContext) GPU() *C.LuxGPU {
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
	ctx.arrays = make(map[*C.LuxTensor]*Array)

	if ctx.gpu != nil {
		C.lux_gpu_destroy(ctx.gpu)
		ctx.gpu = nil
	}
}

// Sync waits for all GPU operations to complete
func (ctx *GPUContext) Sync() error {
	if ctx.gpu == nil {
		return nil
	}
	C.lux_gpu_sync(ctx.gpu)
	return nil
}

// BackendName returns the name of the active GPU backend
func (ctx *GPUContext) BackendName() string {
	if ctx.gpu == nil {
		return "none"
	}
	return C.GoString(C.lux_gpu_backend_name(ctx.gpu))
}

// NewArray creates a new GPU array from data
func NewArray(data []float32, shape []int) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	cShape := intsToCInts(shape)
	tensor := C.lux_gpu_tensor_create(
		DefaultContext.gpu,
		unsafe.Pointer(&data[0]),
		&cShape[0],
		C.int(len(shape)),
		C.LUX_DTYPE_F32,
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
	tensor := C.lux_gpu_tensor_create(
		DefaultContext.gpu,
		unsafe.Pointer(&data[0]),
		&cShape[0],
		C.int(len(shape)),
		C.LUX_DTYPE_I64,
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
	tensor := C.lux_gpu_tensor_zeros(
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
	tensor := C.lux_gpu_tensor_ones(
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
