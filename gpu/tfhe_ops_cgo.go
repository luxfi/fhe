//go:build cgo && luxgpu

// Package gpu provides TFHE-specific GPU-accelerated operations.
// These operations are needed for GPU-accelerated TFHE bootstrapping.

package gpu

/*
#cgo pkg-config: lux-gpu
#include <lux/gpu/gpu.h>
#include <stdlib.h>
*/
import "C"
import (
	"unsafe"
)

// SliceArg represents slicing arguments for Slice operation
type SliceArg struct {
	Start int
	Stop  int
}

// Remainder computes element-wise remainder: a % b
func Remainder(a, b *Array) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	tensor := C.lux_gpu_remainder(
		DefaultContext.gpu,
		(*C.LuxTensor)(a.tensor),
		(*C.LuxTensor)(b.tensor),
	)

	arr := &Array{
		tensor: tensor,
		shape:  a.shape,
		dtype:  a.dtype,
	}
	DefaultContext.Track(arr)
	return arr
}

// Floor computes element-wise floor
func Floor(a *Array) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	tensor := C.lux_gpu_floor(
		DefaultContext.gpu,
		(*C.LuxTensor)(a.tensor),
	)

	arr := &Array{
		tensor: tensor,
		shape:  a.shape,
		dtype:  a.dtype,
	}
	DefaultContext.Track(arr)
	return arr
}

// Round rounds elements to nearest integer
func Round(a *Array) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	tensor := C.lux_gpu_round(
		DefaultContext.gpu,
		(*C.LuxTensor)(a.tensor),
	)

	arr := &Array{
		tensor: tensor,
		shape:  a.shape,
		dtype:  a.dtype,
	}
	DefaultContext.Track(arr)
	return arr
}

// RightShift performs element-wise right shift: a >> b
func RightShift(a, b *Array) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	tensor := C.lux_gpu_right_shift(
		DefaultContext.gpu,
		(*C.LuxTensor)(a.tensor),
		(*C.LuxTensor)(b.tensor),
	)

	arr := &Array{
		tensor: tensor,
		shape:  a.shape,
		dtype:  a.dtype,
	}
	DefaultContext.Track(arr)
	return arr
}

// AsType casts array to specified dtype
func AsType(a *Array, dtype Dtype) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	tensor := C.lux_gpu_astype(
		DefaultContext.gpu,
		(*C.LuxTensor)(a.tensor),
		dtypeToC(dtype),
	)

	arr := &Array{
		tensor: tensor,
		shape:  a.shape,
		dtype:  dtype,
	}
	DefaultContext.Track(arr)
	return arr
}

// Reshape reshapes array to new shape
func Reshape(a *Array, shape []int) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	cShape := intsToCInts(shape)
	tensor := C.lux_gpu_reshape(
		DefaultContext.gpu,
		(*C.LuxTensor)(a.tensor),
		&cShape[0],
		C.int(len(shape)),
	)

	arr := &Array{
		tensor: tensor,
		shape:  shape,
		dtype:  a.dtype,
	}
	DefaultContext.Track(arr)
	return arr
}

// Squeeze removes dimension of size 1 at specified axis
func Squeeze(a *Array, axis int) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	tensor := C.lux_gpu_squeeze(
		DefaultContext.gpu,
		(*C.LuxTensor)(a.tensor),
		C.int(axis),
	)

	// Calculate new shape
	newShape := make([]int, 0, len(a.shape)-1)
	for i, s := range a.shape {
		if i != axis && (axis >= 0 || i != len(a.shape)+axis) {
			newShape = append(newShape, s)
		}
	}
	if len(newShape) == 0 {
		newShape = []int{1}
	}

	arr := &Array{
		tensor: tensor,
		shape:  newShape,
		dtype:  a.dtype,
	}
	DefaultContext.Track(arr)
	return arr
}

// Broadcast broadcasts array to specified shape
func Broadcast(a *Array, shape []int) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	cShape := intsToCInts(shape)
	tensor := C.lux_gpu_broadcast(
		DefaultContext.gpu,
		(*C.LuxTensor)(a.tensor),
		&cShape[0],
		C.int(len(shape)),
	)

	arr := &Array{
		tensor: tensor,
		shape:  shape,
		dtype:  a.dtype,
	}
	DefaultContext.Track(arr)
	return arr
}

// Slice extracts a slice from the array
func Slice(a *Array, args []SliceArg) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	ndim := len(args)
	starts := make([]int, ndim)
	stops := make([]int, ndim)

	for i, arg := range args {
		starts[i] = arg.Start
		stops[i] = arg.Stop
	}

	cStarts := intsToCInts(starts)
	cStops := intsToCInts(stops)
	tensor := C.lux_gpu_slice(
		DefaultContext.gpu,
		(*C.LuxTensor)(a.tensor),
		&cStarts[0],
		&cStops[0],
		C.int(ndim),
	)

	// Calculate new shape
	newShape := make([]int, ndim)
	for i := 0; i < ndim; i++ {
		newShape[i] = stops[i] - starts[i]
	}

	arr := &Array{
		tensor: tensor,
		shape:  newShape,
		dtype:  a.dtype,
	}
	DefaultContext.Track(arr)
	return arr
}

// Take gathers elements along an axis
func Take(a *Array, indices *Array, axis int) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	tensor := C.lux_gpu_take(
		DefaultContext.gpu,
		(*C.LuxTensor)(a.tensor),
		(*C.LuxTensor)(indices.tensor),
		C.int(axis),
	)

	arr := &Array{
		tensor: tensor,
		shape:  indices.shape,
		dtype:  a.dtype,
	}
	DefaultContext.Track(arr)
	return arr
}

// TakeAlongAxis gathers values along an axis using indices of the same shape
func TakeAlongAxis(a, indices *Array, axis int) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	tensor := C.lux_gpu_take_along_axis(
		DefaultContext.gpu,
		(*C.LuxTensor)(a.tensor),
		(*C.LuxTensor)(indices.tensor),
		C.int(axis),
	)

	arr := &Array{
		tensor: tensor,
		shape:  indices.shape,
		dtype:  a.dtype,
	}
	DefaultContext.Track(arr)
	return arr
}

// Concatenate concatenates arrays along an axis
func Concatenate(arrays []Array, axis int) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	tensors := make([]*C.LuxTensor, len(arrays))
	for i := range arrays {
		tensors[i] = arrays[i].tensor
	}

	tensor := C.lux_gpu_concatenate(
		DefaultContext.gpu,
		&tensors[0],
		C.int(len(arrays)),
		C.int(axis),
	)

	// Calculate output shape
	newShape := make([]int, len(arrays[0].shape))
	copy(newShape, arrays[0].shape)
	for i := 1; i < len(arrays); i++ {
		newShape[axis] += arrays[i].shape[axis]
	}

	arr := &Array{
		tensor: tensor,
		shape:  newShape,
		dtype:  arrays[0].dtype,
	}
	DefaultContext.Track(arr)
	return arr
}

// GreaterEqual compares element-wise: a >= b
func GreaterEqual(a, b *Array) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	tensor := C.lux_gpu_greater_equal(
		DefaultContext.gpu,
		(*C.LuxTensor)(a.tensor),
		(*C.LuxTensor)(b.tensor),
	)

	arr := &Array{
		tensor: tensor,
		shape:  a.shape,
		dtype:  Bool,
	}
	DefaultContext.Track(arr)
	return arr
}

// Less compares element-wise: a < b
func Less(a, b *Array) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	tensor := C.lux_gpu_less(
		DefaultContext.gpu,
		(*C.LuxTensor)(a.tensor),
		(*C.LuxTensor)(b.tensor),
	)

	arr := &Array{
		tensor: tensor,
		shape:  a.shape,
		dtype:  Bool,
	}
	DefaultContext.Track(arr)
	return arr
}

// Greater compares element-wise: a > b
func Greater(a, b *Array) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	tensor := C.lux_gpu_greater(
		DefaultContext.gpu,
		(*C.LuxTensor)(a.tensor),
		(*C.LuxTensor)(b.tensor),
	)

	arr := &Array{
		tensor: tensor,
		shape:  a.shape,
		dtype:  Bool,
	}
	DefaultContext.Track(arr)
	return arr
}

// LessEqual compares element-wise: a <= b
func LessEqual(a, b *Array) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	tensor := C.lux_gpu_less_equal(
		DefaultContext.gpu,
		(*C.LuxTensor)(a.tensor),
		(*C.LuxTensor)(b.tensor),
	)

	arr := &Array{
		tensor: tensor,
		shape:  a.shape,
		dtype:  Bool,
	}
	DefaultContext.Track(arr)
	return arr
}

// Where selects elements based on condition: cond ? a : b
func Where(cond, a, b *Array) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	tensor := C.lux_gpu_where(
		DefaultContext.gpu,
		(*C.LuxTensor)(cond.tensor),
		(*C.LuxTensor)(a.tensor),
		(*C.LuxTensor)(b.tensor),
	)

	arr := &Array{
		tensor: tensor,
		shape:  a.shape,
		dtype:  a.dtype,
	}
	DefaultContext.Track(arr)
	return arr
}

// ToSlice downloads array data to a Go slice
func ToSlice[T int64 | float64 | float32 | int32](a *Array) []T {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	// Calculate total size
	total := 1
	for _, s := range a.shape {
		total *= s
	}

	result := make([]T, total)

	// Get data pointer from tensor
	dataPtr := C.lux_gpu_tensor_data((*C.LuxTensor)(a.tensor))
	if dataPtr == nil {
		return result
	}

	// Copy based on type
	switch any(result).(type) {
	case []int64:
		C.memcpy(unsafe.Pointer(&result[0]), dataPtr, C.size_t(total*8))
	case []float64:
		C.memcpy(unsafe.Pointer(&result[0]), dataPtr, C.size_t(total*8))
	case []float32:
		C.memcpy(unsafe.Pointer(&result[0]), dataPtr, C.size_t(total*4))
	case []int32:
		C.memcpy(unsafe.Pointer(&result[0]), dataPtr, C.size_t(total*4))
	}

	return result
}

// ArangeInt creates an array with sequential integer values [start, stop) with step
func ArangeInt(start, stop, step int, dtype Dtype) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	size := (stop - start + step - 1) / step
	if size <= 0 {
		size = 0
	}

	// Create data manually
	data := make([]float32, size)
	val := float32(start)
	for i := range data {
		data[i] = val
		val += float32(step)
	}

	cShape := intsToCInts([]int{size})
	tensor := C.lux_gpu_tensor_create(
		DefaultContext.gpu,
		unsafe.Pointer(&data[0]),
		&cShape[0],
		C.int(1),
		dtypeToC(dtype),
	)

	arr := &Array{
		tensor: tensor,
		shape:  []int{size},
		dtype:  dtype,
	}
	DefaultContext.Track(arr)
	return arr
}

// Subtract performs element-wise subtraction: a - b
func Subtract(a, b *Array) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	tensor := C.lux_gpu_subtract(
		DefaultContext.gpu,
		(*C.LuxTensor)(a.tensor),
		(*C.LuxTensor)(b.tensor),
	)

	arr := &Array{
		tensor: tensor,
		shape:  a.shape,
		dtype:  a.dtype,
	}
	DefaultContext.Track(arr)
	return arr
}

// Divide performs element-wise division: a / b
func Divide(a, b *Array) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	tensor := C.lux_gpu_divide(
		DefaultContext.gpu,
		(*C.LuxTensor)(a.tensor),
		(*C.LuxTensor)(b.tensor),
	)

	arr := &Array{
		tensor: tensor,
		shape:  a.shape,
		dtype:  a.dtype,
	}
	DefaultContext.Track(arr)
	return arr
}

// Full creates an array filled with a constant value
func Full(shape []int, value interface{}, dtype Dtype) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	var fval float32
	switch v := value.(type) {
	case float64:
		fval = float32(v)
	case float32:
		fval = v
	case int:
		fval = float32(v)
	case int32:
		fval = float32(v)
	case int64:
		fval = float32(v)
	case uint64:
		fval = float32(v)
	}

	cShape := intsToCInts(shape)
	tensor := C.lux_gpu_tensor_full(
		DefaultContext.gpu,
		&cShape[0],
		C.int(len(shape)),
		C.float(fval),
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

// Helper functions (re-exported from fhe_types_cgo.go for this file)

// intsToCInts converts a Go []int slice to []C.int for CGO calls
func intsToCInts(ints []int) []C.int {
	cInts := make([]C.int, len(ints))
	for i, v := range ints {
		cInts[i] = C.int(v)
	}
	return cInts
}

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
