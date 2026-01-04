//go:build luxgpu

// Package gpu - TFHE-specific array operations
// These operations are needed for GPU-accelerated TFHE bootstrapping

package gpu

/*
#include <lux/gpu/gpu.h>
*/
import "C"
import (
	"unsafe"
)

// intsToCInts converts a Go []int slice to []C.int for CGO calls
// Go int is 64-bit on 64-bit systems, C int is 32-bit
func intsToCInts(ints []int) []C.int {
	cInts := make([]C.int, len(ints))
	for i, v := range ints {
		cInts[i] = C.int(v)
	}
	return cInts
}

// SliceArg represents slicing arguments for Slice operation
type SliceArg struct {
	Start int
	Stop  int
}

// Subtract performs element-wise subtraction: a - b
func Subtract(a, b *Array) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	handle := C.mlx_subtract(a.handle, b.handle)

	arr := &Array{
		handle: handle,
		shape:  a.shape,
		dtype:  a.dtype,
	}
	DefaultContext.arrays[handle] = arr
	return arr
}

// Divide performs element-wise division: a / b
func Divide(a, b *Array) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	handle := C.mlx_divide(a.handle, b.handle)

	arr := &Array{
		handle: handle,
		shape:  a.shape,
		dtype:  a.dtype,
	}
	DefaultContext.arrays[handle] = arr
	return arr
}

// Remainder computes element-wise remainder: a % b
func Remainder(a, b *Array) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	handle := C.mlx_remainder(a.handle, b.handle)

	arr := &Array{
		handle: handle,
		shape:  a.shape,
		dtype:  a.dtype,
	}
	DefaultContext.arrays[handle] = arr
	return arr
}

// Floor computes element-wise floor
func Floor(a *Array) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	handle := C.mlx_floor(a.handle)

	arr := &Array{
		handle: handle,
		shape:  a.shape,
		dtype:  a.dtype,
	}
	DefaultContext.arrays[handle] = arr
	return arr
}

// Round rounds elements to nearest integer
func Round(a *Array) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	handle := C.mlx_round(a.handle)

	arr := &Array{
		handle: handle,
		shape:  a.shape,
		dtype:  a.dtype,
	}
	DefaultContext.arrays[handle] = arr
	return arr
}

// RightShift performs element-wise right shift: a >> b
func RightShift(a, b *Array) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	handle := C.mlx_right_shift(a.handle, b.handle)

	arr := &Array{
		handle: handle,
		shape:  a.shape,
		dtype:  a.dtype,
	}
	DefaultContext.arrays[handle] = arr
	return arr
}

// AsType casts array to specified dtype
func AsType(a *Array, dtype Dtype) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	handle := C.mlx_astype(a.handle, C.int(dtype))

	arr := &Array{
		handle: handle,
		shape:  a.shape,
		dtype:  dtype,
	}
	DefaultContext.arrays[handle] = arr
	return arr
}

// Full creates an array filled with a constant value
func Full(shape []int, value interface{}, dtype Dtype) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	var fval float64
	switch v := value.(type) {
	case float64:
		fval = v
	case float32:
		fval = float64(v)
	case int:
		fval = float64(v)
	case int32:
		fval = float64(v)
	case int64:
		fval = float64(v)
	case uint64:
		fval = float64(v)
	}

	cShape := intsToCInts(shape)
	handle := C.mlx_full(&cShape[0], C.int(len(shape)), C.double(fval), C.int(dtype))

	arr := &Array{
		handle: handle,
		shape:  shape,
		dtype:  dtype,
	}
	DefaultContext.arrays[handle] = arr
	return arr
}

// Reshape reshapes array to new shape
func Reshape(a *Array, shape []int) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	cShape := intsToCInts(shape)
	handle := C.mlx_reshape(a.handle, &cShape[0], C.int(len(shape)))

	arr := &Array{
		handle: handle,
		shape:  shape,
		dtype:  a.dtype,
	}
	DefaultContext.arrays[handle] = arr
	return arr
}

// Squeeze removes dimension of size 1 at specified axis
func Squeeze(a *Array, axis int) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	handle := C.mlx_squeeze(a.handle, C.int(axis))

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
		handle: handle,
		shape:  newShape,
		dtype:  a.dtype,
	}
	DefaultContext.arrays[handle] = arr
	return arr
}

// Broadcast broadcasts array to specified shape
func Broadcast(a *Array, shape []int) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	cShape := intsToCInts(shape)
	handle := C.mlx_broadcast(a.handle, &cShape[0], C.int(len(shape)))

	arr := &Array{
		handle: handle,
		shape:  shape,
		dtype:  a.dtype,
	}
	DefaultContext.arrays[handle] = arr
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
	handle := C.mlx_slice_nd(a.handle, &cStarts[0], &cStops[0], C.int(ndim))

	// Calculate new shape
	newShape := make([]int, ndim)
	for i := 0; i < ndim; i++ {
		newShape[i] = stops[i] - starts[i]
	}

	arr := &Array{
		handle: handle,
		shape:  newShape,
		dtype:  a.dtype,
	}
	DefaultContext.arrays[handle] = arr
	return arr
}

// Take gathers elements along an axis
func Take(a *Array, indices *Array, axis int) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	handle := C.mlx_take(a.handle, indices.handle, C.int(axis))

	// Shape depends on indices shape replacing the axis dimension
	arr := &Array{
		handle: handle,
		shape:  indices.shape,
		dtype:  a.dtype,
	}
	DefaultContext.arrays[handle] = arr
	return arr
}

// TakeAlongAxis gathers values along an axis using indices of the same shape
func TakeAlongAxis(a, indices *Array, axis int) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	handle := C.mlx_take_along_axis(a.handle, indices.handle, C.int(axis))

	arr := &Array{
		handle: handle,
		shape:  indices.shape,
		dtype:  a.dtype,
	}
	DefaultContext.arrays[handle] = arr
	return arr
}

// Concatenate concatenates arrays along an axis
func Concatenate(arrays []Array, axis int) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	handles := make([]unsafe.Pointer, len(arrays))
	for i := range arrays {
		handles[i] = arrays[i].handle
	}

	handle := C.mlx_concatenate(&handles[0], C.int(len(arrays)), C.int(axis))

	// Calculate output shape
	newShape := make([]int, len(arrays[0].shape))
	copy(newShape, arrays[0].shape)
	for i := 1; i < len(arrays); i++ {
		newShape[axis] += arrays[i].shape[axis]
	}

	arr := &Array{
		handle: handle,
		shape:  newShape,
		dtype:  arrays[0].dtype,
	}
	DefaultContext.arrays[handle] = arr
	return arr
}

// GreaterEqual compares element-wise: a >= b
func GreaterEqual(a, b *Array) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	handle := C.mlx_greater_equal(a.handle, b.handle)

	arr := &Array{
		handle: handle,
		shape:  a.shape,
		dtype:  Bool,
	}
	DefaultContext.arrays[handle] = arr
	return arr
}

// Less compares element-wise: a < b
func Less(a, b *Array) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	handle := C.mlx_less(a.handle, b.handle)

	arr := &Array{
		handle: handle,
		shape:  a.shape,
		dtype:  Bool,
	}
	DefaultContext.arrays[handle] = arr
	return arr
}

// Where selects elements based on condition: cond ? a : b
func Where(cond, a, b *Array) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	handle := C.mlx_where(cond.handle, a.handle, b.handle)

	arr := &Array{
		handle: handle,
		shape:  a.shape,
		dtype:  a.dtype,
	}
	DefaultContext.arrays[handle] = arr
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

	// For int64
	result := make([]T, total)

	switch any(result).(type) {
	case []int64:
		cOut := (*C.longlong)(unsafe.Pointer(&result[0]))
		C.mlx_to_slice_int64(a.handle, cOut, C.int(total))
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

	handle := C.mlx_arange(C.double(start), C.double(stop), C.double(step))

	arr := &Array{
		handle: handle,
		shape:  []int{size},
		dtype:  dtype,
	}
	DefaultContext.arrays[handle] = arr
	return arr
}
