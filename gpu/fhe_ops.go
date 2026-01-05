//go:build cgo && luxgpu

// Package gpu provides GPU-accelerated tensor operations for FHE workloads.
// These operations are needed for GPU-accelerated TFHE bootstrapping.

package gpu

/*
#cgo pkg-config: lux-gpu
#include <lux/gpu/gpu.h>
#include <stdlib.h>
*/
import "C"

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

// Add performs element-wise addition: a + b
func Add(a, b *Array) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	tensor := C.lux_gpu_add(DefaultContext.gpu, a.tensor, b.tensor)

	arr := &Array{
		tensor: tensor,
		shape:  a.shape,
		dtype:  a.dtype,
	}
	DefaultContext.Track(arr)
	return arr
}

// Subtract performs element-wise subtraction: a - b
func Subtract(a, b *Array) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	tensor := C.lux_gpu_subtract(DefaultContext.gpu, a.tensor, b.tensor)

	arr := &Array{
		tensor: tensor,
		shape:  a.shape,
		dtype:  a.dtype,
	}
	DefaultContext.Track(arr)
	return arr
}

// Multiply performs element-wise multiplication: a * b
func Multiply(a, b *Array) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	tensor := C.lux_gpu_multiply(DefaultContext.gpu, a.tensor, b.tensor)

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

	tensor := C.lux_gpu_divide(DefaultContext.gpu, a.tensor, b.tensor)

	arr := &Array{
		tensor: tensor,
		shape:  a.shape,
		dtype:  a.dtype,
	}
	DefaultContext.Track(arr)
	return arr
}

// Remainder computes element-wise remainder: a % b
func Remainder(a, b *Array) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	tensor := C.lux_gpu_remainder(DefaultContext.gpu, a.tensor, b.tensor)

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

	tensor := C.lux_gpu_floor(DefaultContext.gpu, a.tensor)

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

	tensor := C.lux_gpu_round(DefaultContext.gpu, a.tensor)

	arr := &Array{
		tensor: tensor,
		shape:  a.shape,
		dtype:  a.dtype,
	}
	DefaultContext.Track(arr)
	return arr
}

// RightShift performs element-wise right shift: a >> bits
func RightShift(a *Array, bits int) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	tensor := C.lux_gpu_right_shift(DefaultContext.gpu, a.tensor, C.int(bits))

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

	tensor := C.lux_gpu_astype(DefaultContext.gpu, a.tensor, dtypeToC(dtype))

	arr := &Array{
		tensor: tensor,
		shape:  a.shape,
		dtype:  dtype,
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

// Reshape reshapes array to new shape
func Reshape(a *Array, shape []int) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	cShape := intsToCInts(shape)
	tensor := C.lux_gpu_reshape(DefaultContext.gpu, a.tensor, &cShape[0], C.int(len(shape)))

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

	tensor := C.lux_gpu_squeeze(DefaultContext.gpu, a.tensor, C.int(axis))

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
	tensor := C.lux_gpu_broadcast(DefaultContext.gpu, a.tensor, &cShape[0], C.int(len(shape)))

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
	steps := make([]int, ndim)

	for i, arg := range args {
		starts[i] = arg.Start
		stops[i] = arg.Stop
		steps[i] = 1 // Default step
	}

	cStarts := intsToCInts(starts)
	cStops := intsToCInts(stops)
	cSteps := intsToCInts(steps)
	tensor := C.lux_gpu_slice(DefaultContext.gpu, a.tensor, &cStarts[0], &cStops[0], &cSteps[0], C.int(ndim))

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

	tensor := C.lux_gpu_take(DefaultContext.gpu, a.tensor, indices.tensor, C.int(axis))

	// Shape depends on indices shape replacing the axis dimension
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

	tensor := C.lux_gpu_take_along_axis(DefaultContext.gpu, a.tensor, indices.tensor, C.int(axis))

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

	tensor := C.lux_gpu_concatenate(DefaultContext.gpu, &tensors[0], C.int(len(arrays)), C.int(axis))

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

// Less compares element-wise: a < b
func Less(a, b *Array) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	tensor := C.lux_gpu_less(DefaultContext.gpu, a.tensor, b.tensor)

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

	tensor := C.lux_gpu_greater(DefaultContext.gpu, a.tensor, b.tensor)

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

	tensor := C.lux_gpu_less_equal(DefaultContext.gpu, a.tensor, b.tensor)

	arr := &Array{
		tensor: tensor,
		shape:  a.shape,
		dtype:  Bool,
	}
	DefaultContext.Track(arr)
	return arr
}

// GreaterEqual compares element-wise: a >= b
func GreaterEqual(a, b *Array) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	tensor := C.lux_gpu_greater_equal(DefaultContext.gpu, a.tensor, b.tensor)

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

	tensor := C.lux_gpu_where(DefaultContext.gpu, cond.tensor, a.tensor, b.tensor)

	arr := &Array{
		tensor: tensor,
		shape:  a.shape,
		dtype:  a.dtype,
	}
	DefaultContext.Track(arr)
	return arr
}

// Matmul performs matrix multiplication
func Matmul(a, b *Array) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	tensor := C.lux_gpu_matmul(DefaultContext.gpu, a.tensor, b.tensor)

	// Calculate output shape for matmul
	newShape := make([]int, len(a.shape))
	copy(newShape, a.shape)
	if len(b.shape) > 1 {
		newShape[len(newShape)-1] = b.shape[len(b.shape)-1]
	}

	arr := &Array{
		tensor: tensor,
		shape:  newShape,
		dtype:  a.dtype,
	}
	DefaultContext.Track(arr)
	return arr
}

// Sum reduces array by summing along specified axes
func Sum(a *Array, axes []int) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	cAxes := intsToCInts(axes)
	var tensor *C.LuxTensor
	if len(axes) > 0 {
		tensor = C.lux_gpu_sum(DefaultContext.gpu, a.tensor, &cAxes[0], C.int(len(axes)))
	} else {
		tensor = C.lux_gpu_sum(DefaultContext.gpu, a.tensor, nil, 0)
	}

	// Calculate reduced shape
	newShape := make([]int, 0)
	for i, s := range a.shape {
		keep := true
		for _, ax := range axes {
			if i == ax {
				keep = false
				break
			}
		}
		if keep {
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

// Mean reduces array by computing mean along specified axes
func Mean(a *Array, axes []int) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	cAxes := intsToCInts(axes)
	var tensor *C.LuxTensor
	if len(axes) > 0 {
		tensor = C.lux_gpu_mean(DefaultContext.gpu, a.tensor, &cAxes[0], C.int(len(axes)))
	} else {
		tensor = C.lux_gpu_mean(DefaultContext.gpu, a.tensor, nil, 0)
	}

	// Calculate reduced shape
	newShape := make([]int, 0)
	for i, s := range a.shape {
		keep := true
		for _, ax := range axes {
			if i == ax {
				keep = false
				break
			}
		}
		if keep {
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

// Max reduces array by computing max along specified axes
func Max(a *Array, axes []int) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	cAxes := intsToCInts(axes)
	var tensor *C.LuxTensor
	if len(axes) > 0 {
		tensor = C.lux_gpu_max(DefaultContext.gpu, a.tensor, &cAxes[0], C.int(len(axes)))
	} else {
		tensor = C.lux_gpu_max(DefaultContext.gpu, a.tensor, nil, 0)
	}

	// Calculate reduced shape
	newShape := make([]int, 0)
	for i, s := range a.shape {
		keep := true
		for _, ax := range axes {
			if i == ax {
				keep = false
				break
			}
		}
		if keep {
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

// Min reduces array by computing min along specified axes
func Min(a *Array, axes []int) *Array {
	DefaultContext.mu.Lock()
	defer DefaultContext.mu.Unlock()

	cAxes := intsToCInts(axes)
	var tensor *C.LuxTensor
	if len(axes) > 0 {
		tensor = C.lux_gpu_min(DefaultContext.gpu, a.tensor, &cAxes[0], C.int(len(axes)))
	} else {
		tensor = C.lux_gpu_min(DefaultContext.gpu, a.tensor, nil, 0)
	}

	// Calculate reduced shape
	newShape := make([]int, 0)
	for i, s := range a.shape {
		keep := true
		for _, ax := range axes {
			if i == ax {
				keep = false
				break
			}
		}
		if keep {
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
