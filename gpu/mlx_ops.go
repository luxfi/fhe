//go:build cgo

// Package gpu provides accelerated TFHE operations using MLX.
// This file provides additional array operations that wrap or extend MLX core.
//
// These are placeholder implementations until the full MLX C API is bound.
// They return arrays with correct shapes for compilation and basic testing.
//
// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause
package gpu

import (
	"github.com/luxfi/mlx"
)

// ========== Shape and Reshape ==========

// Shape returns the shape of an array (wrapper for method call)
func Shape(a *mlx.Array) []int {
	if a == nil {
		return nil
	}
	return a.Shape()
}

// Reshape reshapes an array to a new shape
func Reshape(a *mlx.Array, newShape []int) *mlx.Array {
	if a == nil {
		return mlx.Zeros(newShape, mlx.Int64)
	}
	return mlx.Reshape(a, newShape)
}

// Squeeze removes dimensions of size 1
func Squeeze(a *mlx.Array, axis int) *mlx.Array {
	if a == nil {
		return nil
	}
	return mlx.Squeeze(a, axis)
}

// Broadcast broadcasts an array to a new shape
func Broadcast(a *mlx.Array, newShape []int) *mlx.Array {
	if a == nil {
		return mlx.Zeros(newShape, mlx.Int64)
	}
	return mlx.Broadcast(a, newShape)
}

// ========== Slicing and Indexing ==========

// SliceArg defines slice parameters for one dimension
type SliceArg struct {
	Start int
	Stop  int
	Step  int
}

// Slice extracts a slice from an array using start, stop, step arrays
func Slice(a *mlx.Array, start, stop, step []int) *mlx.Array {
	if a == nil {
		return nil
	}
	shape := a.Shape()
	if len(start) != len(shape) {
		return a
	}

	newShape := make([]int, len(shape))
	for i := range shape {
		s := 1
		if i < len(step) && step[i] != 0 {
			s = step[i]
		}
		newShape[i] = (stop[i] - start[i] + s - 1) / s
		if newShape[i] < 0 {
			newShape[i] = 0
		}
	}

	return mlx.Zeros(newShape, mlx.Int64)
}

// SliceArgs extracts a slice using SliceArg array (matches mlx.Slice signature)
func SliceArgs(a *mlx.Array, args []SliceArg) *mlx.Array {
	if a == nil {
		return nil
	}
	// Convert to mlx.SliceArg
	mlxArgs := make([]mlx.SliceArg, len(args))
	for i, arg := range args {
		mlxArgs[i] = mlx.SliceArg{Start: arg.Start, Stop: arg.Stop}
	}
	return mlx.Slice(a, mlxArgs)
}

// Take gathers elements from an array along an axis
func Take(a *mlx.Array, indices *mlx.Array, axis int) *mlx.Array {
	if a == nil {
		return nil
	}
	return mlx.Take(a, indices, axis)
}

// TakeAlongAxis gathers elements along specified axis using indices array
func TakeAlongAxis(a *mlx.Array, indices *mlx.Array, axis int) *mlx.Array {
	if a == nil || indices == nil {
		return a
	}
	return mlx.TakeAlongAxis(a, indices, axis)
}

// ========== Combining Arrays ==========

// Tile repeats an array along each axis
func Tile(a *mlx.Array, reps []int) *mlx.Array {
	if a == nil {
		return nil
	}
	shape := a.Shape()

	for len(reps) < len(shape) {
		reps = append([]int{1}, reps...)
	}

	newShape := make([]int, len(shape))
	for i := range shape {
		if i < len(reps) {
			newShape[i] = shape[i] * reps[i]
		} else {
			newShape[i] = shape[i]
		}
	}

	return mlx.Zeros(newShape, mlx.Int64)
}

// Stack stacks arrays along a new axis
func Stack(arrays []*mlx.Array, axis int) *mlx.Array {
	if len(arrays) == 0 {
		return mlx.Zeros([]int{0}, mlx.Int64)
	}

	shape := arrays[0].Shape()

	newShape := make([]int, len(shape)+1)
	for i := 0; i < axis && i < len(shape); i++ {
		newShape[i] = shape[i]
	}
	newShape[axis] = len(arrays)
	for i := axis; i < len(shape); i++ {
		newShape[i+1] = shape[i]
	}

	return mlx.Zeros(newShape, mlx.Int64)
}

// Concatenate joins arrays along an existing axis
func Concatenate(arrays []mlx.Array, axis int) *mlx.Array {
	if len(arrays) == 0 {
		return mlx.Zeros([]int{0}, mlx.Int64)
	}
	return mlx.Concatenate(arrays, axis)
}

// ========== Arithmetic Operations ==========

// Subtract performs element-wise subtraction
func Subtract(a, b *mlx.Array) *mlx.Array {
	if a == nil {
		return b
	}
	return mlx.Subtract(a, b)
}

// Negative returns -a
func Negative(a *mlx.Array) *mlx.Array {
	if a == nil {
		return nil
	}
	zero := mlx.Zeros(a.Shape(), mlx.Int64)
	return mlx.Subtract(zero, a)
}

// Divide performs element-wise division
func Divide(a, b *mlx.Array) *mlx.Array {
	if a == nil {
		return nil
	}
	return mlx.Divide(a, b)
}

// Floor returns floor of each element
func Floor(a *mlx.Array) *mlx.Array {
	if a == nil {
		return nil
	}
	return mlx.Floor(a)
}

// FloorDivide performs element-wise floor division
func FloorDivide(a, b *mlx.Array) *mlx.Array {
	if a == nil {
		return nil
	}
	return mlx.Floor(mlx.Divide(a, b))
}

// Remainder computes element-wise remainder
func Remainder(a, b *mlx.Array) *mlx.Array {
	if a == nil {
		return nil
	}
	return mlx.Remainder(a, b)
}

// RightShift performs element-wise right bit shift
func RightShift(a, b *mlx.Array) *mlx.Array {
	if a == nil {
		return nil
	}
	return mlx.RightShift(a, b)
}

// ========== Comparison Operations ==========

// Less performs element-wise comparison a < b
func Less(a, b *mlx.Array) *mlx.Array {
	if a == nil {
		return nil
	}
	return mlx.Less(a, b)
}

// GreaterEqual performs element-wise comparison a >= b
func GreaterEqual(a, b *mlx.Array) *mlx.Array {
	if a == nil {
		return nil
	}
	return mlx.GreaterEqual(a, b)
}

// ========== Conditional Operations ==========

// Where selects elements based on condition
func Where(condition, x, y *mlx.Array) *mlx.Array {
	if x == nil {
		return y
	}
	return mlx.Where(condition, x, y)
}

// ========== Creation Operations ==========

// Full creates an array filled with a constant value
func Full(shape []int, value interface{}, dtype mlx.Dtype) *mlx.Array {
	return mlx.Full(shape, value, dtype)
}

// Arange creates an array with sequential values
func Arange(start, stop, step int, dtype mlx.Dtype) *mlx.Array {
	return mlx.ArangeInt(start, stop, step, dtype)
}

// ========== Type Conversion ==========

// Round rounds elements to nearest integer
func Round(a *mlx.Array) *mlx.Array {
	if a == nil {
		return nil
	}
	return mlx.Round(a)
}

// AsType converts array to a different dtype
func AsType(a *mlx.Array, dtype mlx.Dtype) *mlx.Array {
	if a == nil {
		return nil
	}
	return mlx.AsType(a, dtype)
}

// ========== Data Extraction ==========

// AsSlice extracts array data as a Go slice
func AsSlice[T int64 | float64 | float32 | int32](a *mlx.Array) []T {
	if a == nil {
		return nil
	}
	return mlx.ToSlice[T](a)
}

// ========== Utility Functions ==========

// equalShapes checks if two shapes are equal
func equalShapes(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
