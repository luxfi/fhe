//go:build !cgo || !luxgpu

// Package gpu provides FHE operations with optional GPU acceleration.
// This file provides stub implementations when CGO is disabled or luxgpu tag is not set.

package gpu

// GPUAvailable returns false when CGO is disabled or luxgpu is not enabled
func GPUAvailable() bool {
	return false
}

// GetBackend returns "CPU (pure Go)" when CGO is disabled or luxgpu is not enabled
func GetBackend() string {
	return "CPU (pure Go)"
}
