//go:build !(linux && cgo && cuda) && !(windows && cgo && cuda)
// +build !linux !cgo !cuda
// +build !windows !cgo !cuda

// Package gpu provides multi-GPU TFHE operations
// This is a stub for platforms without CUDA support
package gpu

import "errors"

// ErrNoCUDA is returned when CUDA multi-GPU is not available
var ErrNoCUDA = errors.New("CUDA multi-GPU not available on this platform")

// MultiGPUEngine is a stub for non-CUDA platforms
type MultiGPUEngine struct{}

// MultiGPUStats is a stub for non-CUDA platforms
type MultiGPUStats struct {
	NumGPUs     int
	TotalMemory uint64
	FreeMemory  uint64
	TotalUsers  int
	UsersPerGPU []int
	TotalOps    uint64
	HasNVLink   bool
}

// NewMultiGPU returns an error on non-CUDA platforms
func NewMultiGPU(cfg Config) (*MultiGPUEngine, error) {
	return nil, ErrNoCUDA
}

// CreateUser is not available without CUDA
func (me *MultiGPUEngine) CreateUser() (uint64, error) {
	return 0, ErrNoCUDA
}

// CreateUserOnGPU is not available without CUDA
func (me *MultiGPUEngine) CreateUserOnGPU(gpuID int) (uint64, error) {
	return 0, ErrNoCUDA
}

// DeleteUser is not available without CUDA
func (me *MultiGPUEngine) DeleteUser(userID uint64) {}

// GetUserGPU is not available without CUDA
func (me *MultiGPUEngine) GetUserGPU(userID uint64) int {
	return 0
}

// ExecuteBatchGates is not available without CUDA
func (me *MultiGPUEngine) ExecuteBatchGates(ops []BatchGateOp) error {
	return ErrNoCUDA
}

// SyncAll is not available without CUDA
func (me *MultiGPUEngine) SyncAll() {}

// GetStats returns empty stats on non-CUDA platforms
func (me *MultiGPUEngine) GetStats() MultiGPUStats {
	return MultiGPUStats{}
}

// Shutdown is not available without CUDA
func (me *MultiGPUEngine) Shutdown() {}

// PerformanceEstimateMultiGPU returns single-GPU estimate on non-CUDA platforms
func PerformanceEstimateMultiGPU(numGPUs int, cfg Config) PerformanceEstimate {
	return EstimatePerformance(cfg)
}
