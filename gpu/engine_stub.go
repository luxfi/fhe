//go:build !cgo

// Package gpu provides accelerated TFHE operations using MLX.
// This is the pure Go stub used when CGO is disabled.
// For MLX acceleration, build with CGO_ENABLED=1.
package gpu

import (
	"errors"

	"github.com/luxfi/tfhe"
)

// ErrNotSupported is returned when MLX acceleration is not available
var ErrNotSupported = errors.New("MLX acceleration not available (build with CGO_ENABLED=1)")

// Config holds GPU TFHE engine configuration
type Config struct {
	N       uint32
	n       uint32
	L       uint32
	Bgbit   uint32
	Q       uint64
	Qks     uint32
	Bks     uint32
	KeysNKS uint32
}

// UserSession holds per-user GPU resources
type UserSession struct {
	UserID uint64
}

// LWEPool holds a batch of LWE ciphertexts on GPU
type LWEPool struct{}

// Engine is the main GPU TFHE engine
type Engine struct{}

// New creates a new GPU TFHE engine (stub - returns error)
func New(cfg Config) (*Engine, error) {
	return nil, ErrNotSupported
}

// CreateUser creates a new user session (stub)
func (e *Engine) CreateUser() (uint64, error) {
	return 0, ErrNotSupported
}

// DeleteUser removes a user session (stub)
func (e *Engine) DeleteUser(userID uint64) {}

// UploadBootstrapKey uploads a user's bootstrap key to GPU (stub)
func (e *Engine) UploadBootstrapKey(userID uint64, bsk *tfhe.BootstrapKey) error {
	return ErrNotSupported
}

// AllocateCiphertexts allocates a pool of LWE ciphertexts on GPU (stub)
func (e *Engine) AllocateCiphertexts(userID uint64, count uint32) (poolIdx uint32, err error) {
	return 0, ErrNotSupported
}

// GateType represents a boolean gate type
type GateType int

// Gate type constants
const (
	GateAND GateType = iota
	GateOR
	GateXOR
	GateNAND
	GateNOR
	GateXNOR
	GateNOT
	GateMUX
)

// BatchGateOp represents a batch of gate operations
type BatchGateOp struct {
	Gate        GateType
	UserIDs     []uint64
	InputPoolsA []uint32
	InputPoolsB []uint32
	OutputPools []uint32
}

// ExecuteBatchGates executes a batch of gate operations on GPU (stub)
func (e *Engine) ExecuteBatchGates(ops []BatchGateOp) error {
	return ErrNotSupported
}

// Sync waits for all GPU operations to complete (stub)
func (e *Engine) Sync() {}

// Stats returns engine statistics
type Stats struct {
	Backend         string
	DeviceName      string
	DeviceMemory    uint64
	AllocatedMemory uint64
	ActiveUsers     int
	TotalBootstraps uint64
}

// GetStats returns current engine statistics (stub)
func (e *Engine) GetStats() Stats {
	return Stats{Backend: "unsupported"}
}

// PerformanceEstimate estimates performance on current hardware
type PerformanceEstimate struct {
	Backend             string
	NumDevices          int
	BootstrapsPerSecond uint64
	LatencyMicroseconds uint64
	MemoryPerUserMB     uint64
	MaxConcurrentUsers  uint64
}

// EstimatePerformance returns performance estimates (stub)
func EstimatePerformance(cfg Config) PerformanceEstimate {
	return PerformanceEstimate{Backend: "unsupported"}
}
