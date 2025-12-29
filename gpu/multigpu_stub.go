//go:build !(linux && cgo && cuda) && !(windows && cgo && cuda)

// Package gpu provides multi-GPU TFHE operations
// This is a stub for platforms without CUDA support
package gpu

import (
	"errors"
	"time"
)

// ErrNoCUDA is returned when CUDA multi-GPU is not available
var ErrNoCUDA = errors.New("CUDA multi-GPU not available on this platform")

// MultiGPUConfig configures the multi-GPU engine
type MultiGPUConfig struct {
	TFHEConfig         Config
	NumGPUs            int
	BSKCacheMemory     int64
	Scheduler          SchedulerConfig
	EnableP2P          bool
	EnableWorkStealing bool
	MaxUsersPerGPU     int
}

func DefaultMultiGPUConfig() MultiGPUConfig {
	return MultiGPUConfig{
		TFHEConfig:         DefaultConfig(),
		NumGPUs:            0,
		BSKCacheMemory:     0,
		Scheduler:          DefaultSchedulerConfig(),
		EnableP2P:          true,
		EnableWorkStealing: true,
		MaxUsersPerGPU:     1000,
	}
}

func H200x8MultiGPUConfig() MultiGPUConfig {
	cfg := DefaultMultiGPUConfig()
	cfg.NumGPUs = 8
	cfg.MaxUsersPerGPU = 1000
	return cfg
}

// MultiGPUEngine is a stub for non-CUDA platforms
type MultiGPUEngine struct{}

// MultiGPUUser stub
type MultiGPUUser struct {
	ID         string
	NumericID  uint64
	PrimaryGPU int
}

// MultiGPUStats is a stub for non-CUDA platforms
type MultiGPUStats struct {
	NumGPUs        int
	TotalMemory    uint64
	FreeMemory     uint64
	TotalUsers     int
	UsersPerGPU    []int
	TotalOps       uint64
	HasNVLink      bool
	P2PEnabled     bool
	Uptime         time.Duration
	BSKCacheStats  BSKCacheStats
	SchedulerStats SchedulerStats
}

// UserOperation represents a user's gate operation
type UserOperation struct {
	UserID string
	Gate   GateType
	Input1 []uint32
	Input2 []uint32
	Output []uint32
}

// NewMultiGPUEngine returns an error on non-CUDA platforms
func NewMultiGPUEngine(cfg MultiGPUConfig) (*MultiGPUEngine, error) {
	return nil, ErrNoCUDA
}

// NewMultiGPU returns an error on non-CUDA platforms
func NewMultiGPU(cfg Config) (*MultiGPUEngine, error) {
	return nil, ErrNoCUDA
}

// CreateUser is not available without CUDA
func (me *MultiGPUEngine) CreateUser() (uint64, error) {
	return 0, ErrNoCUDA
}

// CreateUserWithID is not available without CUDA
func (me *MultiGPUEngine) CreateUserWithID(userID string) error {
	return ErrNoCUDA
}

// CreateUserOnGPU is not available without CUDA
func (me *MultiGPUEngine) CreateUserOnGPU(gpuID int) (uint64, error) {
	return 0, ErrNoCUDA
}

// CreateUserWithIDOnGPU is not available without CUDA
func (me *MultiGPUEngine) CreateUserWithIDOnGPU(userID string, gpuID int) error {
	return ErrNoCUDA
}

// UploadBootstrapKey is not available without CUDA
func (me *MultiGPUEngine) UploadBootstrapKey(userID string, bsk interface{}, ksk interface{}) error {
	return ErrNoCUDA
}

// UploadBootstrapKeyBytes is not available without CUDA
func (me *MultiGPUEngine) UploadBootstrapKeyBytes(userID string, bskData, kskData []byte) error {
	return ErrNoCUDA
}

// ForceUploadKeys is not available without CUDA
func (me *MultiGPUEngine) ForceUploadKeys(userID string) error {
	return ErrNoCUDA
}

// DeleteUser is not available without CUDA
func (me *MultiGPUEngine) DeleteUser(userID uint64) {}

// DeleteUserByID is not available without CUDA
func (me *MultiGPUEngine) DeleteUserByID(userID string) {}

// Submit is not available without CUDA
func (me *MultiGPUEngine) Submit(userID string, gate GateType, input1, input2, output []uint32) (*Future, error) {
	return nil, ErrNoCUDA
}

// SubmitBatch is not available without CUDA
func (me *MultiGPUEngine) SubmitBatch(ops []UserOperation) ([]*Future, error) {
	return nil, ErrNoCUDA
}

// GetUserGPU is not available without CUDA
func (me *MultiGPUEngine) GetUserGPU(userID uint64) int {
	return -1
}

// GetUserGPUByID is not available without CUDA
func (me *MultiGPUEngine) GetUserGPUByID(userID string) int {
	return -1
}

// MigrateUser is not available without CUDA
func (me *MultiGPUEngine) MigrateUser(userID string, targetGPU int) error {
	return ErrNoCUDA
}

// ExecuteBatchGates is not available without CUDA
func (me *MultiGPUEngine) ExecuteBatchGates(ops []BatchGateOp) error {
	return ErrNoCUDA
}

// SyncAll is not available without CUDA
func (me *MultiGPUEngine) SyncAll() {}

// NumGPUs returns 0 on non-CUDA platforms
func (me *MultiGPUEngine) NumGPUs() int {
	return 0
}

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
