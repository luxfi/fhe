//go:build (linux || windows) && cgo && cuda

// Package gpu provides multi-GPU TFHE operations
package gpu

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/luxfi/mlx"
)

// MultiGPUEngine distributes TFHE operations across multiple GPUs
type MultiGPUEngine struct {
	cfg  Config
	mgpu *mlx.MultiGPU

	// Per-GPU engines
	engines []*Engine

	// User to GPU mapping
	userGPU map[uint64]int
	usersMu sync.RWMutex

	// Load balancing
	usersPerGPU []atomic.Uint32

	// Statistics
	totalOps atomic.Uint64
}

// NewMultiGPU creates a multi-GPU TFHE engine
func NewMultiGPU(cfg Config) (*MultiGPUEngine, error) {
	// Initialize multi-GPU
	mgpu, err := mlx.InitMultiGPU(8) // Try up to 8 GPUs
	if err != nil {
		return nil, fmt.Errorf("multi-GPU init failed: %w", err)
	}

	// Enable NVLink peer access
	if err := mgpu.EnablePeerAccess(); err != nil {
		fmt.Printf("Warning: peer access not available: %v\n", err)
	}

	mgpu.PrintTopology()

	numGPUs := mgpu.NumGPUs()
	me := &MultiGPUEngine{
		cfg:         cfg,
		mgpu:        mgpu,
		engines:     make([]*Engine, numGPUs),
		userGPU:     make(map[uint64]int),
		usersPerGPU: make([]atomic.Uint32, numGPUs),
	}

	// Initialize per-GPU engines
	for i := 0; i < numGPUs; i++ {
		mgpu.SetDevice(i)
		engine, err := New(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to init engine on GPU %d: %w", i, err)
		}
		me.engines[i] = engine
	}

	fmt.Printf("Multi-GPU TFHE Engine ready with %d GPUs\n", numGPUs)
	fmt.Printf("  Total memory: %.1f GB\n", float64(mgpu.TotalMemory())/(1024*1024*1024))
	fmt.Printf("  Max users: %d\n", cfg.MaxUsers)

	return me, nil
}

// CreateUser creates a user on the least loaded GPU
func (me *MultiGPUEngine) CreateUser() (uint64, error) {
	// Find GPU with fewest users
	gpuID := me.findBestGPU()

	// Create user on that GPU
	me.mgpu.SetDevice(gpuID)
	userID, err := me.engines[gpuID].CreateUser()
	if err != nil {
		return 0, err
	}

	me.usersMu.Lock()
	me.userGPU[userID] = gpuID
	me.usersMu.Unlock()

	me.usersPerGPU[gpuID].Add(1)

	return userID, nil
}

// CreateUserOnGPU creates a user on a specific GPU
func (me *MultiGPUEngine) CreateUserOnGPU(gpuID int) (uint64, error) {
	if gpuID < 0 || gpuID >= me.mgpu.NumGPUs() {
		return 0, fmt.Errorf("invalid GPU ID %d", gpuID)
	}

	me.mgpu.SetDevice(gpuID)
	userID, err := me.engines[gpuID].CreateUser()
	if err != nil {
		return 0, err
	}

	me.usersMu.Lock()
	me.userGPU[userID] = gpuID
	me.usersMu.Unlock()

	me.usersPerGPU[gpuID].Add(1)

	return userID, nil
}

// DeleteUser removes a user
func (me *MultiGPUEngine) DeleteUser(userID uint64) {
	me.usersMu.Lock()
	gpuID, ok := me.userGPU[userID]
	if ok {
		delete(me.userGPU, userID)
	}
	me.usersMu.Unlock()

	if ok {
		me.mgpu.SetDevice(gpuID)
		me.engines[gpuID].DeleteUser(userID)
		me.usersPerGPU[gpuID].Add(^uint32(0)) // Decrement
	}
}

// GetUserGPU returns which GPU a user is on
func (me *MultiGPUEngine) GetUserGPU(userID uint64) int {
	me.usersMu.RLock()
	defer me.usersMu.RUnlock()
	return me.userGPU[userID]
}

// ExecuteBatchGates executes operations across all GPUs in parallel
func (me *MultiGPUEngine) ExecuteBatchGates(ops []BatchGateOp) error {
	// Group operations by GPU
	gpuOps := make([][]BatchGateOp, me.mgpu.NumGPUs())
	for i := range gpuOps {
		gpuOps[i] = make([]BatchGateOp, 0)
	}

	me.usersMu.RLock()
	for _, op := range ops {
		// Group by user's GPU
		perGPU := make(map[int]*BatchGateOp)

		for i, userID := range op.UserIDs {
			gpuID := me.userGPU[userID]
			if _, ok := perGPU[gpuID]; !ok {
				perGPU[gpuID] = &BatchGateOp{
					Gate: op.Gate,
				}
			}
			perGPU[gpuID].UserIDs = append(perGPU[gpuID].UserIDs, userID)
			perGPU[gpuID].Input1Indices = append(perGPU[gpuID].Input1Indices, op.Input1Indices[i])
			perGPU[gpuID].Input2Indices = append(perGPU[gpuID].Input2Indices, op.Input2Indices[i])
			perGPU[gpuID].OutputIndices = append(perGPU[gpuID].OutputIndices, op.OutputIndices[i])
		}

		for gpuID, gpuOp := range perGPU {
			gpuOps[gpuID] = append(gpuOps[gpuID], *gpuOp)
		}
	}
	me.usersMu.RUnlock()

	// Execute on each GPU in parallel
	var wg sync.WaitGroup
	errChan := make(chan error, me.mgpu.NumGPUs())

	for gpuID := 0; gpuID < me.mgpu.NumGPUs(); gpuID++ {
		if len(gpuOps[gpuID]) == 0 {
			continue
		}

		wg.Add(1)
		go func(gid int, ops []BatchGateOp) {
			defer wg.Done()

			me.mgpu.SetDevice(gid)
			if err := me.engines[gid].ExecuteBatchGates(ops); err != nil {
				errChan <- fmt.Errorf("GPU %d: %w", gid, err)
			}

			// Count operations
			for _, op := range ops {
				me.totalOps.Add(uint64(len(op.UserIDs)))
			}
		}(gpuID, gpuOps[gpuID])
	}

	wg.Wait()
	close(errChan)

	// Check for errors
	for err := range errChan {
		return err
	}

	return nil
}

// SyncAll waits for all GPUs to complete
func (me *MultiGPUEngine) SyncAll() {
	me.mgpu.SyncAll()
}

// findBestGPU returns the GPU with fewest users
func (me *MultiGPUEngine) findBestGPU() int {
	best := 0
	minUsers := me.usersPerGPU[0].Load()

	for i := 1; i < me.mgpu.NumGPUs(); i++ {
		users := me.usersPerGPU[i].Load()
		if users < minUsers {
			minUsers = users
			best = i
		}
	}

	return best
}

// Stats returns multi-GPU statistics
type MultiGPUStats struct {
	NumGPUs     int
	TotalMemory uint64
	FreeMemory  uint64
	TotalUsers  int
	UsersPerGPU []int
	TotalOps    uint64
	HasNVLink   bool
}

// GetStats returns current statistics
func (me *MultiGPUEngine) GetStats() MultiGPUStats {
	stats := MultiGPUStats{
		NumGPUs:     me.mgpu.NumGPUs(),
		TotalMemory: me.mgpu.TotalMemory(),
		FreeMemory:  me.mgpu.TotalFreeMemory(),
		UsersPerGPU: make([]int, me.mgpu.NumGPUs()),
		TotalOps:    me.totalOps.Load(),
	}

	for i := 0; i < me.mgpu.NumGPUs(); i++ {
		stats.UsersPerGPU[i] = int(me.usersPerGPU[i].Load())
		stats.TotalUsers += stats.UsersPerGPU[i]
	}

	// Check if any NVLink
	if me.mgpu.NumGPUs() > 1 {
		stats.HasNVLink = me.mgpu.HasNVLink(0, 1)
	}

	return stats
}

// Shutdown cleans up all resources
func (me *MultiGPUEngine) Shutdown() {
	me.mgpu.Shutdown()
}

// PerformanceEstimateMultiGPU estimates performance on multi-GPU setup
func PerformanceEstimateMultiGPU(numGPUs int, cfg Config) PerformanceEstimate {
	est := EstimatePerformance(cfg)

	// Scale by number of GPUs
	est.NumDevices = numGPUs
	est.TotalMemoryGB *= float64(numGPUs)
	est.BandwidthTBps *= float64(numGPUs)
	est.MaxConcurrentUsers *= uint32(numGPUs)
	est.PeakBootstrapsPerSec *= float64(numGPUs)

	return est
}
