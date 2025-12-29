//go:build (linux || windows) && cgo && cuda

// Package gpu provides multi-GPU TFHE operations with BSK sharing and load balancing
package gpu

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luxfi/mlx"
	"github.com/luxfi/tfhe"
)

// MultiGPUConfig configures the multi-GPU engine
type MultiGPUConfig struct {
	// TFHE configuration
	TFHEConfig Config

	// Number of GPUs to use (0 = all available)
	NumGPUs int

	// Memory limit per GPU for BSK cache (0 = 80% of GPU memory)
	BSKCacheMemory int64

	// Scheduler configuration
	Scheduler SchedulerConfig

	// Enable P2P access (NVLink) if available
	EnableP2P bool

	// Enable work stealing between GPUs
	EnableWorkStealing bool

	// Max concurrent users per GPU
	MaxUsersPerGPU int
}

// DefaultMultiGPUConfig returns sensible defaults
func DefaultMultiGPUConfig() MultiGPUConfig {
	return MultiGPUConfig{
		TFHEConfig:         DefaultConfig(),
		NumGPUs:            0, // Use all
		BSKCacheMemory:     0, // Auto
		Scheduler:          DefaultSchedulerConfig(),
		EnableP2P:          true,
		EnableWorkStealing: true,
		MaxUsersPerGPU:     1000,
	}
}

// H200x8MultiGPUConfig returns configuration for HGX H200 x8
func H200x8MultiGPUConfig() MultiGPUConfig {
	cfg := DefaultMultiGPUConfig()
	cfg.TFHEConfig = H200x8Config()
	cfg.NumGPUs = 8
	cfg.MaxUsersPerGPU = 1000 // 8000 total users
	cfg.Scheduler.BatchSize = 512
	cfg.Scheduler.QueueSize = 50000
	return cfg
}

// MultiGPUEngine coordinates TFHE operations across multiple GPUs
type MultiGPUEngine struct {
	cfg     MultiGPUConfig
	mgpu    *mlx.MultiGPU
	numGPUs int

	// Per-GPU engines
	engines []*Engine

	// BSK cache with P2P sharing
	bskCache *BSKCache

	// Work scheduler
	scheduler *Scheduler

	// User management (string-based IDs for external API)
	users      map[string]*MultiGPUUser
	usersMu    sync.RWMutex
	nextUserID atomic.Uint64

	// Legacy user mapping (uint64-based for backward compatibility)
	userGPU map[uint64]int

	// Per-GPU user counts
	usersPerGPU []atomic.Uint32

	// Statistics
	totalOps   atomic.Uint64
	totalUsers atomic.Uint64
	startTime  time.Time

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	closed atomic.Bool
}

// MultiGPUUser represents a user in the multi-GPU system
type MultiGPUUser struct {
	ID         string
	NumericID  uint64
	PrimaryGPU int
	BSKLoaded  atomic.Bool
	Created    time.Time
	LastActive time.Time

	// Keys (kept for lazy upload)
	bskData []byte
	kskData []byte
	keysMu  sync.Mutex
}

// NewMultiGPUEngine creates a new multi-GPU TFHE engine with full configuration
func NewMultiGPUEngine(cfg MultiGPUConfig) (*MultiGPUEngine, error) {
	// Initialize multi-GPU
	numGPUs := cfg.NumGPUs
	if numGPUs == 0 {
		numGPUs = 8 // Try up to 8
	}

	mgpu, err := mlx.InitMultiGPU(numGPUs)
	if err != nil {
		return nil, fmt.Errorf("multi-GPU init failed: %w", err)
	}

	numGPUs = mgpu.NumGPUs()
	if numGPUs == 0 {
		return nil, fmt.Errorf("no GPUs available")
	}

	// Enable P2P if requested and available
	if cfg.EnableP2P {
		if err := mgpu.EnablePeerAccess(); err != nil {
			fmt.Printf("Warning: P2P access not available: %v\n", err)
		}
	}

	mgpu.PrintTopology()

	ctx, cancel := context.WithCancel(context.Background())

	me := &MultiGPUEngine{
		cfg:         cfg,
		mgpu:        mgpu,
		numGPUs:     numGPUs,
		engines:     make([]*Engine, numGPUs),
		users:       make(map[string]*MultiGPUUser),
		userGPU:     make(map[uint64]int),
		usersPerGPU: make([]atomic.Uint32, numGPUs),
		startTime:   time.Now(),
		ctx:         ctx,
		cancel:      cancel,
	}

	// Initialize per-GPU engines
	for i := 0; i < numGPUs; i++ {
		mgpu.SetDevice(i)
		engine, err := New(cfg.TFHEConfig)
		if err != nil {
			me.Shutdown()
			return nil, fmt.Errorf("failed to init engine on GPU %d: %w", i, err)
		}
		me.engines[i] = engine
	}

	// Initialize BSK cache
	me.bskCache = NewBSKCache(mgpu, cfg.BSKCacheMemory)

	// Initialize scheduler
	schedCfg := cfg.Scheduler
	schedCfg.EnableStealing = cfg.EnableWorkStealing
	me.scheduler = NewScheduler(me.engines, mgpu, me.bskCache, schedCfg)

	fmt.Printf("Multi-GPU TFHE Engine ready with %d GPUs\n", numGPUs)
	fmt.Printf("  Total memory: %.1f GB\n", float64(mgpu.TotalMemory())/(1024*1024*1024))
	fmt.Printf("  Max users: %d\n", cfg.MaxUsersPerGPU*numGPUs)
	fmt.Printf("  P2P enabled: %v\n", cfg.EnableP2P)
	fmt.Printf("  Work stealing: %v\n", cfg.EnableWorkStealing)

	return me, nil
}

// NewMultiGPU creates a multi-GPU TFHE engine (backward compatible)
func NewMultiGPU(cfg Config) (*MultiGPUEngine, error) {
	mcfg := DefaultMultiGPUConfig()
	mcfg.TFHEConfig = cfg
	return NewMultiGPUEngine(mcfg)
}

// CreateUser creates a user on the least loaded GPU (legacy API with uint64 return)
func (me *MultiGPUEngine) CreateUser() (uint64, error) {
	// Find GPU with fewest users
	gpuID := me.findBestGPU()

	if int(me.usersPerGPU[gpuID].Load()) >= me.cfg.MaxUsersPerGPU {
		return 0, fmt.Errorf("all GPUs at max capacity (%d users each)", me.cfg.MaxUsersPerGPU)
	}

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
	me.totalUsers.Add(1)

	// Also register in string-based system
	strID := fmt.Sprintf("%d", userID)
	me.bskCache.PutLazy(strID, gpuID)

	return userID, nil
}

// CreateUserWithID creates a user with a string ID on the least loaded GPU
func (me *MultiGPUEngine) CreateUserWithID(userID string) error {
	me.usersMu.Lock()
	defer me.usersMu.Unlock()

	if _, exists := me.users[userID]; exists {
		return fmt.Errorf("user %s already exists", userID)
	}

	// Find GPU with fewest users
	gpuID := me.findBestGPU()

	if int(me.usersPerGPU[gpuID].Load()) >= me.cfg.MaxUsersPerGPU {
		return fmt.Errorf("all GPUs at max capacity (%d users each)", me.cfg.MaxUsersPerGPU)
	}

	user := &MultiGPUUser{
		ID:         userID,
		NumericID:  me.nextUserID.Add(1),
		PrimaryGPU: gpuID,
		Created:    time.Now(),
		LastActive: time.Now(),
	}

	me.users[userID] = user
	me.userGPU[user.NumericID] = gpuID
	me.usersPerGPU[gpuID].Add(1)
	me.totalUsers.Add(1)

	// Register lazy BSK slot
	me.bskCache.PutLazy(userID, gpuID)

	return nil
}

// CreateUserOnGPU creates a user on a specific GPU
func (me *MultiGPUEngine) CreateUserOnGPU(gpuID int) (uint64, error) {
	if gpuID < 0 || gpuID >= me.numGPUs {
		return 0, fmt.Errorf("invalid GPU ID %d", gpuID)
	}

	if int(me.usersPerGPU[gpuID].Load()) >= me.cfg.MaxUsersPerGPU {
		return 0, fmt.Errorf("GPU %d at max capacity", gpuID)
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
	me.totalUsers.Add(1)

	strID := fmt.Sprintf("%d", userID)
	me.bskCache.PutLazy(strID, gpuID)

	return userID, nil
}

// CreateUserWithIDOnGPU creates a user with a string ID on a specific GPU
func (me *MultiGPUEngine) CreateUserWithIDOnGPU(userID string, gpuID int) error {
	if gpuID < 0 || gpuID >= me.numGPUs {
		return fmt.Errorf("invalid GPU ID %d", gpuID)
	}

	me.usersMu.Lock()
	defer me.usersMu.Unlock()

	if _, exists := me.users[userID]; exists {
		return fmt.Errorf("user %s already exists", userID)
	}

	if int(me.usersPerGPU[gpuID].Load()) >= me.cfg.MaxUsersPerGPU {
		return fmt.Errorf("GPU %d at max capacity", gpuID)
	}

	user := &MultiGPUUser{
		ID:         userID,
		NumericID:  me.nextUserID.Add(1),
		PrimaryGPU: gpuID,
		Created:    time.Now(),
		LastActive: time.Now(),
	}

	me.users[userID] = user
	me.userGPU[user.NumericID] = gpuID
	me.usersPerGPU[gpuID].Add(1)
	me.totalUsers.Add(1)

	me.bskCache.PutLazy(userID, gpuID)

	return nil
}

// UploadBootstrapKey uploads a user's bootstrap and key-switching keys
func (me *MultiGPUEngine) UploadBootstrapKey(userID string, bsk *tfhe.BootstrapKey, ksk *tfhe.KeySwitchingKey) error {
	me.usersMu.RLock()
	user, ok := me.users[userID]
	me.usersMu.RUnlock()

	if !ok {
		return fmt.Errorf("user %s not found", userID)
	}

	// Serialize keys to bytes
	bskData := serializeBSK(bsk, me.cfg.TFHEConfig)
	kskData := serializeKSK(ksk, me.cfg.TFHEConfig)

	// Store for lazy loading
	user.keysMu.Lock()
	user.bskData = bskData
	user.kskData = kskData
	user.keysMu.Unlock()

	return nil
}

// UploadBootstrapKeyBytes uploads pre-serialized keys
func (me *MultiGPUEngine) UploadBootstrapKeyBytes(userID string, bskData, kskData []byte) error {
	me.usersMu.RLock()
	user, ok := me.users[userID]
	me.usersMu.RUnlock()

	if !ok {
		return fmt.Errorf("user %s not found", userID)
	}

	user.keysMu.Lock()
	user.bskData = bskData
	user.kskData = kskData
	user.keysMu.Unlock()

	return nil
}

// ForceUploadKeys immediately uploads keys to GPU (not lazy)
func (me *MultiGPUEngine) ForceUploadKeys(userID string) error {
	me.usersMu.RLock()
	user, ok := me.users[userID]
	me.usersMu.RUnlock()

	if !ok {
		return fmt.Errorf("user %s not found", userID)
	}

	if user.BSKLoaded.Load() {
		return nil // Already loaded
	}

	user.keysMu.Lock()
	bskData := user.bskData
	kskData := user.kskData
	user.keysMu.Unlock()

	if len(bskData) == 0 || len(kskData) == 0 {
		return fmt.Errorf("keys not provided for user %s", userID)
	}

	if err := me.bskCache.UploadKeys(userID, bskData, kskData); err != nil {
		return err
	}

	user.BSKLoaded.Store(true)
	return nil
}

// ensureBSKLoaded ensures a user's BSK is on GPU before operation
func (me *MultiGPUEngine) ensureBSKLoaded(user *MultiGPUUser) error {
	if user.BSKLoaded.Load() {
		return nil
	}

	user.keysMu.Lock()
	bskData := user.bskData
	kskData := user.kskData
	user.keysMu.Unlock()

	if len(bskData) == 0 || len(kskData) == 0 {
		return fmt.Errorf("keys not provided for user %s", user.ID)
	}

	if err := me.bskCache.UploadKeys(user.ID, bskData, kskData); err != nil {
		return err
	}

	user.BSKLoaded.Store(true)
	return nil
}

// DeleteUser removes a user (legacy API with uint64)
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

		strID := fmt.Sprintf("%d", userID)
		me.bskCache.Remove(strID)
		me.scheduler.ClearUserAffinity(strID)
	}
}

// DeleteUserByID removes a user by string ID
func (me *MultiGPUEngine) DeleteUserByID(userID string) {
	me.usersMu.Lock()
	user, ok := me.users[userID]
	if ok {
		delete(me.users, userID)
		delete(me.userGPU, user.NumericID)
		me.usersPerGPU[user.PrimaryGPU].Add(^uint32(0)) // Decrement
	}
	me.usersMu.Unlock()

	if ok {
		me.bskCache.Remove(userID)
		me.scheduler.ClearUserAffinity(userID)
	}
}

// Submit queues an operation for async execution
func (me *MultiGPUEngine) Submit(userID string, gate GateType, input1, input2, output []uint32) (*Future, error) {
	if me.closed.Load() {
		return nil, fmt.Errorf("engine is closed")
	}

	me.usersMu.RLock()
	user, ok := me.users[userID]
	me.usersMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("user %s not found", userID)
	}

	// Ensure BSK is loaded (lazy loading)
	if err := me.ensureBSKLoaded(user); err != nil {
		return nil, err
	}

	user.LastActive = time.Now()
	me.totalOps.Add(1)

	return me.scheduler.Submit(userID, gate, input1, input2, output)
}

// SubmitBatch queues multiple operations
func (me *MultiGPUEngine) SubmitBatch(ops []UserOperation) ([]*Future, error) {
	if me.closed.Load() {
		return nil, fmt.Errorf("engine is closed")
	}

	// Ensure all users' BSKs are loaded
	me.usersMu.RLock()
	for _, op := range ops {
		if user, ok := me.users[op.UserID]; ok {
			if err := me.ensureBSKLoaded(user); err != nil {
				me.usersMu.RUnlock()
				return nil, err
			}
			user.LastActive = time.Now()
		}
	}
	me.usersMu.RUnlock()

	// Convert to scheduler operations
	schedOps := make([]Operation, len(ops))
	for i, op := range ops {
		schedOps[i] = Operation{
			UserID:        op.UserID,
			Gate:          op.Gate,
			Input1Indices: op.Input1,
			Input2Indices: op.Input2,
			OutputIndices: op.Output,
		}
	}

	me.totalOps.Add(uint64(len(ops)))
	return me.scheduler.SubmitBatch(schedOps)
}

// UserOperation represents a user's gate operation
type UserOperation struct {
	UserID string
	Gate   GateType
	Input1 []uint32
	Input2 []uint32
	Output []uint32
}

// ExecuteBatchGates executes operations synchronously (blocking) - backward compatible
func (me *MultiGPUEngine) ExecuteBatchGates(ops []BatchGateOp) error {
	if me.closed.Load() {
		return fmt.Errorf("engine is closed")
	}

	// Group operations by GPU based on user affinity
	gpuOps := make([][]BatchGateOp, me.numGPUs)
	for i := range gpuOps {
		gpuOps[i] = make([]BatchGateOp, 0)
	}

	me.usersMu.RLock()
	for _, op := range ops {
		// Split by user's GPU
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
	errChan := make(chan error, me.numGPUs)

	for gpuID := 0; gpuID < me.numGPUs; gpuID++ {
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

	for err := range errChan {
		return err
	}

	return nil
}

// SyncAll waits for all GPUs to complete
func (me *MultiGPUEngine) SyncAll() {
	me.mgpu.SyncAll()
}

// GetUserGPU returns which GPU a user is on (legacy API)
func (me *MultiGPUEngine) GetUserGPU(userID uint64) int {
	me.usersMu.RLock()
	defer me.usersMu.RUnlock()
	return me.userGPU[userID]
}

// GetUserGPUByID returns which GPU a user is on by string ID
func (me *MultiGPUEngine) GetUserGPUByID(userID string) int {
	me.usersMu.RLock()
	defer me.usersMu.RUnlock()
	if user, ok := me.users[userID]; ok {
		return user.PrimaryGPU
	}
	return -1
}

// MigrateUser moves a user to a different GPU
func (me *MultiGPUEngine) MigrateUser(userID string, targetGPU int) error {
	if targetGPU < 0 || targetGPU >= me.numGPUs {
		return fmt.Errorf("invalid GPU ID %d", targetGPU)
	}

	me.usersMu.Lock()
	user, ok := me.users[userID]
	if !ok {
		me.usersMu.Unlock()
		return fmt.Errorf("user %s not found", userID)
	}

	oldGPU := user.PrimaryGPU
	if oldGPU == targetGPU {
		me.usersMu.Unlock()
		return nil // Already on target GPU
	}

	me.usersPerGPU[oldGPU].Add(^uint32(0)) // Decrement
	me.usersPerGPU[targetGPU].Add(1)
	user.PrimaryGPU = targetGPU
	me.userGPU[user.NumericID] = targetGPU
	me.usersMu.Unlock()

	// Update scheduler affinity
	me.scheduler.SetUserAffinity(userID, targetGPU)

	return nil
}

// findBestGPU returns the GPU with fewest users
func (me *MultiGPUEngine) findBestGPU() int {
	best := 0
	minUsers := me.usersPerGPU[0].Load()

	for i := 1; i < me.numGPUs; i++ {
		users := me.usersPerGPU[i].Load()
		if users < minUsers {
			minUsers = users
			best = i
		}
	}

	return best
}

// NumGPUs returns the number of GPUs
func (me *MultiGPUEngine) NumGPUs() int {
	return me.numGPUs
}

// MultiGPUStats contains multi-GPU engine statistics
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

// GetStats returns current statistics
func (me *MultiGPUEngine) GetStats() MultiGPUStats {
	stats := MultiGPUStats{
		NumGPUs:     me.numGPUs,
		TotalMemory: me.mgpu.TotalMemory(),
		FreeMemory:  me.mgpu.TotalFreeMemory(),
		UsersPerGPU: make([]int, me.numGPUs),
		TotalOps:    me.totalOps.Load(),
		P2PEnabled:  me.cfg.EnableP2P,
		Uptime:      time.Since(me.startTime),
	}

	me.usersMu.RLock()
	stats.TotalUsers = len(me.users) + len(me.userGPU) // Both APIs
	me.usersMu.RUnlock()

	for i := 0; i < me.numGPUs; i++ {
		stats.UsersPerGPU[i] = int(me.usersPerGPU[i].Load())
	}

	// Check if any NVLink
	if me.numGPUs > 1 {
		stats.HasNVLink = me.mgpu.HasNVLink(0, 1)
	}

	if me.bskCache != nil {
		stats.BSKCacheStats = me.bskCache.Stats()
	}
	if me.scheduler != nil {
		stats.SchedulerStats = me.scheduler.Stats()
	}

	return stats
}

// Shutdown cleans up all resources
func (me *MultiGPUEngine) Shutdown() {
	if me.closed.Swap(true) {
		return // Already closed
	}

	if me.cancel != nil {
		me.cancel()
	}

	// Close scheduler first (drains pending operations)
	if me.scheduler != nil {
		me.scheduler.Close()
	}

	// Remove all users
	me.usersMu.Lock()
	for userID := range me.users {
		if me.bskCache != nil {
			me.bskCache.Remove(userID)
		}
	}
	me.users = make(map[string]*MultiGPUUser)
	me.userGPU = make(map[uint64]int)
	me.usersMu.Unlock()

	// Shutdown multi-GPU
	if me.mgpu != nil {
		me.mgpu.Shutdown()
	}
}

// serializeBSK converts a BootstrapKey to bytes for GPU upload
func serializeBSK(bsk *tfhe.BootstrapKey, cfg Config) []byte {
	if bsk == nil {
		return nil
	}
	// Shape: [n, 2, L, 2, N]
	n := cfg.n
	L := cfg.L
	N := cfg.N
	size := int(n) * 2 * int(L) * 2 * int(N) * 8

	data := make([]byte, size)
	// Copy BSK data from the blindrot evaluation key
	// The BSK contains n RGSW ciphertexts, each with L decomposition levels
	// Each RGSW has 2 RLWE ciphertexts (rows), each with 2 polynomials of N coefficients
	if bsk.BRK != nil {
		offset := 0
		for _, rgsw := range bsk.BRK.Value {
			for _, gadgetCt := range rgsw.Value {
				for _, poly := range gadgetCt.Value {
					for _, coeff := range poly.Coeffs[0] {
						if offset+8 <= len(data) {
							data[offset] = byte(coeff)
							data[offset+1] = byte(coeff >> 8)
							data[offset+2] = byte(coeff >> 16)
							data[offset+3] = byte(coeff >> 24)
							data[offset+4] = byte(coeff >> 32)
							data[offset+5] = byte(coeff >> 40)
							data[offset+6] = byte(coeff >> 48)
							data[offset+7] = byte(coeff >> 56)
							offset += 8
						}
					}
				}
			}
		}
	}
	return data
}

// serializeKSK converts a KeySwitchingKey to bytes for GPU upload
func serializeKSK(ksk *tfhe.KeySwitchingKey, cfg Config) []byte {
	if ksk == nil {
		return nil
	}
	// Shape: [N, L_ks, n]
	N := cfg.N
	Lks := uint32(3) // Typical KS decomposition level
	n := cfg.n
	size := int(N) * int(Lks) * int(n) * 8

	data := make([]byte, size)
	// Copy KSK data from the evaluation key
	// The KSK contains decomposition levels of RLWE ciphertexts
	if ksk.KSK != nil && len(ksk.KSK.Value) > 0 {
		offset := 0
		for _, gadgetCt := range ksk.KSK.Value {
			for _, poly := range gadgetCt.Value {
				for _, coeff := range poly.Coeffs[0] {
					if offset+8 <= len(data) {
						data[offset] = byte(coeff)
						data[offset+1] = byte(coeff >> 8)
						data[offset+2] = byte(coeff >> 16)
						data[offset+3] = byte(coeff >> 24)
						data[offset+4] = byte(coeff >> 32)
						data[offset+5] = byte(coeff >> 40)
						data[offset+6] = byte(coeff >> 48)
						data[offset+7] = byte(coeff >> 56)
						offset += 8
					}
				}
			}
		}
	}
	return data
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
