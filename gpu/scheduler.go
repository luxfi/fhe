//go:build (linux || windows) && cgo && cuda

// Package gpu provides multi-GPU TFHE operations
package gpu

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luxfi/mlx"
)

// Scheduler errors
var (
	ErrSchedulerClosed  = errors.New("scheduler is closed")
	ErrQueueFull        = errors.New("operation queue is full")
	ErrUserNotFound     = errors.New("user not found")
	ErrOperationTimeout = errors.New("operation timed out")
)

// Operation represents a TFHE operation to be scheduled
type Operation struct {
	// Operation identity
	ID     uint64
	UserID string

	// Gate operation details
	Gate          GateType
	Input1Indices []uint32
	Input2Indices []uint32
	OutputIndices []uint32

	// Scheduling metadata
	SubmitTime time.Time
	Priority   int // Higher = more urgent

	// Result handling
	future *Future
}

// Future represents a pending operation result
type Future struct {
	done   chan struct{}
	result []byte
	err    error
	mu     sync.Mutex
}

// Wait blocks until the operation completes and returns the result
func (f *Future) Wait() ([]byte, error) {
	<-f.done
	return f.result, f.err
}

// WaitContext blocks until completion or context cancellation
func (f *Future) WaitContext(ctx context.Context) ([]byte, error) {
	select {
	case <-f.done:
		return f.result, f.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Ready returns true if the operation has completed
func (f *Future) Ready() bool {
	select {
	case <-f.done:
		return true
	default:
		return false
	}
}

// complete marks the future as done with result
func (f *Future) complete(result []byte, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	select {
	case <-f.done:
		return // Already completed
	default:
		f.result = result
		f.err = err
		close(f.done)
	}
}

// Batch represents a group of operations to execute together
type Batch struct {
	Gate       GateType
	Operations []*Operation
	UserIDs    []string
}

// Scheduler manages operation distribution across GPUs
type Scheduler struct {
	engines  []*Engine
	mgpu     *mlx.MultiGPU
	bskCache *BSKCache
	numGPUs  int

	// Per-GPU work queues
	queues []chan *Operation

	// User affinity tracking
	userAffinity map[string]int
	affinityMu   sync.RWMutex

	// Load tracking per GPU
	loads        []atomic.Int64
	pendingOps   []atomic.Int64
	completedOps []atomic.Uint64

	// Batch aggregation
	batchSize    int
	batchTimeout time.Duration
	batchBuffers []map[GateType][]*Operation
	batchMu      []sync.Mutex

	// Work stealing
	stealThreshold int64 // Steal if load difference > threshold
	stealEnabled   bool

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	closed atomic.Bool

	// Statistics
	totalSubmitted atomic.Uint64
	totalCompleted atomic.Uint64
	totalStolen    atomic.Uint64
	totalBatched   atomic.Uint64

	// Operation ID generator
	nextOpID atomic.Uint64
}

// SchedulerConfig configures the scheduler
type SchedulerConfig struct {
	QueueSize      int           // Per-GPU queue size (default: 10000)
	BatchSize      int           // Operations per batch (default: 256)
	BatchTimeout   time.Duration // Max wait for batch fill (default: 1ms)
	StealThreshold int64         // Load difference to trigger stealing (default: 100)
	EnableStealing bool          // Enable work stealing (default: true)
}

// DefaultSchedulerConfig returns sensible defaults
func DefaultSchedulerConfig() SchedulerConfig {
	return SchedulerConfig{
		QueueSize:      10000,
		BatchSize:      256,
		BatchTimeout:   time.Millisecond,
		StealThreshold: 100,
		EnableStealing: true,
	}
}

// NewScheduler creates a new multi-GPU scheduler
func NewScheduler(engines []*Engine, mgpu *mlx.MultiGPU, bskCache *BSKCache, cfg SchedulerConfig) *Scheduler {
	numGPUs := len(engines)
	ctx, cancel := context.WithCancel(context.Background())

	s := &Scheduler{
		engines:        engines,
		mgpu:           mgpu,
		bskCache:       bskCache,
		numGPUs:        numGPUs,
		queues:         make([]chan *Operation, numGPUs),
		userAffinity:   make(map[string]int),
		loads:          make([]atomic.Int64, numGPUs),
		pendingOps:     make([]atomic.Int64, numGPUs),
		completedOps:   make([]atomic.Uint64, numGPUs),
		batchSize:      cfg.BatchSize,
		batchTimeout:   cfg.BatchTimeout,
		batchBuffers:   make([]map[GateType][]*Operation, numGPUs),
		batchMu:        make([]sync.Mutex, numGPUs),
		stealThreshold: cfg.StealThreshold,
		stealEnabled:   cfg.EnableStealing,
		ctx:            ctx,
		cancel:         cancel,
	}

	// Initialize queues and batch buffers
	for i := 0; i < numGPUs; i++ {
		s.queues[i] = make(chan *Operation, cfg.QueueSize)
		s.batchBuffers[i] = make(map[GateType][]*Operation)
	}

	// Start worker goroutines
	for i := 0; i < numGPUs; i++ {
		s.wg.Add(1)
		go s.worker(i)
	}

	// Start work stealer if enabled
	if cfg.EnableStealing {
		s.wg.Add(1)
		go s.workStealer()
	}

	// Start batch flusher
	s.wg.Add(1)
	go s.batchFlusher()

	return s
}

// Submit queues an operation for execution
func (s *Scheduler) Submit(userID string, gate GateType, input1, input2, output []uint32) (*Future, error) {
	if s.closed.Load() {
		return nil, ErrSchedulerClosed
	}

	op := &Operation{
		ID:            s.nextOpID.Add(1),
		UserID:        userID,
		Gate:          gate,
		Input1Indices: input1,
		Input2Indices: input2,
		OutputIndices: output,
		SubmitTime:    time.Now(),
		future:        &Future{done: make(chan struct{})},
	}

	gpuIdx := s.selectGPU(userID)

	// Try to add to batch buffer first
	s.batchMu[gpuIdx].Lock()
	s.batchBuffers[gpuIdx][gate] = append(s.batchBuffers[gpuIdx][gate], op)
	batchReady := len(s.batchBuffers[gpuIdx][gate]) >= s.batchSize
	s.batchMu[gpuIdx].Unlock()

	s.pendingOps[gpuIdx].Add(1)
	s.totalSubmitted.Add(1)

	// If batch is ready, flush it
	if batchReady {
		s.flushBatch(gpuIdx, gate)
	}

	return op.future, nil
}

// SubmitBatch queues multiple operations
func (s *Scheduler) SubmitBatch(ops []Operation) ([]*Future, error) {
	if s.closed.Load() {
		return nil, ErrSchedulerClosed
	}

	futures := make([]*Future, len(ops))
	for i := range ops {
		ops[i].ID = s.nextOpID.Add(1)
		ops[i].SubmitTime = time.Now()
		ops[i].future = &Future{done: make(chan struct{})}
		futures[i] = ops[i].future

		gpuIdx := s.selectGPU(ops[i].UserID)

		s.batchMu[gpuIdx].Lock()
		s.batchBuffers[gpuIdx][ops[i].Gate] = append(s.batchBuffers[gpuIdx][ops[i].Gate], &ops[i])
		s.batchMu[gpuIdx].Unlock()

		s.pendingOps[gpuIdx].Add(1)
	}

	s.totalSubmitted.Add(uint64(len(ops)))
	return futures, nil
}

// selectGPU chooses the best GPU for a user's operation
func (s *Scheduler) selectGPU(userID string) int {
	// Check existing affinity
	s.affinityMu.RLock()
	if idx, ok := s.userAffinity[userID]; ok {
		s.affinityMu.RUnlock()
		return idx
	}
	s.affinityMu.RUnlock()

	// Check BSK cache for existing location
	if loc, err := s.bskCache.Get(userID, 0); err == nil {
		s.affinityMu.Lock()
		s.userAffinity[userID] = loc.PrimaryGPU
		s.affinityMu.Unlock()
		s.bskCache.Release(userID)
		return loc.PrimaryGPU
	}

	// Find least loaded GPU
	minLoad := s.loads[0].Load()
	minIdx := 0
	for i := 1; i < s.numGPUs; i++ {
		if load := s.loads[i].Load(); load < minLoad {
			minLoad = load
			minIdx = i
		}
	}

	// Set affinity
	s.affinityMu.Lock()
	s.userAffinity[userID] = minIdx
	s.affinityMu.Unlock()

	return minIdx
}

// SetUserAffinity explicitly sets which GPU a user should use
func (s *Scheduler) SetUserAffinity(userID string, gpuIdx int) error {
	if gpuIdx < 0 || gpuIdx >= s.numGPUs {
		return fmt.Errorf("invalid GPU index %d", gpuIdx)
	}

	s.affinityMu.Lock()
	s.userAffinity[userID] = gpuIdx
	s.affinityMu.Unlock()
	return nil
}

// ClearUserAffinity removes a user's GPU affinity
func (s *Scheduler) ClearUserAffinity(userID string) {
	s.affinityMu.Lock()
	delete(s.userAffinity, userID)
	s.affinityMu.Unlock()
}

// flushBatch sends a batch of operations to the queue
func (s *Scheduler) flushBatch(gpuIdx int, gate GateType) {
	s.batchMu[gpuIdx].Lock()
	ops := s.batchBuffers[gpuIdx][gate]
	if len(ops) == 0 {
		s.batchMu[gpuIdx].Unlock()
		return
	}
	s.batchBuffers[gpuIdx][gate] = nil
	s.batchMu[gpuIdx].Unlock()

	// Send to queue
	for _, op := range ops {
		select {
		case s.queues[gpuIdx] <- op:
			s.loads[gpuIdx].Add(1)
		default:
			// Queue full - complete with error
			op.future.complete(nil, ErrQueueFull)
			s.pendingOps[gpuIdx].Add(-1)
		}
	}

	s.totalBatched.Add(uint64(len(ops)))
}

// worker processes operations for a single GPU
func (s *Scheduler) worker(gpuIdx int) {
	defer s.wg.Done()

	// Pin to GPU
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	s.mgpu.SetDevice(gpuIdx)

	engine := s.engines[gpuIdx]
	batch := make([]*Operation, 0, s.batchSize)

	for {
		select {
		case <-s.ctx.Done():
			// Drain remaining operations
			for len(s.queues[gpuIdx]) > 0 {
				op := <-s.queues[gpuIdx]
				op.future.complete(nil, ErrSchedulerClosed)
			}
			return

		case op := <-s.queues[gpuIdx]:
			batch = append(batch, op)

			// Try to collect more of same gate type
			deadline := time.Now().Add(s.batchTimeout)
		collectLoop:
			for len(batch) < s.batchSize {
				select {
				case nextOp := <-s.queues[gpuIdx]:
					if nextOp.Gate == op.Gate {
						batch = append(batch, nextOp)
					} else {
						// Different gate type - process separately
						s.processOperation(engine, gpuIdx, nextOp)
					}
				default:
					if time.Now().After(deadline) {
						break collectLoop
					}
					runtime.Gosched()
				}
			}

			// Process batch
			s.processBatch(engine, gpuIdx, batch)
			batch = batch[:0]
		}
	}
}

// processBatch executes a batch of same-gate operations
func (s *Scheduler) processBatch(engine *Engine, gpuIdx int, ops []*Operation) {
	if len(ops) == 0 {
		return
	}

	// Group by user for BSK access
	userOps := make(map[string][]*Operation)
	for _, op := range ops {
		userOps[op.UserID] = append(userOps[op.UserID], op)
	}

	// Process each user's operations
	for userID, uops := range userOps {
		// Ensure BSK is accessible
		_, err := s.bskCache.Get(userID, gpuIdx)
		if err != nil {
			for _, op := range uops {
				op.future.complete(nil, err)
				s.pendingOps[gpuIdx].Add(-1)
				s.loads[gpuIdx].Add(-1)
			}
			continue
		}

		// Build batch operation
		batchOp := BatchGateOp{
			Gate:          uops[0].Gate,
			UserIDs:       make([]uint64, len(uops)),
			Input1Indices: make([]uint32, 0, len(uops)*len(uops[0].Input1Indices)),
			Input2Indices: make([]uint32, 0, len(uops)*len(uops[0].Input2Indices)),
			OutputIndices: make([]uint32, 0, len(uops)*len(uops[0].OutputIndices)),
		}

		// Get user ID from cache (numeric)
		for i, op := range uops {
			// Use operation ID as proxy for user numeric ID
			// In real impl, would lookup from user registry
			batchOp.UserIDs[i] = op.ID
			batchOp.Input1Indices = append(batchOp.Input1Indices, op.Input1Indices...)
			batchOp.Input2Indices = append(batchOp.Input2Indices, op.Input2Indices...)
			batchOp.OutputIndices = append(batchOp.OutputIndices, op.OutputIndices...)
		}

		// Execute batch
		err = engine.ExecuteBatchGates([]BatchGateOp{batchOp})

		// Complete futures
		for _, op := range uops {
			if err != nil {
				op.future.complete(nil, err)
			} else {
				op.future.complete(nil, nil) // Result in GPU memory
			}
			s.pendingOps[gpuIdx].Add(-1)
			s.loads[gpuIdx].Add(-1)
			s.completedOps[gpuIdx].Add(1)
		}

		s.bskCache.Release(userID)
	}

	s.totalCompleted.Add(uint64(len(ops)))
}

// processOperation executes a single operation
func (s *Scheduler) processOperation(engine *Engine, gpuIdx int, op *Operation) {
	// Ensure BSK is accessible
	_, err := s.bskCache.Get(op.UserID, gpuIdx)
	if err != nil {
		op.future.complete(nil, err)
		s.pendingOps[gpuIdx].Add(-1)
		s.loads[gpuIdx].Add(-1)
		return
	}

	batchOp := BatchGateOp{
		Gate:          op.Gate,
		UserIDs:       []uint64{op.ID},
		Input1Indices: op.Input1Indices,
		Input2Indices: op.Input2Indices,
		OutputIndices: op.OutputIndices,
	}

	err = engine.ExecuteBatchGates([]BatchGateOp{batchOp})
	if err != nil {
		op.future.complete(nil, err)
	} else {
		op.future.complete(nil, nil)
	}

	s.pendingOps[gpuIdx].Add(-1)
	s.loads[gpuIdx].Add(-1)
	s.completedOps[gpuIdx].Add(1)
	s.totalCompleted.Add(1)
	s.bskCache.Release(op.UserID)
}

// workStealer monitors load and steals work from overloaded GPUs
func (s *Scheduler) workStealer() {
	defer s.wg.Done()

	ticker := time.NewTicker(100 * time.Microsecond)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.trySteal()
		}
	}
}

// trySteal attempts to steal work from overloaded GPUs
func (s *Scheduler) trySteal() {
	// Find most and least loaded GPUs
	maxLoad := s.loads[0].Load()
	maxIdx := 0
	minLoad := s.loads[0].Load()
	minIdx := 0

	for i := 1; i < s.numGPUs; i++ {
		load := s.loads[i].Load()
		if load > maxLoad {
			maxLoad = load
			maxIdx = i
		}
		if load < minLoad {
			minLoad = load
			minIdx = i
		}
	}

	// Check if stealing would help
	if maxLoad-minLoad < s.stealThreshold {
		return
	}

	// Try to steal operations
	stolen := 0
	for stolen < int(s.stealThreshold/2) {
		select {
		case op := <-s.queues[maxIdx]:
			// Check if user's BSK is accessible from target GPU
			if s.bskCache.HasP2PAccess(minIdx, maxIdx) {
				// Can use P2P - steal the operation
				s.queues[minIdx] <- op
				s.loads[maxIdx].Add(-1)
				s.loads[minIdx].Add(1)

				// Update affinity
				s.affinityMu.Lock()
				s.userAffinity[op.UserID] = minIdx
				s.affinityMu.Unlock()

				stolen++
				s.totalStolen.Add(1)
			} else {
				// Put back - can't efficiently steal without P2P
				s.queues[maxIdx] <- op
				return
			}
		default:
			return
		}
	}
}

// batchFlusher periodically flushes incomplete batches
func (s *Scheduler) batchFlusher() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.batchTimeout * 2)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			for gpuIdx := 0; gpuIdx < s.numGPUs; gpuIdx++ {
				s.batchMu[gpuIdx].Lock()
				for gate, ops := range s.batchBuffers[gpuIdx] {
					if len(ops) > 0 {
						// Flush even incomplete batches
						s.batchBuffers[gpuIdx][gate] = nil
						s.batchMu[gpuIdx].Unlock()

						for _, op := range ops {
							select {
							case s.queues[gpuIdx] <- op:
								s.loads[gpuIdx].Add(1)
							default:
								op.future.complete(nil, ErrQueueFull)
								s.pendingOps[gpuIdx].Add(-1)
							}
						}

						s.batchMu[gpuIdx].Lock()
					}
				}
				s.batchMu[gpuIdx].Unlock()
			}
		}
	}
}

// Close shuts down the scheduler
func (s *Scheduler) Close() error {
	if s.closed.Swap(true) {
		return nil // Already closed
	}

	s.cancel()
	s.wg.Wait()
	return nil
}

// SchedulerStats contains scheduler statistics
type SchedulerStats struct {
	TotalSubmitted   uint64
	TotalCompleted   uint64
	TotalStolen      uint64
	TotalBatched     uint64
	PendingPerGPU    []int64
	CompletedPerGPU  []uint64
	LoadPerGPU       []int64
	QueueLengthsGPU  []int
	UserAffinitySize int
}

// Stats returns scheduler statistics
func (s *Scheduler) Stats() SchedulerStats {
	stats := SchedulerStats{
		TotalSubmitted:  s.totalSubmitted.Load(),
		TotalCompleted:  s.totalCompleted.Load(),
		TotalStolen:     s.totalStolen.Load(),
		TotalBatched:    s.totalBatched.Load(),
		PendingPerGPU:   make([]int64, s.numGPUs),
		CompletedPerGPU: make([]uint64, s.numGPUs),
		LoadPerGPU:      make([]int64, s.numGPUs),
		QueueLengthsGPU: make([]int, s.numGPUs),
	}

	for i := 0; i < s.numGPUs; i++ {
		stats.PendingPerGPU[i] = s.pendingOps[i].Load()
		stats.CompletedPerGPU[i] = s.completedOps[i].Load()
		stats.LoadPerGPU[i] = s.loads[i].Load()
		stats.QueueLengthsGPU[i] = len(s.queues[i])
	}

	s.affinityMu.RLock()
	stats.UserAffinitySize = len(s.userAffinity)
	s.affinityMu.RUnlock()

	return stats
}
