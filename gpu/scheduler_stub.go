//go:build !(linux && cgo && cuda) && !(windows && cgo && cuda)

// Package gpu provides multi-GPU TFHE operations
// This is a stub for platforms without CUDA support
package gpu

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	ErrSchedulerClosed  = errors.New("scheduler is closed")
	ErrQueueFull        = errors.New("operation queue is full")
	ErrUserNotFound     = errors.New("user not found")
	ErrOperationTimeout = errors.New("operation timed out")
)

// Operation represents a TFHE operation to be scheduled
type Operation struct {
	ID            uint64
	UserID        string
	Gate          GateType
	Input1Indices []uint32
	Input2Indices []uint32
	OutputIndices []uint32
	SubmitTime    time.Time
	Priority      int
	future        *Future
}

// Future represents a pending operation result
type Future struct {
	done   chan struct{}
	result []byte
	err    error
	mu     sync.Mutex
}

func (f *Future) Wait() ([]byte, error) {
	<-f.done
	return f.result, f.err
}

func (f *Future) WaitContext(ctx context.Context) ([]byte, error) {
	select {
	case <-f.done:
		return f.result, f.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (f *Future) Ready() bool {
	select {
	case <-f.done:
		return true
	default:
		return false
	}
}

func (f *Future) complete(result []byte, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	select {
	case <-f.done:
		return
	default:
		f.result = result
		f.err = err
		close(f.done)
	}
}

// Batch represents a group of operations
type Batch struct {
	Gate       GateType
	Operations []*Operation
	UserIDs    []string
}

// Scheduler stub for non-CUDA platforms
type Scheduler struct{}

// SchedulerConfig configures the scheduler
type SchedulerConfig struct {
	QueueSize      int
	BatchSize      int
	BatchTimeout   time.Duration
	StealThreshold int64
	EnableStealing bool
}

func DefaultSchedulerConfig() SchedulerConfig {
	return SchedulerConfig{
		QueueSize:      10000,
		BatchSize:      256,
		BatchTimeout:   time.Millisecond,
		StealThreshold: 100,
		EnableStealing: true,
	}
}

func NewScheduler(engines []*Engine, mgpu interface{}, bskCache *BSKCache, cfg SchedulerConfig) *Scheduler {
	return &Scheduler{}
}

func (s *Scheduler) Submit(userID string, gate GateType, input1, input2, output []uint32) (*Future, error) {
	return nil, ErrNoCUDA
}

func (s *Scheduler) SubmitBatch(ops []Operation) ([]*Future, error) {
	return nil, ErrNoCUDA
}

func (s *Scheduler) SetUserAffinity(userID string, gpuIdx int) error {
	return ErrNoCUDA
}

func (s *Scheduler) ClearUserAffinity(userID string) {}

func (s *Scheduler) Close() error {
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

func (s *Scheduler) Stats() SchedulerStats {
	return SchedulerStats{}
}
