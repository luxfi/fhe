//go:build !(linux && cgo && cuda) && !(windows && cgo && cuda)

// Package gpu provides multi-GPU TFHE operations
// This is a stub for platforms without CUDA support
package gpu

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// BSK size constants
const (
	BSKSizeBytes = 134217728
	KSKSizeBytes = 12582912
	TotalKeySize = BSKSizeBytes + KSKSizeBytes
)

var (
	ErrBSKNotFound   = errors.New("bootstrap key not found in cache")
	ErrCacheFull     = errors.New("BSK cache is full and cannot evict")
	ErrGPUMemoryFull = errors.New("GPU memory exhausted")
)

// BSKLocation tracks where a user's BSK is stored
type BSKLocation struct {
	UserID     string
	PrimaryGPU int
	Replicas   map[int]struct{}
	GPUPtr     []unsafe.Pointer
	KSKPtr     []unsafe.Pointer
	LastUsed   time.Time
	RefCount   atomic.Int32
	Size       int64
}

// BSKCache stub for non-CUDA platforms
type BSKCache struct {
	mu    sync.RWMutex
	cache map[string]*BSKLocation
}

// BSKCacheStats contains cache statistics
type BSKCacheStats struct {
	TotalUsers     int
	Hits           uint64
	Misses         uint64
	Evictions      uint64
	P2PReads       uint64
	Replicas       uint64
	MemoryPerGPU   []int64
	MemLimitPerGPU []int64
}

// NewBSKCache returns nil on non-CUDA platforms
func NewBSKCache(mgpu interface{}, memLimitPerGPU int64) *BSKCache {
	return &BSKCache{
		cache: make(map[string]*BSKLocation),
	}
}

func (c *BSKCache) Get(userID string, requestingGPU int) (*BSKLocation, error) {
	return nil, ErrNoCUDA
}

func (c *BSKCache) Put(userID string, gpuID int, bskData, kskData []byte) (*BSKLocation, error) {
	return nil, ErrNoCUDA
}

func (c *BSKCache) PutLazy(userID string, gpuID int) *BSKLocation {
	return &BSKLocation{UserID: userID, PrimaryGPU: gpuID}
}

func (c *BSKCache) UploadKeys(userID string, bskData, kskData []byte) error {
	return ErrNoCUDA
}

func (c *BSKCache) Remove(userID string) {}

func (c *BSKCache) Release(userID string) {}

func (c *BSKCache) GetBSKPointer(userID string, gpuID int) (unsafe.Pointer, error) {
	return nil, ErrNoCUDA
}

func (c *BSKCache) GetKSKPointer(userID string, gpuID int) (unsafe.Pointer, error) {
	return nil, ErrNoCUDA
}

func (c *BSKCache) Stats() BSKCacheStats {
	return BSKCacheStats{}
}

func (c *BSKCache) HasP2PAccess(gpu1, gpu2 int) bool {
	return false
}
