//go:build (linux || windows) && cgo && cuda

// Package gpu provides multi-GPU TFHE operations
package gpu

import (
	"container/heap"
	"errors"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/luxfi/mlx"
)

// BSK size constants
const (
	// BSKSizeBytes is the size of a bootstrap key in bytes
	// n=512, L=4, N=1024, 2 components, 2 polynomials, 8 bytes per element
	// 512 * 2 * 4 * 2 * 1024 * 8 = 134,217,728 bytes (128 MB)
	BSKSizeBytes = 134217728

	// KSKSizeBytes is the size of a key switching key in bytes
	// N=1024, L_ks=3, n=512, 8 bytes per element
	// 1024 * 3 * 512 * 8 = 12,582,912 bytes (12 MB)
	KSKSizeBytes = 12582912

	// TotalKeySize is combined BSK + KSK size
	TotalKeySize = BSKSizeBytes + KSKSizeBytes
)

var (
	// ErrBSKNotFound is returned when a bootstrap key is not in cache
	ErrBSKNotFound = errors.New("bootstrap key not found in cache")

	// ErrCacheFull is returned when cache cannot accommodate new entry
	ErrCacheFull = errors.New("BSK cache is full and cannot evict")

	// ErrGPUMemoryFull is returned when GPU memory is exhausted
	ErrGPUMemoryFull = errors.New("GPU memory exhausted")
)

// BSKLocation tracks where a user's BSK is stored
type BSKLocation struct {
	UserID     string
	PrimaryGPU int              // GPU where BSK is authoritative
	Replicas   map[int]struct{} // Other GPUs with copies (for non-NVLink)
	GPUPtr     []unsafe.Pointer // Per-GPU pointers (nil if not present)
	KSKPtr     []unsafe.Pointer // Per-GPU KSK pointers
	LastUsed   time.Time
	RefCount   atomic.Int32 // Active operations using this BSK
	Size       int64
}

// BSKCache manages bootstrap keys across multiple GPUs
type BSKCache struct {
	mu      sync.RWMutex
	cache   map[string]*BSKLocation
	mgpu    *mlx.MultiGPU
	numGPUs int

	// Memory tracking per GPU
	gpuMemUsed  []atomic.Int64
	gpuMemLimit []int64

	// LRU eviction
	lruHeap  *bskLRUHeap
	lruIndex map[string]*bskLRUEntry

	// P2P access enabled (NVLink)
	peerAccess [][]bool

	// Statistics
	hits      atomic.Uint64
	misses    atomic.Uint64
	evictions atomic.Uint64
	p2pReads  atomic.Uint64
	replicas  atomic.Uint64
}

// bskLRUEntry for heap-based LRU eviction
type bskLRUEntry struct {
	userID   string
	lastUsed time.Time
	index    int
}

type bskLRUHeap []*bskLRUEntry

func (h bskLRUHeap) Len() int           { return len(h) }
func (h bskLRUHeap) Less(i, j int) bool { return h[i].lastUsed.Before(h[j].lastUsed) }
func (h bskLRUHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}
func (h *bskLRUHeap) Push(x interface{}) {
	n := len(*h)
	entry := x.(*bskLRUEntry)
	entry.index = n
	*h = append(*h, entry)
}
func (h *bskLRUHeap) Pop() interface{} {
	old := *h
	n := len(old)
	entry := old[n-1]
	old[n-1] = nil
	entry.index = -1
	*h = old[0 : n-1]
	return entry
}

// NewBSKCache creates a new multi-GPU BSK cache
func NewBSKCache(mgpu *mlx.MultiGPU, memLimitPerGPU int64) *BSKCache {
	numGPUs := mgpu.NumGPUs()

	c := &BSKCache{
		cache:       make(map[string]*BSKLocation),
		mgpu:        mgpu,
		numGPUs:     numGPUs,
		gpuMemUsed:  make([]atomic.Int64, numGPUs),
		gpuMemLimit: make([]int64, numGPUs),
		lruHeap:     &bskLRUHeap{},
		lruIndex:    make(map[string]*bskLRUEntry),
		peerAccess:  make([][]bool, numGPUs),
	}

	// Set memory limits
	for i := 0; i < numGPUs; i++ {
		if memLimitPerGPU > 0 {
			c.gpuMemLimit[i] = memLimitPerGPU
		} else {
			// Use 80% of GPU memory for BSK cache
			dev, _ := mgpu.GetDevice(i)
			c.gpuMemLimit[i] = int64(float64(dev.TotalMemory) * 0.8)
		}
	}

	// Build P2P access matrix
	for i := 0; i < numGPUs; i++ {
		c.peerAccess[i] = make([]bool, numGPUs)
		for j := 0; j < numGPUs; j++ {
			c.peerAccess[i][j] = mgpu.HasNVLink(i, j)
		}
	}

	heap.Init(c.lruHeap)
	return c
}

// Get retrieves a BSK location, returning the GPU it's on
// If the BSK isn't on the requested GPU, it handles P2P access or replication
func (c *BSKCache) Get(userID string, requestingGPU int) (*BSKLocation, error) {
	c.mu.RLock()
	loc, ok := c.cache[userID]
	c.mu.RUnlock()

	if !ok {
		c.misses.Add(1)
		return nil, ErrBSKNotFound
	}

	c.hits.Add(1)

	// Update LRU
	c.mu.Lock()
	if entry, ok := c.lruIndex[userID]; ok {
		entry.lastUsed = time.Now()
		heap.Fix(c.lruHeap, entry.index)
	}
	loc.LastUsed = time.Now()
	c.mu.Unlock()

	// Check if BSK is on requesting GPU
	if loc.GPUPtr[requestingGPU] != nil {
		loc.RefCount.Add(1)
		return loc, nil
	}

	// BSK not on requesting GPU - check P2P or replicate
	if c.peerAccess[requestingGPU][loc.PrimaryGPU] {
		// Can use P2P access - no need to copy
		c.p2pReads.Add(1)
		loc.RefCount.Add(1)
		return loc, nil
	}

	// No P2P - need to replicate
	if err := c.replicateTo(loc, requestingGPU); err != nil {
		return nil, err
	}

	c.replicas.Add(1)
	loc.RefCount.Add(1)
	return loc, nil
}

// Put stores a BSK on a specific GPU
func (c *BSKCache) Put(userID string, gpuID int, bskData, kskData []byte) (*BSKLocation, error) {
	size := int64(TotalKeySize)

	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if already exists
	if existing, ok := c.cache[userID]; ok {
		existing.LastUsed = time.Now()
		if entry, ok := c.lruIndex[userID]; ok {
			entry.lastUsed = time.Now()
			heap.Fix(c.lruHeap, entry.index)
		}
		return existing, nil
	}

	// Ensure we have space on target GPU
	for c.gpuMemUsed[gpuID].Load()+size > c.gpuMemLimit[gpuID] {
		if err := c.evictFromGPU(gpuID); err != nil {
			return nil, ErrGPUMemoryFull
		}
	}

	// Allocate on GPU
	bskPtr := c.mgpu.Malloc(gpuID, uint64(BSKSizeBytes))
	if bskPtr == nil {
		return nil, ErrGPUMemoryFull
	}

	kskPtr := c.mgpu.Malloc(gpuID, uint64(KSKSizeBytes))
	if kskPtr == nil {
		c.mgpu.Free(gpuID, bskPtr)
		return nil, ErrGPUMemoryFull
	}

	// Copy data to GPU
	c.mgpu.SetDevice(gpuID)
	copyToGPU(bskPtr, bskData)
	copyToGPU(kskPtr, kskData)

	// Create location entry
	loc := &BSKLocation{
		UserID:     userID,
		PrimaryGPU: gpuID,
		Replicas:   make(map[int]struct{}),
		GPUPtr:     make([]unsafe.Pointer, c.numGPUs),
		KSKPtr:     make([]unsafe.Pointer, c.numGPUs),
		LastUsed:   time.Now(),
		Size:       size,
	}
	loc.GPUPtr[gpuID] = bskPtr
	loc.KSKPtr[gpuID] = kskPtr

	c.cache[userID] = loc
	c.gpuMemUsed[gpuID].Add(size)

	// Add to LRU
	entry := &bskLRUEntry{
		userID:   userID,
		lastUsed: time.Now(),
	}
	heap.Push(c.lruHeap, entry)
	c.lruIndex[userID] = entry

	return loc, nil
}

// PutLazy registers a user without uploading keys yet
// Keys will be uploaded on first operation (lazy loading)
func (c *BSKCache) PutLazy(userID string, gpuID int) *BSKLocation {
	c.mu.Lock()
	defer c.mu.Unlock()

	if existing, ok := c.cache[userID]; ok {
		return existing
	}

	loc := &BSKLocation{
		UserID:     userID,
		PrimaryGPU: gpuID,
		Replicas:   make(map[int]struct{}),
		GPUPtr:     make([]unsafe.Pointer, c.numGPUs),
		KSKPtr:     make([]unsafe.Pointer, c.numGPUs),
		LastUsed:   time.Now(),
		Size:       0, // Not yet allocated
	}

	c.cache[userID] = loc
	return loc
}

// UploadKeys uploads keys for a lazy-registered user
func (c *BSKCache) UploadKeys(userID string, bskData, kskData []byte) error {
	c.mu.Lock()
	loc, ok := c.cache[userID]
	if !ok {
		c.mu.Unlock()
		return ErrBSKNotFound
	}

	// Already uploaded?
	if loc.GPUPtr[loc.PrimaryGPU] != nil {
		c.mu.Unlock()
		return nil
	}

	gpuID := loc.PrimaryGPU
	size := int64(TotalKeySize)

	// Ensure we have space
	for c.gpuMemUsed[gpuID].Load()+size > c.gpuMemLimit[gpuID] {
		if err := c.evictFromGPU(gpuID); err != nil {
			c.mu.Unlock()
			return ErrGPUMemoryFull
		}
	}
	c.mu.Unlock()

	// Allocate and copy
	bskPtr := c.mgpu.Malloc(gpuID, uint64(BSKSizeBytes))
	if bskPtr == nil {
		return ErrGPUMemoryFull
	}

	kskPtr := c.mgpu.Malloc(gpuID, uint64(KSKSizeBytes))
	if kskPtr == nil {
		c.mgpu.Free(gpuID, bskPtr)
		return ErrGPUMemoryFull
	}

	c.mgpu.SetDevice(gpuID)
	copyToGPU(bskPtr, bskData)
	copyToGPU(kskPtr, kskData)

	c.mu.Lock()
	loc.GPUPtr[gpuID] = bskPtr
	loc.KSKPtr[gpuID] = kskPtr
	loc.Size = size
	c.gpuMemUsed[gpuID].Add(size)

	// Add to LRU now that it has data
	entry := &bskLRUEntry{
		userID:   userID,
		lastUsed: time.Now(),
	}
	heap.Push(c.lruHeap, entry)
	c.lruIndex[userID] = entry
	c.mu.Unlock()

	return nil
}

// replicateTo copies a BSK to another GPU (for non-NVLink systems)
func (c *BSKCache) replicateTo(loc *BSKLocation, targetGPU int) error {
	if loc.GPUPtr[targetGPU] != nil {
		return nil // Already there
	}

	srcGPU := loc.PrimaryGPU

	// Ensure space on target
	c.mu.Lock()
	for c.gpuMemUsed[targetGPU].Load()+loc.Size > c.gpuMemLimit[targetGPU] {
		if err := c.evictFromGPU(targetGPU); err != nil {
			c.mu.Unlock()
			return ErrGPUMemoryFull
		}
	}
	c.mu.Unlock()

	// Allocate on target
	bskPtr := c.mgpu.Malloc(targetGPU, uint64(BSKSizeBytes))
	if bskPtr == nil {
		return ErrGPUMemoryFull
	}

	kskPtr := c.mgpu.Malloc(targetGPU, uint64(KSKSizeBytes))
	if kskPtr == nil {
		c.mgpu.Free(targetGPU, bskPtr)
		return ErrGPUMemoryFull
	}

	// P2P copy
	if err := c.mgpu.MemcpyPeer(targetGPU, bskPtr, srcGPU, loc.GPUPtr[srcGPU], BSKSizeBytes); err != nil {
		c.mgpu.Free(targetGPU, bskPtr)
		c.mgpu.Free(targetGPU, kskPtr)
		return err
	}

	if err := c.mgpu.MemcpyPeer(targetGPU, kskPtr, srcGPU, loc.KSKPtr[srcGPU], KSKSizeBytes); err != nil {
		c.mgpu.Free(targetGPU, bskPtr)
		c.mgpu.Free(targetGPU, kskPtr)
		return err
	}

	c.mu.Lock()
	loc.GPUPtr[targetGPU] = bskPtr
	loc.KSKPtr[targetGPU] = kskPtr
	loc.Replicas[targetGPU] = struct{}{}
	c.gpuMemUsed[targetGPU].Add(loc.Size)
	c.mu.Unlock()

	return nil
}

// evictFromGPU evicts the LRU entry from a specific GPU
// Must be called with mu held
func (c *BSKCache) evictFromGPU(gpuID int) error {
	// Find LRU entry that has data on this GPU
	for c.lruHeap.Len() > 0 {
		entry := heap.Pop(c.lruHeap).(*bskLRUEntry)
		delete(c.lruIndex, entry.userID)

		loc, ok := c.cache[entry.userID]
		if !ok {
			continue
		}

		// Skip if still in use
		if loc.RefCount.Load() > 0 {
			// Put back with updated time to try again later
			entry.lastUsed = time.Now()
			heap.Push(c.lruHeap, entry)
			c.lruIndex[entry.userID] = entry
			continue
		}

		// Check if this entry has data on target GPU
		if loc.GPUPtr[gpuID] == nil {
			// Re-add to heap, look for another
			heap.Push(c.lruHeap, entry)
			c.lruIndex[entry.userID] = entry
			continue
		}

		// Evict from this GPU
		c.mgpu.Free(gpuID, loc.GPUPtr[gpuID])
		c.mgpu.Free(gpuID, loc.KSKPtr[gpuID])
		loc.GPUPtr[gpuID] = nil
		loc.KSKPtr[gpuID] = nil
		delete(loc.Replicas, gpuID)
		c.gpuMemUsed[gpuID].Add(-loc.Size)
		c.evictions.Add(1)

		// If this was primary and no replicas left, remove entirely
		if gpuID == loc.PrimaryGPU {
			allNil := true
			for i := 0; i < c.numGPUs; i++ {
				if loc.GPUPtr[i] != nil {
					loc.PrimaryGPU = i
					allNil = false
					break
				}
			}
			if allNil {
				delete(c.cache, entry.userID)
			} else {
				// Re-add to LRU
				heap.Push(c.lruHeap, entry)
				c.lruIndex[entry.userID] = entry
			}
		} else {
			// Re-add to LRU (primary still exists)
			heap.Push(c.lruHeap, entry)
			c.lruIndex[entry.userID] = entry
		}

		return nil
	}

	return ErrCacheFull
}

// Remove completely removes a user's BSK from all GPUs
func (c *BSKCache) Remove(userID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	loc, ok := c.cache[userID]
	if !ok {
		return
	}

	// Wait for operations to complete
	for loc.RefCount.Load() > 0 {
		c.mu.Unlock()
		time.Sleep(time.Millisecond)
		c.mu.Lock()
	}

	// Free from all GPUs
	for i := 0; i < c.numGPUs; i++ {
		if loc.GPUPtr[i] != nil {
			c.mgpu.Free(i, loc.GPUPtr[i])
			c.mgpu.Free(i, loc.KSKPtr[i])
			c.gpuMemUsed[i].Add(-loc.Size)
		}
	}

	// Remove from LRU
	if entry, ok := c.lruIndex[userID]; ok {
		heap.Remove(c.lruHeap, entry.index)
		delete(c.lruIndex, userID)
	}

	delete(c.cache, userID)
}

// Release decrements the reference count on a BSK
func (c *BSKCache) Release(userID string) {
	c.mu.RLock()
	loc, ok := c.cache[userID]
	c.mu.RUnlock()

	if ok {
		loc.RefCount.Add(-1)
	}
}

// GetBSKPointer returns the GPU pointer for a user's BSK
// If P2P is available and BSK is on another GPU, returns that pointer
// Otherwise returns the local pointer (after replication if needed)
func (c *BSKCache) GetBSKPointer(userID string, gpuID int) (unsafe.Pointer, error) {
	loc, err := c.Get(userID, gpuID)
	if err != nil {
		return nil, err
	}

	// If we have local copy, use it
	if loc.GPUPtr[gpuID] != nil {
		return loc.GPUPtr[gpuID], nil
	}

	// Must have P2P access to primary
	if c.peerAccess[gpuID][loc.PrimaryGPU] {
		return loc.GPUPtr[loc.PrimaryGPU], nil
	}

	return nil, errors.New("BSK not accessible from GPU")
}

// GetKSKPointer returns the GPU pointer for a user's KSK
func (c *BSKCache) GetKSKPointer(userID string, gpuID int) (unsafe.Pointer, error) {
	loc, err := c.Get(userID, gpuID)
	if err != nil {
		return nil, err
	}

	if loc.KSKPtr[gpuID] != nil {
		return loc.KSKPtr[gpuID], nil
	}

	if c.peerAccess[gpuID][loc.PrimaryGPU] {
		return loc.KSKPtr[loc.PrimaryGPU], nil
	}

	return nil, errors.New("KSK not accessible from GPU")
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

// Stats returns cache statistics
func (c *BSKCache) Stats() BSKCacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := BSKCacheStats{
		TotalUsers:     len(c.cache),
		Hits:           c.hits.Load(),
		Misses:         c.misses.Load(),
		Evictions:      c.evictions.Load(),
		P2PReads:       c.p2pReads.Load(),
		Replicas:       c.replicas.Load(),
		MemoryPerGPU:   make([]int64, c.numGPUs),
		MemLimitPerGPU: make([]int64, c.numGPUs),
	}

	for i := 0; i < c.numGPUs; i++ {
		stats.MemoryPerGPU[i] = c.gpuMemUsed[i].Load()
		stats.MemLimitPerGPU[i] = c.gpuMemLimit[i]
	}

	return stats
}

// HasP2PAccess checks if two GPUs can access each other's memory
func (c *BSKCache) HasP2PAccess(gpu1, gpu2 int) bool {
	if gpu1 < 0 || gpu1 >= c.numGPUs || gpu2 < 0 || gpu2 >= c.numGPUs {
		return false
	}
	return c.peerAccess[gpu1][gpu2]
}

// copyToGPU copies data from host to GPU memory
// This is a low-level function that uses CUDA memcpy
func copyToGPU(dst unsafe.Pointer, src []byte) {
	if len(src) == 0 || dst == nil {
		return
	}
	// Use C.memcpy or cudaMemcpy
	// For now, use direct memory copy via unsafe
	srcPtr := unsafe.Pointer(&src[0])
	cgoMemcpy(dst, srcPtr, len(src))
}

// cgoMemcpy performs memory copy between GPU and host
// Implemented via CGO in the cuda build
func cgoMemcpy(dst, src unsafe.Pointer, size int)
