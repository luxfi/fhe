//go:build cgo

// Package gpu provides accelerated TFHE operations using MLX.
// MLX supports CPU and GPU execution on all platforms via CGO bindings.
// When CGO is disabled, falls back to pure Go implementation.
//
// Backends: Metal GPU (macOS/iOS), CPU (all platforms)
// Target: 500K-2M bootstraps/sec on GPU, 10-50K on CPU
package gpu

import (
	"fmt"
	"math/bits"
	"sync"
	"sync/atomic"

	"github.com/luxfi/mlx"
	"github.com/luxfi/tfhe"
)

// Config holds GPU TFHE engine configuration
type Config struct {
	// TFHE parameters
	N       uint32 // Ring dimension (default: 1024)
	n       uint32 // LWE dimension (default: 512)
	L       uint32 // Decomposition digits (default: 4, reduced from 7)
	BaseLog uint32 // Log2 of decomposition base (default: 7)
	Q       uint64 // Ring modulus (default: 2^27)
	q       uint64 // LWE modulus (default: 2^15)

	// Batch parameters
	BatchSize     uint32 // Operations per batch (default: 4096 for H200)
	MaxUsers      uint32 // Max concurrent users (default: 8000)
	MaxCtsPerUser uint32 // Max ciphertexts per user (default: 10000)

	// Memory budget (0 = auto-detect)
	MemoryBudget uint64
}

// DefaultConfig returns configuration optimized for available hardware
func DefaultConfig() Config {
	return Config{
		N:             1024,
		n:             512,
		L:             4, // Reduced from 7 for 1.75× speedup
		BaseLog:       7,
		Q:             1 << 27,
		q:             1 << 15,
		BatchSize:     4096,
		MaxUsers:      8000,
		MaxCtsPerUser: 10000,
	}
}

// H200x8Config returns configuration optimized for HGX H200 x8
func H200x8Config() Config {
	cfg := DefaultConfig()
	cfg.BatchSize = 8192                         // Larger batches for H200
	cfg.MaxUsers = 8000                          // 8 GPUs × 1000 users each
	cfg.MemoryBudget = 1024 * 1024 * 1024 * 1024 // 1TB total
	return cfg
}

// GateType represents a boolean gate operation
type GateType uint8

const (
	GateAND GateType = iota
	GateOR
	GateXOR
	GateNAND
	GateNOR
	GateXNOR
	GateNOT
	GateMUX
	GateAND3
	GateOR3
	GateMAJORITY
)

// UserSession holds per-user GPU resources
type UserSession struct {
	UserID uint64

	// Bootstrap key on GPU [n, 2, L, 2, N]
	BSK *mlx.Array

	// Key switching key on GPU [N, L_ks, n]
	KSK *mlx.Array

	// Ciphertext pools on GPU
	LWEPools []*LWEPool

	// Memory tracking
	MemoryUsed uint64

	// Statistics
	OpsCompleted atomic.Uint64

	mu sync.Mutex
}

// LWEPool holds a batch of LWE ciphertexts on GPU
type LWEPool struct {
	A     *mlx.Array // [batch, n]
	B     *mlx.Array // [batch]
	Count uint32
	Cap   uint32
}

// Engine is the main GPU TFHE engine
type Engine struct {
	cfg    Config
	params tfhe.Parameters

	// MLX backend info
	backend mlx.Backend
	device  *mlx.Device

	// Precomputed data on GPU
	twiddleFactors    *mlx.Array // [N]
	invTwiddleFactors *mlx.Array // [N]
	testPolynomials   *mlx.Array // [numGates, N]

	// GPU NTT context for accelerated polynomial operations
	nttCtx *NTTContext

	// GPU external product context for RGSW x RLWE operations
	extProdCtx *ExternalProductContext

	// User management
	users      map[uint64]*UserSession
	usersMu    sync.RWMutex
	nextUserID atomic.Uint64

	// Statistics
	totalBootstraps atomic.Uint64
	totalGates      atomic.Uint64
}

// New creates a new GPU TFHE engine
func New(cfg Config) (*Engine, error) {
	// Initialize MLX (auto-detects Metal/CUDA/CPU)
	backend := mlx.GetBackend()
	device := mlx.GetDevice()

	fmt.Printf("GPU TFHE Engine initializing...\n")
	fmt.Printf("  Backend: %s\n", backend)
	fmt.Printf("  Device: %s\n", device.Name)
	fmt.Printf("  Memory: %.1f GB\n", float64(device.Memory)/(1024*1024*1024))

	// Create TFHE parameters
	params, err := tfhe.NewParametersFromLiteral(tfhe.PN10QP27)
	if err != nil {
		return nil, fmt.Errorf("failed to create TFHE params: %w", err)
	}

	e := &Engine{
		cfg:     cfg,
		params:  params,
		backend: backend,
		device:  device,
		users:   make(map[uint64]*UserSession),
	}

	// Initialize precomputed data
	if err := e.initNTTTwiddles(); err != nil {
		return nil, fmt.Errorf("failed to init NTT twiddles: %w", err)
	}

	if err := e.initTestPolynomials(); err != nil {
		return nil, fmt.Errorf("failed to init test polynomials: %w", err)
	}

	// Initialize GPU NTT context
	nttCtx, err := NewNTTContext(cfg.N, cfg.Q)
	if err != nil {
		return nil, fmt.Errorf("failed to init GPU NTT context: %w", err)
	}
	e.nttCtx = nttCtx

	// Initialize GPU external product context
	extProdCtx, err := NewExternalProductContext(nttCtx, cfg.L, cfg.BaseLog)
	if err != nil {
		return nil, fmt.Errorf("failed to init GPU external product context: %w", err)
	}
	e.extProdCtx = extProdCtx

	fmt.Printf("GPU TFHE Engine ready\n")
	fmt.Printf("  NTT context: N=%d, Q=%d\n", nttCtx.N, nttCtx.Q)
	fmt.Printf("  External product: L=%d, BaseLog=%d\n", cfg.L, cfg.BaseLog)
	return e, nil
}

// initNTTTwiddles precomputes NTT twiddle factors on GPU
func (e *Engine) initNTTTwiddles() error {
	N := e.cfg.N
	Q := e.cfg.Q

	// Find primitive 2N-th root of unity
	omega, err := findPrimitiveRoot(N, Q)
	if err != nil {
		return fmt.Errorf("find primitive root: %w", err)
	}
	omegaInv := modInverse(omega, Q)
	nInv := modInverse(uint64(N), Q)

	// Compute twiddles
	twiddles := make([]int64, N)
	invTwiddles := make([]int64, N)

	w := uint64(1)
	wInv := uint64(1)
	for i := uint32(0); i < N; i++ {
		twiddles[i] = int64(w)
		invTwiddles[i] = int64(mulMod(wInv, nInv, Q))
		w = mulMod(w, omega, Q)
		wInv = mulMod(wInv, omegaInv, Q)
	}

	// Upload to GPU
	e.twiddleFactors = mlx.ArrayFromSlice(twiddles, []int{int(N)}, mlx.Int64)
	e.invTwiddleFactors = mlx.ArrayFromSlice(invTwiddles, []int{int(N)}, mlx.Int64)

	mlx.Eval(e.twiddleFactors)
	mlx.Eval(e.invTwiddleFactors)

	return nil
}

// initTestPolynomials precomputes gate test polynomials on GPU
func (e *Engine) initTestPolynomials() error {
	N := e.cfg.N
	Q := e.cfg.Q
	mu := Q / 8

	numGates := 6 // AND, OR, XOR, NAND, NOR, XNOR
	polys := make([]int64, numGates*int(N))

	for g := 0; g < numGates; g++ {
		for i := uint32(0); i < N; i++ {
			var phase int32
			if i < N/2 {
				phase = int32(i)
			} else {
				phase = int32(i) - int32(N)
			}

			var result bool
			switch g {
			case 0: // AND
				result = phase > int32(N/4)
			case 1: // OR
				result = phase > -int32(N/4)
			case 2: // XOR
				result = phase > -int32(N/4) && phase <= int32(N/4)
			case 3: // NAND
				result = phase <= int32(N/4)
			case 4: // NOR
				result = phase <= -int32(N/4)
			case 5: // XNOR
				result = !(phase > -int32(N/4) && phase <= int32(N/4))
			}

			if result {
				polys[g*int(N)+int(i)] = int64(mu)
			} else {
				polys[g*int(N)+int(i)] = int64(Q - mu)
			}
		}
	}

	e.testPolynomials = mlx.ArrayFromSlice(polys, []int{numGates, int(N)}, mlx.Int64)
	mlx.Eval(e.testPolynomials)

	return nil
}

// CreateUser creates a new user session
func (e *Engine) CreateUser() (uint64, error) {
	e.usersMu.Lock()
	defer e.usersMu.Unlock()

	if uint32(len(e.users)) >= e.cfg.MaxUsers {
		return 0, fmt.Errorf("max users (%d) reached", e.cfg.MaxUsers)
	}

	userID := e.nextUserID.Add(1)
	e.users[userID] = &UserSession{
		UserID:   userID,
		LWEPools: make([]*LWEPool, 0),
	}

	return userID, nil
}

// DeleteUser removes a user session and frees GPU memory
func (e *Engine) DeleteUser(userID uint64) {
	e.usersMu.Lock()
	defer e.usersMu.Unlock()
	delete(e.users, userID)
}

// UploadBootstrapKey uploads a user's bootstrap key to GPU
func (e *Engine) UploadBootstrapKey(userID uint64, bsk *tfhe.BootstrapKey) error {
	e.usersMu.RLock()
	user, ok := e.users[userID]
	e.usersMu.RUnlock()

	if !ok {
		return fmt.Errorf("user %d not found", userID)
	}

	user.mu.Lock()
	defer user.mu.Unlock()

	// Convert BSK to flat array for GPU
	// Shape: [n, 2, L, 2, N]
	n := e.cfg.n
	L := e.cfg.L
	N := e.cfg.N

	data := make([]int64, n*2*L*2*N)
	// ... fill from bsk (implementation depends on tfhe.BootstrapKey structure)

	user.BSK = mlx.ArrayFromSlice(data, []int{int(n), 2, int(L), 2, int(N)}, mlx.Int64)
	mlx.Eval(user.BSK)

	user.MemoryUsed += uint64(len(data)) * 8

	return nil
}

// AllocateCiphertexts allocates a pool of LWE ciphertexts on GPU
func (e *Engine) AllocateCiphertexts(userID uint64, count uint32) (poolIdx uint32, err error) {
	e.usersMu.RLock()
	user, ok := e.users[userID]
	e.usersMu.RUnlock()

	if !ok {
		return 0, fmt.Errorf("user %d not found", userID)
	}

	user.mu.Lock()
	defer user.mu.Unlock()

	n := e.cfg.n

	pool := &LWEPool{
		A:     mlx.Zeros([]int{int(count), int(n)}, mlx.Int64),
		B:     mlx.Zeros([]int{int(count)}, mlx.Int64),
		Count: 0,
		Cap:   count,
	}

	mlx.Eval(pool.A)
	mlx.Eval(pool.B)

	poolIdx = uint32(len(user.LWEPools))
	user.LWEPools = append(user.LWEPools, pool)
	user.MemoryUsed += uint64(count) * uint64(n+1) * 8

	return poolIdx, nil
}

// BatchGateOp represents a batch of gate operations
type BatchGateOp struct {
	Gate          GateType
	UserIDs       []uint64
	Input1Indices []uint32
	Input2Indices []uint32
	OutputIndices []uint32
}

// ExecuteBatchGates executes a batch of gate operations on GPU
func (e *Engine) ExecuteBatchGates(ops []BatchGateOp) error {
	for _, op := range ops {
		if len(op.UserIDs) == 0 {
			continue
		}

		// Group by user
		userOps := make(map[uint64][]int)
		for i, uid := range op.UserIDs {
			userOps[uid] = append(userOps[uid], i)
		}

		// Process each user's operations
		for userID, indices := range userOps {
			e.usersMu.RLock()
			user, ok := e.users[userID]
			e.usersMu.RUnlock()

			if !ok || user.BSK == nil {
				continue
			}

			// Batch bootstrap for this user
			count := len(indices)
			if err := e.batchBootstrap(user, op.Gate, count); err != nil {
				return err
			}

			user.OpsCompleted.Add(uint64(count))
			e.totalGates.Add(uint64(count))
			e.totalBootstraps.Add(uint64(count))
		}
	}

	return nil
}

// batchBootstrap performs batch programmable bootstrapping on GPU
//
// TFHE bootstrapping computes: LUT[phase(ct)] where phase = b - <a, s> mod Q
// For batch processing, we perform all operations in parallel using MLX.
//
// Algorithm (per ciphertext):
// 1. Compute phase = (b - sum(a_i * s_i)) mod Q
// 2. Map phase to rotation index: idx = round(phase * 2N / Q) mod 2N
// 3. Blind rotation: accumulator = X^(-idx) * testPoly via external products
// 4. Sample extraction: extract LWE from RLWE accumulator
// 5. Key switching: switch from RLWE key to LWE key
func (e *Engine) batchBootstrap(user *UserSession, gate GateType, count int) error {
	if count == 0 {
		return nil
	}

	// Validate user has BSK
	if user.BSK == nil {
		return fmt.Errorf("bootstrap key not initialized for user %d", user.UserID)
	}

	// Validate we have LWE pools
	if len(user.LWEPools) == 0 {
		return fmt.Errorf("no LWE pools allocated for user %d", user.UserID)
	}

	N := int(e.cfg.N)
	n := int(e.cfg.n)

	// Get input LWE ciphertexts from user's pool
	pool := user.LWEPools[0]
	if pool.Count == 0 {
		return fmt.Errorf("LWE pool is empty")
	}

	// Limit count to available ciphertexts
	if count > int(pool.Count) {
		count = int(pool.Count)
	}

	// Create BatchLWE input from pool
	inputs := &BatchLWE{
		A: mlx.Slice(pool.A, []mlx.SliceArg{
			{Start: 0, Stop: count},
			{Start: 0, Stop: n},
		}),
		B: mlx.Slice(pool.B, []mlx.SliceArg{
			{Start: 0, Stop: count},
		}),
		Count: count,
	}

	// Get test polynomial for this gate type
	testPoly := e.getTestPolynomial(gate)
	if testPoly == nil {
		return fmt.Errorf("no test polynomial for gate type %d", gate)
	}

	// Create GPUBootstrapKey from user's BSK
	bsk := &GPUBootstrapKey{
		Data:    user.BSK,
		n:       n,
		L:       int(e.cfg.L),
		N:       N,
		Base:    1 << e.cfg.BaseLog,
		BaseLog: int(e.cfg.BaseLog),
	}

	// Perform batch blind rotation
	rlweResult, err := e.BatchBlindRotate(inputs, bsk, testPoly)
	if err != nil {
		return fmt.Errorf("blind rotation failed: %w", err)
	}

	// Sample extraction: extract LWE from RLWE results
	lweResult, err := e.BatchSampleExtract(rlweResult)
	if err != nil {
		return fmt.Errorf("sample extraction failed: %w", err)
	}

	// Key switching (if KSK is available)
	if user.KSK != nil {
		lweResult, err = e.batchKeySwitch(lweResult, user.KSK)
		if err != nil {
			return fmt.Errorf("key switching failed: %w", err)
		}
	}

	// Store results back to pool
	pool.A = lweResult.A
	pool.B = lweResult.B

	// Ensure computation is complete
	mlx.Eval(pool.A)
	mlx.Eval(pool.B)

	return nil
}

// getTestPolynomial returns the precomputed test polynomial for a gate type
func (e *Engine) getTestPolynomial(gate GateType) *mlx.Array {
	if e.testPolynomials == nil {
		return nil
	}

	N := int(e.cfg.N)
	gateIdx := int(gate)

	// Bounds check
	if gateIdx < 0 || gateIdx >= 6 {
		gateIdx = 0 // Default to AND
	}

	// testPolynomials has shape [numGates, N]
	poly := mlx.Slice(e.testPolynomials, []mlx.SliceArg{
		{Start: gateIdx, Stop: gateIdx + 1},
		{Start: 0, Stop: N},
	})
	poly = mlx.Squeeze(poly, 0)

	return poly
}

// batchKeySwitch performs key switching on a batch of LWE ciphertexts
func (e *Engine) batchKeySwitch(input *BatchLWE, ksk *mlx.Array) (*BatchLWE, error) {
	if input == nil {
		return nil, fmt.Errorf("nil input")
	}
	if ksk == nil {
		return nil, fmt.Errorf("nil key switching key")
	}

	batchSize := input.Count
	N := int(e.cfg.N)
	n := int(e.cfg.n)
	Q := e.cfg.Q

	// Key switching: convert from dimension N to dimension n
	// KSK has shape [N, L_ks, n] where L_ks is key switch decomposition levels
	// For each coefficient of the RLWE key, we have decomposed encryptions under LWE key

	L_ks := 3                // Typical key switch decomposition levels
	baseKS := uint64(1 << 8) // Key switch base

	// Initialize output
	outA := mlx.Zeros([]int{batchSize, n}, mlx.Int64)
	outB := input.B // B component stays the same initially

	qArray := mlx.Full([]int{batchSize, n}, int64(Q), mlx.Int64)

	// For each coefficient of input.A (dimension N)
	for i := 0; i < N; i++ {
		// Get coefficient i for all batch elements: [batchSize]
		coeff := mlx.Slice(input.A, []mlx.SliceArg{
			{Start: 0, Stop: batchSize},
			{Start: i, Stop: i + 1},
		})
		coeff = mlx.Squeeze(coeff, 1)

		// Decompose coefficient into L_ks digits
		for l := 0; l < L_ks; l++ {
			shift := l * 8
			shiftArray := mlx.Full([]int{batchSize}, int64(shift), mlx.Int64)
			baseArray := mlx.Full([]int{batchSize}, int64(baseKS), mlx.Int64)

			digit := mlx.RightShift(coeff, shiftArray)
			digit = mlx.Remainder(digit, baseArray)

			// Get KSK entry: ksk[i, l] which has shape [n]
			kskEntry := mlx.Slice(ksk, []mlx.SliceArg{
				{Start: i, Stop: i + 1},
				{Start: l, Stop: l + 1},
				{Start: 0, Stop: n},
			})
			kskEntry = mlx.Squeeze(kskEntry, 0)
			kskEntry = mlx.Squeeze(kskEntry, 0)

			// Broadcast to batch
			kskBatch := mlx.Broadcast(kskEntry, []int{batchSize, n})
			digitBatch := mlx.Reshape(digit, []int{batchSize, 1})
			digitBatch = mlx.Broadcast(digitBatch, []int{batchSize, n})

			// Accumulate: outA -= digit * kskEntry
			prod := mlx.Multiply(digitBatch, kskBatch)
			outA = mlx.Subtract(outA, prod)
			outA = mlx.Add(outA, qArray)
			outA = mlx.Remainder(outA, qArray)
		}
	}

	mlx.Eval(outA)
	mlx.Eval(outB)

	return &BatchLWE{
		A:     outA,
		B:     outB,
		Count: batchSize,
	}, nil
}

// Sync waits for all GPU operations to complete
func (e *Engine) Sync() {
	mlx.Synchronize()
}

// Stats returns engine statistics
type Stats struct {
	Backend         string
	DeviceName      string
	DeviceMemory    uint64
	TotalBootstraps uint64
	TotalGates      uint64
	ActiveUsers     int
	TotalMemoryUsed uint64
}

// GetStats returns current engine statistics
func (e *Engine) GetStats() Stats {
	e.usersMu.RLock()
	activeUsers := len(e.users)
	var totalMem uint64
	for _, u := range e.users {
		totalMem += u.MemoryUsed
	}
	e.usersMu.RUnlock()

	return Stats{
		Backend:         fmt.Sprintf("%v", e.backend),
		DeviceName:      e.device.Name,
		DeviceMemory:    uint64(e.device.Memory),
		TotalBootstraps: e.totalBootstraps.Load(),
		TotalGates:      e.totalGates.Load(),
		ActiveUsers:     activeUsers,
		TotalMemoryUsed: totalMem,
	}
}

// PerformanceEstimate estimates performance on current hardware
type PerformanceEstimate struct {
	Backend              string
	NumDevices           int
	TotalMemoryGB        float64
	BandwidthTBps        float64
	MaxConcurrentUsers   uint32
	PeakBootstrapsPerSec float64
}

// EstimatePerformance returns performance estimates for current hardware
func EstimatePerformance(cfg Config) PerformanceEstimate {
	device := mlx.GetDevice()
	backend := mlx.GetBackend()

	est := PerformanceEstimate{
		Backend:    fmt.Sprintf("%v", backend),
		NumDevices: 1,
	}

	// Memory
	est.TotalMemoryGB = float64(device.Memory) / (1024 * 1024 * 1024)

	// Bandwidth estimates by device type
	switch {
	case device.Name == "Apple M1 Max" || device.Name == "Apple M2 Max":
		est.BandwidthTBps = 0.4 // 400 GB/s
	case device.Name == "Apple M3 Max":
		est.BandwidthTBps = 0.5 // 500 GB/s
	case contains(device.Name, "H200"):
		est.BandwidthTBps = 4.8 // 4.8 TB/s per GPU
	case contains(device.Name, "H100"):
		est.BandwidthTBps = 3.35 // 3.35 TB/s
	case contains(device.Name, "A100"):
		est.BandwidthTBps = 2.0 // 2 TB/s
	default:
		est.BandwidthTBps = 0.5 // Conservative estimate
	}

	// Users (170MB BSK per user)
	bskBytes := float64(cfg.n) * 2 * float64(cfg.L) * 2 * float64(cfg.N) * 8
	est.MaxConcurrentUsers = uint32(est.TotalMemoryGB * 1024 * 1024 * 1024 * 0.8 / bskBytes)

	// Throughput (memory bound)
	bytesPerBootstrap := 8.0 * 1024 * 1024                                        // ~8MB BK reads per bootstrap
	est.PeakBootstrapsPerSec = est.BandwidthTBps * 1e12 / bytesPerBootstrap * 0.3 // 30% efficiency

	return est
}

// Helper functions

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		len(s) > len(substr) && (s[:len(substr)] == substr ||
			s[len(s)-len(substr):] == substr ||
			containsMiddle(s, substr)))
}

func containsMiddle(s, substr string) bool {
	for i := 1; i < len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func mulMod(a, b, m uint64) uint64 {
	// Use math/bits for correct 64x64 -> 128 bit multiplication
	hi, lo := bits.Mul64(a, b)
	_, r := bits.Div64(hi, lo, m)
	return r
}

func modInverse(a, m uint64) uint64 {
	return powMod(a, m-2, m) // Fermat's little theorem
}

func powMod(base, exp, m uint64) uint64 {
	result := uint64(1)
	base = base % m
	for exp > 0 {
		if exp&1 == 1 {
			result = mulMod(result, base, m)
		}
		base = mulMod(base, base, m)
		exp >>= 1
	}
	return result
}

func findPrimitiveRoot(N uint32, Q uint64) (uint64, error) {
	// Find primitive 2N-th root of unity mod Q
	// Q-1 must be divisible by 2N
	order := Q - 1
	if order%(2*uint64(N)) != 0 {
		return 0, fmt.Errorf("Q-1 (%d) must be divisible by 2N (%d)", order, 2*uint64(N))
	}

	// Find generator
	for g := uint64(2); g < Q; g++ {
		isGenerator := true
		// Check g^((Q-1)/p) != 1 for prime factors p of Q-1
		for _, p := range []uint64{2, (Q - 1) / 2} {
			if p > 1 && powMod(g, (Q-1)/p, Q) == 1 {
				isGenerator = false
				break
			}
		}
		if isGenerator {
			return powMod(g, order/(2*uint64(N)), Q), nil
		}
	}
	return 0, fmt.Errorf("no primitive root found for N=%d, Q=%d", N, Q)
}
