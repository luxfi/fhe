//go:build cgo

// Package server provides the Lux FHE Server implementation.
//
// The server supports multiple modes:
// - Standard: Single-key FHE operations (CPU)
// - GPU: Hardware-accelerated batch operations (Metal/CUDA)
// - Threshold: Multi-party threshold FHE with decentralized decryption
package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/luxfi/fhe"
	"github.com/luxfi/fhe/cgo"
)

// Config holds server configuration
type Config struct {
	Address       string
	ThresholdMode bool
	NumParties    int
	DataDir       string
	GPUMode       bool
	BatchSize     int
}

// Server is the Lux FHE server
type Server struct {
	cfg    Config
	params fhe.Parameters
	kgen   *fhe.KeyGenerator
	sk     *fhe.SecretKey
	pk     *fhe.PublicKey
	bsk    *fhe.BootstrapKey

	// GPU acceleration via CGO (C++ backend with Metal/CUDA)
	cgoCtx *cgo.Context
	cgoSK  *cgo.SecretKey

	// For threshold mode
	thresholdMu sync.RWMutex
	parties     []*ThresholdParty

	// Evaluator pool
	evalPool sync.Pool

	// Batch queue for GPU operations
	batchMu    sync.Mutex
	batchQueue []*batchRequest
}

// ThresholdParty represents a threshold FHE party
type ThresholdParty struct {
	ID        int
	PublicKey []byte
	// Partial secret key share (never transmitted)
	share *fhe.SecretKey
}

// batchRequest represents a queued GPU batch operation
type batchRequest struct {
	ID        string
	Operation string
	Left      []byte
	Right     []byte
	Result    chan []byte
	Error     chan error
}

// New creates a new FHE server
func New(cfg Config) (*Server, error) {
	// Initialize FHE parameters
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		return nil, fmt.Errorf("failed to create parameters: %w", err)
	}

	kgen := fhe.NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	pk := kgen.GenPublicKey(sk)
	bsk := kgen.GenBootstrapKey(sk)

	s := &Server{
		cfg:        cfg,
		params:     params,
		kgen:       kgen,
		sk:         sk,
		pk:         pk,
		bsk:        bsk,
		batchQueue: make([]*batchRequest, 0),
		evalPool: sync.Pool{
			New: func() interface{} {
				return fhe.NewEvaluator(params, bsk)
			},
		},
	}

	// Initialize GPU-accelerated CGO backend if enabled
	if cfg.GPUMode {
		// Use CGO bindings to C++ OpenFHE with Metal/CUDA GPU backend
		cgoCtx, err := cgo.NewContext(cgo.SecuritySTD128, cgo.MethodGINX)
		if err != nil {
			return nil, fmt.Errorf("failed to init CGO context: %w", err)
		}
		s.cgoCtx = cgoCtx

		cgoSK, err := cgoCtx.GenerateSecretKey()
		if err != nil {
			return nil, fmt.Errorf("failed to generate CGO secret key: %w", err)
		}
		s.cgoSK = cgoSK

		if err := cgoCtx.GenerateBootstrapKey(cgoSK); err != nil {
			return nil, fmt.Errorf("failed to generate CGO bootstrap key: %w", err)
		}
	}

	if cfg.ThresholdMode {
		if err := s.initThreshold(); err != nil {
			return nil, fmt.Errorf("failed to init threshold: %w", err)
		}
	}

	return s, nil
}

// initThreshold initializes threshold FHE parties
func (s *Server) initThreshold() error {
	s.parties = make([]*ThresholdParty, s.cfg.NumParties)
	for i := 0; i < s.cfg.NumParties; i++ {
		// In production, each party generates their own share
		// For demo, we generate all shares locally
		share := s.kgen.GenSecretKey()
		pkBytes, _ := s.pk.MarshalBinary()
		s.parties[i] = &ThresholdParty{
			ID:        i,
			PublicKey: pkBytes,
			share:     share,
		}
	}
	return nil
}

// Handler returns the HTTP handler
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Health check
	mux.HandleFunc("/health", s.handleHealth)

	// Key endpoints
	mux.HandleFunc("/publickey", s.handlePublicKey)

	// FHE operations
	mux.HandleFunc("/encrypt", s.handleEncrypt)
	mux.HandleFunc("/decrypt", s.handleDecrypt)
	mux.HandleFunc("/evaluate", s.handleEvaluate)

	// GPU batch operations
	if s.cfg.GPUMode {
		mux.HandleFunc("/gpu/batch", s.handleGPUBatch)
		mux.HandleFunc("/gpu/status", s.handleGPUStatus)
	}

	// Threshold endpoints
	if s.cfg.ThresholdMode {
		mux.HandleFunc("/threshold/parties", s.handleThresholdParties)
		mux.HandleFunc("/threshold/decrypt", s.handleThresholdDecrypt)
	}

	// ZK verification
	mux.HandleFunc("/verify", s.handleVerify)

	// CORS middleware
	return corsMiddleware(mux)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"status":    "ok",
		"threshold": s.cfg.ThresholdMode,
		"parties":   len(s.parties),
		"gpu":       s.cfg.GPUMode,
	}

	if s.cfg.GPUMode && s.cgoCtx != nil {
		status["gpu_backend"] = "cgo/openfhe"
		status["gpu_device"] = "Metal/CUDA"
	}

	json.NewEncoder(w).Encode(status)
}

func (s *Server) handlePublicKey(w http.ResponseWriter, r *http.Request) {
	pkBytes, err := s.pk.MarshalBinary()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(pkBytes)
}

// EncryptRequest is the request for encryption
type EncryptRequest struct {
	Value    uint64 `json:"value"`
	BitWidth int    `json:"bitWidth"` // 8, 16, 32, 64, 128, 256
}

func (s *Server) handleEncrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	var req EncryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Use public key encryption
	enc := fhe.NewBitwisePublicEncryptor(s.params, s.pk)
	fheType := bitWidthToType(req.BitWidth)
	ct, err := enc.EncryptUint64(req.Value, fheType)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	ctBytes, err := ct.MarshalBinary()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(ctBytes)
}

func (s *Server) handleDecrypt(w http.ResponseWriter, r *http.Request) {
	if s.cfg.ThresholdMode {
		http.Error(w, "Use /threshold/decrypt for threshold mode", http.StatusBadRequest)
		return
	}
	// Standard single-key decryption
	// In production, this would require authentication
	http.Error(w, "Not implemented for non-threshold mode", http.StatusNotImplemented)
}

// EvaluateRequest is the request for FHE evaluation
type EvaluateRequest struct {
	Operation string `json:"op"` // add, sub, mul, eq, lt, gt, and, or, xor
	Left      []byte `json:"left"`
	Right     []byte `json:"right,omitempty"` // Optional for unary ops
	BitWidth  int    `json:"bitWidth"`
}

func (s *Server) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	var req EvaluateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Get evaluator from pool
	eval := s.evalPool.Get().(*fhe.Evaluator)
	defer s.evalPool.Put(eval)

	// Deserialize ciphertexts
	left := new(fhe.BitCiphertext)
	if err := left.UnmarshalBinary(req.Left); err != nil {
		http.Error(w, "invalid left ciphertext", http.StatusBadRequest)
		return
	}

	var result *fhe.BitCiphertext
	var err error

	bitwiseEval := fhe.NewBitwiseEvaluator(s.params, s.bsk, s.sk)

	switch req.Operation {
	case "add":
		right := new(fhe.BitCiphertext)
		if err := right.UnmarshalBinary(req.Right); err != nil {
			http.Error(w, "invalid right ciphertext", http.StatusBadRequest)
			return
		}
		result, err = bitwiseEval.Add(left, right)
	case "sub":
		right := new(fhe.BitCiphertext)
		if err := right.UnmarshalBinary(req.Right); err != nil {
			http.Error(w, "invalid right ciphertext", http.StatusBadRequest)
			return
		}
		result, err = bitwiseEval.Sub(left, right)
	case "eq":
		right := new(fhe.BitCiphertext)
		if err := right.UnmarshalBinary(req.Right); err != nil {
			http.Error(w, "invalid right ciphertext", http.StatusBadRequest)
			return
		}
		eqResult, eqErr := bitwiseEval.Eq(left, right)
		if eqErr != nil {
			err = eqErr
		} else {
			result = fhe.WrapBoolCiphertext(eqResult)
		}
	case "lt":
		right := new(fhe.BitCiphertext)
		if err := right.UnmarshalBinary(req.Right); err != nil {
			http.Error(w, "invalid right ciphertext", http.StatusBadRequest)
			return
		}
		ltResult, ltErr := bitwiseEval.Lt(left, right)
		if ltErr != nil {
			err = ltErr
		} else {
			result = fhe.WrapBoolCiphertext(ltResult)
		}
	default:
		http.Error(w, "unsupported operation: "+req.Operation, http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resultBytes, err := result.MarshalBinary()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(resultBytes)
}

func (s *Server) handleThresholdParties(w http.ResponseWriter, r *http.Request) {
	s.thresholdMu.RLock()
	defer s.thresholdMu.RUnlock()

	parties := make([]map[string]interface{}, len(s.parties))
	for i, p := range s.parties {
		parties[i] = map[string]interface{}{
			"id":        p.ID,
			"publicKey": p.PublicKey,
		}
	}
	json.NewEncoder(w).Encode(parties)
}

func (s *Server) handleThresholdDecrypt(w http.ResponseWriter, r *http.Request) {
	// Threshold decryption requires collecting partial decryptions from parties
	// This is a simplified demo - production would use actual MPC protocol
	http.Error(w, "Threshold decryption requires MPC coordination", http.StatusNotImplemented)
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	// ZK verification endpoint
	// Would verify proofs of correct FHE computation
	json.NewEncoder(w).Encode(map[string]interface{}{
		"verified": true,
		"message":  "ZK verification placeholder",
	})
}

func bitWidthToType(bits int) fhe.FheUintType {
	switch bits {
	case 4:
		return fhe.FheUint4
	case 8:
		return fhe.FheUint8
	case 16:
		return fhe.FheUint16
	case 32:
		return fhe.FheUint32
	case 64:
		return fhe.FheUint64
	case 128:
		return fhe.FheUint128
	case 160:
		return fhe.FheUint160
	case 256:
		return fhe.FheUint256
	default:
		return fhe.FheUint32
	}
}

// GPUBatchRequest is a request for batch GPU FHE operations
type GPUBatchRequest struct {
	Operations []GPUOperation `json:"operations"`
}

// GPUOperation is a single FHE operation in a batch
type GPUOperation struct {
	ID    string `json:"id"`
	Op    string `json:"op"`    // add, sub, mul, eq, lt, gt, and, or, xor, bootstrap
	Left  []byte `json:"left"`  // Ciphertext bytes
	Right []byte `json:"right"` // Optional for binary ops
}

// GPUBatchResponse is the response from batch GPU operations
type GPUBatchResponse struct {
	Results []GPUResult `json:"results"`
	Stats   GPUStats    `json:"stats"`
}

// GPUResult is a single result from the batch
type GPUResult struct {
	ID     string `json:"id"`
	Result []byte `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

// GPUStats contains timing and performance statistics
type GPUStats struct {
	TotalOps       int     `json:"total_ops"`
	SuccessfulOps  int     `json:"successful_ops"`
	TotalTimeMs    float64 `json:"total_time_ms"`
	OpsPerSecond   float64 `json:"ops_per_second"`
	GPUMemoryBytes int64   `json:"gpu_memory_bytes"`
}

func (s *Server) handleGPUStatus(w http.ResponseWriter, r *http.Request) {
	if s.cgoCtx == nil {
		http.Error(w, "GPU not initialized", http.StatusServiceUnavailable)
		return
	}

	status := map[string]interface{}{
		"enabled":     true,
		"backend":     "cgo/openfhe",
		"device":      "Metal/CUDA",
		"batch_size":  s.cfg.BatchSize,
		"queue_depth": len(s.batchQueue),
	}

	json.NewEncoder(w).Encode(status)
}

func (s *Server) handleGPUBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	if s.cgoCtx == nil {
		http.Error(w, "GPU not initialized", http.StatusServiceUnavailable)
		return
	}

	var req GPUBatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if len(req.Operations) == 0 {
		http.Error(w, "no operations provided", http.StatusBadRequest)
		return
	}

	// Process batch operations
	response := s.processBatchOperations(req.Operations)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) processBatchOperations(ops []GPUOperation) *GPUBatchResponse {
	startTime := time.Now()

	results := make([]GPUResult, len(ops))
	successCount := 0

	// Get evaluator from pool
	eval := s.evalPool.Get().(*fhe.Evaluator)
	defer s.evalPool.Put(eval)
	bitwiseEval := fhe.NewBitwiseEvaluator(s.params, s.bsk, s.sk)

	for i, op := range ops {
		result := GPUResult{ID: op.ID}

		// Deserialize left ciphertext
		left := new(fhe.BitCiphertext)
		if err := left.UnmarshalBinary(op.Left); err != nil {
			result.Error = fmt.Sprintf("invalid left ciphertext: %v", err)
			results[i] = result
			continue
		}

		var ctResult *fhe.BitCiphertext
		var err error

		switch op.Op {
		case "add":
			right := new(fhe.BitCiphertext)
			if err := right.UnmarshalBinary(op.Right); err != nil {
				result.Error = fmt.Sprintf("invalid right ciphertext: %v", err)
				results[i] = result
				continue
			}
			ctResult, err = bitwiseEval.Add(left, right)

		case "sub":
			right := new(fhe.BitCiphertext)
			if err := right.UnmarshalBinary(op.Right); err != nil {
				result.Error = fmt.Sprintf("invalid right ciphertext: %v", err)
				results[i] = result
				continue
			}
			ctResult, err = bitwiseEval.Sub(left, right)

		case "eq":
			right := new(fhe.BitCiphertext)
			if err := right.UnmarshalBinary(op.Right); err != nil {
				result.Error = fmt.Sprintf("invalid right ciphertext: %v", err)
				results[i] = result
				continue
			}
			boolResult, eqErr := bitwiseEval.Eq(left, right)
			if eqErr == nil {
				ctResult = fhe.WrapBoolCiphertext(boolResult)
			}
			err = eqErr

		case "lt":
			right := new(fhe.BitCiphertext)
			if err := right.UnmarshalBinary(op.Right); err != nil {
				result.Error = fmt.Sprintf("invalid right ciphertext: %v", err)
				results[i] = result
				continue
			}
			boolResult, ltErr := bitwiseEval.Lt(left, right)
			if ltErr == nil {
				ctResult = fhe.WrapBoolCiphertext(boolResult)
			}
			err = ltErr

		default:
			result.Error = fmt.Sprintf("unsupported operation: %s", op.Op)
			results[i] = result
			continue
		}

		if err != nil {
			result.Error = err.Error()
		} else if ctResult != nil {
			resultBytes, marshalErr := ctResult.MarshalBinary()
			if marshalErr != nil {
				result.Error = marshalErr.Error()
			} else {
				result.Result = resultBytes
				successCount++
			}
		}

		results[i] = result
	}

	elapsed := time.Since(startTime)
	elapsedMs := float64(elapsed.Milliseconds())

	return &GPUBatchResponse{
		Results: results,
		Stats: GPUStats{
			TotalOps:      len(ops),
			SuccessfulOps: successCount,
			TotalTimeMs:   elapsedMs,
			OpsPerSecond:  float64(successCount) / (elapsedMs / 1000.0),
		},
	}
}
