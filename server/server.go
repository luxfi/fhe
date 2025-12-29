// Package server provides the Lux FHE Server implementation.
//
// The server supports two modes:
// - Standard: Single-key FHE operations
// - Threshold: Multi-party threshold FHE with decentralized decryption
package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/luxfi/tfhe"
)

// Config holds server configuration
type Config struct {
	Address       string
	ThresholdMode bool
	NumParties    int
	DataDir       string
}

// Server is the Lux FHE server
type Server struct {
	cfg    Config
	params tfhe.Parameters
	kgen   *tfhe.KeyGenerator
	sk     *tfhe.SecretKey
	pk     *tfhe.PublicKey
	bsk    *tfhe.BootstrapKey

	// For threshold mode
	thresholdMu sync.RWMutex
	parties     []*ThresholdParty

	// Evaluator pool
	evalPool sync.Pool
}

// ThresholdParty represents a threshold FHE party
type ThresholdParty struct {
	ID        int
	PublicKey []byte
	// Partial secret key share (never transmitted)
	share *tfhe.SecretKey
}

// New creates a new FHE server
func New(cfg Config) (*Server, error) {
	// Initialize TFHE parameters
	params, err := tfhe.NewParametersFromLiteral(tfhe.PN10QP27)
	if err != nil {
		return nil, fmt.Errorf("failed to create parameters: %w", err)
	}

	kgen := tfhe.NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	pk := kgen.GenPublicKey(sk)
	bsk := kgen.GenBootstrapKey(sk)

	s := &Server{
		cfg:    cfg,
		params: params,
		kgen:   kgen,
		sk:     sk,
		pk:     pk,
		bsk:    bsk,
		evalPool: sync.Pool{
			New: func() interface{} {
				return tfhe.NewEvaluator(params, bsk)
			},
		},
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
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "ok",
		"threshold": s.cfg.ThresholdMode,
		"parties":   len(s.parties),
	})
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
	enc := tfhe.NewBitwisePublicEncryptor(s.params, s.pk)
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
	eval := s.evalPool.Get().(*tfhe.Evaluator)
	defer s.evalPool.Put(eval)

	// Deserialize ciphertexts
	left := new(tfhe.BitCiphertext)
	if err := left.UnmarshalBinary(req.Left); err != nil {
		http.Error(w, "invalid left ciphertext", http.StatusBadRequest)
		return
	}

	var result *tfhe.BitCiphertext
	var err error

	bitwiseEval := tfhe.NewBitwiseEvaluator(s.params, s.bsk, s.sk)

	switch req.Operation {
	case "add":
		right := new(tfhe.BitCiphertext)
		if err := right.UnmarshalBinary(req.Right); err != nil {
			http.Error(w, "invalid right ciphertext", http.StatusBadRequest)
			return
		}
		result, err = bitwiseEval.Add(left, right)
	case "sub":
		right := new(tfhe.BitCiphertext)
		if err := right.UnmarshalBinary(req.Right); err != nil {
			http.Error(w, "invalid right ciphertext", http.StatusBadRequest)
			return
		}
		result, err = bitwiseEval.Sub(left, right)
	case "eq":
		right := new(tfhe.BitCiphertext)
		if err := right.UnmarshalBinary(req.Right); err != nil {
			http.Error(w, "invalid right ciphertext", http.StatusBadRequest)
			return
		}
		eqResult, eqErr := bitwiseEval.Eq(left, right)
		if eqErr != nil {
			err = eqErr
		} else {
			result = tfhe.WrapBoolCiphertext(eqResult)
		}
	case "lt":
		right := new(tfhe.BitCiphertext)
		if err := right.UnmarshalBinary(req.Right); err != nil {
			http.Error(w, "invalid right ciphertext", http.StatusBadRequest)
			return
		}
		ltResult, ltErr := bitwiseEval.Lt(left, right)
		if ltErr != nil {
			err = ltErr
		} else {
			result = tfhe.WrapBoolCiphertext(ltResult)
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

func bitWidthToType(bits int) tfhe.FheUintType {
	switch bits {
	case 4:
		return tfhe.FheUint4
	case 8:
		return tfhe.FheUint8
	case 16:
		return tfhe.FheUint16
	case 32:
		return tfhe.FheUint32
	case 64:
		return tfhe.FheUint64
	case 128:
		return tfhe.FheUint128
	case 160:
		return tfhe.FheUint160
	case 256:
		return tfhe.FheUint256
	default:
		return tfhe.FheUint32
	}
}
