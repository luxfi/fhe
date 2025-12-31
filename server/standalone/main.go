// Lux FHE Server - Pure Go standalone server
//
// This is a pure Go implementation that doesn't require CGO.
// Implements boolean FHE (TFHE) with programmable bootstrapping.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/luxfi/fhe"
)

type server struct {
	params fhe.Parameters
	sk     *fhe.SecretKey
	pk     *fhe.PublicKey
	bsk    *fhe.BootstrapKey
	enc    *fhe.Encryptor
	dec    *fhe.Decryptor
	eval   *fhe.Evaluator
}

func main() {
	var (
		addr      = flag.String("addr", ":8448", "HTTP server address")
		threshold = flag.Bool("threshold", false, "Enable threshold FHE mode")
		parties   = flag.Int("parties", 5, "Number of threshold parties")
		dataDir   = flag.String("data", "./data", "Data directory for keys")
	)
	flag.Parse()

	log.Printf("Lux FHE Server (Pure Go) starting...")
	log.Printf("  Address: %s", *addr)
	log.Printf("  Threshold mode: %v", *threshold)
	if *threshold {
		log.Printf("  Parties: %d", *parties)
	}
	log.Printf("  Data dir: %s", *dataDir)

	// Ensure data directory exists
	if err := os.MkdirAll(*dataDir, 0755); err != nil {
		log.Fatalf("Failed to create data directory: %v", err)
	}

	// Create FHE context with 128-bit security parameters
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		log.Fatalf("Failed to create parameters: %v", err)
	}

	// Generate keys
	kgen := fhe.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()
	bsk := kgen.GenBootstrapKey(sk)

	log.Printf("FHE keys generated (128-bit security)")

	srv := &server{
		params: params,
		sk:     sk,
		pk:     pk,
		bsk:    bsk,
		enc:    fhe.NewEncryptor(params, sk), // Encryptor uses secret key
		dec:    fhe.NewDecryptor(params, sk),
		eval:   fhe.NewEvaluator(params, bsk),
	}

	// Create HTTP handler
	mux := http.NewServeMux()

	// Health check
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "ok",
			"version":  "1.0.0",
			"security": "128-bit",
			"mode":     "boolean-fhe",
		})
	})

	// Encrypt bit endpoint
	mux.HandleFunc("/encrypt/bit", srv.handleEncryptBit)

	// Encrypt uint8 endpoint (8 bits)
	mux.HandleFunc("/encrypt/uint8", srv.handleEncryptUint8)

	// Decrypt bit endpoint
	mux.HandleFunc("/decrypt/bit", srv.handleDecryptBit)

	// Decrypt uint8 endpoint
	mux.HandleFunc("/decrypt/uint8", srv.handleDecryptUint8)

	// Boolean gate endpoints
	mux.HandleFunc("/gate/and", srv.handleGateAND)
	mux.HandleFunc("/gate/or", srv.handleGateOR)
	mux.HandleFunc("/gate/xor", srv.handleGateXOR)
	mux.HandleFunc("/gate/not", srv.handleGateNOT)
	mux.HandleFunc("/gate/nand", srv.handleGateNAND)

	// Integer operations (on encrypted bits)
	mux.HandleFunc("/op/add", srv.handleAdd)
	mux.HandleFunc("/op/compare", srv.handleCompare)

	// Setup HTTP server
	httpServer := &http.Server{
		Addr:         *addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Printf("FHE Server listening on %s", *addr)
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down FHE Server...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}

	fmt.Println("FHE Server stopped")
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func intToBool(i int) bool {
	return i != 0
}

func (s *server) handleEncryptBit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Value bool `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ct := s.enc.EncryptBit(boolToInt(req.Value))
	data, err := ct.MarshalBinary()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"ciphertext": hex.EncodeToString(data),
	})
}

func (s *server) handleEncryptUint8(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Value uint8 `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Encrypt each bit
	bits := make([]*fhe.Ciphertext, 8)
	for i := 0; i < 8; i++ {
		bit := int((req.Value >> i) & 1)
		bits[i] = s.enc.EncryptBit(bit)
	}

	// Serialize all bits
	result := make([]string, 8)
	for i, ct := range bits {
		data, err := ct.MarshalBinary()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		result[i] = hex.EncodeToString(data)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string][]string{
		"ciphertexts": result,
	})
}

func (s *server) handleDecryptBit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	data, err := hex.DecodeString(req.Ciphertext)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ct := new(fhe.Ciphertext)
	if err := ct.UnmarshalBinary(data); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	bit := s.dec.DecryptBit(ct)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{
		"value": intToBool(bit),
	})
}

func (s *server) handleDecryptUint8(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Ciphertexts []string `json:"ciphertexts"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if len(req.Ciphertexts) != 8 {
		http.Error(w, "expected 8 ciphertexts for uint8", http.StatusBadRequest)
		return
	}

	var result uint8
	for i, ctHex := range req.Ciphertexts {
		data, err := hex.DecodeString(ctHex)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		ct := new(fhe.Ciphertext)
		if err := ct.UnmarshalBinary(data); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		bit := s.dec.DecryptBit(ct)
		if bit != 0 {
			result |= 1 << i
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]uint8{
		"value": result,
	})
}

func (s *server) parseGateRequest(r *http.Request) (*fhe.Ciphertext, *fhe.Ciphertext, error) {
	var req struct {
		A string `json:"a"`
		B string `json:"b"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, nil, err
	}

	dataA, err := hex.DecodeString(req.A)
	if err != nil {
		return nil, nil, err
	}
	ctA := new(fhe.Ciphertext)
	if err := ctA.UnmarshalBinary(dataA); err != nil {
		return nil, nil, err
	}

	dataB, err := hex.DecodeString(req.B)
	if err != nil {
		return nil, nil, err
	}
	ctB := new(fhe.Ciphertext)
	if err := ctB.UnmarshalBinary(dataB); err != nil {
		return nil, nil, err
	}

	return ctA, ctB, nil
}

func (s *server) returnCiphertext(w http.ResponseWriter, ct *fhe.Ciphertext) {
	data, err := ct.MarshalBinary()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"result": hex.EncodeToString(data),
	})
}

func (s *server) handleGateAND(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctA, ctB, err := s.parseGateRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	result, err := s.eval.AND(ctA, ctB)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.returnCiphertext(w, result)
}

func (s *server) handleGateOR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctA, ctB, err := s.parseGateRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	result, err := s.eval.OR(ctA, ctB)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.returnCiphertext(w, result)
}

func (s *server) handleGateXOR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctA, ctB, err := s.parseGateRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	result, err := s.eval.XOR(ctA, ctB)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.returnCiphertext(w, result)
}

func (s *server) handleGateNOT(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		A string `json:"a"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	data, err := hex.DecodeString(req.A)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ct := new(fhe.Ciphertext)
	if err := ct.UnmarshalBinary(data); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	result := s.eval.NOT(ct)
	s.returnCiphertext(w, result)
}

func (s *server) handleGateNAND(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctA, ctB, err := s.parseGateRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	result, err := s.eval.NAND(ctA, ctB)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.returnCiphertext(w, result)
}

func (s *server) handleAdd(w http.ResponseWriter, r *http.Request) {
	// Integer addition on encrypted bits using ripple carry
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func (s *server) handleCompare(w http.ResponseWriter, r *http.Request) {
	// Integer comparison on encrypted bits
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}
