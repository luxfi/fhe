//go:build cgo

// Lux FHE Server - Standalone FHE service node
//
// Provides:
// - FHE operations (encrypt, decrypt, evaluate)
// - GPU-accelerated batch operations via MLX
// - Threshold FHE decryption network
// - ZK verification service
// - Key management
//
// Run as sidecar for Solidity stack:
//
//	fhe-server -addr :8448 -gpu
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/luxfi/fhe/server"
)

func main() {
	var (
		addr      = flag.String("addr", ":8448", "HTTP server address")
		threshold = flag.Bool("threshold", false, "Enable threshold FHE mode")
		parties   = flag.Int("parties", 5, "Number of threshold parties")
		dataDir   = flag.String("data", "./data", "Data directory for keys")
		gpuMode   = flag.Bool("gpu", false, "Enable GPU acceleration (Metal/CUDA)")
		batchSize = flag.Int("batch", 32, "Batch size for GPU operations")
	)
	flag.Parse()

	log.Printf("Lux FHE Server starting...")
	log.Printf("  Address: %s", *addr)
	log.Printf("  GPU mode: %v", *gpuMode)
	log.Printf("  Threshold mode: %v", *threshold)
	if *threshold {
		log.Printf("  Parties: %d", *parties)
	}
	if *gpuMode {
		log.Printf("  Batch size: %d", *batchSize)
	}

	// Create server config
	cfg := server.Config{
		Address:       *addr,
		ThresholdMode: *threshold,
		NumParties:    *parties,
		DataDir:       *dataDir,
		GPUMode:       *gpuMode,
		BatchSize:     *batchSize,
	}

	// Initialize FHE server
	srv, err := server.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Setup HTTP server
	httpServer := &http.Server{
		Addr:         cfg.Address,
		Handler:      srv.Handler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Printf("FHE Server listening on %s", cfg.Address)
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down FHE Server...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}

	fmt.Println("FHE Server stopped")
}
