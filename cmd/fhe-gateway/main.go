// Command fhe-gateway runs the blockchain event listener and job gateway.
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

	"github.com/luxfi/fhe/internal/queue"
	"github.com/luxfi/fhe/internal/storage"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		redisAddr   = flag.String("redis", "localhost:6379", "Redis address")
		redisDB     = flag.Int("redis-db", 0, "Redis database number")
		queueName   = flag.String("queue", "default", "queue name")
		storagePath = flag.String("storage", "/tmp/fhe-storage", "ciphertext storage path")
		httpAddr    = flag.String("http", ":8080", "HTTP API address")
		rpcURL      = flag.String("rpc", "", "Blockchain RPC URL")
	)
	flag.Parse()

	log.Printf("FHE Gateway starting...")
	log.Printf("  Redis: %s", *redisAddr)
	log.Printf("  Storage: %s", *storagePath)
	log.Printf("  HTTP: %s", *httpAddr)
	if *rpcURL != "" {
		log.Printf("  RPC: %s", *rpcURL)
	}

	// Queue.
	q, err := queue.NewRedisQueue(queue.RedisConfig{
		Addr: *redisAddr,
		DB:   *redisDB,
	}, *queueName)
	if err != nil {
		return fmt.Errorf("create queue: %w", err)
	}
	defer q.Close()

	// Storage.
	store, err := storage.NewFileStorage(*storagePath)
	if err != nil {
		return fmt.Errorf("create storage: %w", err)
	}

	// Context with cancellation.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// HTTP API.
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"status":"running"}`)
	})

	mux.HandleFunc("/job/", func(w http.ResponseWriter, r *http.Request) {
		jobID := r.URL.Path[len("/job/"):]
		if jobID == "" {
			http.Error(w, "job ID required", http.StatusBadRequest)
			return
		}

		job, err := q.Get(r.Context(), jobID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":"%s","status":%d,"result":"%s","error":"%s"}`,
			job.ID, job.Status, job.ResultHandle, job.Error)
	})

	// Store ciphertext endpoint
	mux.HandleFunc("/store", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}

		data := make([]byte, r.ContentLength)
		if _, err := r.Body.Read(data); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		handle, err := store.Store(r.Context(), data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"handle":"%s"}`, handle)
	})

	server := &http.Server{
		Addr:         *httpAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("HTTP server starting on %s", *httpAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	// Wait for shutdown signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigCh
	log.Printf("Received signal: %s", sig.String())

	// Graceful shutdown.
	shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 30*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("HTTP server shutdown error: %v", err)
	}

	log.Println("Shutdown complete")
	return nil
}
