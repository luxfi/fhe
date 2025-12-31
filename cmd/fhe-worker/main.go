// Command fhe-worker runs FHE computation workers.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/luxfi/fhe"
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
		numWorkers  = flag.Int("workers", 4, "number of worker goroutines")
		redisAddr   = flag.String("redis", "localhost:6379", "Redis address")
		redisDB     = flag.Int("redis-db", 0, "Redis database number")
		queueName   = flag.String("queue", "default", "queue name")
		storagePath = flag.String("storage", "/tmp/fhe-storage", "ciphertext storage path")
		metricsAddr = flag.String("metrics", ":9090", "metrics server address")
	)
	flag.Parse()

	log.Printf("FHE Worker starting...")
	log.Printf("  Workers: %d", *numWorkers)
	log.Printf("  Redis: %s", *redisAddr)
	log.Printf("  Storage: %s", *storagePath)
	log.Printf("  Metrics: %s", *metricsAddr)

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

	// Initialize FHE parameters
	params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
	if err != nil {
		return fmt.Errorf("create FHE parameters: %w", err)
	}

	kgen := fhe.NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	bsk := kgen.GenBootstrapKey(sk)

	// Worker pool.
	pool := &WorkerPool{
		numWorkers: *numWorkers,
		queue:      q,
		storage:    store,
		params:     params,
		bsk:        bsk,
		sk:         sk,
	}

	// Context with cancellation.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start workers.
	if err := pool.Start(ctx); err != nil {
		return fmt.Errorf("start workers: %w", err)
	}

	// Metrics server.
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "# HELP fhe_operations_total Total FHE operations\n")
		fmt.Fprintf(w, "# TYPE fhe_operations_total counter\n")
		fmt.Fprintf(w, "fhe_operations_total{status=\"success\"} %d\n", pool.successCount.Load())
		fmt.Fprintf(w, "fhe_operations_total{status=\"failure\"} %d\n", pool.failureCount.Load())
	})

	server := &http.Server{
		Addr:    *metricsAddr,
		Handler: mux,
	}

	go func() {
		log.Printf("Metrics server starting on %s", *metricsAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Metrics server error: %v", err)
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
		log.Printf("Metrics server shutdown error: %v", err)
	}

	if err := pool.Stop(); err != nil {
		log.Printf("Worker pool shutdown error: %v", err)
	}

	log.Println("Shutdown complete")
	return nil
}

// WorkerPool manages a pool of FHE computation workers.
type WorkerPool struct {
	numWorkers   int
	queue        queue.Queue
	storage      storage.Storage
	params       fhe.Parameters
	bsk          *fhe.BootstrapKey
	sk           *fhe.SecretKey
	wg           sync.WaitGroup
	cancel       context.CancelFunc
	running      atomic.Bool
	successCount atomic.Int64
	failureCount atomic.Int64
}

// Start starts the worker pool.
func (p *WorkerPool) Start(ctx context.Context) error {
	if p.running.Load() {
		return errors.New("pool already running")
	}

	ctx, p.cancel = context.WithCancel(ctx)
	p.running.Store(true)

	log.Printf("Starting %d workers", p.numWorkers)

	for i := 0; i < p.numWorkers; i++ {
		p.wg.Add(1)
		go p.worker(ctx, i)
	}

	return nil
}

// Stop gracefully stops the worker pool.
func (p *WorkerPool) Stop() error {
	if !p.running.Load() {
		return nil
	}

	log.Println("Stopping worker pool...")
	p.cancel()

	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("Worker pool stopped")
	case <-time.After(30 * time.Second):
		log.Println("Shutdown timeout exceeded")
		return errors.New("shutdown timeout")
	}

	p.running.Store(false)
	return nil
}

func (p *WorkerPool) worker(ctx context.Context, id int) {
	defer p.wg.Done()

	log.Printf("Worker %d started", id)

	for {
		select {
		case <-ctx.Done():
			log.Printf("Worker %d stopping", id)
			return
		default:
		}

		job, err := p.queue.Pop(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			log.Printf("Worker %d: failed to pop job: %v", id, err)
			time.Sleep(time.Second)
			continue
		}

		p.processJob(ctx, id, job)
	}
}

func (p *WorkerPool) processJob(ctx context.Context, workerID int, job *queue.Job) {
	log.Printf("Worker %d: processing job %s (op=%d)", workerID, job.ID, job.Operation)

	// Mark as processing.
	job.Status = queue.StatusProcessing
	if err := p.queue.Update(ctx, job); err != nil {
		log.Printf("Worker %d: failed to update job status: %v", workerID, err)
	}

	// Load ciphertexts
	lhsData, err := p.storage.Load(ctx, storage.Handle(job.LHSHandle))
	if err != nil {
		job.Status = queue.StatusFailed
		job.Error = fmt.Sprintf("load lhs: %v", err)
		p.queue.Update(ctx, job)
		p.failureCount.Add(1)
		return
	}

	// Create evaluator
	bitwiseEval := fhe.NewBitwiseEvaluator(p.params, p.bsk, p.sk)

	// Deserialize LHS
	lhs := new(fhe.BitCiphertext)
	if err := lhs.UnmarshalBinary(lhsData); err != nil {
		job.Status = queue.StatusFailed
		job.Error = fmt.Sprintf("unmarshal lhs: %v", err)
		p.queue.Update(ctx, job)
		p.failureCount.Add(1)
		return
	}

	var result *fhe.BitCiphertext

	// Execute operation
	switch job.Operation {
	case 0: // Add
		rhsData, err := p.storage.Load(ctx, storage.Handle(job.RHSHandle))
		if err != nil {
			job.Status = queue.StatusFailed
			job.Error = fmt.Sprintf("load rhs: %v", err)
			p.queue.Update(ctx, job)
			p.failureCount.Add(1)
			return
		}
		rhs := new(fhe.BitCiphertext)
		if err := rhs.UnmarshalBinary(rhsData); err != nil {
			job.Status = queue.StatusFailed
			job.Error = fmt.Sprintf("unmarshal rhs: %v", err)
			p.queue.Update(ctx, job)
			p.failureCount.Add(1)
			return
		}
		result, err = bitwiseEval.Add(lhs, rhs)
		if err != nil {
			job.Status = queue.StatusFailed
			job.Error = fmt.Sprintf("add: %v", err)
			p.queue.Update(ctx, job)
			p.failureCount.Add(1)
			return
		}
	default:
		job.Status = queue.StatusFailed
		job.Error = fmt.Sprintf("unsupported operation: %d", job.Operation)
		p.queue.Update(ctx, job)
		p.failureCount.Add(1)
		return
	}

	// Store result
	resultData, err := result.MarshalBinary()
	if err != nil {
		job.Status = queue.StatusFailed
		job.Error = fmt.Sprintf("marshal result: %v", err)
		p.queue.Update(ctx, job)
		p.failureCount.Add(1)
		return
	}

	handle, err := p.storage.Store(ctx, resultData)
	if err != nil {
		job.Status = queue.StatusFailed
		job.Error = fmt.Sprintf("store result: %v", err)
		p.queue.Update(ctx, job)
		p.failureCount.Add(1)
		return
	}

	// Update job status.
	job.Status = queue.StatusCompleted
	job.ResultHandle = string(handle)
	if err := p.queue.Update(ctx, job); err != nil {
		log.Printf("Worker %d: failed to update job result: %v", workerID, err)
	}

	p.successCount.Add(1)
	log.Printf("Worker %d: job %s completed", workerID, job.ID)
}
