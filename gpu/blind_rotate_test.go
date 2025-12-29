//go:build cgo

// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package gpu

import (
	"testing"

	"github.com/luxfi/mlx"
)

func TestBatchBlindRotateBasic(t *testing.T) {
	// Initialize engine with default config
	cfg := DefaultConfig()
	engine, err := New(cfg)
	if err != nil {
		t.Skipf("GPU not available: %v", err)
		return
	}

	N := int(cfg.N)
	n := int(cfg.n)
	L := int(cfg.L)
	batchSize := 4

	// Create test LWE ciphertexts
	aVecs := make([][]uint64, batchSize)
	bVals := make([]uint64, batchSize)
	for i := 0; i < batchSize; i++ {
		aVecs[i] = make([]uint64, n)
		for j := 0; j < n; j++ {
			aVecs[i][j] = uint64((i*n + j) % 1024)
		}
		bVals[i] = uint64(i * 100)
	}

	inputs, err := engine.UploadBatchLWE(aVecs, bVals)
	if err != nil {
		t.Fatalf("UploadBatchLWE failed: %v", err)
	}

	// Create dummy bootstrap key
	bskData := make([]int64, n*2*L*2*N)
	for i := range bskData {
		bskData[i] = int64(i % 128)
	}
	bskArray := mlx.ArrayFromSlice(bskData, []int{n, 2, L, 2, N}, mlx.Int64)
	mlx.Eval(bskArray)

	bsk := &GPUBootstrapKey{
		Data:    bskArray,
		n:       n,
		L:       L,
		N:       N,
		Base:    1 << cfg.BaseLog,
		BaseLog: int(cfg.BaseLog),
	}

	// Create test polynomial
	testPoly := make([]int64, N)
	for i := 0; i < N; i++ {
		if i < N/2 {
			testPoly[i] = int64(cfg.Q / 8)
		} else {
			testPoly[i] = int64(cfg.Q - cfg.Q/8)
		}
	}
	testPolyArray := mlx.ArrayFromSlice(testPoly, []int{N}, mlx.Int64)
	mlx.Eval(testPolyArray)

	// Run batch blind rotation
	result, err := engine.BatchBlindRotate(inputs, bsk, testPolyArray)
	if err != nil {
		t.Fatalf("BatchBlindRotate failed: %v", err)
	}

	// Verify result shape
	if result.Count != batchSize {
		t.Errorf("Expected batch count %d, got %d", batchSize, result.Count)
	}

	c0Shape := result.C0.Shape()
	c1Shape := result.C1.Shape()

	if len(c0Shape) != 2 || c0Shape[0] != batchSize || c0Shape[1] != N {
		t.Errorf("C0 shape mismatch: expected [%d, %d], got %v", batchSize, N, c0Shape)
	}
	if len(c1Shape) != 2 || c1Shape[0] != batchSize || c1Shape[1] != N {
		t.Errorf("C1 shape mismatch: expected [%d, %d], got %v", batchSize, N, c1Shape)
	}

	t.Logf("BatchBlindRotate completed successfully:")
	t.Logf("  Batch size: %d", batchSize)
	t.Logf("  Ring dimension N: %d", N)
	t.Logf("  LWE dimension n: %d", n)
	t.Logf("  Decomposition levels L: %d", L)
}

func TestBlindRotateSingle(t *testing.T) {
	cfg := DefaultConfig()
	engine, err := New(cfg)
	if err != nil {
		t.Skipf("GPU not available: %v", err)
		return
	}

	N := int(cfg.N)
	n := int(cfg.n)
	L := int(cfg.L)

	// Create single LWE ciphertext
	a := make([]uint64, n)
	for j := 0; j < n; j++ {
		a[j] = uint64(j * 7 % 1024)
	}
	b := uint64(42)

	// Create bootstrap key
	bskData := make([]int64, n*2*L*2*N)
	bskArray := mlx.ArrayFromSlice(bskData, []int{n, 2, L, 2, N}, mlx.Int64)
	mlx.Eval(bskArray)

	bsk := &GPUBootstrapKey{
		Data:    bskArray,
		n:       n,
		L:       L,
		N:       N,
		Base:    1 << cfg.BaseLog,
		BaseLog: int(cfg.BaseLog),
	}

	// Create test polynomial
	testPoly := make([]uint64, N)
	for i := 0; i < N; i++ {
		testPoly[i] = uint64(cfg.Q / 8)
	}

	result, err := engine.BlindRotateSingle(a, b, bsk, testPoly)
	if err != nil {
		t.Fatalf("BlindRotateSingle failed: %v", err)
	}

	c0Shape := result.C0.Shape()
	c1Shape := result.C1.Shape()

	if len(c0Shape) != 1 || c0Shape[0] != N {
		t.Errorf("C0 shape mismatch: expected [%d], got %v", N, c0Shape)
	}
	if len(c1Shape) != 1 || c1Shape[0] != N {
		t.Errorf("C1 shape mismatch: expected [%d], got %v", N, c1Shape)
	}

	t.Logf("BlindRotateSingle completed successfully")
}

func TestBatchSampleExtract(t *testing.T) {
	cfg := DefaultConfig()
	engine, err := New(cfg)
	if err != nil {
		t.Skipf("GPU not available: %v", err)
		return
	}

	N := int(cfg.N)
	batchSize := 8

	// Create batch RLWE
	c0Data := make([]int64, batchSize*N)
	c1Data := make([]int64, batchSize*N)
	for i := range c0Data {
		c0Data[i] = int64(i % 1000)
		c1Data[i] = int64((i + 500) % 1000)
	}

	batch := &BatchRLWE{
		C0:    mlx.ArrayFromSlice(c0Data, []int{batchSize, N}, mlx.Int64),
		C1:    mlx.ArrayFromSlice(c1Data, []int{batchSize, N}, mlx.Int64),
		Count: batchSize,
	}
	mlx.Eval(batch.C0)
	mlx.Eval(batch.C1)

	result, err := engine.BatchSampleExtract(batch)
	if err != nil {
		t.Fatalf("BatchSampleExtract failed: %v", err)
	}

	if result.Count != batchSize {
		t.Errorf("Expected count %d, got %d", batchSize, result.Count)
	}

	aShape := result.A.Shape()
	bShape := result.B.Shape()

	if len(aShape) != 2 || aShape[0] != batchSize || aShape[1] != N {
		t.Errorf("A shape mismatch: expected [%d, %d], got %v", batchSize, N, aShape)
	}
	if len(bShape) != 1 || bShape[0] != batchSize {
		t.Errorf("B shape mismatch: expected [%d], got %v", batchSize, bShape)
	}

	t.Logf("BatchSampleExtract completed successfully")
}

func BenchmarkBatchBlindRotate(b *testing.B) {
	cfg := DefaultConfig()
	engine, err := New(cfg)
	if err != nil {
		b.Skipf("GPU not available: %v", err)
		return
	}

	N := int(cfg.N)
	n := int(cfg.n)
	L := int(cfg.L)
	batchSize := 1024 // Target batch size for H200

	// Setup
	aVecs := make([][]uint64, batchSize)
	bVals := make([]uint64, batchSize)
	for i := 0; i < batchSize; i++ {
		aVecs[i] = make([]uint64, n)
		for j := 0; j < n; j++ {
			aVecs[i][j] = uint64((i*n + j) % 1024)
		}
		bVals[i] = uint64(i * 100 % 1024)
	}

	inputs, _ := engine.UploadBatchLWE(aVecs, bVals)

	bskData := make([]int64, n*2*L*2*N)
	bskArray := mlx.ArrayFromSlice(bskData, []int{n, 2, L, 2, N}, mlx.Int64)
	mlx.Eval(bskArray)

	bsk := &GPUBootstrapKey{
		Data:    bskArray,
		n:       n,
		L:       L,
		N:       N,
		Base:    1 << cfg.BaseLog,
		BaseLog: int(cfg.BaseLog),
	}

	testPoly := make([]int64, N)
	for i := 0; i < N; i++ {
		testPoly[i] = int64(cfg.Q / 8)
	}
	testPolyArray := mlx.ArrayFromSlice(testPoly, []int{N}, mlx.Int64)
	mlx.Eval(testPolyArray)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := engine.BatchBlindRotate(inputs, bsk, testPolyArray)
		if err != nil {
			b.Fatal(err)
		}
		mlx.Synchronize()
	}

	b.ReportMetric(float64(batchSize*b.N)/b.Elapsed().Seconds(), "bootstraps/sec")
}
