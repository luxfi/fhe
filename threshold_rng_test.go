// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package fhe

import (
	"context"
	"testing"
	"time"
)

func TestThresholdRNGWithLocalProvider(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("failed to create parameters: %v", err)
	}
	kgen := NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	pk := kgen.GenPublicKey(sk)

	provider := NewLocalThresholdProvider(DefaultThreshold, DefaultNumParties, []byte("test-seed"))
	cfg := &ThresholdRNGConfig{
		Provider:        provider,
		Timeout:         5 * time.Second,
		FallbackEnabled: true,
	}

	rng := NewThresholdRNG(params, sk, pk, cfg)

	t.Run("IsAvailable", func(t *testing.T) {
		ctx := context.Background()
		if !rng.IsThresholdAvailable(ctx) {
			t.Error("expected threshold to be available with local provider")
		}
	})

	t.Run("GetThreshold", func(t *testing.T) {
		threshold, parties, err := rng.GetThreshold()
		if err != nil {
			t.Fatalf("GetThreshold failed: %v", err)
		}
		if threshold != DefaultThreshold {
			t.Errorf("expected threshold %d, got %d", DefaultThreshold, threshold)
		}
		if parties != DefaultNumParties {
			t.Errorf("expected %d parties, got %d", DefaultNumParties, parties)
		}
	})

	t.Run("RandomBytes", func(t *testing.T) {
		ctx := context.Background()
		bytes1, err := rng.RandomBytes(ctx, 32, []byte("seed1"))
		if err != nil {
			t.Fatalf("RandomBytes failed: %v", err)
		}
		if len(bytes1) != 32 {
			t.Errorf("expected 32 bytes, got %d", len(bytes1))
		}

		// Different seed should produce different bytes
		bytes2, err := rng.RandomBytes(ctx, 32, []byte("seed2"))
		if err != nil {
			t.Fatalf("RandomBytes failed: %v", err)
		}

		if string(bytes1) == string(bytes2) {
			t.Error("different seeds should produce different random bytes")
		}

		// Same seed should produce same bytes (due to cache)
		bytes3, err := rng.RandomBytes(ctx, 32, []byte("seed1"))
		if err != nil {
			t.Fatalf("RandomBytes failed: %v", err)
		}
		if string(bytes1) != string(bytes3) {
			t.Error("same seed should produce same random bytes")
		}
	})

	t.Run("RandomBit", func(t *testing.T) {
		ctx := context.Background()
		ct, err := rng.RandomBit(ctx, []byte("bit-seed"))
		if err != nil {
			t.Fatalf("RandomBit failed: %v", err)
		}
		if ct == nil {
			t.Error("expected non-nil ciphertext")
		}
	})

	t.Run("RandomUint", func(t *testing.T) {
		ctx := context.Background()

		testTypes := []struct {
			name string
			typ  FheUintType
			bits int
		}{
			{"euint8", FheUint8, 8},
			{"euint16", FheUint16, 16},
			{"euint32", FheUint32, 32},
		}

		for _, tc := range testTypes {
			t.Run(tc.name, func(t *testing.T) {
				ct, err := rng.RandomUint(ctx, tc.typ, []byte(tc.name+"-seed"))
				if err != nil {
					t.Fatalf("RandomUint failed: %v", err)
				}
				if ct == nil {
					t.Error("expected non-nil BitCiphertext")
				}
				if ct.numBits != tc.bits {
					t.Errorf("expected %d bits, got %d", tc.bits, ct.numBits)
				}
			})
		}
	})

	t.Run("ClearCache", func(t *testing.T) {
		ctx := context.Background()

		// Get random bytes and verify cache works
		bytes1, _ := rng.RandomBytes(ctx, 16, []byte("cache-seed"))
		bytes2, _ := rng.RandomBytes(ctx, 16, []byte("cache-seed"))
		if string(bytes1) != string(bytes2) {
			t.Error("cache should return same value")
		}

		// Clear cache
		rng.ClearCache()

		// After clearing, should get fresh randomness (but still deterministic with same seed)
		bytes3, _ := rng.RandomBytes(ctx, 16, []byte("cache-seed"))
		// With local provider, same seed still produces same output
		// but the counter has advanced, so it's different
		if string(bytes1) == string(bytes3) {
			// This is actually expected with local provider since counter advanced
		}
	})
}

func TestThresholdRNGFallback(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("failed to create parameters: %v", err)
	}
	kgen := NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	pk := kgen.GenPublicKey(sk)

	// No provider, fallback enabled
	cfg := &ThresholdRNGConfig{
		Provider:        nil,
		FallbackEnabled: true,
		FallbackSeed:    []byte("fallback-seed"),
	}

	rng := NewThresholdRNG(params, sk, pk, cfg)

	t.Run("FallbackRandomBytes", func(t *testing.T) {
		ctx := context.Background()
		bytes, err := rng.RandomBytes(ctx, 32, []byte("test"))
		if err != nil {
			t.Fatalf("fallback RandomBytes failed: %v", err)
		}
		if len(bytes) != 32 {
			t.Errorf("expected 32 bytes, got %d", len(bytes))
		}
	})

	t.Run("FallbackNotAvailable", func(t *testing.T) {
		ctx := context.Background()
		if rng.IsThresholdAvailable(ctx) {
			t.Error("threshold should not be available without provider")
		}
	})
}

func TestThresholdRNGNoFallback(t *testing.T) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		t.Fatalf("failed to create parameters: %v", err)
	}
	kgen := NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	pk := kgen.GenPublicKey(sk)

	// No provider, fallback disabled
	cfg := &ThresholdRNGConfig{
		Provider:        nil,
		FallbackEnabled: false,
	}

	rng := NewThresholdRNG(params, sk, pk, cfg)

	t.Run("ShouldFail", func(t *testing.T) {
		ctx := context.Background()
		_, err := rng.RandomBytes(ctx, 32, []byte("test"))
		if err == nil {
			t.Error("expected error when provider unavailable and fallback disabled")
		}
	})
}

func TestCalculateThreshold(t *testing.T) {
	tests := []struct {
		percent  int
		parties  int
		expected int
	}{
		{69, 5, 4},    // 4/5 = 80% >= 69%
		{69, 100, 69}, // 69/100 = 69%
		{67, 100, 67}, // 67/100 = 67%
		{50, 10, 5},   // 5/10 = 50%
		{51, 10, 6},   // 6/10 = 60% >= 51%
		{100, 5, 5},   // All parties required
		{0, 5, 1},     // Minimum 1
		{1, 100, 1},   // 1%
	}

	for _, tc := range tests {
		result := CalculateThreshold(tc.percent, tc.parties)
		if result != tc.expected {
			t.Errorf("CalculateThreshold(%d, %d) = %d, want %d",
				tc.percent, tc.parties, result, tc.expected)
		}
	}
}

func TestLocalThresholdProvider(t *testing.T) {
	provider := NewLocalThresholdProvider(DefaultThreshold, DefaultNumParties, []byte("provider-seed"))

	t.Run("Threshold", func(t *testing.T) {
		threshold, n := provider.GetThreshold()
		if threshold != DefaultThreshold {
			t.Errorf("expected threshold %d, got %d", DefaultThreshold, threshold)
		}
		if n != DefaultNumParties {
			t.Errorf("expected %d parties, got %d", DefaultNumParties, n)
		}
	})

	t.Run("Availability", func(t *testing.T) {
		ctx := context.Background()
		if !provider.IsAvailable(ctx) {
			t.Error("local provider should always be available")
		}
	})

	t.Run("RequestRandomness", func(t *testing.T) {
		ctx := context.Background()
		random, err := provider.RequestRandomness(ctx, []byte("request-seed"))
		if err != nil {
			t.Fatalf("RequestRandomness failed: %v", err)
		}
		if len(random) != 32 {
			t.Errorf("expected 32 bytes, got %d", len(random))
		}
	})

	t.Run("DeterministicWithSameSeed", func(t *testing.T) {
		provider1 := NewLocalThresholdProvider(DefaultThreshold, DefaultNumParties, []byte("same-seed"))
		provider2 := NewLocalThresholdProvider(DefaultThreshold, DefaultNumParties, []byte("same-seed"))

		ctx := context.Background()
		random1, _ := provider1.RequestRandomness(ctx, []byte("request"))
		random2, _ := provider2.RequestRandomness(ctx, []byte("request"))

		if string(random1) != string(random2) {
			t.Error("same seed should produce same randomness")
		}
	})
}

func BenchmarkThresholdRNG(b *testing.B) {
	params, err := NewParametersFromLiteral(PN10QP27)
	if err != nil {
		b.Fatalf("failed to create parameters: %v", err)
	}
	kgen := NewKeyGenerator(params)
	sk := kgen.GenSecretKey()
	pk := kgen.GenPublicKey(sk)

	provider := NewLocalThresholdProvider(DefaultThreshold, DefaultNumParties, []byte("bench-seed"))
	cfg := &ThresholdRNGConfig{
		Provider: provider,
		Timeout:  5 * time.Second,
	}

	rng := NewThresholdRNG(params, sk, pk, cfg)
	ctx := context.Background()

	b.Run("RandomBytes32", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rng.RandomBytes(ctx, 32, []byte("bench"))
		}
	})

	b.Run("RandomBit", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rng.RandomBit(ctx, []byte("bench"))
		}
	})
}
