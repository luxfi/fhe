//go:build cgo

package gpu

import (
	"testing"
)

// Test parameters - TFHE standard
const (
	testN = 1024
	testQ = 1 << 27 // 134217728 - a prime where Q-1 is divisible by 2N
)

// Actually use Q = 132120577 which is prime and Q-1 = 132120576 = 2^11 * 64509 = 2048 * 64509
// For N=1024, we need Q-1 divisible by 2048, which works.
const tfheQ = 132120577

func TestNewNTTContext(t *testing.T) {
	ctx, err := NewNTTContext(testN, tfheQ)
	if err != nil {
		t.Fatalf("NewNTTContext failed: %v", err)
	}

	if ctx.N != testN {
		t.Errorf("N = %d, want %d", ctx.N, testN)
	}
	if ctx.Q != tfheQ {
		t.Errorf("Q = %d, want %d", ctx.Q, tfheQ)
	}
	if ctx.Log2N != 10 { // log2(1024) = 10
		t.Errorf("Log2N = %d, want 10", ctx.Log2N)
	}

	// Verify nInv * N = 1 mod Q
	check := mulModNTT(ctx.nInv, uint64(ctx.N), ctx.Q)
	if check != 1 {
		t.Errorf("nInv * N = %d mod Q, want 1", check)
	}

	// Verify twiddle factors are populated
	if len(ctx.twiddleFactors) != int(ctx.N) {
		t.Errorf("len(twiddleFactors) = %d, want %d", len(ctx.twiddleFactors), ctx.N)
	}
	if len(ctx.invTwiddleFactors) != int(ctx.N) {
		t.Errorf("len(invTwiddleFactors) = %d, want %d", len(ctx.invTwiddleFactors), ctx.N)
	}

	// First twiddle should be 1
	if ctx.twiddleFactors[0] != 1 {
		t.Errorf("twiddleFactors[0] = %d, want 1", ctx.twiddleFactors[0])
	}
	if ctx.invTwiddleFactors[0] != 1 {
		t.Errorf("invTwiddleFactors[0] = %d, want 1", ctx.invTwiddleFactors[0])
	}
}

func TestNTTRoundtrip(t *testing.T) {
	ctx, err := NewNTTContext(testN, tfheQ)
	if err != nil {
		t.Fatalf("NewNTTContext failed: %v", err)
	}

	// Create test polynomial
	poly := make([]uint64, testN)
	for i := 0; i < testN; i++ {
		poly[i] = uint64(i * 17 % int(tfheQ))
	}

	// Forward NTT
	nttPoly, err := ctx.NTTSingle(poly)
	if err != nil {
		t.Fatalf("NTT failed: %v", err)
	}

	// Inverse NTT
	recovered, err := ctx.INTTSingle(nttPoly)
	if err != nil {
		t.Fatalf("INTT failed: %v", err)
	}

	// Verify roundtrip
	for i := 0; i < testN; i++ {
		if recovered[i] != poly[i] {
			t.Errorf("recovered[%d] = %d, want %d", i, recovered[i], poly[i])
			if i > 5 {
				t.FailNow()
			}
		}
	}
}

func TestNTTBatch(t *testing.T) {
	ctx, err := NewNTTContext(testN, tfheQ)
	if err != nil {
		t.Fatalf("NewNTTContext failed: %v", err)
	}

	// Create batch of test polynomials
	batchSize := 8
	polys := make([][]uint64, batchSize)
	for b := 0; b < batchSize; b++ {
		polys[b] = make([]uint64, testN)
		for i := 0; i < testN; i++ {
			polys[b][i] = uint64((b*1000 + i) % int(tfheQ))
		}
	}

	// Forward NTT batch
	nttPolys, err := ctx.NTT(polys)
	if err != nil {
		t.Fatalf("NTT batch failed: %v", err)
	}

	// Inverse NTT batch
	recovered, err := ctx.INTT(nttPolys)
	if err != nil {
		t.Fatalf("INTT batch failed: %v", err)
	}

	// Verify roundtrip
	for b := 0; b < batchSize; b++ {
		for i := 0; i < testN; i++ {
			if recovered[b][i] != polys[b][i] {
				t.Errorf("batch[%d][%d] = %d, want %d", b, i, recovered[b][i], polys[b][i])
				if i > 5 {
					break
				}
			}
		}
	}
}

func TestPolyMul(t *testing.T) {
	ctx, err := NewNTTContext(testN, tfheQ)
	if err != nil {
		t.Fatalf("NewNTTContext failed: %v", err)
	}

	// Simple test: multiply by 1 polynomial
	poly := make([]uint64, testN)
	one := make([]uint64, testN)
	poly[0] = 42
	poly[1] = 17
	one[0] = 1 // 1 + 0*X + 0*X^2 + ...

	result, err := ctx.PolyMulSingle(poly, one)
	if err != nil {
		t.Fatalf("PolyMul failed: %v", err)
	}

	// Result should be same as poly (multiplied by 1)
	for i := 0; i < testN; i++ {
		if result[i] != poly[i] {
			t.Errorf("result[%d] = %d, want %d", i, result[i], poly[i])
		}
	}
}

func TestPolyAdd(t *testing.T) {
	ctx, err := NewNTTContext(testN, tfheQ)
	if err != nil {
		t.Fatalf("NewNTTContext failed: %v", err)
	}

	a := make([]uint64, testN)
	b := make([]uint64, testN)
	for i := 0; i < testN; i++ {
		a[i] = uint64(i)
		b[i] = uint64(100)
	}

	result := ctx.PolyAdd(a, b)
	for i := 0; i < testN; i++ {
		expected := uint64(i + 100)
		if result[i] != expected {
			t.Errorf("result[%d] = %d, want %d", i, result[i], expected)
		}
	}
}

func TestPolySub(t *testing.T) {
	ctx, err := NewNTTContext(testN, tfheQ)
	if err != nil {
		t.Fatalf("NewNTTContext failed: %v", err)
	}

	a := make([]uint64, testN)
	b := make([]uint64, testN)
	for i := 0; i < testN; i++ {
		a[i] = uint64(i + 100)
		b[i] = uint64(100)
	}

	result := ctx.PolySub(a, b)
	for i := 0; i < testN; i++ {
		expected := uint64(i)
		if result[i] != expected {
			t.Errorf("result[%d] = %d, want %d", i, result[i], expected)
		}
	}
}

func TestPolyRotate(t *testing.T) {
	ctx, err := NewNTTContext(testN, tfheQ)
	if err != nil {
		t.Fatalf("NewNTTContext failed: %v", err)
	}

	// Simple polynomial: 1 + 2*X
	poly := make([]uint64, testN)
	poly[0] = 1
	poly[1] = 2

	// Rotate by 1: X * (1 + 2*X) = X + 2*X^2
	rotated := ctx.PolyRotate(poly, 1)
	if rotated[0] != 0 {
		t.Errorf("rotated[0] = %d, want 0", rotated[0])
	}
	if rotated[1] != 1 {
		t.Errorf("rotated[1] = %d, want 1", rotated[1])
	}
	if rotated[2] != 2 {
		t.Errorf("rotated[2] = %d, want 2", rotated[2])
	}
}

func TestModularArithmetic(t *testing.T) {
	Q := uint64(tfheQ)

	// Test addMod
	if addModNTT(Q-1, 2, Q) != 1 {
		t.Error("addMod wrap failed")
	}
	if addModNTT(10, 20, Q) != 30 {
		t.Error("addMod simple failed")
	}

	// Test subMod
	if subModNTT(2, Q-1, Q) != 3 {
		t.Error("subMod wrap failed")
	}
	if subModNTT(20, 10, Q) != 10 {
		t.Error("subMod simple failed")
	}

	// Test mulMod
	if mulModNTT(2, 3, Q) != 6 {
		t.Error("mulMod simple failed")
	}

	// Test powMod
	if powModNTT(2, 10, Q) != 1024 {
		t.Error("powMod 2^10 failed")
	}

	// Test modInverse: a * a^(-1) = 1 mod Q
	a := uint64(12345)
	aInv := modInverseNTT(a, Q)
	if mulModNTT(a, aInv, Q) != 1 {
		t.Errorf("modInverse failed: %d * %d = %d mod %d", a, aInv, mulModNTT(a, aInv, Q), Q)
	}
}

func BenchmarkNTTSingle(b *testing.B) {
	ctx, err := NewNTTContext(testN, tfheQ)
	if err != nil {
		b.Fatalf("NewNTTContext failed: %v", err)
	}

	poly := make([]uint64, testN)
	for i := 0; i < testN; i++ {
		poly[i] = uint64(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ctx.NTTSingle(poly)
	}
}

func BenchmarkNTTBatch8(b *testing.B) {
	ctx, err := NewNTTContext(testN, tfheQ)
	if err != nil {
		b.Fatalf("NewNTTContext failed: %v", err)
	}

	polys := make([][]uint64, 8)
	for j := 0; j < 8; j++ {
		polys[j] = make([]uint64, testN)
		for i := 0; i < testN; i++ {
			polys[j][i] = uint64(i + j*1000)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ctx.NTT(polys)
	}
}

func BenchmarkPolyMul(b *testing.B) {
	ctx, err := NewNTTContext(testN, tfheQ)
	if err != nil {
		b.Fatalf("NewNTTContext failed: %v", err)
	}

	a := make([]uint64, testN)
	c := make([]uint64, testN)
	for i := 0; i < testN; i++ {
		a[i] = uint64(i)
		c[i] = uint64(testN - i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ctx.PolyMulSingle(a, c)
	}
}
