// Copyright (c) 2025, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

//go:build profile

package tfhe

import (
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"time"
)

// ProfileConfig holds profiling configuration
type ProfileConfig struct {
	// CPUProfile enables CPU profiling to the specified file
	CPUProfile string
	// MemProfile enables memory profiling to the specified file
	MemProfile string
	// BlockProfile enables block (contention) profiling
	BlockProfile string
	// MutexProfile enables mutex profiling
	MutexProfile string
	// TraceFile enables execution tracing
	TraceFile string
}

// Profiler wraps profiling functionality
type Profiler struct {
	config    ProfileConfig
	cpuFile   *os.File
	startTime time.Time
}

// NewProfiler creates a new profiler with the given configuration
func NewProfiler(config ProfileConfig) *Profiler {
	return &Profiler{config: config}
}

// Start begins profiling
func (p *Profiler) Start() error {
	p.startTime = time.Now()

	// Enable block profiling if requested
	if p.config.BlockProfile != "" {
		runtime.SetBlockProfileRate(1)
	}

	// Enable mutex profiling if requested
	if p.config.MutexProfile != "" {
		runtime.SetMutexProfileFraction(1)
	}

	// Start CPU profiling
	if p.config.CPUProfile != "" {
		f, err := os.Create(p.config.CPUProfile)
		if err != nil {
			return fmt.Errorf("create CPU profile: %w", err)
		}
		p.cpuFile = f
		if err := pprof.StartCPUProfile(f); err != nil {
			f.Close()
			return fmt.Errorf("start CPU profile: %w", err)
		}
	}

	return nil
}

// Stop ends profiling and writes all profile files
func (p *Profiler) Stop() error {
	duration := time.Since(p.startTime)
	fmt.Printf("Profiling duration: %v\n", duration)

	// Stop CPU profiling
	if p.cpuFile != nil {
		pprof.StopCPUProfile()
		p.cpuFile.Close()
		fmt.Printf("CPU profile written to: %s\n", p.config.CPUProfile)
	}

	// Write memory profile
	if p.config.MemProfile != "" {
		f, err := os.Create(p.config.MemProfile)
		if err != nil {
			return fmt.Errorf("create memory profile: %w", err)
		}
		defer f.Close()
		runtime.GC() // Get up-to-date statistics
		if err := pprof.WriteHeapProfile(f); err != nil {
			return fmt.Errorf("write memory profile: %w", err)
		}
		fmt.Printf("Memory profile written to: %s\n", p.config.MemProfile)
	}

	// Write block profile
	if p.config.BlockProfile != "" {
		f, err := os.Create(p.config.BlockProfile)
		if err != nil {
			return fmt.Errorf("create block profile: %w", err)
		}
		defer f.Close()
		if err := pprof.Lookup("block").WriteTo(f, 0); err != nil {
			return fmt.Errorf("write block profile: %w", err)
		}
		runtime.SetBlockProfileRate(0)
		fmt.Printf("Block profile written to: %s\n", p.config.BlockProfile)
	}

	// Write mutex profile
	if p.config.MutexProfile != "" {
		f, err := os.Create(p.config.MutexProfile)
		if err != nil {
			return fmt.Errorf("create mutex profile: %w", err)
		}
		defer f.Close()
		if err := pprof.Lookup("mutex").WriteTo(f, 0); err != nil {
			return fmt.Errorf("write mutex profile: %w", err)
		}
		runtime.SetMutexProfileFraction(0)
		fmt.Printf("Mutex profile written to: %s\n", p.config.MutexProfile)
	}

	return nil
}

// MemStats returns current memory statistics
func MemStats() runtime.MemStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m
}

// PrintMemStats prints memory statistics
func PrintMemStats() {
	m := MemStats()
	fmt.Printf("Memory Statistics:\n")
	fmt.Printf("  Alloc:       %d MB\n", m.Alloc/1024/1024)
	fmt.Printf("  TotalAlloc:  %d MB\n", m.TotalAlloc/1024/1024)
	fmt.Printf("  Sys:         %d MB\n", m.Sys/1024/1024)
	fmt.Printf("  NumGC:       %d\n", m.NumGC)
	fmt.Printf("  HeapObjects: %d\n", m.HeapObjects)
}

// Timer is a simple operation timer
type Timer struct {
	name  string
	start time.Time
}

// NewTimer creates a timer that prints duration on Stop
func NewTimer(name string) *Timer {
	return &Timer{name: name, start: time.Now()}
}

// Stop prints the elapsed time
func (t *Timer) Stop() time.Duration {
	d := time.Since(t.start)
	fmt.Printf("%s: %v\n", t.name, d)
	return d
}

// Elapsed returns elapsed time without stopping
func (t *Timer) Elapsed() time.Duration {
	return time.Since(t.start)
}
