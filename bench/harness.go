// Copyright (c) 2026, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package bench

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// HostInfo captures the environment of a benchmark run so that two runs
// on different days are byte-comparable.
type HostInfo struct {
	Time          string `json:"time"`
	GoVersion     string `json:"go_version"`
	GOOS          string `json:"goos"`
	GOARCH        string `json:"goarch"`
	NumCPU        int    `json:"num_cpu"`
	GOMAXPROCS    int    `json:"gomaxprocs"`
	CPUBrand      string `json:"cpu_brand,omitempty"`
	OSProduct     string `json:"os_product,omitempty"`
	OSVersion     string `json:"os_version,omitempty"`
	BuildTags     string `json:"build_tags"`
	FHECommit     string `json:"fhe_commit,omitempty"`
	LatticeCommit string `json:"lattice_commit,omitempty"`
}

// CollectHostInfo populates a HostInfo. cpu/os fields are best-effort
// (Darwin only). Failures are silently ignored -- this is a record, not
// a precondition.
func CollectHostInfo(buildTags string) HostInfo {
	info := HostInfo{
		Time:       time.Now().UTC().Format(time.RFC3339),
		GoVersion:  runtime.Version(),
		GOOS:       runtime.GOOS,
		GOARCH:     runtime.GOARCH,
		NumCPU:     runtime.NumCPU(),
		GOMAXPROCS: runtime.GOMAXPROCS(0),
		BuildTags:  buildTags,
	}

	if runtime.GOOS == "darwin" {
		if out, err := exec.Command("sysctl", "-n", "machdep.cpu.brand_string").Output(); err == nil {
			info.CPUBrand = strings.TrimSpace(string(out))
		}
		if out, err := exec.Command("sw_vers", "-productName").Output(); err == nil {
			info.OSProduct = strings.TrimSpace(string(out))
		}
		if out, err := exec.Command("sw_vers", "-productVersion").Output(); err == nil {
			info.OSVersion = strings.TrimSpace(string(out))
		}
	}

	if commit := gitCommit("/Users/z/work/lux/fhe"); commit != "" {
		info.FHECommit = commit
	}
	if commit := gitCommit("/Users/z/work/lux/lattice"); commit != "" {
		info.LatticeCommit = commit
	}

	return info
}

func gitCommit(dir string) string {
	cmd := exec.Command("git", "-C", dir, "rev-parse", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// Sample is a single timed iteration in nanoseconds.
type Sample int64

// Cell is one (parameter combination) row in the ladder. Latencies in
// nanoseconds, throughput in ops/sec.
type Cell struct {
	Name        string            `json:"name"`
	Params      map[string]string `json:"params"`
	Status      string            `json:"status"` // "ok", "skipped", "error"
	Reason      string            `json:"reason,omitempty"`
	Iterations  int               `json:"iterations"`
	MedianNS    int64             `json:"median_ns,omitempty"`
	MeanNS      int64             `json:"mean_ns,omitempty"`
	P50NS       int64             `json:"p50_ns,omitempty"`
	P95NS       int64             `json:"p95_ns,omitempty"`
	P99NS       int64             `json:"p99_ns,omitempty"`
	OpsPerSec   float64           `json:"ops_per_sec,omitempty"`
	BytesArena  int64             `json:"bytes_arena,omitempty"`
	BytesPerOp  int64             `json:"bytes_per_op,omitempty"`
	Allocations int64             `json:"allocs_per_op,omitempty"`
	Notes       string            `json:"notes,omitempty"`
}

// Stats reduces a sample series into the percentiles we report. We use
// the simple nearest-rank percentile (no interpolation) because Go bench
// timing already smears across iterations.
func Stats(samples []Sample) (median, mean, p50, p95, p99 int64) {
	if len(samples) == 0 {
		return 0, 0, 0, 0, 0
	}
	sorted := make([]int64, len(samples))
	for i, s := range samples {
		sorted[i] = int64(s)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	pct := func(p float64) int64 {
		if len(sorted) == 0 {
			return 0
		}
		idx := int(float64(len(sorted)-1) * p)
		return sorted[idx]
	}

	median = pct(0.5)
	p50 = median
	p95 = pct(0.95)
	p99 = pct(0.99)

	var sum int64
	for _, s := range sorted {
		sum += s
	}
	mean = sum / int64(len(sorted))
	return
}

// Ladder is a full sweep result that gets serialized into results/.
type Ladder struct {
	Name    string   `json:"name"`
	Host    HostInfo `json:"host"`
	Command string   `json:"command"`
	Cells   []Cell   `json:"cells"`
}

var resultsDir = func() string {
	// We anchor to the directory of this source file so the harness
	// finds results/ even when go test runs from /tmp.
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "results"
	}
	return filepath.Join(filepath.Dir(file), "results")
}()

// WriteLadder serializes a Ladder to results/<name>_<timestamp>.json.
// Errors are returned but most callers in tests ignore them -- failure
// to write a result file should not fail the benchmark.
func WriteLadder(l *Ladder) (string, error) {
	if err := os.MkdirAll(resultsDir, 0o755); err != nil {
		return "", err
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	path := filepath.Join(resultsDir, fmt.Sprintf("%s_%s.json", l.Name, stamp))
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return "", err
	}
	return path, os.WriteFile(path, data, 0o644)
}

// LadderRegistry is the global accumulator. Tests append cells via
// Record; the package-level TestMain in suite_test.go flushes once.
var (
	registryMu sync.Mutex
	registry   = map[string]*Ladder{}
)

// Record appends a cell to the named ladder.
func Record(ladderName string, cell Cell) {
	registryMu.Lock()
	defer registryMu.Unlock()
	l, ok := registry[ladderName]
	if !ok {
		l = &Ladder{
			Name:    ladderName,
			Host:    CollectHostInfo(buildTagsValue),
			Command: invocationCommand(),
		}
		registry[ladderName] = l
	}
	l.Cells = append(l.Cells, cell)
}

// FlushAll writes every recorded ladder to results/. Returns paths
// written and the first error (if any). Used by TestMain.
func FlushAll() ([]string, error) {
	registryMu.Lock()
	defer registryMu.Unlock()
	var paths []string
	var firstErr error
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		path, err := WriteLadder(registry[n])
		if err != nil && firstErr == nil {
			firstErr = err
		}
		if path != "" {
			paths = append(paths, path)
		}
	}
	return paths, firstErr
}

func invocationCommand() string {
	if len(os.Args) == 0 {
		return ""
	}
	parts := []string{"go", "test"}
	parts = append(parts, os.Args[1:]...)
	return strings.Join(parts, " ")
}

// Median returns the middle sample by sort order for use as the
// canonical headline number. Matches PHILOSOPHY.md "median >=10 runs".
func Median(samples []Sample) int64 {
	if len(samples) == 0 {
		return 0
	}
	cp := make([]int64, len(samples))
	for i, s := range samples {
		cp[i] = int64(s)
	}
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	return cp[len(cp)/2]
}
