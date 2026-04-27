// Copyright (c) 2026, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package bench

import (
	"fmt"
	"os"
	"testing"
)

// TestMain flushes the ladder registry to results/ on exit. Without
// this every benchmark run would dump cells into the in-memory map and
// then exit before serializing to disk.
func TestMain(m *testing.M) {
	code := m.Run()
	paths, err := FlushAll()
	if err != nil {
		fmt.Fprintf(os.Stderr, "bench: WriteLadder error: %v\n", err)
	}
	for _, p := range paths {
		fmt.Fprintf(os.Stderr, "bench: wrote %s\n", p)
	}
	os.Exit(code)
}
