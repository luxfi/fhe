// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build integration

// Package main, file standalone_test.go.
//
// Exercises fhed in standalone (single-node) mode. fhed has no Lux-mainnet
// connection: every deployment is self-contained. "Standalone" here means
// `fhed start --mode standard` with no peer discovery — a single node that
// owns its own keys, encrypts, evaluates, and decrypts entirely locally.
//
// Smoke flow:
//   1. spawn fhed in a child process with a temp data dir + free port
//   2. wait for /v1/fhe/health to report status=healthy
//   3. POST /v1/fhe/encrypt with a single bit
//   4. POST /v1/fhe/decrypt with the returned ciphertext
//   5. assert the round-trip preserves the bit
//
// Run: `go test -tags=integration ./cmd/fhed/... -count=1 -timeout 120s`.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitHealthy(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	url := "http://" + addr + "/v1/fhe/health"
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			body := make([]byte, 1024)
			n, _ := resp.Body.Read(body)
			resp.Body.Close()
			if resp.StatusCode == 200 && strings.Contains(string(body[:n]), `"status":"healthy"`) {
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("fhed never became healthy on %s", addr)
}

func TestStandaloneEncryptDecryptRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()

	// Build fhed binary into the temp dir so we don't depend on PATH.
	binPath := filepath.Join(tmpDir, "fhed")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = "."
	build.Stdout, build.Stderr = os.Stdout, os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("go build: %v", err)
	}

	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	dataDir := filepath.Join(tmpDir, "data")

	cmd := exec.Command(binPath,
		"start",
		"--mode", "standard",
		"--http", addr,
		"--data", dataDir,
		"--password", "smoke-test-password",
		"--log-level", "warn",
		// STD128 has the smallest bootstrap key — the larger PNxxQPxx
		// parameter sets blow past zapdb's max blob size on first
		// keygen. STD128 is sufficient for a smoke test that only
		// asserts encrypt/decrypt correctness.
		"--params", "STD128",
	)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start fhed: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	waitHealthy(t, addr)

	// Encrypt true.
	in := bytes.NewBufferString(`{"bit": true}`)
	resp, err := http.Post("http://"+addr+"/v1/fhe/encrypt", "application/json", in)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("encrypt: err=%v status=%v", err, resp)
	}
	var enc struct {
		Ciphertext string `json:"ciphertext"`
		NumBits    int    `json:"numBits"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&enc); err != nil {
		t.Fatalf("decode encrypt: %v", err)
	}
	resp.Body.Close()
	if enc.Ciphertext == "" || enc.NumBits != 1 {
		t.Fatalf("unexpected encrypt response: %+v", enc)
	}

	// Decrypt and confirm bit is true.
	body, _ := json.Marshal(map[string]string{"ciphertext": enc.Ciphertext})
	resp, err = http.Post("http://"+addr+"/v1/fhe/decrypt", "application/json", bytes.NewReader(body))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("decrypt: err=%v status=%v", err, resp)
	}
	var dec struct {
		Bit *bool `json:"bit"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&dec); err != nil {
		t.Fatalf("decode decrypt: %v", err)
	}
	resp.Body.Close()
	if dec.Bit == nil || *dec.Bit != true {
		t.Fatalf("round-trip lost the bit: got %+v want true", dec.Bit)
	}
}
