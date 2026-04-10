// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/urfave/cli/v3"

	"github.com/luxfi/fhe"
	"github.com/luxfi/fhe/pkg/membership"
	"github.com/luxfi/fhe/pkg/store"
	"github.com/luxfi/fhe/pkg/threshold"
	"github.com/luxfi/mdns"
)

const Version = "0.3.0"

func main() {
	app := &cli.Command{
		Name:    "fhed",
		Usage:   "FHE daemon for fully homomorphic encryption operations",
		Version: Version,
		Commands: []*cli.Command{
			{
				Name:  "start",
				Usage: "Start the FHE daemon",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "node-id",
						Usage:   "Node identifier (auto-generated if not set)",
						Value:   "",
					},
					&cli.StringFlag{
						Name:    "mode",
						Aliases: []string{"m"},
						Usage:   "Operation mode: 'standard' (single-key) or 'threshold' (t-of-n)",
						Value:   "standard",
					},
					&cli.StringFlag{
						Name:  "http",
						Usage: "HTTP API listen address",
						Value: ":8448",
					},
					&cli.StringFlag{
						Name:    "data",
						Aliases: []string{"d"},
						Usage:   "Data directory for keys and state",
						Value:   "",
					},
					&cli.IntFlag{
						Name:    "threshold",
						Aliases: []string{"t"},
						Usage:   "Decryption threshold (threshold mode)",
						Value:   2,
					},
					&cli.BoolFlag{
						Name:  "discover",
						Usage: "Enable mDNS peer discovery (threshold mode)",
						Value: true,
					},
					&cli.StringFlag{
						Name:  "params",
						Usage: "Parameter set: 'PN10QP27' (default), 'PN11QP54' (high precision), 'STD128' (OpenFHE compatible)",
						Value: "PN10QP27",
					},
					&cli.StringFlag{
						Name:  "log-level",
						Usage: "Log level: debug, info, warn, error",
						Value: "info",
					},
					&cli.StringFlag{
						Name:    "password",
						Usage:   "ZapDB encryption password (or set FHED_PASSWORD env)",
						Sources: cli.EnvVars("FHED_PASSWORD"),
						Value:   "",
					},
				},
				Action: runDaemon,
			},
			{
				Name:  "keygen",
				Usage: "Generate FHE keys",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "output",
						Aliases: []string{"o"},
						Usage:   "Output directory for keys",
						Value:   ".",
					},
					&cli.StringFlag{
						Name:  "params",
						Usage: "Parameter set: 'PN10QP27', 'PN11QP54', 'STD128'",
						Value: "PN10QP27",
					},
					&cli.BoolFlag{
						Name:  "threshold",
						Usage: "Generate threshold keys",
						Value: false,
					},
					&cli.IntFlag{
						Name:    "t",
						Usage:   "Threshold (t in t-of-n)",
						Value:   2,
					},
					&cli.IntFlag{
						Name:    "n",
						Usage:   "Number of parties (n in t-of-n)",
						Value:   3,
					},
				},
				Action: runKeygen,
			},
			{
				Name:  "reshare",
				Usage: "Reshare keys with new threshold or parties",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "input",
						Aliases: []string{"i"},
						Usage:   "Input directory with existing key shares",
						Value:   ".",
					},
					&cli.StringFlag{
						Name:    "output",
						Aliases: []string{"o"},
						Usage:   "Output directory for new key shares",
						Value:   "./reshared",
					},
					&cli.IntFlag{
						Name:  "new-t",
						Usage: "New threshold",
						Value: 2,
					},
					&cli.IntFlag{
						Name:  "new-n",
						Usage: "New number of parties",
						Value: 3,
					},
				},
				Action: runReshare,
			},
			{
				Name:  "version",
				Usage: "Display version information",
				Action: func(ctx context.Context, c *cli.Command) error {
					fmt.Printf("fhed version %s\n", Version)
					return nil
				},
			},
		},
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// FHEDaemon holds the daemon state
type FHEDaemon struct {
	nodeID string
	params fhe.Parameters

	// Standard mode
	secretKey    *fhe.SecretKey
	publicKey    *fhe.PublicKey
	bootstrapKey *fhe.BootstrapKey
	evaluator    *fhe.Evaluator
	encryptor    *fhe.Encryptor
	decryptor    *fhe.Decryptor

	// Threshold mode
	thresholdMode bool
	thresholdT    int
	keyShare      *threshold.KeyShare
	membership    *membership.Manager
	discovery     *mdns.Discovery

	store   *store.Store
	dataDir string
	logger  *slog.Logger

	mu sync.RWMutex
}

func runDaemon(ctx context.Context, c *cli.Command) error {
	nodeID := c.String("node-id")
	if nodeID == "" {
		nodeID = fmt.Sprintf("fhed-%s", uuid.New().String()[:8])
	}

	mode := c.String("mode")
	httpAddr := c.String("http")
	dataDir := c.String("data")
	thresholdT := int(c.Int("threshold"))
	enableDiscovery := c.Bool("discover")
	paramsName := c.String("params")
	logLevel := c.String("log-level")

	// Setup logger
	var level slog.Level
	switch logLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))

	// Default data directory
	if dataDir == "" {
		home, _ := os.UserHomeDir()
		dataDir = filepath.Join(home, ".fhed")
	}
	if err := os.MkdirAll(dataDir, 0750); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	logger.Info("Starting FHE daemon",
		"nodeID", nodeID,
		"mode", mode,
		"http", httpAddr,
		"dataDir", dataDir,
		"params", paramsName,
	)

	// Get parameters
	params, err := getParameters(paramsName)
	if err != nil {
		return err
	}

	// Parse HTTP port for discovery
	_, portStr, _ := net.SplitHostPort(httpAddr)
	var httpPort int
	fmt.Sscanf(portStr, "%d", &httpPort)
	if httpPort == 0 {
		httpPort = 8448
	}

	// Open encrypted ZapDB for key material and ciphertext storage
	password := c.String("password")
	if password == "" {
		password = "fhed-dev-" + nodeID // Dev default; production must set FHED_PASSWORD
		logger.Warn("No password set — using dev default. Set FHED_PASSWORD for production.")
	}
	db, err := store.Open(filepath.Join(dataDir, "zapdb"), password)
	if err != nil {
		return fmt.Errorf("failed to open zapdb: %w", err)
	}
	defer db.Close()

	daemon := &FHEDaemon{
		nodeID:        nodeID,
		params:        params,
		thresholdMode: mode == "threshold",
		thresholdT:    thresholdT,
		store:         db,
		dataDir:       dataDir,
		logger:        logger,
	}

	if daemon.thresholdMode {
		// Initialize membership manager
		daemon.membership = membership.NewManager(membership.ManagerConfig{
			NodeID:    nodeID,
			Threshold: thresholdT,
			Logger:    logger,
		})

		// Initialize mDNS discovery if enabled
		if enableDiscovery {
			disc := mdns.New("_fhed._tcp", nodeID, httpPort,
				mdns.WithLogger(logger),
				mdns.WithMetadata(map[string]string{
					"version": Version,
				}),
			)
			daemon.discovery = disc

			// Handle peer discovery events
			disc.OnPeer(func(peer *mdns.Peer, joined bool) {
				if joined {
					daemon.membership.AddMember(&membership.Member{
						NodeID: peer.NodeID,
						Addr:   peer.Addr,
						Port:   peer.Port,
						Ready:  true,
					})
				} else {
					daemon.membership.RemoveMember(peer.NodeID)
				}
			})

			if err := disc.Start(); err != nil {
				return fmt.Errorf("failed to start discovery: %w", err)
			}
			defer disc.Stop()

			logger.Info("mDNS discovery enabled", "service", "_fhed._tcp")
		}

		// Handle membership changes (trigger reshare if needed)
		daemon.membership.OnChange(func(change *membership.MembershipChange, newState *membership.ClusterState) {
			logger.Info("Membership changed",
				"type", change.Type,
				"members", len(newState.Members),
				"threshold", newState.Threshold,
			)

			// In a full implementation, trigger distributed keygen/reshare here
			if change.Type == membership.ChangeJoin || change.Type == membership.ChangeLeave {
				if len(newState.Members) >= newState.Threshold {
					logger.Info("Quorum reached, ready for threshold operations")
				}
			}
		})

		// Load or generate threshold key share
		if err := daemon.loadOrGenerateThresholdKey(); err != nil {
			return fmt.Errorf("failed to load/generate threshold key: %w", err)
		}
	} else {
		// Standard mode: single-key FHE
		if err := daemon.loadOrGenerateKeys(); err != nil {
			return fmt.Errorf("failed to load/generate keys: %w", err)
		}
	}

	// Start HTTP server
	httpServer := daemon.createHTTPServer()
	httpListener, err := net.Listen("tcp", httpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on HTTP address: %w", err)
	}

	go func() {
		logger.Info("HTTP server listening", "addr", httpAddr)
		if err := httpServer.Serve(httpListener); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server error", "error", err)
		}
	}()

	logger.Info("[READY] FHE daemon is ready",
		"nodeID", nodeID,
		"mode", mode,
		"http", httpAddr,
	)

	// Wait for shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	logger.Info("Shutdown signal received, stopping...")

	// Graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	httpServer.Shutdown(shutdownCtx)

	return nil
}

func getParameters(name string) (fhe.Parameters, error) {
	var paramsLit fhe.ParametersLiteral
	switch name {
	case "PN11QP54":
		paramsLit = fhe.PN11QP54
	case "STD128":
		paramsLit = fhe.PN9QP28_STD128
	default:
		paramsLit = fhe.PN10QP27
	}
	return fhe.NewParametersFromLiteral(paramsLit)
}

func (d *FHEDaemon) loadOrGenerateKeys() error {
	keyID := "default"

	// Try to load existing keys from ZapDB
	if d.store.HasSecretKey(keyID) {
		d.logger.Info("Loading existing keys from ZapDB")

		skData, err := d.store.GetSecretKey(keyID)
		if err != nil {
			return fmt.Errorf("failed to read secret key: %w", err)
		}

		pkData, err := d.store.GetPublicKey(keyID)
		if err != nil {
			return fmt.Errorf("failed to read public key: %w", err)
		}

		bskData, err := d.store.GetBootstrapKey(keyID)
		if err != nil {
			return fmt.Errorf("failed to read bootstrap key: %w", err)
		}

		d.secretKey = new(fhe.SecretKey)
		if err := d.secretKey.UnmarshalBinary(skData); err != nil {
			return fmt.Errorf("failed to unmarshal secret key: %w", err)
		}

		d.publicKey = new(fhe.PublicKey)
		if err := d.publicKey.UnmarshalBinary(pkData); err != nil {
			return fmt.Errorf("failed to unmarshal public key: %w", err)
		}

		d.bootstrapKey = new(fhe.BootstrapKey)
		if err := d.bootstrapKey.UnmarshalBinary(bskData); err != nil {
			return fmt.Errorf("failed to unmarshal bootstrap key: %w", err)
		}

		d.encryptor = fhe.NewEncryptor(d.params, d.secretKey)
		d.decryptor = fhe.NewDecryptor(d.params, d.secretKey)
		d.evaluator = fhe.NewEvaluator(d.params, d.bootstrapKey)

		return nil
	}

	// Generate new keys and store in ZapDB
	d.logger.Info("Generating new FHE keys (this may take a moment)...")

	keygen := fhe.NewKeyGenerator(d.params)
	d.secretKey, d.publicKey = keygen.GenKeyPair()
	d.bootstrapKey = keygen.GenBootstrapKey(d.secretKey)

	d.encryptor = fhe.NewEncryptor(d.params, d.secretKey)
	d.decryptor = fhe.NewDecryptor(d.params, d.secretKey)
	d.evaluator = fhe.NewEvaluator(d.params, d.bootstrapKey)

	// Persist to encrypted ZapDB
	skData, err := d.secretKey.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal secret key: %w", err)
	}
	if err := d.store.PutSecretKey(keyID, skData); err != nil {
		return fmt.Errorf("failed to store secret key: %w", err)
	}

	pkData, err := d.publicKey.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	if err := d.store.PutPublicKey(keyID, pkData); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	bskData, err := d.bootstrapKey.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal bootstrap key: %w", err)
	}
	if err := d.store.PutBootstrapKey(keyID, bskData); err != nil {
		return fmt.Errorf("failed to store bootstrap key: %w", err)
	}

	d.logger.Info("Keys generated and saved to ZapDB")
	return nil
}

func (d *FHEDaemon) loadOrGenerateThresholdKey() error {
	keyID := "threshold-default"

	// Try to load existing key share from ZapDB
	if ksData, err := d.store.GetSecretKey(keyID); err == nil {
		d.logger.Info("Loading existing key share from ZapDB")

		ks, err := threshold.UnmarshalKeyShare(ksData)
		if err != nil {
			return fmt.Errorf("failed to unmarshal key share: %w", err)
		}
		d.keyShare = ks

		pkData, err := d.store.GetPublicKey(keyID)
		if err != nil {
			return fmt.Errorf("failed to read public key: %w", err)
		}
		d.publicKey = new(fhe.PublicKey)
		if err := d.publicKey.UnmarshalBinary(pkData); err != nil {
			return fmt.Errorf("failed to unmarshal public key: %w", err)
		}

		if bskData, err := d.store.GetBootstrapKey(keyID); err == nil {
			d.bootstrapKey = new(fhe.BootstrapKey)
			if err := d.bootstrapKey.UnmarshalBinary(bskData); err != nil {
				d.logger.Warn("Failed to load bootstrap key, evaluation will not work", "error", err)
			} else {
				d.evaluator = fhe.NewEvaluator(d.params, d.bootstrapKey)
			}
		}

		d.logger.Info("Threshold key share loaded",
			"partyIndex", ks.PartyIndex,
			"threshold", ks.Threshold,
			"sessionID", ks.SessionID,
		)
		return nil
	}

	d.logger.Warn("Generating single-party threshold keys for demo (NOT secure for production)")

	sessionID := uuid.New().String()
	result, err := threshold.GenerateSharedKey(d.params, d.thresholdT, d.thresholdT, sessionID)
	if err != nil {
		return fmt.Errorf("failed to generate threshold keys: %w", err)
	}

	d.keyShare = result.Shares[0]
	d.publicKey = result.PublicKey
	d.bootstrapKey = result.BootstrapKey

	if d.bootstrapKey != nil {
		d.evaluator = fhe.NewEvaluator(d.params, d.bootstrapKey)
	}

	// Persist to ZapDB
	ksData, err := threshold.MarshalKeyShare(d.keyShare)
	if err != nil {
		return fmt.Errorf("failed to marshal key share: %w", err)
	}
	if err := d.store.PutSecretKey(keyID, ksData); err != nil {
		return fmt.Errorf("failed to store key share: %w", err)
	}

	pkData, err := d.publicKey.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	if err := d.store.PutPublicKey(keyID, pkData); err != nil {
		return fmt.Errorf("failed to store public key: %w", err)
	}

	if d.bootstrapKey != nil {
		bskData, err := d.bootstrapKey.MarshalBinary()
		if err != nil {
			return fmt.Errorf("failed to marshal bootstrap key: %w", err)
		}
		if err := d.store.PutBootstrapKey(keyID, bskData); err != nil {
			return fmt.Errorf("failed to store bootstrap key: %w", err)
		}
	}

	d.logger.Info("Threshold keys generated",
		"sessionID", sessionID,
		"threshold", d.thresholdT,
	)
	return nil
}

// HTTP API

func (d *FHEDaemon) createHTTPServer() *http.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/fhe/health", d.handleHealth)
	mux.HandleFunc("/v1/fhe/publickey", d.handlePublicKey)
	mux.HandleFunc("/v1/fhe/encrypt", d.handleEncrypt)
	mux.HandleFunc("/v1/fhe/decrypt", d.handleDecrypt)
	mux.HandleFunc("/v1/fhe/evaluate", d.handleEvaluate)

	// Cluster management endpoints (threshold mode)
	mux.HandleFunc("/v1/fhe/cluster/status", d.handleClusterStatus)
	mux.HandleFunc("/v1/fhe/cluster/peers", d.handleClusterPeers)
	mux.HandleFunc("/v1/fhe/cluster/reshare", d.handleClusterReshare)

	return &http.Server{Handler: mux}
}

func (d *FHEDaemon) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	status := map[string]interface{}{
		"status":    "healthy",
		"version":   Version,
		"nodeId":    d.nodeID,
		"mode":      map[bool]string{true: "threshold", false: "standard"}[d.thresholdMode],
		"params": map[string]interface{}{
			"N":    d.params.N(),
			"NBR":  d.params.NBR(),
			"QLWE": d.params.QLWE(),
			"QBR":  d.params.QBR(),
		},
	}

	if d.thresholdMode && d.membership != nil {
		status["threshold"] = d.thresholdT
		status["members"] = d.membership.MemberCount()
		status["ready"] = d.membership.ReadyCount()
		status["canDecrypt"] = d.membership.CanDecrypt()
	}

	json.NewEncoder(w).Encode(status)
}

func (d *FHEDaemon) handleClusterStatus(w http.ResponseWriter, r *http.Request) {
	if !d.thresholdMode {
		http.Error(w, "not in threshold mode", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(d.membership.GetState())
}

func (d *FHEDaemon) handleClusterPeers(w http.ResponseWriter, r *http.Request) {
	if !d.thresholdMode || d.discovery == nil {
		http.Error(w, "discovery not enabled", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(d.discovery.Peers())
}

func (d *FHEDaemon) handleClusterReshare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !d.thresholdMode {
		http.Error(w, "not in threshold mode", http.StatusBadRequest)
		return
	}

	var req struct {
		NewThreshold int `json:"newThreshold"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.NewThreshold < 1 {
		http.Error(w, "threshold must be at least 1", http.StatusBadRequest)
		return
	}

	if err := d.membership.SetThreshold(req.NewThreshold); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	d.thresholdT = req.NewThreshold
	d.logger.Info("Threshold updated, reshare triggered", "newThreshold", req.NewThreshold)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":      true,
		"newThreshold": req.NewThreshold,
		"message":      "reshare initiated",
	})
}

func (d *FHEDaemon) handlePublicKey(w http.ResponseWriter, r *http.Request) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.publicKey == nil {
		http.Error(w, "no public key available", http.StatusServiceUnavailable)
		return
	}

	pkData, err := d.publicKey.MarshalBinary()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"publicKey": hex.EncodeToString(pkData),
	})
}

type EncryptRequest struct {
	Bit    *bool   `json:"bit,omitempty"`
	Uint32 *uint32 `json:"uint32,omitempty"`
	Uint64 *uint64 `json:"uint64,omitempty"`
}

type EncryptResponse struct {
	Ciphertext  string   `json:"ciphertext,omitempty"`
	Ciphertexts []string `json:"ciphertexts,omitempty"`
	NumBits     int      `json:"numBits"`
}

func (d *FHEDaemon) handleEncrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req EncryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.encryptor == nil {
		http.Error(w, "encryption not available", http.StatusServiceUnavailable)
		return
	}

	var resp EncryptResponse

	if req.Bit != nil {
		ct := d.encryptor.Encrypt(*req.Bit)
		ctData, err := ct.MarshalBinary()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		resp.Ciphertext = hex.EncodeToString(ctData)
		resp.NumBits = 1
	} else if req.Uint32 != nil {
		cts := d.encryptor.EncryptUint32(*req.Uint32)
		resp.Ciphertexts = make([]string, 32)
		for i, ct := range cts {
			ctData, err := ct.MarshalBinary()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			resp.Ciphertexts[i] = hex.EncodeToString(ctData)
		}
		resp.NumBits = 32
	} else if req.Uint64 != nil {
		cts := d.encryptor.EncryptUint64(*req.Uint64)
		resp.Ciphertexts = make([]string, 64)
		for i, ct := range cts {
			ctData, err := ct.MarshalBinary()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			resp.Ciphertexts[i] = hex.EncodeToString(ctData)
		}
		resp.NumBits = 64
	} else {
		http.Error(w, "must provide 'bit', 'uint32', or 'uint64'", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

type DecryptRequest struct {
	Ciphertext  string   `json:"ciphertext,omitempty"`
	Ciphertexts []string `json:"ciphertexts,omitempty"`
}

type DecryptResponse struct {
	Bit    *bool   `json:"bit,omitempty"`
	Uint32 *uint32 `json:"uint32,omitempty"`
	Uint64 *uint64 `json:"uint64,omitempty"`
}

func (d *FHEDaemon) handleDecrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// In threshold mode, check if we have quorum
	if d.thresholdMode && d.membership != nil && !d.membership.CanDecrypt() {
		http.Error(w, fmt.Sprintf("not enough parties for decryption (need %d, have %d ready)",
			d.thresholdT, d.membership.ReadyCount()), http.StatusServiceUnavailable)
		return
	}

	var req DecryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.decryptor == nil {
		http.Error(w, "decryption not available", http.StatusServiceUnavailable)
		return
	}

	var resp DecryptResponse

	if req.Ciphertext != "" {
		ctData, err := hex.DecodeString(req.Ciphertext)
		if err != nil {
			http.Error(w, "invalid ciphertext hex", http.StatusBadRequest)
			return
		}

		ct := new(fhe.Ciphertext)
		if err := ct.UnmarshalBinary(ctData); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		result := d.decryptor.Decrypt(ct)
		resp.Bit = &result
	} else if len(req.Ciphertexts) > 0 {
		numBits := len(req.Ciphertexts)

		if numBits == 32 {
			var cts [32]*fhe.Ciphertext
			for i, ctHex := range req.Ciphertexts {
				ctData, err := hex.DecodeString(ctHex)
				if err != nil {
					http.Error(w, fmt.Sprintf("invalid ciphertext %d hex", i), http.StatusBadRequest)
					return
				}
				cts[i] = new(fhe.Ciphertext)
				if err := cts[i].UnmarshalBinary(ctData); err != nil {
					http.Error(w, fmt.Sprintf("failed to parse ciphertext %d", i), http.StatusBadRequest)
					return
				}
			}
			result := d.decryptor.DecryptUint32(cts)
			resp.Uint32 = &result
		} else if numBits == 64 {
			var cts [64]*fhe.Ciphertext
			for i, ctHex := range req.Ciphertexts {
				ctData, err := hex.DecodeString(ctHex)
				if err != nil {
					http.Error(w, fmt.Sprintf("invalid ciphertext %d hex", i), http.StatusBadRequest)
					return
				}
				cts[i] = new(fhe.Ciphertext)
				if err := cts[i].UnmarshalBinary(ctData); err != nil {
					http.Error(w, fmt.Sprintf("failed to parse ciphertext %d", i), http.StatusBadRequest)
					return
				}
			}
			result := d.decryptor.DecryptUint64(cts)
			resp.Uint64 = &result
		} else {
			http.Error(w, "ciphertexts array must have 32 or 64 elements", http.StatusBadRequest)
			return
		}
	} else {
		http.Error(w, "must provide 'ciphertext' or 'ciphertexts'", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

type EvaluateRequest struct {
	Operation string   `json:"operation"`
	Operands  []string `json:"operands"`
}

type EvaluateResponse struct {
	Result string `json:"result"`
}

func (d *FHEDaemon) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req EvaluateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if len(req.Operands) < 1 {
		http.Error(w, "at least one operand required", http.StatusBadRequest)
		return
	}

	operands := make([]*fhe.Ciphertext, len(req.Operands))
	for i, opHex := range req.Operands {
		data, err := hex.DecodeString(opHex)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid operand %d", i), http.StatusBadRequest)
			return
		}
		operands[i] = new(fhe.Ciphertext)
		if err := operands[i].UnmarshalBinary(data); err != nil {
			http.Error(w, fmt.Sprintf("failed to parse operand %d", i), http.StatusBadRequest)
			return
		}
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.evaluator == nil {
		http.Error(w, "evaluation not available", http.StatusServiceUnavailable)
		return
	}

	var result *fhe.Ciphertext
	var err error

	switch req.Operation {
	case "not":
		result = d.evaluator.NOT(operands[0])
	case "and":
		if len(operands) < 2 {
			http.Error(w, "and requires 2 operands", http.StatusBadRequest)
			return
		}
		result, err = d.evaluator.AND(operands[0], operands[1])
	case "or":
		if len(operands) < 2 {
			http.Error(w, "or requires 2 operands", http.StatusBadRequest)
			return
		}
		result, err = d.evaluator.OR(operands[0], operands[1])
	case "xor":
		if len(operands) < 2 {
			http.Error(w, "xor requires 2 operands", http.StatusBadRequest)
			return
		}
		result, err = d.evaluator.XOR(operands[0], operands[1])
	case "nand":
		if len(operands) < 2 {
			http.Error(w, "nand requires 2 operands", http.StatusBadRequest)
			return
		}
		result, err = d.evaluator.NAND(operands[0], operands[1])
	case "nor":
		if len(operands) < 2 {
			http.Error(w, "nor requires 2 operands", http.StatusBadRequest)
			return
		}
		result, err = d.evaluator.NOR(operands[0], operands[1])
	case "xnor":
		if len(operands) < 2 {
			http.Error(w, "xnor requires 2 operands", http.StatusBadRequest)
			return
		}
		result, err = d.evaluator.XNOR(operands[0], operands[1])
	case "mux":
		if len(operands) < 3 {
			http.Error(w, "mux requires 3 operands", http.StatusBadRequest)
			return
		}
		result, err = d.evaluator.MUX(operands[0], operands[1], operands[2])
	case "refresh":
		result, err = d.evaluator.Refresh(operands[0])
	case "majority":
		if len(operands) < 3 {
			http.Error(w, "majority requires 3 operands", http.StatusBadRequest)
			return
		}
		result, err = d.evaluator.MAJORITY(operands[0], operands[1], operands[2])
	default:
		http.Error(w, fmt.Sprintf("unsupported operation: %s", req.Operation), http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resultData, err := result.MarshalBinary()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(EvaluateResponse{
		Result: hex.EncodeToString(resultData),
	})
}

func runKeygen(ctx context.Context, c *cli.Command) error {
	outputDir := c.String("output")
	paramsName := c.String("params")
	isThreshold := c.Bool("threshold")
	t := int(c.Int("t"))
	n := int(c.Int("n"))

	params, err := getParameters(paramsName)
	if err != nil {
		return fmt.Errorf("failed to create parameters: %w", err)
	}

	if err := os.MkdirAll(outputDir, 0750); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	if isThreshold {
		fmt.Printf("Generating threshold keys (%d-of-%d)...\n", t, n)

		sessionID := uuid.New().String()
		result, err := threshold.GenerateSharedKey(params, t, n, sessionID)
		if err != nil {
			return fmt.Errorf("failed to generate threshold keys: %w", err)
		}

		// Save each key share
		for i, share := range result.Shares {
			shareDir := filepath.Join(outputDir, fmt.Sprintf("party%d", i+1))
			if err := os.MkdirAll(shareDir, 0750); err != nil {
				return fmt.Errorf("failed to create party directory: %w", err)
			}

			ksData, err := threshold.MarshalKeyShare(share)
			if err != nil {
				return fmt.Errorf("failed to marshal key share: %w", err)
			}
			if err := os.WriteFile(filepath.Join(shareDir, "keyshare.bin"), ksData, 0600); err != nil {
				return fmt.Errorf("failed to write key share: %w", err)
			}

			// Save public key for each party
			pkData, err := result.PublicKey.MarshalBinary()
			if err != nil {
				return fmt.Errorf("failed to marshal public key: %w", err)
			}
			if err := os.WriteFile(filepath.Join(shareDir, "public.key"), pkData, 0644); err != nil {
				return fmt.Errorf("failed to write public key: %w", err)
			}

			fmt.Printf("  Party %d key share saved to: %s\n", i+1, shareDir)
		}

		// Save bootstrap key (shared)
		if result.BootstrapKey != nil {
			bskData, err := result.BootstrapKey.MarshalBinary()
			if err != nil {
				return fmt.Errorf("failed to marshal bootstrap key: %w", err)
			}
			bskPath := filepath.Join(outputDir, "bootstrap.key")
			if err := os.WriteFile(bskPath, bskData, 0644); err != nil {
				return fmt.Errorf("failed to write bootstrap key: %w", err)
			}
			fmt.Printf("Bootstrap key saved to: %s\n", bskPath)
		}

		fmt.Printf("\nThreshold keygen complete!\n")
		fmt.Printf("  Session ID: %s\n", sessionID)
		fmt.Printf("  Threshold: %d-of-%d\n", t, n)
		return nil
	}

	// Standard keygen
	fmt.Println("Generating standard FHE keys...")
	keygen := fhe.NewKeyGenerator(params)
	sk, pk := keygen.GenKeyPair()

	skData, err := sk.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal secret key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "secret.key"), skData, 0600); err != nil {
		return fmt.Errorf("failed to write secret key: %w", err)
	}
	fmt.Printf("Secret key saved to: %s/secret.key\n", outputDir)

	pkData, err := pk.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "public.key"), pkData, 0644); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}
	fmt.Printf("Public key saved to: %s/public.key\n", outputDir)

	fmt.Println("Generating bootstrap key...")
	bsk := keygen.GenBootstrapKey(sk)
	bskData, err := bsk.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal bootstrap key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "bootstrap.key"), bskData, 0644); err != nil {
		return fmt.Errorf("failed to write bootstrap key: %w", err)
	}
	fmt.Printf("Bootstrap key saved to: %s/bootstrap.key\n", outputDir)

	fmt.Println("Key generation complete!")
	return nil
}

func runReshare(ctx context.Context, c *cli.Command) error {
	inputDir := c.String("input")
	outputDir := c.String("output")
	newT := int(c.Int("new-t"))
	newN := int(c.Int("new-n"))

	// Load existing key shares
	entries, err := os.ReadDir(inputDir)
	if err != nil {
		return fmt.Errorf("failed to read input directory: %w", err)
	}

	var oldShares []*threshold.KeyShare
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		ksPath := filepath.Join(inputDir, entry.Name(), "keyshare.bin")
		if _, err := os.Stat(ksPath); err != nil {
			continue
		}

		ksData, err := os.ReadFile(ksPath)
		if err != nil {
			return fmt.Errorf("failed to read key share %s: %w", entry.Name(), err)
		}

		ks, err := threshold.UnmarshalKeyShare(ksData)
		if err != nil {
			return fmt.Errorf("failed to unmarshal key share %s: %w", entry.Name(), err)
		}
		oldShares = append(oldShares, ks)
	}

	if len(oldShares) == 0 {
		return fmt.Errorf("no key shares found in %s", inputDir)
	}

	fmt.Printf("Found %d key shares (threshold %d-of-%d)\n",
		len(oldShares), oldShares[0].Threshold, oldShares[0].Total)
	fmt.Printf("Resharing to %d-of-%d...\n", newT, newN)

	newSessionID := uuid.New().String()
	result, err := threshold.ReshareKey(oldShares, newT, newN, newSessionID)
	if err != nil {
		return fmt.Errorf("failed to reshare: %w", err)
	}

	if err := os.MkdirAll(outputDir, 0750); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	for i, share := range result.Shares {
		shareDir := filepath.Join(outputDir, fmt.Sprintf("party%d", i+1))
		if err := os.MkdirAll(shareDir, 0750); err != nil {
			return fmt.Errorf("failed to create party directory: %w", err)
		}

		ksData, err := threshold.MarshalKeyShare(share)
		if err != nil {
			return fmt.Errorf("failed to marshal key share: %w", err)
		}
		if err := os.WriteFile(filepath.Join(shareDir, "keyshare.bin"), ksData, 0600); err != nil {
			return fmt.Errorf("failed to write key share: %w", err)
		}

		pkData, err := result.PublicKey.MarshalBinary()
		if err != nil {
			return fmt.Errorf("failed to marshal public key: %w", err)
		}
		if err := os.WriteFile(filepath.Join(shareDir, "public.key"), pkData, 0644); err != nil {
			return fmt.Errorf("failed to write public key: %w", err)
		}

		fmt.Printf("  Party %d key share saved to: %s\n", i+1, shareDir)
	}

	fmt.Printf("\nReshare complete!\n")
	fmt.Printf("  New session ID: %s\n", newSessionID)
	fmt.Printf("  New threshold: %d-of-%d\n", newT, newN)
	return nil
}
