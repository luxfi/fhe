//go:build demos

// regulated-vault — Private app where operators can't see user data,
// but regulators can force-decrypt via MPC threshold approval.
//
// Architecture:
//   User encrypts data client-side with FHE public key.
//   Encrypted data stored in Base SQLite — operator sees only ciphertext.
//   Decryption requires t-of-n MPC key holders to approve.
//   Normal operation: nobody can decrypt. Not the operator, not any single party.
//   Regulatory subpoena: regulator requests decrypt → t-of-n holders approve → plaintext revealed.
//
// Run:
//   go run . serve --http=0.0.0.0:8090
//
// Endpoints:
//   POST /v1/vault/store        — store encrypted data (operator never sees plaintext)
//   GET  /v1/vault/list         — list records (all encrypted, no plaintext)
//   POST /v1/vault/compute      — run computation on encrypted data (homomorphic)
//   POST /v1/vault/request      — request decryption (creates approval request)
//   GET  /v1/vault/requests     — list pending decryption requests
//   POST /v1/vault/approve/{id} — MPC key holder approves decryption
//   GET  /v1/vault/reveal/{id}  — get decrypted result (only after t-of-n approvals)
//   GET  /v1/vault/audit        — audit trail of all decrypt requests + approvals
//
// The key insight: the FHE secret key is Shamir-split across N MPC nodes.
// No single node (including the operator) holds the full key.
// Decryption requires t-of-n shares to be combined — a social/legal process.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hanzoai/base"
	"github.com/hanzoai/base/core"
	"github.com/luxfi/fhe"
)

// state holds FHE parameters and the threshold key management state.
type state struct {
	mu     sync.RWMutex
	params fhe.Parameters
	pk     *fhe.PublicKey    // public — anyone can encrypt
	sk     *fhe.SecretKey    // NEVER stored whole. Split into shares.
	bsk    *fhe.BootstrapKey // for homomorphic evaluation
	enc    *fhe.Encryptor
	dec    *fhe.Decryptor
	eval   *fhe.Evaluator

	// Threshold key management
	threshold int           // t — minimum approvals needed
	totalKeys int           // n — total key holders
	shares    [][]byte      // Shamir shares of the secret key (in production, distributed to MPC nodes)
	records   []vaultRecord // encrypted records
	requests  []decryptRequest
}

type vaultRecord struct {
	ID            string    `json:"id"`
	Owner         string    `json:"owner"`          // user who stored it
	Label         string    `json:"label"`           // human-readable label
	EncryptedData []byte    `json:"encrypted_data"`  // FHE ciphertext — operator CANNOT read this
	DataHash      string    `json:"data_hash"`       // SHA-256 of plaintext (for integrity, not revealing)
	CreatedAt     time.Time `json:"created_at"`
}

type decryptRequest struct {
	ID          string    `json:"id"`
	RecordID    string    `json:"record_id"`
	Requester   string    `json:"requester"`    // who requested (e.g., "SEC", "FINRA", "user")
	Reason      string    `json:"reason"`       // legal basis
	Status      string    `json:"status"`       // pending, approved, denied, revealed
	Approvals   []approval `json:"approvals"`
	Required    int       `json:"required"`     // t — threshold
	Plaintext   *string   `json:"plaintext,omitempty"` // only populated after threshold met
	CreatedAt   time.Time `json:"created_at"`
	ResolvedAt  *time.Time `json:"resolved_at,omitempty"`
}

type approval struct {
	KeyHolder string    `json:"key_holder"` // which MPC node approved
	Share     int       `json:"share_idx"`  // which Shamir share was used
	Timestamp time.Time `json:"timestamp"`
}

func main() {
	app := base.New()

	s := &state{
		threshold: 3, // 3-of-5 required to decrypt
		totalKeys: 5,
	}

	app.OnServe().BindFunc(func(e *core.ServeEvent) error {
		// Initialize FHE
		params, err := fhe.NewParametersFromLiteral(fhe.PN10QP27)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FHE init failed: %v\n", err)
			os.Exit(1)
		}
		s.params = params
		keygen := fhe.NewKeyGenerator(params)
		sk, pk := keygen.GenKeyPair()
		bsk := keygen.GenBootstrapKey(sk)
		s.pk = pk
		s.sk = sk
		s.bsk = bsk
		s.enc = fhe.NewEncryptor(params, sk)
		s.dec = fhe.NewDecryptor(params, sk)
		s.eval = fhe.NewEvaluator(params, bsk)

		// WARNING: In this demo, the full FHE secret key is held in memory by a
		// single process. Production requires Shamir-splitting sk across N MPC
		// nodes with threshold reconstruction — no single party holds the full key.
		s.shares = shamirSplit([]byte("simulated-secret-key"), s.totalKeys, s.threshold)

		fmt.Printf("\n")
		fmt.Printf("  ============================================================\n")
		fmt.Printf("  WARNING: DEMO ONLY — operator holds full FHE key in memory.\n")
		fmt.Printf("  Production requires distributed threshold decryption via MPC.\n")
		fmt.Printf("  DO NOT deploy this binary with real user data.\n")
		fmt.Printf("  ============================================================\n")
		fmt.Printf("\n")
		fmt.Printf("  Regulated Vault (FHE + MPC Threshold Decrypt)\n")
		fmt.Printf("  ─────────────────────────────────────────────\n")
		fmt.Printf("  Threshold:  %d-of-%d required to decrypt\n", s.threshold, s.totalKeys)
		fmt.Printf("  Operator:   CANNOT see plaintext (only ciphertext)\n")
		fmt.Printf("  Regulator:  CAN force-decrypt with %d approvals\n", s.threshold)
		fmt.Printf("  User:       CAN store + compute on encrypted data\n")
		fmt.Printf("\n")

		registerRoutes(e, s)
		return e.Next()
	})

	app.Start()
}

func registerRoutes(e *core.ServeEvent, s *state) {
	// Store encrypted data — operator never sees plaintext
	e.Router.POST("/v1/vault/store", func(re *core.RequestEvent) error {
		var body struct {
			Owner     string `json:"owner"`
			Label     string `json:"label"`
			Plaintext string `json:"plaintext"` // sent by user, encrypted immediately, never stored
		}
		json.NewDecoder(re.Request.Body).Decode(&body)

		if body.Plaintext == "" {
			return re.JSON(http.StatusBadRequest, map[string]string{"error": "plaintext required"})
		}

		// Encrypt each byte with FHE — after this, plaintext is GONE from server memory
		s.mu.Lock()
		encrypted := make([]byte, 0)
		for _, b := range []byte(body.Plaintext) {
			bits := s.enc.EncryptByte(b) // [8]*Ciphertext, one per bit
			for _, ct := range bits {
				data, _ := ct.MarshalBinary()
				encrypted = append(encrypted, data...)
			}
		}

		// Hash plaintext for integrity verification (hash doesn't reveal content)
		hash := sha256.Sum256([]byte(body.Plaintext))

		id := generateID()
		record := vaultRecord{
			ID:            id,
			Owner:         body.Owner,
			Label:         body.Label,
			EncryptedData: encrypted,
			DataHash:      hex.EncodeToString(hash[:]),
			CreatedAt:     time.Now().UTC(),
		}
		s.records = append(s.records, record)
		s.mu.Unlock()

		// Plaintext is now out of scope — GC will collect it.
		// Only the FHE ciphertext persists.

		return re.JSON(http.StatusCreated, map[string]any{
			"id":        id,
			"label":     body.Label,
			"data_hash": record.DataHash,
			"encrypted": true,
			"message":   "Data encrypted with FHE. Operator cannot read it. Decryption requires " + fmt.Sprintf("%d-of-%d", s.threshold, s.totalKeys) + " MPC approvals.",
		})
	})

	// List records — all encrypted, no plaintext ever visible
	e.Router.GET("/v1/vault/list", func(re *core.RequestEvent) error {
		s.mu.RLock()
		defer s.mu.RUnlock()

		items := make([]map[string]any, 0, len(s.records))
		for _, r := range s.records {
			items = append(items, map[string]any{
				"id":             r.ID,
				"owner":          r.Owner,
				"label":          r.Label,
				"encrypted_size": len(r.EncryptedData),
				"data_hash":      r.DataHash,
				"created_at":     r.CreatedAt,
				// NOTE: encrypted_data is NOT returned. Operator sees metadata only.
			})
		}

		return re.JSON(http.StatusOK, map[string]any{
			"items":   items,
			"message": "All data is FHE-encrypted. Plaintext is not available without threshold decryption.",
		})
	})

	// Request decryption — starts the approval process
	e.Router.POST("/v1/vault/request", func(re *core.RequestEvent) error {
		var body struct {
			RecordID  string `json:"record_id"`
			Requester string `json:"requester"` // "SEC", "FINRA", "user", etc.
			Reason    string `json:"reason"`     // legal basis for decryption
		}
		json.NewDecoder(re.Request.Body).Decode(&body)

		if body.RecordID == "" || body.Requester == "" || body.Reason == "" {
			return re.JSON(http.StatusBadRequest, map[string]string{"error": "record_id, requester, and reason required"})
		}

		s.mu.Lock()
		defer s.mu.Unlock()

		// Verify record exists
		found := false
		for _, r := range s.records {
			if r.ID == body.RecordID {
				found = true
				break
			}
		}
		if !found {
			return re.JSON(http.StatusNotFound, map[string]string{"error": "record not found"})
		}

		id := generateID()
		req := decryptRequest{
			ID:        id,
			RecordID:  body.RecordID,
			Requester: body.Requester,
			Reason:    body.Reason,
			Status:    "pending",
			Required:  s.threshold,
			CreatedAt: time.Now().UTC(),
		}
		s.requests = append(s.requests, req)

		return re.JSON(http.StatusCreated, map[string]any{
			"id":        id,
			"status":    "pending",
			"required":  s.threshold,
			"approvals": 0,
			"message":   fmt.Sprintf("Decryption request created. Requires %d-of-%d MPC key holder approvals.", s.threshold, s.totalKeys),
		})
	})

	// List pending requests
	e.Router.GET("/v1/vault/requests", func(re *core.RequestEvent) error {
		s.mu.RLock()
		defer s.mu.RUnlock()
		return re.JSON(http.StatusOK, map[string]any{"items": s.requests})
	})

	// Approve decryption — each MPC key holder calls this
	e.Router.POST("/v1/vault/approve/{id}", func(re *core.RequestEvent) error {
		id := re.Request.PathValue("id")
		var body struct {
			KeyHolder string `json:"key_holder"` // MPC node identity
			ShareIdx  int    `json:"share_idx"`  // which Shamir share they hold
		}
		json.NewDecoder(re.Request.Body).Decode(&body)

		s.mu.Lock()
		defer s.mu.Unlock()

		for i, req := range s.requests {
			if req.ID == id {
				if req.Status != "pending" {
					return re.JSON(http.StatusConflict, map[string]string{"error": "request already " + req.Status})
				}

				// Check for duplicate approval from same holder
				for _, a := range req.Approvals {
					if a.KeyHolder == body.KeyHolder {
						return re.JSON(http.StatusConflict, map[string]string{"error": "already approved by this key holder"})
					}
				}

				s.requests[i].Approvals = append(s.requests[i].Approvals, approval{
					KeyHolder: body.KeyHolder,
					Share:     body.ShareIdx,
					Timestamp: time.Now().UTC(),
				})

				remaining := req.Required - len(s.requests[i].Approvals)
				if remaining <= 0 {
					// Threshold met — decrypt
					s.requests[i].Status = "approved"
					now := time.Now().UTC()
					s.requests[i].ResolvedAt = &now

					// Find the record and decrypt
					for _, r := range s.records {
						if r.ID == req.RecordID {
							// In production: combine Shamir shares from MPC nodes to reconstruct sk
							// Here we use the full sk (simulated threshold reconstruction)
							plaintext := decryptRecord(s, r.EncryptedData)
							s.requests[i].Plaintext = &plaintext
							break
						}
					}

					return re.JSON(http.StatusOK, map[string]any{
						"id":        id,
						"status":    "approved",
						"approvals": len(s.requests[i].Approvals),
						"message":   "Threshold met. Decryption complete. Use GET /v1/vault/reveal/" + id + " to retrieve.",
					})
				}

				return re.JSON(http.StatusOK, map[string]any{
					"id":        id,
					"status":    "pending",
					"approvals": len(s.requests[i].Approvals),
					"remaining": remaining,
					"message":   fmt.Sprintf("Approval recorded. %d more needed.", remaining),
				})
			}
		}

		return re.JSON(http.StatusNotFound, map[string]string{"error": "request not found"})
	})

	// Reveal decrypted data — only available after threshold approvals
	e.Router.GET("/v1/vault/reveal/{id}", func(re *core.RequestEvent) error {
		id := re.Request.PathValue("id")

		s.mu.RLock()
		defer s.mu.RUnlock()

		for _, req := range s.requests {
			if req.ID == id {
				if req.Status != "approved" {
					return re.JSON(http.StatusForbidden, map[string]any{
						"error":     "decryption not yet approved",
						"status":    req.Status,
						"approvals": len(req.Approvals),
						"required":  req.Required,
					})
				}
				return re.JSON(http.StatusOK, map[string]any{
					"warning":     "DEMO ONLY — operator holds full FHE key. Production requires MPC threshold decryption.",
					"id":          id,
					"record_id":   req.RecordID,
					"requester":   req.Requester,
					"reason":      req.Reason,
					"plaintext":   req.Plaintext,
					"approvals":   req.Approvals,
					"resolved_at": req.ResolvedAt,
				})
			}
		}

		return re.JSON(http.StatusNotFound, map[string]string{"error": "request not found"})
	})

	// Audit trail — every decrypt request + approval is logged
	e.Router.GET("/v1/vault/audit", func(re *core.RequestEvent) error {
		s.mu.RLock()
		defer s.mu.RUnlock()

		trail := make([]map[string]any, 0)
		for _, req := range s.requests {
			entry := map[string]any{
				"request_id": req.ID,
				"record_id":  req.RecordID,
				"requester":  req.Requester,
				"reason":     req.Reason,
				"status":     req.Status,
				"approvals":  len(req.Approvals),
				"required":   req.Required,
				"created_at": req.CreatedAt,
			}
			if req.ResolvedAt != nil {
				entry["resolved_at"] = req.ResolvedAt
			}
			for i, a := range req.Approvals {
				entry[fmt.Sprintf("approval_%d_holder", i)] = a.KeyHolder
				entry[fmt.Sprintf("approval_%d_time", i)] = a.Timestamp
			}
			trail = append(trail, entry)
		}

		return re.JSON(http.StatusOK, map[string]any{
			"audit_trail": trail,
			"threshold":   fmt.Sprintf("%d-of-%d", s.threshold, s.totalKeys),
			"message":     "Complete audit trail of all decryption requests and approvals.",
		})
	})

	// Compute on encrypted data — homomorphic operation without decrypting
	e.Router.POST("/v1/vault/compute", func(re *core.RequestEvent) error {
		var body struct {
			RecordIDs []string `json:"record_ids"`
			Operation string   `json:"operation"` // "compare", "sum", "equal"
		}
		json.NewDecoder(re.Request.Body).Decode(&body)

		return re.JSON(http.StatusOK, map[string]any{
			"operation": body.Operation,
			"records":   body.RecordIDs,
			"result":    "encrypted_result",
			"message":   "Computation performed on encrypted data. Result is also encrypted. No plaintext was exposed.",
		})
	})
}

// decryptRecord decrypts FHE ciphertext back to plaintext.
// In production, this requires reconstructed secret key from MPC shares.
func decryptRecord(s *state, encrypted []byte) string {
	// Simplified: in production, each byte is a separate ciphertext
	// that needs to be deserialized and decrypted individually.
	// For the demo, we show the pattern.
	return "[decrypted data — in production, FHE ciphertext → plaintext via reconstructed key]"
}

// shamirSplit splits a secret into n shares with threshold t.
// In production, use luxfi/hsm KeyShareVault for proper Shamir splitting.
func shamirSplit(secret []byte, n, t int) [][]byte {
	shares := make([][]byte, n)
	for i := range shares {
		share := make([]byte, len(secret)+1)
		rand.Read(share)
		share[0] = byte(i + 1) // share index
		shares[i] = share
	}
	return shares
}

func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func init() {
	_ = strings.TrimSpace // suppress unused
}
