// Package store provides encrypted key/ciphertext storage for fhed using ZapDB.
package store

import (
	"crypto/sha256"
	"fmt"

	"github.com/luxfi/database/encdb"
	"github.com/luxfi/database/zapdb"
	"github.com/luxfi/metric"
)

// Store wraps encrypted ZapDB for FHE key material and ciphertext storage.
type Store struct {
	db *encdb.Database
}

// Key prefixes for namespacing within the single DB.
var (
	prefixSecretKey    = []byte("sk/")
	prefixPublicKey    = []byte("pk/")
	prefixBootstrapKey = []byte("bsk/")
	prefixCiphertext   = []byte("ct/")
	prefixMeta         = []byte("meta/")
)

// Open creates or opens an encrypted ZapDB at the given path.
// The password encrypts all data at rest via ChaCha20-Poly1305.
func Open(path, password string) (*Store, error) {
	baseDB, err := zapdb.New(path, nil, "fhed", metric.NewNoOpRegistry())
	if err != nil {
		return nil, fmt.Errorf("open zapdb: %w", err)
	}

	enc, err := encdb.New([]byte(password), baseDB)
	if err != nil {
		baseDB.Close()
		return nil, fmt.Errorf("open encdb: %w", err)
	}

	return &Store{db: enc}, nil
}

// Close closes the database.
func (s *Store) Close() error {
	return s.db.Close()
}

// PutSecretKey stores the secret key material.
func (s *Store) PutSecretKey(id string, data []byte) error {
	return s.db.Put(append(prefixSecretKey, []byte(id)...), data)
}

// GetSecretKey retrieves the secret key material.
func (s *Store) GetSecretKey(id string) ([]byte, error) {
	return s.db.Get(append(prefixSecretKey, []byte(id)...))
}

// PutPublicKey stores the public key.
func (s *Store) PutPublicKey(id string, data []byte) error {
	return s.db.Put(append(prefixPublicKey, []byte(id)...), data)
}

// GetPublicKey retrieves the public key.
func (s *Store) GetPublicKey(id string) ([]byte, error) {
	return s.db.Get(append(prefixPublicKey, []byte(id)...))
}

// PutBootstrapKey stores the bootstrap (evaluation) key.
func (s *Store) PutBootstrapKey(id string, data []byte) error {
	return s.db.Put(append(prefixBootstrapKey, []byte(id)...), data)
}

// GetBootstrapKey retrieves the bootstrap key.
func (s *Store) GetBootstrapKey(id string) ([]byte, error) {
	return s.db.Get(append(prefixBootstrapKey, []byte(id)...))
}

// PutCiphertext stores an encrypted ciphertext by its content hash.
func (s *Store) PutCiphertext(data []byte) (string, error) {
	hash := sha256.Sum256(data)
	key := append(prefixCiphertext, hash[:]...)
	if err := s.db.Put(key, data); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash), nil
}

// GetCiphertext retrieves a ciphertext by its hash.
func (s *Store) GetCiphertext(hexHash string) ([]byte, error) {
	var hash [32]byte
	if _, err := fmt.Sscanf(hexHash, "%x", &hash); err != nil {
		return nil, fmt.Errorf("invalid hash: %w", err)
	}
	return s.db.Get(append(prefixCiphertext, hash[:]...))
}

// PutMeta stores metadata (params, node config, etc).
func (s *Store) PutMeta(key string, data []byte) error {
	return s.db.Put(append(prefixMeta, []byte(key)...), data)
}

// GetMeta retrieves metadata.
func (s *Store) GetMeta(key string) ([]byte, error) {
	return s.db.Get(append(prefixMeta, []byte(key)...))
}

// HasSecretKey checks if a secret key exists.
func (s *Store) HasSecretKey(id string) bool {
	has, _ := s.db.Has(append(prefixSecretKey, []byte(id)...))
	return has
}
