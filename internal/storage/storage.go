// Package storage provides ciphertext storage and retrieval.
package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Common errors.
var (
	ErrNotFound      = errors.New("ciphertext not found")
	ErrStorageFull   = errors.New("storage capacity exceeded")
	ErrInvalidHandle = errors.New("invalid ciphertext handle")
)

// Handle uniquely identifies a ciphertext.
type Handle string

// ComputeHandle generates a handle from ciphertext data.
func ComputeHandle(data []byte) Handle {
	hash := sha256.Sum256(data)
	return Handle(hex.EncodeToString(hash[:]))
}

// Storage defines the interface for ciphertext storage.
type Storage interface {
	// Store saves a ciphertext and returns its handle.
	Store(ctx context.Context, data []byte) (Handle, error)
	// Load retrieves a ciphertext by handle.
	Load(ctx context.Context, handle Handle) ([]byte, error)
	// Delete removes a ciphertext.
	Delete(ctx context.Context, handle Handle) error
	// Exists checks if a ciphertext exists.
	Exists(ctx context.Context, handle Handle) (bool, error)
	// Close closes the storage.
	Close() error
}

// MemoryStorage implements in-memory ciphertext storage.
type MemoryStorage struct {
	mu       sync.RWMutex
	data     map[Handle][]byte
	capacity int64
	size     int64
}

// NewMemoryStorage creates a new in-memory storage.
func NewMemoryStorage(capacityMB int64) *MemoryStorage {
	return &MemoryStorage{
		data:     make(map[Handle][]byte),
		capacity: capacityMB * 1024 * 1024,
	}
}

func (s *MemoryStorage) Store(ctx context.Context, data []byte) (Handle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	handle := ComputeHandle(data)

	if _, exists := s.data[handle]; exists {
		return handle, nil // Dedup by content hash.
	}

	if s.size+int64(len(data)) > s.capacity {
		return "", ErrStorageFull
	}

	s.data[handle] = append([]byte(nil), data...)
	s.size += int64(len(data))

	return handle, nil
}

func (s *MemoryStorage) Load(ctx context.Context, handle Handle) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, exists := s.data[handle]
	if !exists {
		return nil, ErrNotFound
	}

	return append([]byte(nil), data...), nil
}

func (s *MemoryStorage) Delete(ctx context.Context, handle Handle) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, exists := s.data[handle]
	if !exists {
		return ErrNotFound
	}

	s.size -= int64(len(data))
	delete(s.data, handle)
	return nil
}

func (s *MemoryStorage) Exists(ctx context.Context, handle Handle) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, exists := s.data[handle]
	return exists, nil
}

func (s *MemoryStorage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.data = nil
	s.size = 0
	return nil
}

// FileStorage implements file-based ciphertext storage.
type FileStorage struct {
	baseDir string
}

// NewFileStorage creates a new file-based storage.
func NewFileStorage(baseDir string) (*FileStorage, error) {
	if err := os.MkdirAll(baseDir, 0750); err != nil {
		return nil, fmt.Errorf("create storage dir: %w", err)
	}

	return &FileStorage{baseDir: baseDir}, nil
}

func (s *FileStorage) path(handle Handle) string {
	h := string(handle)
	if len(h) < 4 {
		return filepath.Join(s.baseDir, h)
	}
	// Shard by first 2 chars to avoid too many files in one directory.
	return filepath.Join(s.baseDir, h[:2], h)
}

func (s *FileStorage) Store(ctx context.Context, data []byte) (Handle, error) {
	handle := ComputeHandle(data)
	path := s.path(handle)

	if _, err := os.Stat(path); err == nil {
		return handle, nil // Already exists (dedup).
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return "", fmt.Errorf("create shard dir: %w", err)
	}

	// Write atomically via temp file.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return "", fmt.Errorf("write temp file: %w", err)
	}

	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return "", fmt.Errorf("rename temp file: %w", err)
	}

	return handle, nil
}

func (s *FileStorage) Load(ctx context.Context, handle Handle) ([]byte, error) {
	data, err := os.ReadFile(s.path(handle))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("read file: %w", err)
	}
	return data, nil
}

func (s *FileStorage) Delete(ctx context.Context, handle Handle) error {
	if err := os.Remove(s.path(handle)); err != nil {
		if os.IsNotExist(err) {
			return ErrNotFound
		}
		return fmt.Errorf("remove file: %w", err)
	}
	return nil
}

func (s *FileStorage) Exists(ctx context.Context, handle Handle) (bool, error) {
	_, err := os.Stat(s.path(handle))
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, fmt.Errorf("stat file: %w", err)
}

func (s *FileStorage) Close() error {
	return nil
}
