// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package membership manages dynamic FHE cluster membership with LSSS resharing.
package membership

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Member represents a cluster member
type Member struct {
	NodeID    string    `json:"nodeId"`
	Addr      string    `json:"addr"`
	Port      int       `json:"port"`
	PublicKey []byte    `json:"publicKey"`
	ShareIdx  int       `json:"shareIdx"` // LSSS share index (1-based)
	Joined    time.Time `json:"joined"`
	Ready     bool      `json:"ready"`
}

// ClusterState represents the current cluster state
type ClusterState struct {
	Version   uint64    `json:"version"`   // Monotonic version for state changes
	Threshold int       `json:"threshold"` // t in t-of-n
	Members   []*Member `json:"members"`
	KeyGenID  string    `json:"keyGenId"`  // Current keygen session ID
	UpdatedAt time.Time `json:"updatedAt"`
}

// MembershipChange represents a change in membership
type MembershipChange struct {
	Type      ChangeType `json:"type"`
	Member    *Member    `json:"member"`
	Timestamp time.Time  `json:"timestamp"`
}

// ChangeType indicates the type of membership change
type ChangeType string

const (
	ChangeJoin      ChangeType = "join"
	ChangeLeave     ChangeType = "leave"
	ChangeThreshold ChangeType = "threshold"
	ChangeReshare   ChangeType = "reshare"
)

// ChangeHandler is called when membership changes
type ChangeHandler func(change *MembershipChange, newState *ClusterState)

// Manager handles cluster membership
type Manager struct {
	nodeID    string
	threshold int
	logger    *slog.Logger

	mu       sync.RWMutex
	state    *ClusterState
	handlers []ChangeHandler

	// Pending operations
	pendingJoins  map[string]*Member
	pendingLeaves map[string]struct{}
}

// ManagerConfig configures the membership manager
type ManagerConfig struct {
	NodeID    string
	Threshold int
	Logger    *slog.Logger
}

// NewManager creates a new membership manager
func NewManager(cfg ManagerConfig) *Manager {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return &Manager{
		nodeID:        cfg.NodeID,
		threshold:     cfg.Threshold,
		logger:        cfg.Logger,
		state:         &ClusterState{Threshold: cfg.Threshold},
		pendingJoins:  make(map[string]*Member),
		pendingLeaves: make(map[string]struct{}),
	}
}

// OnChange registers a change handler
func (m *Manager) OnChange(handler ChangeHandler) {
	m.mu.Lock()
	m.handlers = append(m.handlers, handler)
	m.mu.Unlock()
}

// GetState returns the current cluster state
func (m *Manager) GetState() *ClusterState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Deep copy
	state := &ClusterState{
		Version:   m.state.Version,
		Threshold: m.state.Threshold,
		KeyGenID:  m.state.KeyGenID,
		UpdatedAt: m.state.UpdatedAt,
		Members:   make([]*Member, len(m.state.Members)),
	}
	for i, mem := range m.state.Members {
		memCopy := *mem
		state.Members[i] = &memCopy
	}
	return state
}

// GetMember returns a member by ID
func (m *Manager) GetMember(nodeID string) (*Member, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, mem := range m.state.Members {
		if mem.NodeID == nodeID {
			return mem, true
		}
	}
	return nil, false
}

// MemberCount returns the number of members
func (m *Manager) MemberCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.state.Members)
}

// ReadyCount returns the number of ready members
func (m *Manager) ReadyCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	count := 0
	for _, mem := range m.state.Members {
		if mem.Ready {
			count++
		}
	}
	return count
}

// CanDecrypt returns true if we have enough members for threshold decryption
func (m *Manager) CanDecrypt() bool {
	return m.ReadyCount() >= m.threshold
}

// AddMember adds a new member (triggers reshare if threshold reached)
func (m *Manager) AddMember(member *Member) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if already exists
	for _, existing := range m.state.Members {
		if existing.NodeID == member.NodeID {
			// Update existing member
			existing.Addr = member.Addr
			existing.Port = member.Port
			existing.Ready = member.Ready
			existing.PublicKey = member.PublicKey
			return nil
		}
	}

	// Assign share index
	member.ShareIdx = len(m.state.Members) + 1
	member.Joined = time.Now()

	m.state.Members = append(m.state.Members, member)
	m.state.Version++
	m.state.UpdatedAt = time.Now()

	change := &MembershipChange{
		Type:      ChangeJoin,
		Member:    member,
		Timestamp: time.Now(),
	}

	m.logger.Info("Member added",
		"nodeID", member.NodeID,
		"shareIdx", member.ShareIdx,
		"totalMembers", len(m.state.Members),
	)

	// Notify handlers
	for _, h := range m.handlers {
		go h(change, m.GetState())
	}

	return nil
}

// RemoveMember removes a member (triggers reshare)
func (m *Manager) RemoveMember(nodeID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var removed *Member
	newMembers := make([]*Member, 0, len(m.state.Members)-1)
	for _, mem := range m.state.Members {
		if mem.NodeID == nodeID {
			removed = mem
		} else {
			newMembers = append(newMembers, mem)
		}
	}

	if removed == nil {
		return fmt.Errorf("member not found: %s", nodeID)
	}

	// Reassign share indices
	for i, mem := range newMembers {
		mem.ShareIdx = i + 1
	}

	m.state.Members = newMembers
	m.state.Version++
	m.state.UpdatedAt = time.Now()

	change := &MembershipChange{
		Type:      ChangeLeave,
		Member:    removed,
		Timestamp: time.Now(),
	}

	m.logger.Info("Member removed",
		"nodeID", nodeID,
		"remainingMembers", len(m.state.Members),
	)

	// Notify handlers
	for _, h := range m.handlers {
		go h(change, m.GetState())
	}

	return nil
}

// SetThreshold updates the threshold (triggers reshare)
func (m *Manager) SetThreshold(t int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if t < 1 {
		return fmt.Errorf("threshold must be at least 1")
	}
	if t > len(m.state.Members) {
		return fmt.Errorf("threshold cannot exceed member count (%d)", len(m.state.Members))
	}

	oldThreshold := m.state.Threshold
	m.state.Threshold = t
	m.state.Version++
	m.state.UpdatedAt = time.Now()

	change := &MembershipChange{
		Type:      ChangeThreshold,
		Timestamp: time.Now(),
	}

	m.logger.Info("Threshold updated",
		"oldThreshold", oldThreshold,
		"newThreshold", t,
	)

	for _, h := range m.handlers {
		go h(change, m.GetState())
	}

	return nil
}

// SetKeyGenID sets the current keygen session ID
func (m *Manager) SetKeyGenID(id string) {
	m.mu.Lock()
	m.state.KeyGenID = id
	m.state.Version++
	m.state.UpdatedAt = time.Now()
	m.mu.Unlock()
}

// SetMemberReady marks a member as ready
func (m *Manager) SetMemberReady(nodeID string, ready bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, mem := range m.state.Members {
		if mem.NodeID == nodeID {
			mem.Ready = ready
			break
		}
	}
}

// MarshalJSON implements json.Marshaler
func (m *Manager) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.GetState())
}

// LoadState loads state from JSON
func (m *Manager) LoadState(data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var state ClusterState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}
	m.state = &state
	return nil
}

// WaitForQuorum waits until we have enough ready members
func (m *Manager) WaitForQuorum(ctx context.Context) error {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if m.CanDecrypt() {
				return nil
			}
			m.logger.Debug("Waiting for quorum",
				"ready", m.ReadyCount(),
				"threshold", m.threshold,
			)
		}
	}
}
