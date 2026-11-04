package flags

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// FeatureFlag defines a client-side feature flag schema
type FeatureFlag struct {
	Key          string   `json:"key"`
	Description  string   `json:"description"`
	Enabled      bool     `json:"enabled"`
	RolloutPct   int      `json:"rollout_pct"`
	Environments []string `json:"environments,omitempty"`
	UpdatedAt    string   `json:"updated_at"`
}

// Store maintains thread-safe in-memory cache of edge feature flags
type Store struct {
	mu     sync.RWMutex
	flags  map[string]FeatureFlag
	logger *slog.Logger
}

func NewStore(logger *slog.Logger) *Store {
	if logger == nil {
		logger = slog.Default()
	}
	return &Store{
		flags:  make(map[string]FeatureFlag),
		logger: logger,
	}
}

// UpdateFromJSON parses incoming JSON (array, wrapped object, or single flag) and updates in-memory flags
func (s *Store) UpdateFromJSON(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. Check if wrapped in {"flags": [...]}
	var wrapped struct {
		Flags []FeatureFlag `json:"flags"`
	}
	if err := json.Unmarshal(data, &wrapped); err == nil && len(wrapped.Flags) > 0 {
		for _, f := range wrapped.Flags {
			s.flags[f.Key] = f
		}
		s.logger.Debug("Updated feature flags in memory from wrapped JSON", "count", len(wrapped.Flags))
		return nil
	}

	// 2. Check if array of flags [...]
	var batch []FeatureFlag
	if err := json.Unmarshal(data, &batch); err == nil && len(batch) > 0 {
		for _, f := range batch {
			s.flags[f.Key] = f
		}
		s.logger.Debug("Updated batch feature flags in memory", "count", len(batch))
		return nil
	}

	// 3. Check if single flag object {"key": "..."}
	var single FeatureFlag
	if err := json.Unmarshal(data, &single); err == nil && single.Key != "" {
		s.flags[single.Key] = single
		s.logger.Info("Updated feature flag in memory", "key", single.Key, "enabled", single.Enabled)
		return nil
	}

	return nil
}

// IsEnabled returns true if the flag is enabled in memory
func (s *Store) IsEnabled(key string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	flag, exists := s.flags[key]
	if !exists {
		return false
	}
	return flag.Enabled
}

// Get returns the flag for key if present
func (s *Store) Get(key string) (FeatureFlag, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	flag, exists := s.flags[key]
	return flag, exists
}

// GetAll returns a copy of all loaded flags
func (s *Store) GetAll() []FeatureFlag {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]FeatureFlag, 0, len(s.flags))
	for _, f := range s.flags {
		result = append(result, f)
	}
	return result
}

// DumpJSON returns serialized JSON of all flags wrapped in {"flags": [...], "count": N}
func (s *Store) DumpJSON() ([]byte, error) {
	flags := s.GetAll()
	return json.Marshal(map[string]any{
		"flags": flags,
		"count": len(flags),
	})
}

// SyncToFile writes all flags to dir/flags.json (atomic write via temp file) and dir/flags.env
func (s *Store) SyncToFile(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create flags dir: %w", err)
	}

	flags := s.GetAll()
	jsonData, err := json.MarshalIndent(map[string]any{
		"flags": flags,
		"count": len(flags),
	}, "", "  ")
	if err != nil {
		return err
	}

	jsonPath := filepath.Join(dir, "flags.json")
	tmpJsonPath := filepath.Join(dir, "flags.json.tmp")
	if err := os.WriteFile(tmpJsonPath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write tmp flags.json: %w", err)
	}
	if err := os.Rename(tmpJsonPath, jsonPath); err != nil {
		return fmt.Errorf("failed to rename tmp flags.json: %w", err)
	}

	// Also generate flags.env for shell/docker env file compatibility
	var envLines []string
	for _, f := range flags {
		cleanKey := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(f.Key, "-", "_"), ".", "_"))
		envLines = append(envLines, fmt.Sprintf("FEATURE_FLAG_%s=%t", cleanKey, f.Enabled))
	}
	envData := []byte(strings.Join(envLines, "\n") + "\n")
	envPath := filepath.Join(dir, "flags.env")
	tmpEnvPath := filepath.Join(dir, "flags.env.tmp")
	if err := os.WriteFile(tmpEnvPath, envData, 0644); err == nil {
		_ = os.Rename(tmpEnvPath, envPath)
	}

	return nil
}
