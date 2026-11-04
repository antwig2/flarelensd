package mesh

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"time"
)

// MeshState represents persisted local device state for status and daemon synchronization
type MeshState struct {
	DeviceName     string    `json:"device_name"`
	PublicKey      string    `json:"public_key"`
	PrivateKeyPath string    `json:"private_key_path"`
	OverlayIP      string    `json:"overlay_ip"`
	Subnet         string    `json:"subnet"`
	ControlURL     string    `json:"control_url"`
	ApprovedBy     string    `json:"approved_by,omitempty"`
	Interface      string    `json:"interface"`
	ConfigPath     string    `json:"config_path"`
	Peers          []Peer    `json:"peers"`
	LastUpdated    time.Time `json:"last_updated"`
}

// DefaultStatePath resolves the standard location for persisting mesh state
func DefaultStatePath() string {
	if custom := os.Getenv("FLARELENS_STATE_PATH"); custom != "" {
		return custom
	}
	if os.Geteuid() == 0 {
		return "/var/lib/flarelens/mesh-state.json"
	}
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		return filepath.Join(home, ".flarelens", "mesh-state.json")
	}
	return ".flarelens-state.json"
}

// SaveState persists the mesh state to disk with secure permissions
func SaveState(state *MeshState) error {
	if state == nil {
		return fmt.Errorf("state is nil")
	}
	path := DefaultStatePath()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		path = ".flarelens-state.json"
	}

	state.LastUpdated = time.Now()
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return err
	}

	// If running under sudo, also save a copy to the invoking user's home directory
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" && sudoUser != "root" {
		if usr, err := user.Lookup(sudoUser); err == nil && usr.HomeDir != "" {
			userDir := filepath.Join(usr.HomeDir, ".flarelens")
			if err := os.MkdirAll(userDir, 0755); err == nil {
				userPath := filepath.Join(userDir, "mesh-state.json")
				if err := os.WriteFile(userPath, data, 0644); err == nil {
					// Attempt to set ownership to invoking user
					var uid, gid int
					if _, err := fmt.Sscanf(usr.Uid, "%d", &uid); err == nil {
						if _, err := fmt.Sscanf(usr.Gid, "%d", &gid); err == nil {
							_ = os.Chown(userPath, uid, gid)
						}
					}
				}
			}
		}
	}

	return nil
}

// LoadState reads persisted mesh state from the standard paths
func LoadState() (*MeshState, error) {
	var paths []string

	if custom := os.Getenv("FLARELENS_STATE_PATH"); custom != "" {
		paths = append(paths, custom)
	}

	paths = append(paths,
		DefaultStatePath(),
		"/var/lib/flarelens/mesh-state.json",
		"/etc/flarelens/mesh-state.json",
	)

	if home, err := os.UserHomeDir(); err == nil && home != "" {
		paths = append(paths, filepath.Join(home, ".flarelens", "mesh-state.json"))
	}
	paths = append(paths, ".flarelens-state.json")

	for _, p := range paths {
		if data, err := os.ReadFile(p); err == nil {
			var state MeshState
			if err := json.Unmarshal(data, &state); err == nil {
				return &state, nil
			}
		}
	}

	return nil, os.ErrNotExist
}

// LoadStateFromPath reads persisted mesh state from an explicit file path
func LoadStateFromPath(p string) (*MeshState, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var state MeshState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

