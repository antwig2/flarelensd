package mesh

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestStatePersistence(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "mesh-state.json")
	t.Setenv("FLARELENS_STATE_PATH", statePath)

	state := &MeshState{
		DeviceName:     "test-workstation",
		PublicKey:      "TESTPUBKEY1234567890=",
		PrivateKeyPath: filepath.Join(tmpDir, "mesh.key"),
		OverlayIP:      "100.64.0.5",
		Subnet:         "100.64.0.0/10",
		ControlURL:     "https://control.flarelens.dev",
		ApprovedBy:     "admin@example.com",
		Interface:      "flarelens0",
		ConfigPath:     filepath.Join(tmpDir, "flarelens-mesh.conf"),
		Peers: []Peer{
			{
				ID:        "node-1",
				Name:      "node-1",
				PublicKey: "PEERPUBKEY1234567890=",
				OverlayIP: "100.64.0.1",
				Endpoint:  "198.51.100.1:51820",
			},
		},
	}

	if err := SaveState(state); err != nil {
		t.Fatalf("SaveState failed: %v", err)
	}

	loaded, err := LoadState()
	if err != nil {
		t.Fatalf("LoadState failed: %v", err)
	}

	if loaded.DeviceName != "test-workstation" {
		t.Errorf("Expected DeviceName test-workstation, got %s", loaded.DeviceName)
	}
	if loaded.OverlayIP != "100.64.0.5" {
		t.Errorf("Expected OverlayIP 100.64.0.5, got %s", loaded.OverlayIP)
	}
	if len(loaded.Peers) != 1 || loaded.Peers[0].ID != "node-1" {
		t.Errorf("Expected 1 peer with ID node-1, got %+v", loaded.Peers)
	}
}

func TestFormatHelpers(t *testing.T) {
	if FormatBytes(500) != "500 B" {
		t.Errorf("Expected '500 B', got '%s'", FormatBytes(500))
	}
	if FormatBytes(1024*1024*5) != "5.0 MB" {
		t.Errorf("Expected '5.0 MB', got '%s'", FormatBytes(1024*1024*5))
	}

	if FormatTimeAgo(time.Time{}) != "never" {
		t.Errorf("Expected 'never', got '%s'", FormatTimeAgo(time.Time{}))
	}
	if FormatTimeAgo(time.Now().Add(-15*time.Second)) != "15s ago" {
		t.Errorf("Expected '15s ago', got '%s'", FormatTimeAgo(time.Now().Add(-15*time.Second)))
	}
}

func TestRunStatusWithSavedState(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "mesh-state.json")
	t.Setenv("FLARELENS_STATE_PATH", statePath)

	state := &MeshState{
		DeviceName: "laptop-dev",
		OverlayIP:  "100.64.0.42",
		ControlURL: "https://control.flarelens.dev",
		ApprovedBy: "alice@example.com",
		ConfigPath: filepath.Join(tmpDir, "mesh.conf"),
		Interface:  "dummy-nonexistent-iface",
	}
	if err := SaveState(state); err != nil {
		t.Fatalf("SaveState failed: %v", err)
	}

	// Should report disconnected state cleanly
	if err := RunStatus(context.Background(), nil); err != nil {
		t.Fatalf("RunStatus failed: %v", err)
	}
}
