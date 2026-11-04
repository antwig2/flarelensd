package mesh

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestEnsureSSHKeypair(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "flarelens-ssh-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// 1. Generate keypair for the first time
	privPath, pubStr, err := EnsureSSHKeypair(tempDir)
	if err != nil {
		t.Fatalf("EnsureSSHKeypair failed: %v", err)
	}

	if privPath != filepath.Join(tempDir, DefaultSSHKeyName) {
		t.Errorf("Unexpected private key path: got %s, want %s", privPath, filepath.Join(tempDir, DefaultSSHKeyName))
	}

	if !strings.HasPrefix(pubStr, "ssh-ed25519 ") {
		t.Errorf("Public key does not have ssh-ed25519 prefix: %s", pubStr)
	}

	// Verify key can be parsed by crypto/ssh
	parsedKey, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(pubStr))
	if err != nil {
		t.Fatalf("Failed to parse generated authorized key: %v", err)
	}
	if parsedKey.Type() != "ssh-ed25519" {
		t.Errorf("Expected key type ssh-ed25519, got %s", parsedKey.Type())
	}
	if comment != "flarelens-mesh" {
		t.Errorf("Expected comment 'flarelens-mesh', got '%s'", comment)
	}

	// Verify file permissions
	privInfo, err := os.Stat(privPath)
	if err != nil {
		t.Fatalf("Failed to stat private key: %v", err)
	}
	if perm := privInfo.Mode().Perm(); perm != 0600 {
		t.Errorf("Private key permission expected 0600, got %o", perm)
	}

	// 2. Calling EnsureSSHKeypair again should idempotently reuse the same key
	privPath2, pubStr2, err := EnsureSSHKeypair(tempDir)
	if err != nil {
		t.Fatalf("Second EnsureSSHKeypair failed: %v", err)
	}
	if privPath2 != privPath || pubStr2 != pubStr {
		t.Errorf("EnsureSSHKeypair did not reuse existing key. Got %s, want %s", pubStr2, pubStr)
	}
}

func TestRunSSHAuth(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "flarelens-sshauth-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	statePath := filepath.Join(tempDir, "mesh-state.json")

	// Sample test keys
	key1 := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGe94g2w98f249h82f4hf2489fh2948fh2489fh2489f dev-laptop"
	key2 := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH923hf2983hf2893hf2893hf2893hf2893hf2893hf admin-macbook"

	state := MeshState{
		DeviceName: "node-1",
		OverlayIP:  "100.64.0.1",
		Peers: []Peer{
			{
				ID:           "client-dev",
				Name:         "dev-laptop",
				SSHPublicKey: key1,
			},
			{
				ID:           "client-admin",
				Name:         "admin-macbook",
				SSHPublicKey: key2,
			},
			{
				ID:           "node-no-ssh",
				Name:         "unrelated-node",
				SSHPublicKey: "",
			},
		},
	}

	data, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("Failed to marshal state: %v", err)
	}
	if err := os.WriteFile(statePath, data, 0644); err != nil {
		t.Fatalf("Failed to write state: %v", err)
	}

	// Test 1: Match specific incoming key (OpenSSH %k passes base64 blob)
	key1Fields := strings.Fields(key1)
	base64Key1 := key1Fields[1]

	var out1 bytes.Buffer
	err = RunSSHAuth("root", base64Key1, "ssh-ed25519", statePath, &out1, nil)
	if err != nil {
		t.Fatalf("RunSSHAuth failed: %v", err)
	}
	if strings.TrimSpace(out1.String()) != key1 {
		t.Errorf("Expected key1 authorized, got: %s", out1.String())
	}

	// Test 2: Unknown incoming key -> nothing emitted
	var out2 bytes.Buffer
	err = RunSSHAuth("root", "AAAAC3NzaC1lZDI1NTE5AAAAIUNKNOWNKEYBLOB999999999999999999999", "ssh-ed25519", statePath, &out2, nil)
	if err != nil {
		t.Fatalf("RunSSHAuth failed: %v", err)
	}
	if strings.TrimSpace(out2.String()) != "" {
		t.Errorf("Expected empty output for unknown key, got: %s", out2.String())
	}

	// Test 3: Empty incoming key -> all approved keys emitted
	var out3 bytes.Buffer
	err = RunSSHAuth("root", "", "", statePath, &out3, nil)
	if err != nil {
		t.Fatalf("RunSSHAuth failed: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out3.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("Expected 2 keys emitted, got %d: %v", len(lines), lines)
	}
	if lines[0] != key1 || lines[1] != key2 {
		t.Errorf("Unexpected keys emitted: %v", lines)
	}

	// Test 4: Missing state file -> returns nil gracefully without error
	var out4 bytes.Buffer
	err = RunSSHAuth("root", base64Key1, "ssh-ed25519", filepath.Join(tempDir, "nonexistent.json"), &out4, nil)
	if err != nil {
		t.Errorf("RunSSHAuth should succeed gracefully on missing state, got: %v", err)
	}
	if out4.Len() != 0 {
		t.Errorf("Expected empty output on missing state, got: %s", out4.String())
	}
}
