package mesh

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

type recordedDisconnectCmd struct {
	cmd  string
	args []string
}

type mockDisconnectExecutor struct {
	ifaceExists bool
	calls       []recordedDisconnectCmd
}

func (m *mockDisconnectExecutor) Run(_ context.Context, cmd string, args ...string) ([]byte, error) {
	m.calls = append(m.calls, recordedDisconnectCmd{cmd: cmd, args: args})
	if cmd == "ip" && len(args) >= 3 && args[0] == "link" && args[1] == "show" {
		if !m.ifaceExists {
			return []byte("Device does not exist"), os.ErrNotExist
		}
	}
	return []byte("ok"), nil
}

func TestStripMagicDNSHostsBlock(t *testing.T) {
	raw := "127.0.0.1 localhost\n::1 localhost\n\n" +
		MagicDNSHostsHeader + "\n" +
		"# Managed dynamically\n100.64.0.1       app-1.mesh\n" +
		MagicDNSHostsFooter + "\n"

	cleaned, changed := StripMagicDNSHostsBlock(raw)
	if !changed {
		t.Fatal("expected changed=true when MagicDNS block is present")
	}
	if strings.Contains(cleaned, "app-1.mesh") || strings.Contains(cleaned, MagicDNSHostsHeader) {
		t.Fatalf("expected MagicDNS block to be removed, got:\n%s", cleaned)
	}
	if !strings.Contains(cleaned, "127.0.0.1 localhost") {
		t.Fatalf("expected existing /etc/hosts entries preserved, got:\n%s", cleaned)
	}
}

func TestSignMeshLeaveProofAndRunDisconnectLogout(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Generate SSH Ed25519 keypair + WireGuard keypair + /etc/hosts + mesh-state.json
	sshPrivPath, sshPubAuthorized, err := EnsureSSHKeypair(tmpDir)
	if err != nil {
		t.Fatalf("EnsureSSHKeypair failed: %v", err)
	}
	wgKeyPath := filepath.Join(tmpDir, "mesh.key")
	_, wgPubKey, err := LoadOrGenerateKeypair(wgKeyPath)
	if err != nil {
		t.Fatalf("LoadOrGenerateKeypair failed: %v", err)
	}

	hostsPath := filepath.Join(tmpDir, "hosts")
	initialHosts := "127.0.0.1 localhost\n\n" +
		MagicDNSHostsHeader + "\n100.64.0.5 laptop.mesh\n" + MagicDNSHostsFooter + "\n"
	if err := os.WriteFile(hostsPath, []byte(initialHosts), 0644); err != nil {
		t.Fatalf("write hosts failed: %v", err)
	}

	confPath := filepath.Join(tmpDir, "flarelens-mesh.conf")
	_ = os.WriteFile(confPath, []byte("[Interface]\n"), 0600)

	statePath := filepath.Join(tmpDir, "mesh-state.json")
	t.Setenv("FLARELENS_STATE_PATH", statePath)

	// 2. Mock Control Plane verifying Ed25519 signature against sshPubAuthorized
	var receivedBody map[string]string
	var receivedAuthHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/control/mesh/leave" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		receivedAuthHeader = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &receivedBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"deleted"}`))
	}))
	defer srv.Close()

	state := &MeshState{
		DeviceName:     "dev-macbook",
		PublicKey:      wgPubKey,
		PrivateKeyPath: wgKeyPath,
		OverlayIP:      "100.64.0.5",
		ControlURL:     srv.URL,
		Interface:      "flarelens0",
		ConfigPath:     confPath,
	}
	if err := SaveState(state); err != nil {
		t.Fatalf("SaveState failed: %v", err)
	}

	execRecorder := &mockDisconnectExecutor{ifaceExists: true}

	res, err := RunDisconnect(t.Context(), DisconnectOptions{
		HostsPath:    hostsPath,
		SSHKeyPath:   sshPrivPath,
		GOOS:         "linux",
		RevokeRemote: true,
		PurgeState:   true,
		PurgeKeys:    true,
		Executor:     execRecorder,
		HTTPClient:   srv.Client(),
	}, nil)
	if err != nil {
		t.Fatalf("RunDisconnect failed: %v", err)
	}

	if !res.RemoteRevoked || !res.InterfaceRemoved || !res.HostsCleaned {
		t.Fatalf("unexpected DisconnectResult: %+v", res)
	}
	if receivedAuthHeader != "" {
		t.Fatalf("expected keyless SSO logout without Authorization header, got %q", receivedAuthHeader)
	}

	// Cryptographically verify the Ed25519 signature sent by the agent!
	parsedPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(sshPubAuthorized))
	if err != nil {
		t.Fatalf("ParseAuthorizedKey failed: %v", err)
	}
	cryptoPub := parsedPub.(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey)
	sigBytes, err := base64.StdEncoding.DecodeString(receivedBody["ssh_signature"])
	if err != nil {
		t.Fatalf("decode ssh_signature failed: %v", err)
	}
	expectedMsg := "flarelens-mesh-leave:" + wgPubKey + ":" + receivedBody["timestamp"]
	if !ed25519.Verify(cryptoPub, []byte(expectedMsg), sigBytes) {
		t.Fatalf("Ed25519 signature verification failed for message %q", expectedMsg)
	}

	// Verify state, .conf, and keys were purged and /etc/hosts was cleaned
	for _, gone := range []string{statePath, confPath, wgKeyPath, sshPrivPath} {
		if _, statErr := os.Stat(gone); !os.IsNotExist(statErr) {
			t.Errorf("expected %s to be deleted, statErr=%v", gone, statErr)
		}
	}
	afterHosts, _ := os.ReadFile(hostsPath)
	if strings.Contains(string(afterHosts), "laptop.mesh") {
		t.Errorf("expected laptop.mesh removed from hosts, got: %s", string(afterHosts))
	}
}

func TestValidateInterfaceNameRejectsFlags(t *testing.T) {
	if err := ValidateInterfaceName("--help"); err == nil {
		t.Fatal("expected flag-like interface name to be rejected")
	}
	if err := ValidateInterfaceName("flarelens0"); err != nil {
		t.Fatalf("expected flarelens0 to be valid: %v", err)
	}
}
