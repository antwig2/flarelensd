package mesh

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestRunRemoteLogsCLIKeylessEd25519StreamAndClose(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	pemBlock, err := ssh.MarshalPrivateKey(priv, "dev@workstation")
	if err != nil {
		t.Fatalf("marshal ssh key: %v", err)
	}
	sshPath := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(sshPath, pem.EncodeToMemory(pemBlock), 0o600); err != nil {
		t.Fatalf("write ssh key: %v", err)
	}

	var mu sync.Mutex
	pollCount := 0
	closed := false
	openSigned := false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/control/containers/logs/sessions":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			openSigned = body["ssh_signature"] != nil && body["ssh_signature"] != ""
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"session": map[string]any{
					"session_id": "lsess_cli_1",
					"node_id":    "node-1",
				},
			})

		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/control/containers/logs/sessions/lsess_cli_1":
			mu.Lock()
			pollCount++
			c := pollCount
			mu.Unlock()
			if c == 1 {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"session": map[string]any{"status": "streaming", "container_name": "postgres-uat"},
					"chunks": []map[string]any{
						{"seq": 1, "text": "database system is ready to accept connections\n"},
					},
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"session": map[string]any{"status": "eof", "container_name": "postgres-uat"},
				"chunks": []map[string]any{
					{"seq": 2, "text": "checkpoint complete\n"},
				},
			})

		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/control/containers/logs/sessions/lsess_cli_1":
			mu.Lock()
			closed = true
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"closed"}`))
		}
	}))
	defer srv.Close()

	var out bytes.Buffer
	err = RunRemoteLogsCLI(t.Context(), RemoteLogsOptions{
		Target:     "postgres",
		Env:        "uat",
		Follow:     true,
		TailLines:  50,
		ControlURL: srv.URL,
		PeerID:     "laptop-dev",
		PublicKey:  "wgLaptopKey=",
		SSHKeyPath: sshPath,
		Output:     &out,
		PollEvery:  25 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("RunRemoteLogsCLI failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if !openSigned {
		t.Fatal("expected Ed25519 signature on log session open")
	}
	if !closed {
		t.Fatal("expected DELETE session cleanup on exit")
	}
	got := out.String()
	if !strings.Contains(got, "database system is ready") || !strings.Contains(got, "checkpoint complete") {
		t.Fatalf("unexpected log output: %q", got)
	}
}
