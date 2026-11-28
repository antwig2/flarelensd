package mesh

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseFunnelTarget(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port int
	}{
		{"3000", "127.0.0.1", 3000},
		{":8080", "127.0.0.1", 8080},
		{"localhost:5173", "localhost", 5173},
		{"http://127.0.0.1:9000", "127.0.0.1", 9000},
	}
	for _, tc := range cases {
		h, p, err := ParseFunnelTarget(tc.in)
		if err != nil {
			t.Fatalf("ParseFunnelTarget(%q) unexpected error: %v", tc.in, err)
		}
		if h != tc.host || p != tc.port {
			t.Fatalf("ParseFunnelTarget(%q) = (%q, %d), want (%q, %d)", tc.in, h, p, tc.host, tc.port)
		}
	}
}

func TestRunFunnelRegistrationForwardingBasicAuthAndTeardown(t *testing.T) {
	// 1. Start mock developer localhost server
	var receivedHost, receivedFwdHost, receivedFwdProto string
	localApp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHost = r.Host
		receivedFwdHost = r.Header.Get("X-Forwarded-Host")
		receivedFwdProto = r.Header.Get("X-Forwarded-Proto")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("webhook-accepted"))
	}))
	defer localApp.Close()

	appURL, _ := url.Parse(localApp.URL)
	_, appPortStr, _ := net.SplitHostPort(appURL.Host)
	appPort, _ := strconv.Atoi(appPortStr)

	// 2. Generate Ed25519 SSH keypair for keyless workstation tunnel auth
	keyDir := t.TempDir()
	sshPrivPath, _, err := EnsureSSHKeypair(keyDir)
	if err != nil {
		t.Fatalf("EnsureSSHKeypair: %v", err)
	}

	// 3. Mock Control Plane recording POST /api/v1/control/tunnels and DELETE /api/v1/control/tunnels/:id
	var (
		mu             sync.Mutex
		createdPayload map[string]any
		deletedIDs     []string
		meshTargetPort int
	)
	readyCh := make(chan struct{})

	cpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/control/tunnels":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			createdPayload = body
			meshTargetPort = int(body["target_port"].(float64))
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "created",
				"tunnel": map[string]any{
					"tunnel_id":   "tun_test_01",
					"domain":      "my-dev.example.com",
					"public_url":  "https://my-dev.example.com",
					"node_id":     "gateway-1",
					"target_ip":   "127.0.0.1",
					"target_port": meshTargetPort,
					"local_port":  appPort,
				},
			})
			close(readyCh)

		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v1/control/tunnels/"):
			id := strings.TrimPrefix(r.URL.Path, "/api/v1/control/tunnels/")
			mu.Lock()
			deletedIDs = append(deletedIDs, id)
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"closed"}`))

		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer cpSrv.Close()

	ctx, cancel := context.WithCancel(t.Context())
	var outBuf bytes.Buffer
	errCh := make(chan error, 1)

	go func() {
		errCh <- RunFunnel(ctx, FunnelOptions{
			LocalHost:  "127.0.0.1",
			LocalPort:  appPort,
			ListenIP:   "127.0.0.1",
			Subdomain:  "my-dev",
			BasicAuth:  "demo:secret123",
			HostHeader: "rewrite",
			ControlURL: cpSrv.URL,
			PeerID:     "dev-laptop",
			PublicKey:  "wgPubKeyTest123=",
			SSHKeyPath: sshPrivPath,
			Output:     &outBuf,
		})
	}()

	select {
	case <-readyCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for tunnel registration")
	}

	mu.Lock()
	sig, _ := createdPayload["ssh_signature"].(string)
	targetPort := meshTargetPort
	mu.Unlock()

	if sig == "" {
		t.Fatal("expected Ed25519 ssh_signature in tunnel registration request")
	}

	funnelEndpoint := "http://127.0.0.1:" + strconv.Itoa(targetPort) + "/webhooks/stripe"

	// Unauthenticated request must return 401 when --auth is set
	unauthResp, err := http.Post(funnelEndpoint, "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST unauth: %v", err)
	}
	_ = unauthResp.Body.Close()
	if unauthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without Basic Auth, got %d", unauthResp.StatusCode)
	}

	// Authenticated request simulating Traefik forwarding Public Host header
	authReq, _ := http.NewRequest(http.MethodPost, funnelEndpoint, strings.NewReader(`{"ok":true}`))
	authReq.Host = "my-dev.example.com"
	authReq.SetBasicAuth("demo", "secret123")
	authResp, err := http.DefaultClient.Do(authReq)
	if err != nil {
		t.Fatalf("POST auth: %v", err)
	}
	respBody, _ := io.ReadAll(authResp.Body)
	_ = authResp.Body.Close()

	if authResp.StatusCode != http.StatusCreated || string(respBody) != "webhook-accepted" {
		t.Fatalf("expected 201 webhook-accepted, got %d %q", authResp.StatusCode, string(respBody))
	}
	if receivedHost != "localhost:"+strconv.Itoa(appPort) {
		t.Fatalf("expected rewritten Host=localhost:%d, got %q", appPort, receivedHost)
	}
	if receivedFwdHost != "my-dev.example.com" || receivedFwdProto != "https" {
		t.Fatalf("expected X-Forwarded-Host=my-dev.example.com & Proto=https, got %q / %q", receivedFwdHost, receivedFwdProto)
	}

	// Cancel context (simulates Ctrl+C) -> must invoke DELETE /api/v1/control/tunnels/tun_test_01
	cancel()
	if runErr := <-errCh; runErr != nil {
		t.Fatalf("RunFunnel returned unexpected error: %v", runErr)
	}

	mu.Lock()
	gotDeleted := append([]string(nil), deletedIDs...)
	mu.Unlock()
	if len(gotDeleted) != 1 || gotDeleted[0] != "tun_test_01" {
		t.Fatalf("expected DELETE /api/v1/control/tunnels/tun_test_01 on exit, got %v", gotDeleted)
	}
}
