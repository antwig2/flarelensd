package deploy

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestSyncAndRemoveFunnelTunnel(t *testing.T) {
	routesDir := t.TempDir()
	flipper := NewTraefikRouteFlipper(routesDir)
	orch := NewOrchestrator(NewDockerRunner("mock"), NewHealthProber(), flipper, nil, "node-1", slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer orch.CloseAllFunnelTunnels()

	// Reject non-CGNAT target IP (prevents SSRF to arbitrary internal/LAN IPs)
	if _, err := orch.SyncFunnelTunnel(t.Context(), FunnelTunnelSpec{
		TunnelID:   "tun_bad",
		Domain:     "dev.example.com",
		TargetIP:   "127.0.0.1",
		TargetPort: 3000,
	}); err == nil {
		t.Fatalf("expected SyncFunnelTunnel to reject non-100.64.0.0/10 target_ip")
	}

	// Valid WireGuard CGNAT target writes funnel-tun-abc.yaml atomically
	upstream, err := orch.SyncFunnelTunnel(t.Context(), FunnelTunnelSpec{
		TunnelID:   "tun_abc",
		Domain:     "webhook-dev.example.com",
		TargetIP:   "100.64.0.99",
		TargetPort: 43120,
	})
	if err != nil {
		t.Fatalf("SyncFunnelTunnel failed: %v", err)
	}
	if upstream != "http://100.64.0.99:43120" {
		t.Fatalf("expected direct mesh upstream, got %q", upstream)
	}

	routeFile := filepath.Join(routesDir, "funnel-tun-abc.yaml")
	rawYaml, err := os.ReadFile(routeFile)
	if err != nil {
		t.Fatalf("expected route file %s to exist: %v", routeFile, err)
	}
	text := string(rawYaml)
	if !strings.Contains(text, "Host(`webhook-dev.example.com`)") || !strings.Contains(text, `http://100.64.0.99:43120`) {
		t.Fatalf("unexpected Traefik route YAML:\n%s", text)
	}

	// Test TCP bridge relay helper end-to-end
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello-through-bridge-relay"))
	}))
	defer backend.Close()

	u, _ := url.Parse(backend.URL)
	_, portStr, _ := net.SplitHostPort(u.Host)
	portNum, _ := strconv.Atoi(portStr)
	relay, err := startFunnelBridgeRelay("tun_relay", "127.0.0.1", "127.0.0.0/8", net.JoinHostPort("127.0.0.1", strconv.Itoa(portNum)))
	if err != nil {
		t.Fatalf("startFunnelBridgeRelay: %v", err)
	}
	defer relay.close()

	resp, err := http.Get("http://" + relay.listenAddr + "/test")
	if err != nil {
		t.Fatalf("GET via bridge relay failed: %v", err)
	}
	bodyBytes, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(bodyBytes) != "hello-through-bridge-relay" {
		t.Fatalf("unexpected relay body: %q", string(bodyBytes))
	}

	// RemoveFunnelTunnel deletes the Traefik route file cleanly
	orch.RemoveFunnelTunnel("tun_abc")
	if _, statErr := os.Stat(routeFile); !os.IsNotExist(statErr) {
		t.Fatalf("expected %s to be deleted after RemoveFunnelTunnel", routeFile)
	}
}
