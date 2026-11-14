package heartbeat

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/antwig2/flarelens/internal/config"
	"github.com/antwig2/flarelens/internal/transport"
)

func TestReporterPiggybackedHeartbeatSync(t *testing.T) {
	var ingestCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/ingest" {
			http.NotFound(w, r)
			return
		}
		ingestCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{
			"status":"ok",
			"count":1,
			"commands":[{"id":"cmd_1","type":"self_update","version":"v0.2.1"}],
			"flags_version":"fv_12345"
		}`))
	}))
	defer srv.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{}
	cfg.Identity.NodeID = "node-test-1"
	cfg.ControlPlane.Endpoint = srv.URL
	cfg.ControlPlane.EnrollToken = "token-1"

	// Start in-process embedded NATS to verify HTTP heartbeat still executes when NATS is active
	natsClient := transport.NewNATSClient("", "", logger)
	if err := natsClient.StartEmbedded(t.Context(), transport.EmbeddedOptions{DontListen: true}); err != nil {
		t.Fatalf("StartEmbedded failed: %v", err)
	}
	defer natsClient.Close()

	rep := NewReporter(cfg, nil, nil, natsClient, "0.2.1", logger)

	var gotCmdCount int
	var gotFlagsVer string
	var gotPiggybacked bool
	rep.SetSyncHandler(func(_ context.Context, commands []json.RawMessage, flagsVersion string, piggybacked bool) {
		gotCmdCount = len(commands)
		gotFlagsVer = flagsVersion
		gotPiggybacked = piggybacked
	})

	rep.sendHeartbeat(t.Context())

	if ingestCalls.Load() != 1 {
		t.Fatalf("expected 1 HTTP ingest call even with embedded NATS active, got %d", ingestCalls.Load())
	}
	if !gotPiggybacked {
		t.Fatal("expected piggybacked=true when flags_version is present")
	}
	if gotCmdCount != 1 {
		t.Fatalf("expected 1 piggybacked command, got %d", gotCmdCount)
	}
	if gotFlagsVer != "fv_12345" {
		t.Fatalf("expected flags_version fv_12345, got %q", gotFlagsVer)
	}
}

func TestReporterLegacyControlPlaneFallbackDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"ok","count":1}`))
	}))
	defer srv.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{}
	cfg.Identity.NodeID = "node-test-legacy"
	cfg.ControlPlane.Endpoint = srv.URL

	rep := NewReporter(cfg, nil, nil, nil, "0.2.1", logger)

	called := false
	gotPiggybacked := true
	rep.SetSyncHandler(func(_ context.Context, _ []json.RawMessage, _ string, piggybacked bool) {
		called = true
		gotPiggybacked = piggybacked
	})

	rep.sendHeartbeat(t.Context())

	if !called {
		t.Fatal("expected SyncHandler to be invoked on 202 response")
	}
	if gotPiggybacked {
		t.Fatal("expected piggybacked=false when control plane omits flags_version")
	}
}
